from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
import zipfile
from pathlib import Path

from .models import ApkAnalysis, ReverseState


DEX_PATTERN = re.compile(r"^classes(?:[2-9][0-9]*)?\.dex$")
NATIVE_LIBRARY_PATTERN = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")
MAX_APK_SIZE = 4 * 1024 * 1024 * 1024
MAX_MEMBERS = 50_000
KNOWN_ABIS = {
    "armeabi",
    "armeabi-v7a",
    "arm64-v8a",
    "x86",
    "x86_64",
    "mips",
    "mips64",
    "riscv64",
}

PACKER_LIBRARIES = {
    "libbaiduprotect.so",
    "libdexhelper.so",
    "libexecmain.so",
    "libjiagu.so",
    "libnqshield.so",
    "libprotectclass.so",
    "libsecexe.so",
    "libsecmain.so",
}
PACKER_ASSETS = {"assets/ijiami.dat"}


class ApkAnalysisError(ValueError):
    """Raised when the target cannot be inspected safely as an APK."""


def analyze_apk(target: str | Path) -> ApkAnalysis:
    path = Path(target).expanduser()
    if not path.exists():
        raise ApkAnalysisError(f"APK does not exist: {path}")
    if not path.is_file():
        raise ApkAnalysisError(f"APK target is not a regular file: {path}")

    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            file_size = handle.tell()
            if file_size > MAX_APK_SIZE:
                raise ApkAnalysisError("APK exceeds the 4 GiB MVP safety limit")
            _preflight_member_count(handle, file_size)
            handle.seek(0)
            digest = _sha256(handle)
            handle.seek(0)
            with zipfile.ZipFile(handle) as archive:
                members = archive.infolist()
    except ApkAnalysisError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ApkAnalysisError(f"cannot read APK as a ZIP archive: {exc}") from exc

    if len(members) > MAX_MEMBERS:
        raise ApkAnalysisError(f"APK contains more than {MAX_MEMBERS:,} ZIP members")

    unique: dict[str, zipfile.ZipInfo] = {}
    duplicates: set[str] = set()
    unsafe_count = 0
    for member in members:
        name = member.filename
        if _unsafe_member(member):
            unsafe_count += 1
            continue
        if name in unique:
            duplicates.add(name)
            continue
        unique[name] = member

    files = {
        name: member
        for name, member in unique.items()
        if not member.is_dir() and not name.endswith("/")
    }
    if "AndroidManifest.xml" not in files:
        raise ApkAnalysisError("archive is missing root AndroidManifest.xml")
    if "AndroidManifest.xml" in duplicates:
        raise ApkAnalysisError("archive contains duplicate root AndroidManifest.xml entries")
    if files["AndroidManifest.xml"].file_size <= 0:
        raise ApkAnalysisError("root AndroidManifest.xml is empty")

    names = set(files)
    dex_names = sorted(name for name in names if DEX_PATTERN.fullmatch(name))
    native_matches = [
        (name, NATIVE_LIBRARY_PATTERN.fullmatch(name)) for name in sorted(names)
    ]
    native = []
    ignored_native_count = 0
    for name, match in native_matches:
        if match is None:
            continue
        if (
            match.group(1) in KNOWN_ABIS
            and files[name].file_size > 0
            and not _is_symlink(files[name])
        ):
            native.append((name, match))
        else:
            ignored_native_count += 1
    abis = tuple(sorted({match.group(1) for _, match in native}))
    native_basenames = {match.group(2).casefold() for _, match in native}
    asset_names = sorted(name for name in names if name.startswith("assets/"))

    framework_hits: list[str] = []
    if "libflutter.so" in native_basenames or any(
        name.startswith("assets/flutter_assets/") for name in names
    ):
        framework_hits.append("flutter")
    if native_basenames & {"libunity.so", "libil2cpp.so"} or any(
        name.startswith("assets/bin/Data/") for name in names
    ):
        framework_hits.append("unity")
    if native_basenames & {"libreactnativejni.so", "libreactnative.so"} or (
        "assets/index.android.bundle" in names
    ):
        framework_hits.append("react_native")

    indicators: list[str] = []
    notes: list[str] = []
    if len(framework_hits) == 1:
        framework = framework_hits[0]
        indicators.append(f"Framework indicator: {framework}")
    elif framework_hits:
        framework = "mixed"
        hit_text = ", ".join(sorted(framework_hits))
        indicators.append(f"Multiple framework indicators: {hit_text}")
        notes.append(f"Multiple framework indicators detected: {hit_text}")
    else:
        framework = "android"

    packer_hits = sorted(
        (native_basenames & PACKER_LIBRARIES)
        | ({name.casefold() for name in names} & PACKER_ASSETS)
    )
    packer_suspected = True if packer_hits else None
    if packer_hits:
        packer_text = ", ".join(packer_hits)
        indicators.append(f"Packer indicator: {packer_text}")
        notes.append(f"Known packer artifact detected: {packer_text}")
    if duplicates:
        notes.append(f"Ignored {len(duplicates)} duplicate ZIP member name(s)")
    if unsafe_count:
        notes.append(f"Ignored {unsafe_count} unsafe ZIP member path(s)")
    if ignored_native_count:
        notes.append(
            f"Ignored {ignored_native_count} nonstandard or empty native library entry(s)"
        )

    state = ReverseState(
        framework=framework,
        dex_count=len(dex_names),
        native_library_count=len(native),
        packer_suspected=packer_suspected,
        notes=notes,
    )
    return ApkAnalysis(
        target=path.resolve(),
        sha256=digest,
        file_size=file_size,
        abis=abis,
        asset_count=len(asset_names),
        indicators=tuple(indicators),
        state=state,
    )


def _unsafe_member(member: zipfile.ZipInfo) -> bool:
    original = getattr(member, "orig_filename", member.filename)
    if original != member.filename or _contains_controls(original):
        return True
    return _unsafe_member_name(member.filename) or _is_symlink(member)


def _unsafe_member_name(name: str) -> bool:
    return (
        not name
        or name.startswith("/")
        or WINDOWS_DRIVE_PATTERN.match(name) is not None
        or "\\" in name
        or ".." in name.split("/")
    )


def _sha256(handle: object) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _contains_controls(value: str) -> bool:
    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)


def _is_symlink(member: zipfile.ZipInfo) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return mode != 0 and stat.S_ISLNK(mode)


def _preflight_member_count(handle: object, file_size: int) -> None:
    """Read EOCD before ZipFile allocates one ZipInfo per archive member."""

    tail_size = min(file_size, 65_557)
    handle.seek(file_size - tail_size)
    tail = handle.read(tail_size)
    signature = b"PK\x05\x06"
    offset = tail.rfind(signature)
    while offset >= 0:
        if len(tail) - offset >= 22:
            fields = struct.unpack_from("<4s4H2LH", tail, offset)
            disk_number, central_disk, disk_entries, total_entries = fields[1:5]
            comment_length = fields[7]
            if offset + 22 + comment_length == len(tail):
                if disk_number or central_disk or disk_entries != total_entries:
                    raise ApkAnalysisError("multi-disk ZIP archives are not supported")
                if total_entries == 0xFFFF:
                    raise ApkAnalysisError("ZIP64 member counts are outside the MVP safety limit")
                if total_entries > MAX_MEMBERS:
                    raise ApkAnalysisError(
                        f"APK contains more than {MAX_MEMBERS:,} ZIP members"
                    )
                return
        offset = tail.rfind(signature, 0, offset)
    raise ApkAnalysisError(
        "cannot read APK as a ZIP archive: end-of-central-directory record not found"
    )
