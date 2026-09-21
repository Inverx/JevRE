from __future__ import annotations

import hashlib
import zipfile

import pytest

from jevre.analyzer import ApkAnalysisError, _unsafe_member, analyze_apk


def test_analyzer_extracts_basic_metadata_without_member_contents(apk_factory, monkeypatch) -> None:
    apk = apk_factory(
        {
            "classes.dex": b"dex",
            "classes2.dex": b"dex2",
            "classes1.dex": b"not canonical",
            "nested/classes3.dex": b"nested",
            "lib/arm64-v8a/libflutter.so": b"native",
            "lib/armeabi-v7a/libapp.so": b"native",
            "assets/flutter_assets/kernel_blob.bin": b"asset",
            "assets/config.json": b"{}",
        }
    )
    expected_hash = hashlib.sha256(apk.read_bytes()).hexdigest()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("analyzer must not read or extract ZIP members")

    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "testzip", forbidden)
    result = analyze_apk(apk)

    assert result.sha256 == expected_hash
    assert result.state.dex_count == 2
    assert result.state.native_library_count == 2
    assert result.abis == ("arm64-v8a", "armeabi-v7a")
    assert result.asset_count == 2
    assert result.state.framework == "flutter"
    assert result.state.packer_suspected is None


def test_analyzer_detects_packer_and_mixed_framework(apk_factory) -> None:
    apk = apk_factory(
        {
            "classes.dex": b"dex",
            "lib/arm64-v8a/libjiagu.so": b"packer",
            "lib/arm64-v8a/libunity.so": b"unity",
            "assets/index.android.bundle": b"react native",
        }
    )

    result = analyze_apk(apk)

    assert result.state.packer_suspected is True
    assert result.state.framework == "mixed"
    assert "react_native" in " ".join(result.state.notes)
    assert "libjiagu.so" in " ".join(result.state.notes)


def test_analyzer_ignores_unsafe_member_paths(apk_factory, tmp_path) -> None:
    apk = apk_factory(
        {
            "classes.dex": b"dex",
            "../lib/arm64-v8a/libjiagu.so": b"unsafe",
            "\\assets\\index.android.bundle": b"unsafe",
            "/lib/arm64-v8a/libflutter.so": b"unsafe",
        }
    )

    result = analyze_apk(apk)

    assert result.state.native_library_count == 0
    assert result.state.packer_suspected is None
    assert result.state.framework == "android"
    assert any("unsafe ZIP member" in note for note in result.state.notes)
    assert not (tmp_path / "lib").exists()


def test_analyzer_rejects_corrupt_or_non_apk(tmp_path, apk_factory) -> None:
    corrupt = tmp_path / "corrupt.apk"
    corrupt.write_bytes(b"not a zip")
    with pytest.raises(ApkAnalysisError, match="ZIP archive"):
        analyze_apk(corrupt)

    missing_manifest = tmp_path / "missing.apk"
    with zipfile.ZipFile(missing_manifest, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    with pytest.raises(ApkAnalysisError, match="AndroidManifest"):
        analyze_apk(missing_manifest)

    with pytest.raises(ApkAnalysisError, match="regular file"):
        analyze_apk(tmp_path)


def test_analyzer_ignores_unknown_abis_and_empty_native_entries(apk_factory) -> None:
    entries = {f"lib/not-an-abi/libfake{index}.so": b"x" for index in range(8)}
    entries["lib/arm64-v8a/libempty.so"] = b""
    entries["classes.dex"] = b"dex"
    result = analyze_apk(apk_factory(entries))

    assert result.state.native_library_count == 0
    assert result.abis == ()
    assert result.state.framework == "android"
    assert any("nonstandard or empty" in note for note in result.state.notes)


def test_analyzer_rejects_nul_control_name_metadata() -> None:
    member = zipfile.ZipInfo("AndroidManifest.xml\x00junk")
    assert member.filename == "AndroidManifest.xml"
    assert _unsafe_member(member) is True


def test_analyzer_rejects_empty_or_duplicate_manifest(tmp_path) -> None:
    empty = tmp_path / "empty-manifest.apk"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"")
    with pytest.raises(ApkAnalysisError, match="Manifest.*empty"):
        analyze_apk(empty)

    duplicate = tmp_path / "duplicate-manifest.apk"
    with pytest.warns(UserWarning):
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"first")
            archive.writestr("AndroidManifest.xml", b"second")
    with pytest.raises(ApkAnalysisError, match="duplicate.*AndroidManifest"):
        analyze_apk(duplicate)
