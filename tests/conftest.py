from __future__ import annotations

import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def apk_factory(tmp_path: Path):
    def create(entries: dict[str, bytes] | None = None, name: str = "sample.apk") -> Path:
        contents = {"AndroidManifest.xml": b"manifest"}
        if entries:
            contents.update(entries)
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in contents.items():
                archive.writestr(member, data)
        return path

    return create

