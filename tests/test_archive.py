import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from evidenceveil.core.errors import InputError
from evidenceveil.formats.archive import extract_archive


def test_zip_safe_extract(tmp_path: Path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("safe/x.txt", "ok")
    out = tmp_path / "out"
    files = extract_archive(z, out)
    assert files[0].read_text() == "ok"


def test_zip_traversal_blocked(tmp_path: Path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../escape.txt", "bad")
    with pytest.raises(InputError):
        extract_archive(z, tmp_path / "out")


def test_tar_traversal_blocked(tmp_path: Path):
    t = tmp_path / "evil.tar"
    with tarfile.open(t, "w") as f:
        data = b"bad"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        f.addfile(info, io.BytesIO(data))
    with pytest.raises(InputError):
        extract_archive(t, tmp_path / "out")
