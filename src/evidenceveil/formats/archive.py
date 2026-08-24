from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from ..core.errors import InputError

MAX_FILES = 10_000
MAX_BYTES = 10 * 1024 * 1024 * 1024


def _safe_target(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    if root.resolve() not in target.parents and target != root.resolve():
        raise InputError("Archive traversal attempt blocked.")
    return target


def extract_archive(
    path: Path, dest: Path, max_files: int = MAX_FILES, max_bytes: int = MAX_BYTES
) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total = 0
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            if len(infos) > max_files:
                raise InputError("Archive file-count limit exceeded.")
            for info in infos:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > max_bytes:
                    raise InputError("Archive uncompressed-size limit exceeded.")
                target = _safe_target(dest, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, target.open("wb") as out:
                    while chunk := src.read(1024 * 1024):
                        out.write(chunk)
                extracted.append(target)
        return extracted
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as t:
            members = t.getmembers()
            files = [m for m in members if m.isfile()]
            if len(files) > max_files:
                raise InputError("Archive file-count limit exceeded.")
            for member in files:
                if member.issym() or member.islnk():
                    raise InputError("Archive links are blocked.")
                total += member.size
                if total > max_bytes:
                    raise InputError("Archive uncompressed-size limit exceeded.")
                target = _safe_target(dest, member.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                tar_src = t.extractfile(member)
                if tar_src is None:
                    continue
                with tar_src, target.open("wb") as out:
                    while chunk := tar_src.read(1024 * 1024):
                        out.write(chunk)
                extracted.append(target)
        return extracted
    raise InputError("Unsupported archive format.")
