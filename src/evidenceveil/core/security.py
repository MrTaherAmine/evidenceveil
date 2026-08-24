from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path

from .errors import InputError

TERMINAL_ESC = "\x1b"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_display(value: str) -> str:
    return value.replace(TERMINAL_ESC, "\\x1b").replace("\r", "\\r")


def ensure_distinct_paths(input_path: Path, output_path: Path) -> None:
    inp = input_path.resolve()
    out = output_path.resolve(strict=False)
    if inp == out:
        raise InputError("In-place transformation is not supported.")
    if input_path.is_file() and out == inp.parent:
        raise InputError("Output directory cannot replace the input file location.")


def ensure_no_symlink(path: Path) -> None:
    if path.is_symlink():
        raise InputError("Symlink inputs are blocked by default.")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
