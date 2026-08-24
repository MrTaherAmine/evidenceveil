from __future__ import annotations

from pathlib import Path

from .core.errors import IntegrityError
from .core.security import sha256_file


def verify_bundle(root: Path) -> dict[str, object]:
    checks = root / "checksums.sha256"
    if not checks.exists():
        raise IntegrityError("checksums.sha256 is missing.")
    checked = 0
    for line in checks.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        p = root / rel
        if not p.exists() or sha256_file(p) != expected:
            raise IntegrityError("Bundle integrity verification failed.")
        checked += 1
    return {"valid": True, "files_checked": checked}
