from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from ..core.errors import EvidenceVeilError

MASTER_BYTES = 32


def generate_key() -> bytes:
    return os.urandom(MASTER_BYTES)


def load_key_file(path: Path) -> bytes:
    data = path.read_bytes().strip()
    if len(data) == MASTER_BYTES:
        return data
    try:
        decoded = bytes.fromhex(data.decode())
    except Exception:
        try:
            decoded = base64.urlsafe_b64decode(data)
        except Exception:
            raise EvidenceVeilError(
                "Key file must contain 32 raw bytes, hex, or URL-safe base64."
            ) from None
    if len(decoded) != MASTER_BYTES:
        raise EvidenceVeilError("Key material must decode to exactly 32 bytes.")
    return decoded


def derive(master: bytes, namespace: str, value: str, length: int = 16) -> str:
    msg = f"evidenceveil/v1/{namespace}\x00{value}".encode()
    digest = hmac.new(master, msg, hashlib.sha256).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=")[:length].lower()


def key_id(master: bytes) -> str:
    return hashlib.sha256(b"EvidenceVeil key id\x00" + master).hexdigest()[:16]
