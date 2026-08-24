from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..core.errors import VaultError
from ..core.security import atomic_write

AAD = b"EvidenceVeil vault v1"


def _kdf(
    passphrase: str, salt: bytes, memory_kib: int = 65536, iterations: int = 3, parallelism: int = 1
) -> bytes:
    if len(passphrase) < 12:
        raise VaultError("Vault passphrase must be at least 12 characters.")
    return hash_secret_raw(
        passphrase.encode(),
        salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


def write_vault(path: Path, passphrase: str, payload: dict[str, object]) -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _kdf(passphrase, salt)
    plain = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    cipher = ChaCha20Poly1305(key).encrypt(nonce, plain, AAD)
    env = {
        "vault_version": "1.0",
        "kdf": {
            "name": "argon2id",
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 1,
            "salt": base64.b64encode(salt).decode(),
        },
        "aead": {"name": "chacha20-poly1305", "nonce": base64.b64encode(nonce).decode()},
        "ciphertext": base64.b64encode(cipher).decode(),
    }
    atomic_write(path, json.dumps(env, indent=2, sort_keys=True).encode())


def read_vault(path: Path, passphrase: str) -> dict[str, object]:
    try:
        env = json.loads(path.read_text(encoding="utf-8"))
        kdf = env["kdf"]
        salt = base64.b64decode(kdf["salt"])
        nonce = base64.b64decode(env["aead"]["nonce"])
        cipher = base64.b64decode(env["ciphertext"])
        key = _kdf(
            passphrase,
            salt,
            int(kdf["memory_kib"]),
            int(kdf["iterations"]),
            int(kdf["parallelism"]),
        )
        plain = ChaCha20Poly1305(key).decrypt(nonce, cipher, AAD)
        data = json.loads(plain)
        if not isinstance(data, dict):
            raise ValueError
        return data
    except VaultError:
        raise
    except Exception:
        raise VaultError("Vault authentication failed or the vault is malformed.") from None
