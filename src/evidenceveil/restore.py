from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from .core.errors import InputError, VaultError
from .formats.detect import detect_format
from .metadata import attribution_dict
from .vault.envelope import read_vault


def _restore_text(text: str, mapping: dict[str, str]) -> str:
    for sanitized in sorted(mapping, key=len, reverse=True):
        text = text.replace(sanitized, mapping[sanitized])
    return text


def restore(
    input_path: Path,
    vault: Path,
    output: Path,
    passphrase: str,
    expected_dataset_id: str | None = None,
) -> dict[str, object]:
    if output.exists():
        raise InputError("Restore output already exists.")
    data = read_vault(vault, passphrase)
    if expected_dataset_id and data.get("dataset_id") != expected_dataset_id:
        raise VaultError("Vault does not match this dataset.")
    mapping_raw = data.get("mappings")
    if not isinstance(mapping_raw, dict):
        raise VaultError("Vault has no valid mapping table.")
    mapping = {str(k): str(v) for k, v in mapping_raw.items()}
    stage = Path(
        tempfile.mkdtemp(
            prefix=".evidenceveil-restore-",
            dir=str(output.parent if output.parent.exists() else Path.cwd()),
        )
    )
    try:
        files = (
            [input_path]
            if input_path.is_file()
            else [p for p in sorted(input_path.rglob("*")) if p.is_file()]
        )
        base = input_path if input_path.is_dir() else input_path.parent
        restored = 0
        for src in files:
            rel = src.relative_to(base)
            dst = stage / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            fmt = detect_format(src)
            if fmt in {"json", "jsonl", "text", "syslog", "cef", "leef", "csv", "tsv"}:
                text = src.read_text(encoding="utf-8")
                dst.write_text(_restore_text(text, mapping), encoding="utf-8")
            else:
                shutil.copy2(src, dst)
            restored += 1
        manifest = {
            "dataset_id": data.get("dataset_id"),
            "files_restored": restored,
            "restoration_type": "mapping restoration; irreversible transformations remain irreversible",
            "tool": {
                "name": "EvidenceVeil",
                "version": data.get("tool_version", "1.0.0"),
                **attribution_dict(),
            },
        }
        (stage / "restoration-manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        os.replace(stage, output)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
