from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

from ..core.errors import InputError
from ..core.security import atomic_write, ensure_distinct_paths, sha256_file
from ..crypto.keys import generate_key, key_id, load_key_file
from ..discovery import discover, iter_files
from ..formats.detect import detect_format, open_text
from ..metadata import (
    AUTHOR_NAME,
    COPYRIGHT,
    GITHUB_HANDLE,
    LICENSE_ID,
    REPOSITORY,
    WEBSITE,
    attribution_dict,
)
from ..policies.engine import load_policy, policy_hash
from ..reporting.html import render_report
from ..risk.audit import audit_path
from ..transforms.engine import TransformContext, transform_obj, transform_text
from ..utility.validate import basic_utility
from ..vault.envelope import write_vault

SAFE_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _safe_csv_value(v: Any) -> Any:
    if isinstance(v, str) and v.startswith(SAFE_FORMULA_PREFIXES):
        return "'" + v
    return v


def _transform_file(src: Path, dst: Path, ctx: TransformContext) -> int:
    fmt = detect_format(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    if fmt == "json":
        data = json.loads(src.read_text(encoding="utf-8"))
        transformed = transform_obj(data, ctx)
        atomic_write(
            dst,
            (json.dumps(transformed, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode(),
        )
        return len(data) if isinstance(data, list) else 1
    if fmt == "jsonl":
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        with (
            src.open("r", encoding="utf-8") as inp,
            tmp.open("w", encoding="utf-8", newline="\n") as out,
        ):
            for line in inp:
                if not line.strip():
                    continue
                obj = json.loads(line)
                out.write(
                    json.dumps(transform_obj(obj, ctx), ensure_ascii=False, sort_keys=True) + "\n"
                )
                count += 1
        os.replace(tmp, dst)
        return count
    if fmt in {"csv", "tsv"}:
        delim = "," if fmt == "csv" else "\t"
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        with (
            src.open("r", encoding="utf-8", newline="") as inp,
            tmp.open("w", encoding="utf-8", newline="") as out,
        ):
            reader = csv.DictReader(inp, delimiter=delim)
            if reader.fieldnames is None:
                raise InputError("CSV/TSV input has no header.")
            writer = csv.DictWriter(
                out, fieldnames=reader.fieldnames, delimiter=delim, lineterminator="\n"
            )
            writer.writeheader()
            for row in reader:
                tr = transform_obj(row, ctx)
                writer.writerow({k: _safe_csv_value(tr.get(k, "")) for k in reader.fieldnames})
                count += 1
        os.replace(tmp, dst)
        return count
    if fmt in {"text", "gzip", "syslog", "cef", "leef"}:
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        with open_text(src) as inp, tmp.open("w", encoding="utf-8", newline="") as out:
            for line in inp:
                out.write(transform_text(line, ctx))
                count += 1
        os.replace(tmp, dst)
        return count
    raise InputError(f"Unsupported input format for sanitization: {fmt}")


def _checksums(root: Path) -> str:
    rows = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != "checksums.sha256":
            rows.append(f"{sha256_file(p)}  {p.relative_to(root).as_posix()}")
    return "\n".join(rows) + "\n"


def sanitize(
    input_path: Path,
    policy_value: str | Path,
    output: Path,
    *,
    key_file: Path | None = None,
    vault: Path | None = None,
    passphrase: str | None = None,
    report: bool = False,
    reproducible: bool = False,
    tlp: str | None = None,
) -> dict[str, Any]:
    ensure_distinct_paths(input_path, output)
    if output.exists():
        raise InputError("Output already exists; refusing to replace it.")
    if vault:
        v = vault.resolve(strict=False)
        o = output.resolve(strict=False)
        if o == v or o in v.parents:
            raise InputError("Vault must be outside the shareable output directory.")
    policy = load_policy(policy_value)
    key = load_key_file(key_file) if key_file else generate_key()
    inv = discover(input_path)
    if any(f.format.startswith("malformed") or f.format == "binary-unsupported" for f in inv.files):
        raise InputError("Unsupported or malformed input detected; sanitize refused.")
    p_hash = policy_hash(policy)
    input_fingerprint = hashlib.sha256(
        "".join(sorted(f.sha256 for f in inv.files)).encode()
    ).hexdigest()
    dataset_id = hashlib.sha256(f"{input_fingerprint}:{p_hash}".encode()).hexdigest()[:24]
    if reproducible:
        run_id = hashlib.sha256(key + f"{dataset_id}:{p_hash}".encode()).hexdigest()[:24]
    else:
        run_id = os.urandom(12).hex()
    stage = Path(
        tempfile.mkdtemp(
            prefix=".evidenceveil-stage-",
            dir=str(output.parent if output.parent.exists() else Path.cwd()),
        )
    )
    try:
        sanitized_root = stage / "sanitized"
        ctx = TransformContext(key, policy, "mixed")
        records = 0
        files = iter_files(input_path)
        base = input_path if input_path.is_dir() else input_path.parent
        for src in files:
            rel = src.relative_to(base)
            dst = sanitized_root / rel
            ctx.fmt = detect_format(src)
            records += _transform_file(src, dst, ctx)
        utility = basic_utility(inv, sanitized_root)
        risk = audit_path(sanitized_root)
        resolved = policy.model_dump(mode="json")
        if tlp:
            resolved.setdefault("tlp", {})["label"] = tlp
        (stage / "policy").mkdir(parents=True, exist_ok=True)
        (stage / "provenance").mkdir(parents=True, exist_ok=True)
        (stage / "review").mkdir(parents=True, exist_ok=True)
        (stage / "reports").mkdir(parents=True, exist_ok=True)
        atomic_write(
            stage / "policy/resolved-policy.yaml",
            yaml.safe_dump(resolved, sort_keys=False).encode(),
        )
        atomic_write(
            stage / "provenance/input-inventory.json",
            json.dumps(inv.model_dump(mode="json"), indent=2, sort_keys=True).encode(),
        )
        atomic_write(
            stage / "provenance/transformations.json",
            json.dumps({"counts": ctx.counts}, indent=2, sort_keys=True).encode(),
        )
        atomic_write(
            stage / "provenance/utility-results.json",
            json.dumps(utility, indent=2, sort_keys=True).encode(),
        )
        atomic_write(
            stage / "provenance/risk-findings.json",
            json.dumps(risk, indent=2, sort_keys=True).encode(),
        )
        atomic_write(
            stage / "review/quarantined-records.json", json.dumps(ctx.quarantine, indent=2).encode()
        )
        output_hashes = {
            p.relative_to(sanitized_root).as_posix(): sha256_file(p)
            for p in sorted(sanitized_root.rglob("*"))
            if p.is_file()
        }
        manifest = {
            "schema_version": "1.0",
            "tool": {"name": "EvidenceVeil", "version": "1.0.0", **attribution_dict()},
            "policy": {"id": policy.id, "sha256": p_hash},
            "run_id": run_id,
            "dataset_id": dataset_id,
            "input_hashes": {Path(f.path).name: f.sha256 for f in inv.files},
            "output_hashes": output_hashes,
            "source_formats": sorted({f.format for f in inv.files}),
            "records_processed": records,
            "transformation_counts": ctx.counts,
            "semantic_category_counts": inv.semantic_counts,
            "utility": utility,
            "risk_status": risk["status"],
            "tlp": tlp or (policy.tlp.label if policy.tlp else None),
            "key_id": key_id(key),
            "vault_id": hashlib.sha256(f"{dataset_id}:{key_id(key)}".encode()).hexdigest()[:16]
            if vault
            else None,
            "reproducible": reproducible,
            "warnings": [
                "EvidenceVeil reduces identified disclosure risks but cannot determine legal anonymisation or eliminate all re-identification risk."
            ],
        }
        atomic_write(
            stage / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode()
        )
        if report:
            atomic_write(
                stage / "reports/evidenceveil-report.html",
                render_report(manifest, risk, utility).encode(),
            )
        atomic_write(
            stage / "reports/executive-summary.md",
            (
                f"# EvidenceVeil Executive Summary\n\n"
                f"**Created and maintained by {AUTHOR_NAME}**  \n"
                f"{WEBSITE} · GitHub: {GITHUB_HANDLE}  \n"
                f"License: {LICENSE_ID}\n\n"
                f"Risk status: **{risk['status']}**\n\n"
                f"Records processed: {records}\n\n"
                "EvidenceVeil reduces identified disclosure risks but cannot determine legal anonymisation "
                "or eliminate all re-identification risk. Release decisions require the data owner’s review.\n\n"
                f"---\n{COPYRIGHT} · {REPOSITORY}\n"
            ).encode(),
        )
        atomic_write(
            stage / "reports/technical-report.json",
            json.dumps(
                {"manifest": manifest, "risk": risk, "utility": utility}, indent=2, sort_keys=True
            ).encode(),
        )
        atomic_write(stage / "checksums.sha256", _checksums(stage).encode())
        if vault:
            if not passphrase:
                raise InputError("A vault passphrase is required when --vault is used.")
            payload: dict[str, object] = {
                "vault_format_version": "1.0",
                "tool_version": "1.0.0",
                "dataset_id": dataset_id,
                "policy_hash": p_hash,
                "key_id": key_id(key),
                "master_key_hex": key.hex(),
                "mappings": ctx.mapping,
            }
            write_vault(vault, passphrase, payload)
        os.replace(stage, output)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
