from __future__ import annotations

from pathlib import Path

from ..classifiers import classify_value
from ..formats.detect import detect_format, open_text

DISCLAIMER = "EvidenceVeil reduces identified disclosure risks but cannot determine legal anonymisation or eliminate all re-identification risk. Release decisions require the data owner’s review of purpose, recipients, auxiliary information, applicable law and organizational controls."


def audit_path(path: Path) -> dict[str, object]:
    counts: dict[str, int] = {}
    free_text = 0
    audit_root = path / "sanitized" if path.is_dir() and (path / "sanitized").is_dir() else path
    files = (
        [audit_root] if audit_root.is_file() else [p for p in audit_root.rglob("*") if p.is_file()]
    )
    for p in files:
        if (
            p.name in {"manifest.json", "checksums.sha256"}
            or "reports" in p.parts
            or "provenance" in p.parts
        ):
            continue
        fmt = detect_format(p)
        try:
            if fmt == "json":
                text = p.read_text(encoding="utf-8")
                values = [text]
            elif fmt in {"jsonl", "text", "gzip", "syslog", "cef", "leef", "csv", "tsv"}:
                with open_text(p) as f:
                    values = list(f)
                    if fmt in {"text", "syslog", "cef", "leef"}:
                        free_text += len(values)
            else:
                continue
            for v in values:
                for sem in classify_value(v):
                    counts[sem] = counts.get(sem, 0) + 1
        except OSError:
            continue
    secret_count = sum(v for k, v in counts.items() if k.startswith("authentication."))
    direct_count = sum(v for k, v in counts.items() if k.startswith("identity."))
    if secret_count:
        status = "blocked"
    elif direct_count or free_text:
        status = "review-required"
    else:
        status = "eligible-for-controlled-review"
    return {
        "status": status,
        "residual_counts": counts,
        "untransformed_free_text_records": free_text,
        "disclaimer": DISCLAIMER,
    }
