from __future__ import annotations

import csv
import json
from pathlib import Path

from .classifiers import classify_field, classify_value
from .core.models import DiscoveryResult, FileInfo
from .core.security import ensure_no_symlink, sha256_file
from .formats.detect import detect_format, open_text

SUPPORTED = {
    "json",
    "jsonl",
    "csv",
    "tsv",
    "text",
    "gzip",
    "syslog",
    "cef",
    "leef",
}


def iter_files(root: Path, recursive: bool = True) -> list[Path]:
    ensure_no_symlink(root)
    if root.is_file():
        return [root]
    pat = "**/*" if recursive else "*"
    files = []
    for p in sorted(root.glob(pat)):
        if p.is_symlink():
            continue
        if p.is_file():
            files.append(p)
    return files


def _scan_obj(obj: object, counts: dict[str, int]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            sem = classify_field(str(k), v)
            if sem:
                counts[sem] = counts.get(sem, 0) + 1
            _scan_obj(v, counts)
    elif isinstance(obj, list):
        for v in obj:
            _scan_obj(v, counts)
    elif isinstance(obj, str):
        for sem in classify_value(obj):
            counts[sem] = counts.get(sem, 0) + 1


def discover(root: Path, recursive: bool = True) -> DiscoveryResult:
    infos: list[FileInfo] = []
    counts: dict[str, int] = {}
    unsupported: list[str] = []
    uncertainty: list[str] = []
    for path in iter_files(root, recursive):
        fmt = detect_format(path)
        approx = 0
        if fmt == "json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
                _scan_obj(obj, counts)
                approx = len(obj) if isinstance(obj, list) else 1
            except Exception:
                uncertainty.append(path.name)
        elif fmt in {"csv", "tsv"}:
            try:
                delimiter = "\t" if fmt == "tsv" else ","
                with open_text(path) as f:
                    reader = csv.DictReader(f, delimiter=delimiter)
                    for row in reader:
                        approx += 1
                        _scan_obj(row, counts)
            except (OSError, csv.Error):
                uncertainty.append(path.name)
        elif fmt in {"jsonl", "text", "gzip", "syslog", "cef", "leef"}:
            try:
                with open_text(path) as f:
                    for i, line in enumerate(f, 1):
                        approx = i
                        if fmt == "jsonl":
                            try:
                                _scan_obj(json.loads(line), counts)
                            except json.JSONDecodeError:
                                uncertainty.append(path.name)
                                break
                        else:
                            _scan_obj(line, counts)
            except OSError:
                uncertainty.append(path.name)
        elif fmt not in SUPPORTED:
            unsupported.append(path.name)
        infos.append(
            FileInfo(
                path=str(path),
                format=fmt,
                bytes=path.stat().st_size,
                sha256=sha256_file(path),
                approximate_records=approx,
            )
        )
    secrets = sum(v for k, v in counts.items() if k.startswith("authentication."))
    return DiscoveryResult(
        files=infos,
        semantic_counts=counts,
        potential_secrets=secrets,
        unsupported=unsupported,
        parsing_uncertainty=sorted(set(uncertainty)),
    )
