from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import TextIO

TEXT_EXTS = {".log", ".txt", ".syslog", ".cef", ".leef"}


def detect_format(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "jsonl"
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".tsv"):
        return "tsv"
    if name.endswith(".gz"):
        return "gzip"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        return "tar"
    if name.endswith(".evtx"):
        return "evtx"
    if name.endswith(".parquet"):
        return "parquet"
    head = path.read_bytes()[:4096]
    stripped = head.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            json.loads(path.read_text(encoding="utf-8"))
            return "json"
        except (UnicodeDecodeError, json.JSONDecodeError):
            if path.suffix.lower() == ".json":
                return "malformed-json"
    if path.suffix.lower() in TEXT_EXTS or b"\x00" not in head:
        text = head.decode("utf-8", errors="ignore")
        if text.startswith("CEF:"):
            return "cef"
        if text.startswith("LEEF:"):
            return "leef"
        if text.startswith("<") and " " in text[:100]:
            return "syslog"
        return "text"
    return "binary-unsupported"


def open_text(path: Path) -> TextIO:
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return path.open("r", encoding="utf-8", errors="replace", newline="")
