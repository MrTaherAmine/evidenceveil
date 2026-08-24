#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PUBLIC_IPV4 = re.compile(
    r"\b(?:(?!10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d{1,3}\.){3}\d{1,3}\b"
)
LIVE_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|dev|app|cloud)\b", re.I)
SECRET = re.compile(
    r"(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*[^\s,;]{8,}"
)


def scan(root: Path) -> list[dict[str, object]]:
    findings = []
    for p in sorted(root.rglob("*")) if root.is_dir() else [root]:
        if not p.is_file() or p.suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".pdf",
            ".evlt",
        }:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for rule, regex, level in [
            ("EV001", SECRET, "error"),
            ("EV002", PUBLIC_IPV4, "warning"),
            ("EV003", LIVE_DOMAIN, "warning"),
        ]:
            if regex.search(text):
                findings.append(
                    {
                        "rule": rule,
                        "level": level,
                        "path": str(p),
                        "message": {
                            "EV001": "credential-like value found",
                            "EV002": "non-reserved public IPv4-like value found",
                            "EV003": "live-domain-like value found",
                        }[rule],
                    }
                )
    return findings


def sarif(findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EvidenceVeil Fixture Safety",
                        "rules": [{"id": "EV001"}, {"id": "EV002"}, {"id": "EV003"}],
                    }
                },
                "results": [
                    {
                        "ruleId": f["rule"],
                        "level": f["level"],
                        "message": {"text": f["message"]},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--sarif", type=Path)
    args = ap.parse_args()
    findings = scan(args.path)
    if args.sarif:
        args.sarif.write_text(json.dumps(sarif(findings), indent=2), encoding="utf-8")
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    return 1 if any(f["level"] == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
