from __future__ import annotations

import html
import json
from typing import Any

from ..metadata import AUTHOR_NAME, COPYRIGHT, GITHUB_HANDLE, LICENSE_ID, REPOSITORY, WEBSITE


def render_report(manifest: dict[str, Any], risk: dict[str, Any], utility: dict[str, Any]) -> str:
    m = html.escape(json.dumps(manifest, indent=2, sort_keys=True))
    r = html.escape(json.dumps(risk, indent=2, sort_keys=True))
    u = html.escape(json.dumps(utility, indent=2, sort_keys=True))
    title = html.escape(f"EvidenceVeil Report — {manifest['run_id']}")
    author = html.escape(AUTHOR_NAME)
    website = html.escape(WEBSITE)
    repository = html.escape(REPOSITORY)
    github = html.escape(GITHUB_HANDLE)
    license_id = html.escape(LICENSE_ID)
    copyright_text = html.escape(COPYRIGHT)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="author" content="{author}"><title>{title}</title><style>
:root{{color-scheme:light dark;--bg:#07131f;--card:#0d2235;--text:#e9f2f7;--muted:#93aab9;--accent:#f39c12}}*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text)}}main{{max-width:1100px;margin:auto;padding:40px 20px}}h1,h2{{letter-spacing:-.02em}}a{{color:inherit}}.hero{{border-left:4px solid var(--accent);padding-left:18px}}.byline{{color:var(--muted);margin-top:8px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:24px 0}}.card{{background:var(--card);padding:18px;border-radius:12px}}pre{{white-space:pre-wrap;word-break:break-word;background:#02070c;padding:16px;border-radius:10px;overflow:auto}}.warn{{border:1px solid #a66c00;padding:16px;border-radius:10px}}footer{{margin-top:34px;padding-top:18px;border-top:1px solid rgba(147,170,185,.35);color:var(--muted);font-size:13px}}@media print{{body{{background:white;color:black}}.card,pre{{background:#f4f4f4;color:black}}.byline,footer{{color:#444}}}}</style></head><body><main><div class="hero"><h1>EvidenceVeil</h1><p>Share incident data without exposing the incident.</p><p class="byline"><strong>Created and maintained by {author}</strong><br><a href="{website}">{website}</a> · GitHub: {github}</p></div><div class="grid"><div class="card"><strong>Risk status</strong><br>{html.escape(str(manifest["risk_status"]))}</div><div class="card"><strong>Policy</strong><br>{html.escape(str(manifest["policy"]["id"]))}</div><div class="card"><strong>Records</strong><br>{manifest["records_processed"]}</div><div class="card"><strong>TLP</strong><br>{html.escape(str(manifest.get("tlp") or "Not set"))}</div></div><h2>Project attribution</h2><div class="card"><strong>{author}</strong><br>Creator &amp; maintainer of EvidenceVeil<br><a href="{website}">{website}</a><br><a href="{repository}">{repository}</a><br>License: {license_id}</div><h2>Utility</h2><pre>{u}</pre><h2>Residual risk</h2><pre>{r}</pre><h2>Manifest</h2><pre>{m}</pre><p class="warn">EvidenceVeil reduces identified disclosure risks but cannot determine legal anonymisation or eliminate all re-identification risk. Release decisions require the data owner’s review of purpose, recipients, auxiliary information, applicable law and organizational controls.</p><footer>{copyright_text} · EvidenceVeil {html.escape(str(manifest["tool"]["version"]))} · <a href="{website}">{website}</a></footer></main></body></html>'''
