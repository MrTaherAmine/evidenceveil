from __future__ import annotations

import ipaddress
import re
from typing import Any

EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
TOKEN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*[^\s,;]{6,}"
)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

FIELD_MAP = {
    "user.name": "identity.username",
    "username": "identity.username",
    "user": "identity.username",
    "user.email": "identity.email",
    "email": "identity.email",
    "mail": "identity.email",
    "employee_id": "identity.employee_id",
    "customer_id": "identity.customer_id",
    "password": "authentication.secret",  # nosec B105
    "passwd": "authentication.secret",  # nosec B105
    "api_key": "authentication.secret",  # nosec B105
    "authorization": "authentication.token",
    "access_token": "authentication.token",
    "refresh_token": "authentication.token",
    "client_secret": "authentication.secret",  # nosec B105
    "cookie": "authentication.token",
    "jwt": "authentication.token",
    "source.ip": "network.ip",
    "destination.ip": "network.ip",
    "src_ip": "network.ip",
    "dst_ip": "network.ip",
    "ip": "network.ip",
    "host.name": "infrastructure.hostname",
    "hostname": "infrastructure.hostname",
    "computer_name": "infrastructure.hostname",
    "url.full": "network.url",
    "url": "network.url",
    "domain": "network.domain",
    "dns.question.name": "network.domain",
    "session.id": "identifier.session",
    "session_id": "identifier.session",
    "uuid": "identifier.uuid",
    "event.created": "time.event",
    "timestamp": "time.event",
    "@timestamp": "time.event",
    "time": "time.event",
    "mac": "network.mac",
    "mac_address": "network.mac",
    "aws.account.id": "cloud.aws.account",
    "account_id": "cloud.account",
    "tenant_id": "cloud.azure.tenant",
    "subscription_id": "cloud.azure.subscription",
    "project_id": "cloud.gcp.project",
    "kubernetes.namespace": "cloud.kubernetes.namespace",
    "namespace": "cloud.kubernetes.namespace",
    "repository": "cicd.repository",
    "repo": "cicd.repository",
}


def _norm(name: str) -> str:
    return name.strip().lower().replace("[", ".").replace("]", "").replace("_", "_")


def classify_field(name: str, value: Any) -> str | None:
    n = _norm(name)
    if n in FIELD_MAP:
        return FIELD_MAP[n]
    compact = n.replace("_", ".")
    if compact in FIELD_MAP:
        return FIELD_MAP[compact]
    if any(
        x in n for x in ("password", "secret", "api_key", "apikey", "access_token", "refresh_token")
    ):
        return "authentication.secret"  # nosec B105
    if "email" in n:
        return "identity.email"
    if n.endswith("ip") or ".ip" in n:
        return "network.ip"
    if "hostname" in n or n.endswith("host"):
        return "infrastructure.hostname"
    if "session" in n:
        return "identifier.session"
    if isinstance(value, str):
        vals = classify_value(value)
        return vals[0] if vals else None
    return None


def classify_value(value: str) -> list[str]:
    found: list[str] = []
    if JWT_RE.search(value):
        found.append("authentication.token")
    else:
        token_match = TOKEN_RE.search(value)
        if token_match:
            found.append("authentication.token")
    if EMAIL_RE.search(value):
        found.append("identity.email")
    for m in IP_RE.finditer(value):
        try:
            ipaddress.ip_address(m.group(0))
            found.append("network.ip")
            break
        except ValueError:
            pass
    if URL_RE.search(value):
        found.append("network.url")
    if UUID_RE.search(value):
        found.append("identifier.uuid")
    if MAC_RE.search(value):
        found.append("network.mac")
    return found
