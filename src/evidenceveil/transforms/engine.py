from __future__ import annotations

import datetime as dt
import ipaddress
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..classifiers import EMAIL_RE, IP_RE, URL_RE, classify_field
from ..core.models import ActionSpec, Policy
from ..crypto.keys import derive
from ..policies.engine import choose_rule, default_action_for


class TransformContext:
    def __init__(self, key: bytes, policy: Policy, fmt: str, time_shift_seconds: int = 86400 * 17):
        self.key = key
        self.policy = policy
        self.fmt = fmt
        self.time_shift_seconds = time_shift_seconds
        self.mapping: dict[str, str] = {}
        self.forward_mapping: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.quarantine: list[dict[str, str]] = []

    def count(self, action: str) -> None:
        self.counts[action] = self.counts.get(action, 0) + 1


_PUBLIC_IPV4_POOL_BASE = int(ipaddress.IPv4Address("198.18.0.0"))
_PUBLIC_IPV4_POOL_SIZE = (1 << 17) - 2
_PRIVATE_IPV4_POOL_SIZE = 256 * 256 * 253


def _record_mapping(ctx: TransformContext, pseudonym: str, original: str) -> None:
    existing = ctx.mapping.get(pseudonym)
    if existing is not None and existing != original:
        raise ValueError(
            f"Mapping collision for pseudonym '{pseudonym}': "
            f"cannot map both '{existing}' and '{original}'."
        )
    existing_forward = ctx.forward_mapping.get(original)
    if existing_forward is not None and existing_forward != pseudonym:
        raise ValueError(
            f"Mapping conflict for original value '{original}': "
            f"existing pseudonym '{existing_forward}', attempted '{pseudonym}'."
        )
    ctx.mapping[pseudonym] = original
    ctx.forward_mapping[original] = pseudonym


def _ip_probe_token(
    ctx: TransformContext, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, probe: int
) -> int:
    return int.from_bytes(
        __import__("hmac")
        .new(
            ctx.key,
            b"ip\x00" + ip.packed + probe.to_bytes(4, "big", signed=False),
            __import__("hashlib").sha256,
        )
        .digest()[:16],
        "big",
    )


def _map_ip(value: str, ctx: TransformContext) -> str:
    existing = ctx.forward_mapping.get(value)
    if existing is not None:
        return existing
    ip = ipaddress.ip_address(value)
    max_probes = (
        _PRIVATE_IPV4_POOL_SIZE if ip.version == 4 and ip.is_private else _PUBLIC_IPV4_POOL_SIZE
    )
    if ip.version == 6:
        max_probes = 100_000
    for probe in range(max_probes):
        token = _ip_probe_token(ctx, ip, probe)
        if ip.version == 4:
            if ip.is_private:
                a = 10
                b = (token >> 8) & 255
                c = token & 255
                mapped = f"{a}.{b}.{c}.{1 + ((token >> 16) % 253)}"
            else:
                mapped = str(
                    ipaddress.IPv4Address(
                        _PUBLIC_IPV4_POOL_BASE + 1 + (token % _PUBLIC_IPV4_POOL_SIZE)
                    )
                )
        else:
            mapped = str(
                ipaddress.IPv6Address(
                    int(ipaddress.IPv6Address("2001:db8::")) + 1 + (token % ((1 << 96) - 2))
                )
            )
        owner = ctx.mapping.get(mapped)
        if owner is None or owner == value:
            return mapped
    raise RuntimeError(
        f"Unable to allocate unique pseudonym for IP '{value}': namespace exhausted after {max_probes} attempts."
    )


def _email(value: str, ctx: TransformContext, namespace: str) -> str:
    m = EMAIL_RE.fullmatch(value)
    if not m:
        return f"user-{derive(ctx.key, namespace, value, 12)}@example.example"
    local, domain = m.groups()
    mapped_domain = f"domain-{derive(ctx.key, namespace + '-domain', domain, 8)}.example"
    return f"user-{derive(ctx.key, namespace, value, 12)}@{mapped_domain}"


def _hostname(value: str, ctx: TransformContext, namespace: str) -> str:
    return f"host-{derive(ctx.key, namespace, value, 12)}.example"


def _url(value: str, ctx: TransformContext, namespace: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or "host"
        mapped_host = f"site-{derive(ctx.key, namespace + '-host', host, 8)}.example"
        port = f":{parts.port}" if parts.port else ""
        userless = mapped_host + port
        query = urlencode(
            [
                (k, f"v-{derive(ctx.key, namespace + '-query', k + v, 8)}")
                for k, v in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
        return urlunsplit((parts.scheme or "https", userless, parts.path, query, ""))
    except Exception:
        return f"https://site-{derive(ctx.key, namespace, value, 10)}.example/"


def _shift_time(value: str, ctx: TransformContext) -> str:
    raw = value.replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(raw)
        shifted = d + dt.timedelta(seconds=ctx.time_shift_seconds)
        out = shifted.isoformat()
        return out.replace("+00:00", "Z") if value.endswith("Z") else out
    except ValueError:
        return value


def apply_action(
    value: Any, action: ActionSpec, semantic: str | None, ctx: TransformContext, field: str
) -> Any:
    kind = action.type
    ctx.count(kind)
    if kind in {"keep", "preserve"}:
        return value
    if kind == "drop":
        return _DROP
    if kind == "redact":
        return action.replacement or "[REDACTED]"
    if kind == "replace":
        return action.replacement or "[REPLACED]"
    if kind == "quarantine":
        ctx.quarantine.append({"field": field, "reason": "policy quarantine"})
        return _DROP
    if not isinstance(value, str):
        if kind in {"generalize", "bucket"} and isinstance(value, (int, float)):
            return int(value // 10 * 10)
        return value
    namespace = action.namespace or semantic or "generic"
    if kind == "mask":
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    if kind in {"tokenize", "hmac"}:
        return f"tok_{derive(ctx.key, namespace, value, 16)}"
    if kind in {"pseudonymize", "synthesize"}:
        if semantic == "identity.email":
            out = _email(value, ctx, namespace)
        elif semantic == "network.ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                out = f"ip-{derive(ctx.key, namespace, value, 12)}"
            else:
                out = _map_ip(value, ctx)
        elif semantic == "infrastructure.hostname" or semantic == "network.domain":
            out = _hostname(value, ctx, namespace)
        elif semantic == "network.url":
            out = _url(value, ctx, namespace)
        elif semantic == "network.mac":
            h = derive(ctx.key, namespace, value, 12)
            out = ":".join(["02", h[0:2], h[2:4], h[4:6], h[6:8], h[8:10]])
        elif semantic == "identifier.uuid":
            raw = derive(ctx.key, namespace, value, 32)
            out = f"{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-a{raw[17:20]}-{raw[20:32]}"
        else:
            out = f"{namespace.split('.')[-1]}-{derive(ctx.key, namespace, value, 12)}"
        _record_mapping(ctx, out, value)
        return out
    if kind == "generalize":
        if semantic == "network.ip":
            try:
                ip = ipaddress.ip_address(value)
                return str(
                    ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)
                )
            except ValueError:
                return "[GENERALIZED]"
        return "[GENERALIZED]"
    if kind == "bucket":
        return "[BUCKETED]"
    if kind == "shift":
        return _shift_time(value, ctx)
    if kind == "truncate":
        return value[:8]
    return value


class _Drop:
    pass


_DROP = _Drop()


def transform_obj(obj: Any, ctx: TransformContext, prefix: str = "") -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            field = f"{prefix}.{k}" if prefix else str(k)
            # Structured containers are traversed first so a parent name such as
            # "user" or "host" cannot suppress policies for nested scalar fields.
            if isinstance(v, (dict, list)):
                out[k] = transform_obj(v, ctx, field)
                continue
            semantic = classify_field(field, v) or classify_field(str(k), v)
            rule = choose_rule(ctx.policy, field, semantic, ctx.fmt, v)
            action = rule.action if rule else default_action_for(ctx.policy)
            tv = apply_action(v, action, semantic, ctx, field)
            if tv is not _DROP:
                out[k] = tv
        return out
    if isinstance(obj, list):
        return [transform_obj(v, ctx, prefix) for v in obj]
    if isinstance(obj, str):
        return transform_text(obj, ctx)
    return obj


def transform_text(text: str, ctx: TransformContext) -> str:
    if "[SECRET_REMOVED]" in text or "[REDACTED]" in text:
        return text
    result = text
    # secrets first
    from ..classifiers import JWT_RE, TOKEN_RE

    result = JWT_RE.sub("[SECRET_REMOVED]", result)
    result = TOKEN_RE.sub(
        lambda m: m.group(0).split(":", 1)[0].split("=", 1)[0] + ": [SECRET_REMOVED]", result
    )
    # URLs before domains/IPs
    for m in list(URL_RE.finditer(result))[::-1]:
        val = m.group(0)
        out = _url(val, ctx, "url")
        _record_mapping(ctx, out, val)
        result = result[: m.start()] + out + result[m.end() :]
    for m in list(EMAIL_RE.finditer(result))[::-1]:
        val = m.group(0)
        out = _email(val, ctx, "identity")
        _record_mapping(ctx, out, val)
        result = result[: m.start()] + out + result[m.end() :]
    for m in list(IP_RE.finditer(result))[::-1]:
        val = m.group(0)
        try:
            ipaddress.ip_address(val)
        except ValueError:
            continue
        out = _map_ip(val, ctx)
        _record_mapping(ctx, out, val)
        result = result[: m.start()] + out + result[m.end() :]
    return result
