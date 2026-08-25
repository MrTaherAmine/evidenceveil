from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from evidenceveil.core.models import ActionSpec
from evidenceveil.packaging.bundle import sanitize
from evidenceveil.policies.engine import load_policy
from evidenceveil.restore import restore
from evidenceveil.transforms import engine
from evidenceveil.transforms.engine import (
    TransformContext,
    apply_action,
    _map_ip,
    _record_mapping,
    preseed_ip_mappings,
    transform_text,
)

ISSUE_KEY_HEX = "27737e7498de65b7c4225311628d20a969fcc3b5ed950c7b495efd2233dd453d"


_SRC_RE = re.compile(r"src=([0-9.]+)")


def _src_ip(line: str) -> str:
    m = _SRC_RE.search(line)
    assert m is not None
    return m.group(1)


def test_issue_2_regression_collision_free_and_restorable() -> None:
    policy = load_policy("vendor-support")
    ctx = TransformContext(bytes.fromhex(ISSUE_KEY_HEX), policy, "text")
    line_a = "2026-01-10T08:00:01Z DENY src=13.73.109.75 dst=10.0.0.5 port=443 session=aaa-111\n"
    line_b = "2026-01-10T09:15:33Z DENY src=22.109.214.131 dst=10.0.0.9 port=80 session=bbb-222\n"

    out_a = transform_text(line_a, ctx)
    out_b = transform_text(line_b, ctx)
    mapped_a = _src_ip(out_a)
    mapped_b = _src_ip(out_b)

    assert mapped_a != mapped_b
    assert ctx.mapping[mapped_a] == "13.73.109.75"
    assert ctx.mapping[mapped_b] == "22.109.214.131"

    restored = out_a + out_b
    for pseudonym, original in ctx.mapping.items():
        restored = restored.replace(pseudonym, original)
    assert "src=13.73.109.75" in restored
    assert "src=22.109.214.131" in restored


def test_ipv4_collision_resolution_path_and_mapping_insert_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_policy("vendor-support")
    ctx = TransformContext(b"k" * 32, policy, "text")

    def fake_ip_probe_token(
        _ctx: TransformContext, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, probe: int
    ) -> int:  # pragma: no cover - probe behavior asserted via outputs
        if probe == 0:
            return 7
        return int(ip) + probe

    monkeypatch.setattr(engine, "_ip_probe_token", fake_ip_probe_token)

    first = _map_ip("8.8.8.8", ctx)
    _record_mapping(ctx, first, "8.8.8.8", scope="network.ip::network.ip")

    second = _map_ip("9.9.9.9", ctx)
    _record_mapping(ctx, second, "9.9.9.9", scope="network.ip::network.ip")

    assert first != second
    with pytest.raises(ValueError):
        _record_mapping(ctx, first, "1.1.1.1")


def test_forward_mapping_is_scoped_by_semantic_namespace() -> None:
    policy = load_policy("vendor-support")
    ctx = TransformContext(bytes.fromhex(ISSUE_KEY_HEX), policy, "text")

    generic = apply_action(
        "8.8.8.8",
        ActionSpec(type="pseudonymize", namespace="identifier.customer"),
        "identifier.customer",
        ctx,
        "customer.id",
    )
    ip_value = apply_action(
        "8.8.8.8",
        ActionSpec(type="pseudonymize", namespace="network.ip"),
        "network.ip",
        ctx,
        "src",
    )
    other_namespace = apply_action(
        "8.8.8.8",
        ActionSpec(type="pseudonymize", namespace="identifier.ticket"),
        "identifier.ticket",
        ctx,
        "ticket",
    )

    assert isinstance(generic, str)
    assert isinstance(ip_value, str)
    assert isinstance(other_namespace, str)
    assert generic != ip_value
    assert other_namespace != ip_value
    assert generic != other_namespace
    ipaddress.ip_address(ip_value)


def test_ipv4_collision_resolution_is_order_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_policy("vendor-support")
    ip_a = "8.8.8.8"
    ip_b = "9.9.9.9"

    def fake_ip_probe_token(
        _ctx: TransformContext, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, probe: int
    ) -> int:  # pragma: no cover - probe behavior asserted via outputs
        if probe == 0:
            return 7
        return int(ip) + probe

    monkeypatch.setattr(engine, "_ip_probe_token", fake_ip_probe_token)

    forward_results: list[dict[str, str]] = []
    for order in ([ip_a, ip_b], [ip_b, ip_a]):
        ctx = TransformContext(b"k" * 32, policy, "text")
        preseed_ip_mappings(order, ctx)
        forward_results.append({ip_a: _map_ip(ip_a, ctx), ip_b: _map_ip(ip_b, ctx)})

    assert forward_results[0] == forward_results[1]
    assert forward_results[0][ip_a] != forward_results[0][ip_b]


def test_stress_ipv4_deterministic_unique_and_roundtrip(tmp_path: Path) -> None:
    key_bytes = bytes.fromhex(ISSUE_KEY_HEX)
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(key_bytes)

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    public_ips = [f"11.{i // 256}.{i % 256}.1" for i in range(1000)]
    shared_ip = public_ips[42]

    file_a_lines = [
        f"2026-01-10T08:00:{i % 60:02d}Z ALLOW src={ip} dst=10.0.0.{(i % 9) + 1} session=s-{i}\n"
        for i, ip in enumerate(public_ips[:700])
    ]
    file_a_lines.append(
        f"2026-01-10T08:59:59Z ALLOW src={shared_ip} dst=10.1.0.1 session=repeat-a\n"
    )
    file_b_lines = [
        f"2026-01-10T09:00:{i % 60:02d}Z DENY src={ip} dst=192.168.1.{(i % 9) + 1} session=t-{i}\n"
        for i, ip in enumerate(public_ips[700:])
    ]
    file_b_lines.append(
        f"2026-01-10T09:59:59Z DENY src={shared_ip} dst=172.16.0.8 session=repeat-b\n"
    )
    (evidence / "a.log").write_text("".join(file_a_lines), encoding="utf-8")
    (evidence / "b.log").write_text("".join(file_b_lines), encoding="utf-8")

    out1 = tmp_path / "out1"
    vault = tmp_path / "case.evlt"
    sanitize(
        evidence,
        "vendor-support",
        out1,
        key_file=key_file,
        vault=vault,
        passphrase="this-is-a-test-passphrase",
        reproducible=True,
    )

    sanitized_a = (out1 / "sanitized" / "a.log").read_text(encoding="utf-8")
    sanitized_b = (out1 / "sanitized" / "b.log").read_text(encoding="utf-8")

    original_sources = public_ips[:700] + [shared_ip] + public_ips[700:] + [shared_ip]
    sanitized_sources = [
        _src_ip(line) for line in (sanitized_a + sanitized_b).splitlines() if "src=" in line
    ]
    assert len(sanitized_sources) == len(original_sources)

    seen: dict[str, str] = {}
    for original, sanitized in zip(original_sources, sanitized_sources, strict=True):
        previous = seen.get(original)
        if previous is None:
            seen[original] = sanitized
            continue
        assert previous == sanitized

    assert len(seen) == 1000
    assert len(set(seen.values())) == 1000

    shared_mapped_a = _src_ip(next(line for line in sanitized_a.splitlines() if "repeat-a" in line))
    shared_mapped_b = _src_ip(next(line for line in sanitized_b.splitlines() if "repeat-b" in line))
    assert shared_mapped_a == shared_mapped_b

    out2 = tmp_path / "out2"
    sanitize(evidence, "vendor-support", out2, key_file=key_file, reproducible=True)
    assert (out1 / "sanitized" / "a.log").read_bytes() == (
        out2 / "sanitized" / "a.log"
    ).read_bytes()
    assert (out1 / "sanitized" / "b.log").read_bytes() == (
        out2 / "sanitized" / "b.log"
    ).read_bytes()

    restored = tmp_path / "restored"
    restore(out1 / "sanitized", vault, restored, "this-is-a-test-passphrase")
    assert (restored / "a.log").read_text(encoding="utf-8") == (evidence / "a.log").read_text(
        encoding="utf-8"
    )
    assert (restored / "b.log").read_text(encoding="utf-8") == (evidence / "b.log").read_text(
        encoding="utf-8"
    )
