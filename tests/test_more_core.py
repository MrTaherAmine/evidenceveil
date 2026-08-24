from __future__ import annotations

import base64
import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from evidenceveil.classifiers import classify_field, classify_value
from evidenceveil.core.errors import (
    EvidenceVeilError,
    InputError,
    IntegrityError,
    PolicyError,
    VaultError,
)
from evidenceveil.core.models import ActionSpec, Policy
from evidenceveil.core.security import atomic_write, ensure_no_symlink
from evidenceveil.crypto.keys import load_key_file
from evidenceveil.discovery import discover, iter_files
from evidenceveil.formats.archive import extract_archive
from evidenceveil.formats.detect import detect_format, open_text
from evidenceveil.policies.engine import (
    choose_rule,
    default_action_for,
    load_policy,
    validate_policy,
)
from evidenceveil.risk.audit import audit_path
from evidenceveil.transforms.engine import TransformContext, apply_action, transform_obj
from evidenceveil.utility.validate import validate_contract
from evidenceveil.vault.envelope import read_vault, write_vault
from evidenceveil.verify import verify_bundle

ROOT = Path(__file__).resolve().parents[1]


def test_classify_more_fields_and_values():
    assert classify_field("foo_password", "x") == "authentication.secret"
    assert classify_field("contact_email", "x") == "identity.email"
    assert classify_field("client_ip", "x") == "network.ip"
    assert classify_field("server_hostname", "x") == "infrastructure.hostname"
    assert classify_field("my_session", "x") == "identifier.session"
    assert classify_field("random", "https://abc.example/a") == "network.url"
    assert classify_field("count", 4) is None
    assert "network.mac" in classify_value("02:11:22:33:44:55")
    assert classify_value("999.999.999.999") == []
    assert "authentication.token" not in classify_value("authorization: [SECRET_REMOVED]")


def test_key_file_forms_and_errors(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.write_bytes(b"r" * 32)
    assert load_key_file(raw) == b"r" * 32
    hx = tmp_path / "hex"
    hx.write_text((b"h" * 32).hex())
    assert load_key_file(hx) == b"h" * 32
    b64 = tmp_path / "b64"
    b64.write_bytes(base64.urlsafe_b64encode(b"b" * 32))
    assert load_key_file(b64) == b"b" * 32
    bad = tmp_path / "bad"
    bad.write_text("no")
    with pytest.raises(EvidenceVeilError):
        load_key_file(bad)
    wrong = tmp_path / "wrong"
    wrong.write_text("00" * 2)
    with pytest.raises(EvidenceVeilError):
        load_key_file(wrong)


def test_detect_all_common_formats(tmp_path: Path):
    cases = {
        "a.csv": "csv",
        "a.tsv": "tsv",
        "a.zip": "zip",
        "a.evtx": "evtx",
        "a.parquet": "parquet",
        "a.cef": "cef",
        "a.leef": "leef",
        "a.syslog": "syslog",
        "a.txt": "text",
    }
    contents = {
        "a.cef": "CEF:0|x",
        "a.leef": "LEEF:2.0|x",
        "a.syslog": "<34>1 2026-01-01 x",
        "a.txt": "hello",
    }
    for name, expected in cases.items():
        p = tmp_path / name
        if name == "a.zip":
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("x", "y")
        else:
            p.write_text(contents.get(name, "x"))
        assert detect_format(p) == expected
    g = tmp_path / "a.gz"
    with gzip.open(g, "wt") as f:
        f.write("hello\n")
    assert detect_format(g) == "gzip"
    with open_text(g) as f:
        assert f.read() == "hello\n"
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"a\x00b")
    assert detect_format(binary) == "binary-unsupported"


def test_archive_tar_success_and_limits(tmp_path: Path):
    t = tmp_path / "safe.tar"
    with tarfile.open(t, "w") as f:
        data = b"ok"
        info = tarfile.TarInfo("safe/x.txt")
        info.size = len(data)
        f.addfile(info, io.BytesIO(data))
    out = tmp_path / "out"
    files = extract_archive(t, out)
    assert files[0].read_bytes() == b"ok"
    with pytest.raises(InputError):
        extract_archive(t, tmp_path / "out2", max_files=0)
    with pytest.raises(InputError):
        extract_archive(t, tmp_path / "out3", max_bytes=1)
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("x", "123")
    with pytest.raises(InputError):
        extract_archive(z, tmp_path / "zo", max_files=0)
    with pytest.raises(InputError):
        extract_archive(z, tmp_path / "zo2", max_bytes=1)
    bogus = tmp_path / "x.dat"
    bogus.write_text("not archive")
    with pytest.raises(InputError):
        extract_archive(bogus, tmp_path / "bo")


def test_symlink_input_blocked(tmp_path: Path):
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(InputError):
        ensure_no_symlink(link)
    with pytest.raises(InputError):
        iter_files(link)


def test_discovery_file_and_uncertainty(tmp_path: Path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"user":{"email":"a@example.example"}}\n{bad}\n')
    d = discover(p)
    assert d.files[0].approximate_records == 2
    assert "x.jsonl" in d.parsing_uncertainty
    b = tmp_path / "b.bin"
    b.write_bytes(b"x\x00y")
    d2 = discover(b)
    assert "b.bin" in d2.unsupported


def test_policy_validation_branches(tmp_path: Path):
    bad_tlp = Policy.model_validate(
        {"id": "x", "title": "x", "tlp": {"label": "TLP:WHITE"}, "rules": []}
    )
    with pytest.raises(PolicyError):
        validate_policy(bad_tlp)
    bad_regex = Policy.model_validate(
        {
            "id": "x",
            "title": "x",
            "rules": [{"id": "r", "match": {"patterns": ["("]}, "action": {"type": "redact"}}],
        }
    )
    with pytest.raises(PolicyError):
        validate_policy(bad_regex)
    long_regex = Policy.model_validate(
        {
            "id": "x",
            "title": "x",
            "rules": [
                {"id": "r", "match": {"patterns": ["a" * 501]}, "action": {"type": "redact"}}
            ],
        }
    )
    with pytest.raises(PolicyError):
        validate_policy(long_regex)
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")
    broken = tmp_path / "broken.yaml"
    broken.write_text("- not: a-policy")
    with pytest.raises(PolicyError):
        load_policy(broken)


def test_choose_rule_all_match_kinds():
    p = Policy.model_validate(
        {
            "id": "x",
            "title": "x",
            "default_action": "drop",
            "rules": [
                {
                    "id": "field",
                    "priority": 1,
                    "match": {"fields": ["a"]},
                    "action": {"type": "redact"},
                },
                {
                    "id": "format",
                    "priority": 2,
                    "match": {"formats": ["json"]},
                    "action": {"type": "mask"},
                },
                {
                    "id": "pattern",
                    "priority": 3,
                    "match": {"patterns": ["foo"]},
                    "action": {"type": "tokenize"},
                },
            ],
        }
    )
    assert choose_rule(p, "a", None, "text", "x").id == "field"
    assert choose_rule(p, "z", None, "json", "x").id == "format"
    assert choose_rule(p, "z", None, "text", "foobar").id == "pattern"
    assert choose_rule(p, "z", None, "text", "none") is None
    assert default_action_for(p).type == "drop"
    p.default_action = "keep"
    assert default_action_for(p).type == "keep"


def test_all_transform_actions():
    p = load_policy("vendor-support")
    ctx = TransformContext(b"x" * 32, p, "json")
    assert apply_action("abcdef", ActionSpec(type="mask"), None, ctx, "f") == "ab**ef"
    assert apply_action("abc", ActionSpec(type="mask"), None, ctx, "f") == "***"
    assert str(
        apply_action("abc", ActionSpec(type="tokenize", namespace="x"), None, ctx, "f")
    ).startswith("tok_")
    assert apply_action(27, ActionSpec(type="bucket"), None, ctx, "f") == 20
    assert apply_action("abcdefghi", ActionSpec(type="truncate"), None, ctx, "f") == "abcdefgh"
    assert apply_action("x", ActionSpec(type="replace", replacement="Y"), None, ctx, "f") == "Y"
    assert apply_action("x", ActionSpec(type="redact"), None, ctx, "f") == "[REDACTED]"
    assert (
        apply_action("203.0.113.8", ActionSpec(type="generalize"), "network.ip", ctx, "f")
        == "203.0.113.0/24"
    )
    assert (
        apply_action("not-ip", ActionSpec(type="generalize"), "network.ip", ctx, "f")
        == "[GENERALIZED]"
    )
    assert apply_action("x", ActionSpec(type="generalize"), None, ctx, "f") == "[GENERALIZED]"
    assert (
        apply_action("2026-08-01T00:00:00Z", ActionSpec(type="shift"), "time.event", ctx, "f")
        != "2026-08-01T00:00:00Z"
    )
    assert apply_action("not-time", ActionSpec(type="shift"), "time.event", ctx, "f") == "not-time"
    assert apply_action(
        "host.example",
        ActionSpec(type="synthesize", namespace="h"),
        "infrastructure.hostname",
        ctx,
        "f",
    ).endswith(".example")
    assert apply_action(
        "https://real.invalid/a?q=1",
        ActionSpec(type="pseudonymize", namespace="u"),
        "network.url",
        ctx,
        "f",
    ).startswith("https://site-")
    mac = apply_action(
        "02:11:22:33:44:55", ActionSpec(type="pseudonymize", namespace="m"), "network.mac", ctx, "f"
    )
    assert str(mac).count(":") == 5
    uuid = apply_action(
        "550e8400-e29b-41d4-a716-446655440000",
        ActionSpec(type="pseudonymize", namespace="id"),
        "identifier.uuid",
        ctx,
        "f",
    )
    assert len(str(uuid)) == 36
    obj = transform_obj([{"email": "a@example.example"}], ctx)
    assert obj[0]["email"] != "a@example.example"


def test_risk_statuses(tmp_path: Path):
    safe = tmp_path / "safe"
    safe.mkdir()
    (safe / "x.json").write_text('{"x":"ok"}')
    assert audit_path(safe)["status"] == "eligible-for-controlled-review"
    review = tmp_path / "review"
    review.mkdir()
    (review / "x.txt").write_text("plain free text")
    assert audit_path(review)["status"] == "review-required"
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "x.txt").write_text("authorization: actualsecretvalue")
    assert audit_path(blocked)["status"] == "blocked"


def test_utility_contract_types(tmp_path: Path):
    orig = tmp_path / "o"
    san = tmp_path / "s"
    orig.mkdir()
    san.mkdir()
    (orig / "x.jsonl").write_text('{"a":1}\n')
    (san / "x.jsonl").write_text('{"a":1}\n')
    c = tmp_path / "c.yaml"
    c.write_text(
        """utility_contract_version: "1.0"\nrequirements:\n  - {id: a, type: stable_relationship}\n  - {id: b, type: temporal_order}\n  - {id: c, type: required_fields}\n  - {id: d, type: unknown}\n"""
    )
    r = validate_contract(orig, san, c)
    assert r["passed"] is False
    assert [x["passed"] for x in r["requirements"]] == [True, True, True, False]


def test_atomic_write_and_verify_errors(tmp_path: Path):
    p = tmp_path / "a/b"
    atomic_write(p, b"ok")
    assert p.read_bytes() == b"ok"
    with pytest.raises(IntegrityError):
        verify_bundle(tmp_path)
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "checksums.sha256").write_text("deadbeef  missing\n")
    with pytest.raises(IntegrityError):
        verify_bundle(root)


def test_vault_short_passphrase_and_malformed(tmp_path: Path):
    p = tmp_path / "v"
    with pytest.raises(VaultError):
        write_vault(p, "short", {})
    p.write_text("not-json")
    with pytest.raises(VaultError):
        read_vault(p, "this-is-long-enough")


def test_discovery_counts_csv_records_and_fields():
    from evidenceveil.discovery import discover

    root = Path(__file__).resolve().parents[1]
    result = discover(root / "samples/enterprise-incident")
    csv_info = next(f for f in result.files if f.path.endswith("records.csv"))
    assert csv_info.approximate_records == 2
    assert result.semantic_counts.get("identity.email", 0) >= 2


def test_audit_bundle_targets_sanitized_payload(tmp_path: Path):
    bundle = tmp_path / "bundle"
    sanitized = bundle / "sanitized"
    policy = bundle / "policy"
    sanitized.mkdir(parents=True)
    policy.mkdir()
    (sanitized / "event.log").write_text("safe event\n")
    (policy / "resolved-policy.yaml").write_text("title: policy metadata\n" * 50)

    result = audit_path(bundle)

    assert result["untransformed_free_text_records"] == 1
