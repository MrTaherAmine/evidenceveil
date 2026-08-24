from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceveil.classifiers import classify_field, classify_value
from evidenceveil.core.errors import InputError, PolicyError, VaultError
from evidenceveil.core.models import Policy
from evidenceveil.core.security import ensure_distinct_paths, safe_display
from evidenceveil.crypto.keys import derive, generate_key, key_id
from evidenceveil.formats.detect import detect_format
from evidenceveil.policies.engine import load_policy, validate_policy
from evidenceveil.transforms.engine import TransformContext, transform_obj, transform_text
from evidenceveil.vault.envelope import read_vault, write_vault

ROOT = Path(__file__).resolve().parents[1]


def test_classification_fields_and_values():
    assert classify_field("user.email", "x") == "identity.email"
    assert classify_field("authorization", "Bearer foo") == "authentication.token"
    assert "identity.email" in classify_value("alice@example.example")
    assert "network.ip" in classify_value("203.0.113.8")
    assert "identifier.uuid" in classify_value("550e8400-e29b-41d4-a716-446655440000")


def test_policy_load_all():
    for p in (ROOT / "policies").glob("*.yaml"):
        assert load_policy(p).id == p.stem


def test_policy_duplicate_rejected():
    raw = {
        "id": "bad",
        "title": "bad",
        "rules": [
            {
                "id": "x",
                "match": {"semantic_types": ["identity.email"]},
                "action": {"type": "redact"},
            },
            {
                "id": "x",
                "match": {"semantic_types": ["identity.username"]},
                "action": {"type": "redact"},
            },
        ],
    }
    with pytest.raises(PolicyError):
        validate_policy(Policy.model_validate(raw))


def test_policy_secret_keep_rejected():
    raw = {
        "id": "bad",
        "title": "bad",
        "rules": [
            {
                "id": "x",
                "match": {"semantic_types": ["authentication.secret"]},
                "action": {"type": "keep"},
            }
        ],
    }
    with pytest.raises(PolicyError):
        validate_policy(Policy.model_validate(raw))


def test_hmac_determinism_and_domain_separation():
    key = b"k" * 32
    assert derive(key, "a", "alice") == derive(key, "a", "alice")
    assert derive(key, "a", "alice") != derive(key, "b", "alice")
    assert derive(key, "a", "alice") != derive(b"z" * 32, "a", "alice")
    assert len(key_id(key)) == 16
    assert len(generate_key()) == 32


def test_transform_structured_preserves_correlation():
    pol = load_policy("vendor-support")
    ctx = TransformContext(b"k" * 32, pol, "json")
    obj = {
        "user": {"email": "alice@example.example", "name": "alice"},
        "source": {"ip": "203.0.113.9"},
        "authorization": "Bearer synthetic-secret-123456",
        "@timestamp": "2026-08-01T00:00:00Z",
    }
    a = transform_obj(obj, ctx)
    b = transform_obj(obj, ctx)
    assert a["user"]["email"] == b["user"]["email"]
    assert a["user"]["email"].endswith(".example")
    assert a["authorization"] == "[SECRET_REMOVED]"
    assert a["source"]["ip"] != obj["source"]["ip"]
    assert a["@timestamp"] != obj["@timestamp"]


def test_transform_text_no_secret_leak():
    pol = load_policy("vendor-support")
    ctx = TransformContext(b"x" * 32, pol, "text")
    raw = "alice@example.example 203.0.113.9 authorization: Bearer eyJabcde.abcdefgh.ijklmnop"
    out = transform_text(raw, ctx)
    assert "alice@example.example" not in out
    assert "203.0.113.9" not in out
    assert "eyJabcde" not in out
    assert "[SECRET_REMOVED]" in out


def test_safe_display():
    assert "\x1b" not in safe_display("x\x1b[31m")
    assert "\\x1b" in safe_display("x\x1b[31m")


def test_distinct_paths(tmp_path: Path):
    p = tmp_path / "a.txt"
    p.write_text("x")
    with pytest.raises(InputError):
        ensure_distinct_paths(p, p)


def test_format_detection(tmp_path: Path):
    j = tmp_path / "x.data"
    j.write_text('{"a":1}')
    assert detect_format(j) == "json"
    jl = tmp_path / "x.jsonl"
    jl.write_text('{"a":1}\n')
    assert detect_format(jl) == "jsonl"
    bad = tmp_path / "x.json"
    bad.write_text("{broken")
    assert detect_format(bad) == "malformed-json"


def test_vault_roundtrip_and_tamper(tmp_path: Path):
    p = tmp_path / "v.evlt"
    write_vault(p, "this-is-a-long-passphrase", {"mappings": {"x": "y"}, "dataset_id": "d"})
    assert read_vault(p, "this-is-a-long-passphrase")["dataset_id"] == "d"
    env = json.loads(p.read_text())
    env["ciphertext"] = env["ciphertext"][:-4] + "AAAA"
    p.write_text(json.dumps(env))
    with pytest.raises(VaultError):
        read_vault(p, "this-is-a-long-passphrase")
