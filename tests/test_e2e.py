from __future__ import annotations

from pathlib import Path

import pytest

from evidenceveil.core.errors import InputError, IntegrityError, VaultError
from evidenceveil.packaging.bundle import sanitize
from evidenceveil.restore import restore
from evidenceveil.verify import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "enterprise-incident"


def test_full_sanitize_verify_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "bundle"
    vault = tmp_path / "vaults" / "demo.evlt"
    vault.parent.mkdir()
    original = {p.name: p.read_bytes() for p in SAMPLE.iterdir() if p.is_file()}
    manifest = sanitize(
        SAMPLE,
        ROOT / "policies/vendor-support.yaml",
        out,
        vault=vault,
        passphrase="this-is-a-test-passphrase",
        report=True,
    )
    assert out.exists() and vault.exists()
    assert not list(out.rglob("*.evlt"))
    assert verify_bundle(out)["valid"] is True
    assert (out / "reports/evidenceveil-report.html").exists()
    report_html = (out / "reports/evidenceveil-report.html").read_text(encoding="utf-8")
    assert "Taher Amine ELHOUARI" in report_html
    assert "https://www.taheramine.org" in report_html
    assert "MrTaherAmine" in report_html
    executive = (out / "reports/executive-summary.md").read_text(encoding="utf-8")
    assert "Taher Amine ELHOUARI" in executive
    assert manifest["tool"]["author"] == "Taher Amine ELHOUARI"
    assert manifest["tool"]["website"] == "https://www.taheramine.org"
    all_output = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (out / "sanitized").rglob("*")
        if p.is_file()
    )
    assert "SYNTHETIC-SECRET-DO-NOT-USE-123456" not in all_output
    assert "alice@corp.example" not in all_output
    assert "alice@example.example" not in all_output
    restored = tmp_path / "restored"
    r = restore(out / "sanitized", vault, restored, "this-is-a-test-passphrase")
    assert r["files_restored"] >= 1
    for name, content in original.items():
        assert (SAMPLE / name).read_bytes() == content
    assert manifest["risk_status"] in {
        "review-required",
        "eligible-for-controlled-review",
        "blocked",
    }


def test_wrong_passphrase_fails(tmp_path: Path):
    out = tmp_path / "bundle"
    vault = tmp_path / "demo.evlt"
    sanitize(SAMPLE, "vendor-support", out, vault=vault, passphrase="this-is-a-test-passphrase")
    with pytest.raises(VaultError):
        restore(out / "sanitized", vault, tmp_path / "restored", "this-is-the-wrong-password")


def test_output_exists_refused(tmp_path: Path):
    out = tmp_path / "bundle"
    out.mkdir()
    with pytest.raises(InputError):
        sanitize(SAMPLE, "vendor-support", out)


def test_vault_inside_output_refused(tmp_path: Path):
    out = tmp_path / "bundle"
    with pytest.raises(InputError):
        sanitize(
            SAMPLE,
            "vendor-support",
            out,
            vault=out / "secret.evlt",
            passphrase="this-is-a-test-passphrase",
        )


def test_bundle_tamper_detected(tmp_path: Path):
    out = tmp_path / "bundle"
    sanitize(SAMPLE, "vendor-support", out)
    target = next((out / "sanitized").rglob("*.jsonl"))
    target.write_text(target.read_text() + "tamper")
    with pytest.raises(IntegrityError):
        verify_bundle(out)


def test_reproducible_same_key(tmp_path: Path):
    key = tmp_path / "key.bin"
    key.write_bytes(b"a" * 32)
    a, b = tmp_path / "a", tmp_path / "b"
    ma = sanitize(SAMPLE, "vendor-support", a, key_file=key, reproducible=True)
    mb = sanitize(SAMPLE, "vendor-support", b, key_file=key, reproducible=True)
    assert ma["run_id"] == mb["run_id"]
    af = {
        p.relative_to(a / "sanitized"): p.read_bytes()
        for p in (a / "sanitized").rglob("*")
        if p.is_file()
    }
    bf = {
        p.relative_to(b / "sanitized"): p.read_bytes()
        for p in (b / "sanitized").rglob("*")
        if p.is_file()
    }
    assert af == bf


def test_different_keys_change_pseudonyms(tmp_path: Path):
    k1, k2 = tmp_path / "k1", tmp_path / "k2"
    k1.write_bytes(b"1" * 32)
    k2.write_bytes(b"2" * 32)
    a, b = tmp_path / "a", tmp_path / "b"
    sanitize(SAMPLE, "vendor-support", a, key_file=k1)
    sanitize(SAMPLE, "vendor-support", b, key_file=k2)
    assert (a / "sanitized/ecs.jsonl").read_bytes() != (b / "sanitized/ecs.jsonl").read_bytes()


def test_csv_formula_neutralized(tmp_path: Path):
    out = tmp_path / "bundle"
    sanitize(SAMPLE, "vendor-support", out, key_file=None)
    text = (out / "sanitized/records.csv").read_text()
    assert "'=CMD" in text
