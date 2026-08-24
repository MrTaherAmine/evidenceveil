from pathlib import Path

import pytest

from evidenceveil.core.errors import InputError, VaultError
from evidenceveil.packaging.bundle import sanitize
from evidenceveil.restore import restore

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/enterprise-incident"


def test_restore_output_exists_and_dataset_mismatch(tmp_path: Path):
    out = tmp_path / "bundle"
    vault = tmp_path / "v.evlt"
    sanitize(SAMPLE, "vendor-support", out, vault=vault, passphrase="this-is-a-test-passphrase")
    existing = tmp_path / "restored"
    existing.mkdir()
    with pytest.raises(InputError):
        restore(out / "sanitized", vault, existing, "this-is-a-test-passphrase")
    with pytest.raises(VaultError):
        restore(
            out / "sanitized",
            vault,
            tmp_path / "other",
            "this-is-a-test-passphrase",
            expected_dataset_id="wrong",
        )
