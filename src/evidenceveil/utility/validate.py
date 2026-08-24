from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.models import DiscoveryResult
from ..discovery import discover


def basic_utility(original: DiscoveryResult, sanitized_root: Path) -> dict[str, Any]:
    san = discover(sanitized_root)
    return {
        "schema_validity": len(san.parsing_uncertainty) == 0,
        "original_files": len(original.files),
        "sanitized_files": len(san.files),
        "file_count_preserved": len(original.files) == len(san.files),
        "record_counts": {Path(f.path).name: f.approximate_records for f in san.files},
        "requested_invariants": [
            "event_order",
            "entity_correlation",
            "schema_validity",
            "field_types",
        ],
    }


def validate_contract(original: Path, sanitized: Path, contract: Path) -> dict[str, Any]:
    import yaml

    spec = yaml.safe_load(contract.read_text(encoding="utf-8"))
    result = {
        "contract_version": spec.get("utility_contract_version", "1.0"),
        "requirements": [],
        "passed": True,
    }
    orig = discover(original)
    san = discover(sanitized)
    for req in spec.get("requirements", []):
        typ = req.get("type")
        passed = True
        note = "checked structurally"
        if typ == "required_fields":
            # lightweight v1 check: sanitized files must parse and exist
            passed = bool(san.files) and not san.parsing_uncertainty
        elif typ == "temporal_order" or typ == "stable_relationship":
            passed = len(orig.files) == len(san.files)
        else:
            passed = False
            note = "unsupported utility requirement"
        result["requirements"].append(
            {"id": req.get("id"), "type": typ, "passed": passed, "note": note}
        )
        result["passed"] = bool(result["passed"] and passed)
    return result
