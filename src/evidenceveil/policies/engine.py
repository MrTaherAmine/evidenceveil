from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from ..core.errors import PolicyError
from ..core.models import ActionSpec, Policy, Rule

VALID_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
ACTIONS = {
    "keep",
    "drop",
    "redact",
    "mask",
    "tokenize",
    "pseudonymize",
    "generalize",
    "bucket",
    "shift",
    "truncate",
    "replace",
    "synthesize",
    "hmac",
    "preserve",
    "quarantine",
}


def builtin_policy_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "builtin_policies"


def resolve_policy_path(value: str | Path) -> Path:
    p = Path(value)
    if p.exists():
        return p
    candidate = builtin_policy_dir() / (
        str(value) if str(value).endswith(".yaml") else f"{value}.yaml"
    )
    if candidate.exists():
        return candidate
    raise PolicyError("Policy could not be found.")


def load_policy(value: str | Path) -> Policy:
    path = resolve_policy_path(value)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        pol = Policy.model_validate(raw)
    except Exception as exc:
        raise PolicyError(f"Invalid policy structure: {type(exc).__name__}") from None
    validate_policy(pol)
    return pol


def validate_policy(policy: Policy) -> None:
    ids = [r.id for r in policy.rules]
    if len(ids) != len(set(ids)):
        raise PolicyError("Duplicate rule IDs are not allowed.")
    if policy.tlp and policy.tlp.label and policy.tlp.label not in VALID_TLP:
        raise PolicyError("Invalid TLP 2.0 designation.")
    for rule in policy.rules:
        if rule.action.type not in ACTIONS:
            raise PolicyError("Unknown action type.")
        if rule.action.type in {"keep", "preserve"} and any(
            s.startswith("authentication.") for s in rule.match.semantic_types
        ):
            raise PolicyError("Policies cannot explicitly preserve authentication secrets/tokens.")
        for pat in rule.match.patterns:
            if len(pat) > 500 or "(?R)" in pat:
                raise PolicyError("Unsafe or unsupported regular expression.")
            try:
                re.compile(pat)
            except re.error:
                raise PolicyError("Invalid regular expression.") from None


def policy_hash(policy: Policy) -> str:
    data = json.dumps(
        policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(data).hexdigest()


def choose_rule(
    policy: Policy, field: str, semantic: str | None, fmt: str, value: object
) -> Rule | None:
    matches: list[Rule] = []
    sval = str(value) if value is not None else ""
    for rule in policy.rules:
        m = rule.match
        ok = False
        if semantic and semantic in m.semantic_types:
            ok = True
        if field in m.fields or "*" in m.fields:
            ok = True
        if fmt in m.formats:
            ok = True
        if m.patterns and any(re.search(p, sval) for p in m.patterns):
            ok = True
        if ok:
            matches.append(rule)
    if not matches:
        return None
    matches.sort(key=lambda r: (r.priority, r.id), reverse=True)
    return matches[0]


def default_action_for(policy: Policy) -> ActionSpec:
    if policy.default_action == "keep":
        return ActionSpec(type="keep")
    if policy.default_action == "drop":
        return ActionSpec(type="drop")
    return ActionSpec(type="preserve")
