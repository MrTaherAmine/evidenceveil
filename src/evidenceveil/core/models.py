from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ActionType = Literal[
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
]


class MatchSpec(BaseModel):
    semantic_types: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    formats: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)


class ActionSpec(BaseModel):
    type: ActionType
    replacement: str | None = None
    namespace: str | None = None
    preserve_order: bool = False
    preserve_deltas: bool = False


class Rule(BaseModel):
    id: str
    priority: int = 0
    match: MatchSpec = Field(default_factory=MatchSpec)
    action: ActionSpec
    description: str | None = None
    rationale: str | None = None


class TLP(BaseModel):
    label: str | None = None
    set_by_user: bool = True


class Policy(BaseModel):
    policy_version: str = "1.0"
    id: str
    title: str
    release_model: str = "known-recipient"
    default_action: str = "review"
    key_scope: str = "per_run"
    tlp: TLP | None = None
    rules: list[Rule]
    utility: dict[str, Any] = Field(default_factory=dict)
    risk: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    category: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    count: int = 1
    message: str


class FileInfo(BaseModel):
    path: str
    format: str
    bytes: int
    sha256: str
    approximate_records: int = 0


class DiscoveryResult(BaseModel):
    files: list[FileInfo]
    semantic_counts: dict[str, int]
    potential_secrets: int
    unsupported: list[str] = Field(default_factory=list)
    parsing_uncertainty: list[str] = Field(default_factory=list)
    recommended_policy: str = "vendor-support"
