from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ReleaseState(StrEnum):
    DRAFT = "DRAFT"
    CONTRACTED = "CONTRACTED"
    REVIEWING = "REVIEWING"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    AWAITING_OWNER = "AWAITING_OWNER"
    READY = "READY"
    HOLD = "HOLD"
    SHIP_WITH_CONDITIONS = "SHIP_WITH_CONDITIONS"


class EvidenceStatus(StrEnum):
    DETERMINISTIC = "deterministically_verified"
    BROWSER = "browser_observed"
    SOURCE = "source_verified"
    MODEL = "model_reviewed"
    OWNER = "owner_confirmed"
    AGENT = "agent_reported"
    MISSING = "missing_evidence"
    NA = "not_applicable"


class FindingState(StrEnum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    TASKED = "TASKED"
    FIXING = "FIXING"
    VERIFYING = "VERIFYING"
    CLOSED = "CLOSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    DEFERRED = "DEFERRED"
    BLOCKED = "BLOCKED"


class DecisionResolution(StrEnum):
    RESOLVED = "resolved"
    ACCEPTED_CONDITION = "accepted_condition"


@dataclass
class Evidence:
    status: str
    kind: str
    value: Any = None
    reference: str | None = None

    def can_close(self) -> bool:
        return self.status in {
            EvidenceStatus.DETERMINISTIC,
            EvidenceStatus.BROWSER,
            EvidenceStatus.SOURCE,
            EvidenceStatus.OWNER,
        }


@dataclass
class Finding:
    id: str
    criterion_id: str
    title: str
    severity: str
    blocking: bool
    state: str = FindingState.DETECTED
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Release:
    release_id: str
    repository: dict[str, Any]
    deployment: dict[str, Any]
    product: dict[str, Any]
    mode: str = "controlled"
    capabilities: dict[str, bool] = field(default_factory=dict)
    owner_constraints: list[str] = field(default_factory=list)
    schema_version: str = "release.v0"
    policies: dict[str, Any] = field(default_factory=lambda: {
        "max_immediate_owner_decisions": 2,
        "auto_fix_mode": "bounded",
        "auto_merge": False,
    })
    state: str = ReleaseState.CONTRACTED
    panel: dict[str, Any] = field(default_factory=lambda: {"selected_modules": [], "skipped_modules": []})
    checks: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    remediation_tasks: list[dict[str, Any]] = field(default_factory=list)
    owner_decisions: list[dict[str, Any]] = field(default_factory=list)
    verdict: dict[str, Any] = field(default_factory=lambda: {"status": "DRAFT", "reason_codes": []})
    telemetry: dict[str, Any] = field(default_factory=dict)
    integrations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Release":
        required = {"release_id", "repository", "deployment", "product"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"missing release fields: {sorted(missing)}")
        if data.get("schema_version", "release.v0") != "release.v0":
            raise ValueError("unsupported release schema")
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
