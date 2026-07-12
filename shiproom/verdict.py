from __future__ import annotations

from .models import DecisionResolution, Evidence, EvidenceStatus, FindingState, ReleaseState

TERMINAL_SUCCESS_STATES = {ReleaseState.READY, ReleaseState.SHIP_WITH_CONDITIONS}


def is_terminal_success(status: str) -> bool:
    return status in TERMINAL_SUCCESS_STATES


def finding_can_close(finding: dict) -> bool:
    if not finding.get("evidence"):
        return False
    return any(Evidence(**e).can_close() for e in finding["evidence"])


def close_finding(finding: dict, evidence: dict) -> dict:
    if not Evidence(**evidence).can_close():
        raise ValueError("independent acceptable evidence required for closure")
    finding = dict(finding)
    finding.setdefault("evidence", []).append(evidence)
    finding["state"] = FindingState.CLOSED
    return finding


def calculate(release: dict) -> dict:
    unresolved = [f for f in release.get("findings", []) if f.get("blocking") and f.get("state") not in {FindingState.CLOSED, FindingState.ACCEPTED_RISK}]
    if unresolved:
        return {"status": ReleaseState.HOLD, "reason_codes": ["VERIFIED_BLOCKER_UNRESOLVED"]}
    pending = [
        d for d in release.get("owner_decisions", [])
        if not d.get("choice") or d.get("resolution") not in {DecisionResolution.RESOLVED, DecisionResolution.ACCEPTED_CONDITION}
    ]
    if pending:
        return {"status": ReleaseState.AWAITING_OWNER, "reason_codes": ["OWNER_DECISION_REQUIRED"]}
    accepted = [f for f in release.get("findings", []) if f.get("state") == FindingState.ACCEPTED_RISK]
    accepted_decisions = [d for d in release.get("owner_decisions", []) if d.get("resolution") == DecisionResolution.ACCEPTED_CONDITION]
    status = ReleaseState.SHIP_WITH_CONDITIONS if accepted or accepted_decisions else ReleaseState.READY
    return {"status": status, "reason_codes": []}
