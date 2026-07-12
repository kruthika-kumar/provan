from __future__ import annotations

from .models import Evidence, EvidenceStatus, FindingState, ReleaseState


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
    pending = [d for d in release.get("owner_decisions", []) if not d.get("choice")]
    if pending:
        return {"status": ReleaseState.AWAITING_OWNER, "reason_codes": ["OWNER_DECISION_REQUIRED"]}
    accepted = [f for f in release.get("findings", []) if f.get("state") == FindingState.ACCEPTED_RISK]
    status = ReleaseState.SHIP_WITH_CONDITIONS if accepted or release.get("owner_decisions") else ReleaseState.READY
    return {"status": status, "reason_codes": []}

