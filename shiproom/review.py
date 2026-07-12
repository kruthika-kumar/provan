from __future__ import annotations

import uuid

from .evidence import validate_module_result
from .models import EvidenceStatus
from .runs import RunStore


def validate_reviewer_result(result: dict, *, expected_module: str) -> list[str]:
    reasons: list[str] = []
    try: validate_module_result(result)
    except ValueError as exc: return [str(exc)]
    if result.get("module_id") != expected_module: reasons.append("claim outside reviewer mandate: module_id mismatch")
    for item in [*result.get("checks", []), *result.get("findings", [])]:
        evidence = item.get("evidence", [])
        reference = item.get("target") or any(e.get("reference") for e in evidence if isinstance(e, dict))
        if not reference: reasons.append("material result lacks an evidence reference")
        statuses = [item.get("evidence_status"), *(e.get("status") for e in evidence if isinstance(e, dict))]
        if EvidenceStatus.DETERMINISTIC in statuses and item.get("type") in {"model_review", "agent_review"}:
            reasons.append("model judgment is incorrectly labelled deterministic proof")
    return sorted(set(reasons))


class ReviewerCorrection:
    def __init__(self, store: RunStore, release_id: str): self.store, self.release_id, self.attempts = store, release_id, {}
    def submit(self, result: dict, *, expected_module: str, delegation_id: str, parent_event_id: str | None = None) -> dict:
        result_id = result.get("result_id") or f"result_{uuid.uuid4().hex[:12]}"; result = dict(result); result["result_id"] = result_id
        count = self.attempts.get(expected_module, 0); reasons = validate_reviewer_result(result, expected_module=expected_module)
        if not reasons:
            event_type = "revision_accepted" if count else "delegate_completed"
            self.store.append(self.release_id, event_type, parent_event_id=parent_event_id, module_id=expected_module, delegation_id=delegation_id, status="accepted", evidence_references=_references(result), metadata={"result_id": result_id, "revision_number": count})
            return {"status": "accepted", "result": result}
        self.attempts[expected_module] = count + 1
        self.store.append(self.release_id, "result_rejected", parent_event_id=parent_event_id, module_id=expected_module, delegation_id=delegation_id, status="rejected", metadata={"result_id": result_id, "rejection_reasons": reasons, "revision_number": count})
        if count >= 1: return {"status": "failed", "result_id": result_id, "reasons": reasons}
        revision = self.store.append(self.release_id, "revision_requested", parent_event_id=parent_event_id, module_id=expected_module, delegation_id=delegation_id, status="requested", metadata={"original_result_id": result_id, "rejection_reasons": reasons, "max_revisions": 1})
        return {"status": "revision_required", "result_id": result_id, "reasons": reasons, "revision_event_id": revision["event_id"]}


def _references(result: dict) -> list[str]:
    refs = []
    for item in [*result.get("checks", []), *result.get("findings", [])]:
        if item.get("target"): refs.append(item["target"])
        refs.extend(e["reference"] for e in item.get("evidence", []) if isinstance(e, dict) and e.get("reference"))
    return sorted(set(refs))
