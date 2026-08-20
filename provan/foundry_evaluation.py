from __future__ import annotations

import json
import secrets
import uuid
from typing import Any, Callable

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .session12r_validators import hard_qualification


SemanticCall = Callable[[str, dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]


def arm_a(source_bundle_digest: str, call: SemanticCall, budget: dict[str, Any]) -> dict[str, Any]:
    output, receipt = call("arm_a_one_pass", {"source_bundle_digest": source_bundle_digest})
    return {"schema_id": "provan.internal.foundry_baseline_arm.v1", "arm": "A", "label": "STRONG_FRONTIER_MODEL_PROMPT_BASELINE", "source_bundle_digest": source_bundle_digest, "steps": [{"role": "one_pass", "input_digest": source_bundle_digest, "output_digest": sha256_bytes(canonical_bytes(output)), "conversation_state": None, "previous_response_id": None, "background": False}], "output": output, "receipts": [receipt], "budget": budget}


def arm_b(source_bundle_digest: str, call: SemanticCall, budget: dict[str, Any]) -> dict[str, Any]:
    proposal, proposer_receipt = call("arm_b_proposer", {"source_bundle_digest": source_bundle_digest})
    proposal_digest = sha256_bytes(canonical_bytes(proposal))
    review, reviewer_receipt = call("arm_b_adversarial_reviewer", {"source_bundle_digest": source_bundle_digest, "proposal_digest": proposal_digest})
    review_digest = sha256_bytes(canonical_bytes(review))
    revision, revision_receipt = call("arm_b_revision", {"source_bundle_digest": source_bundle_digest, "proposal_digest": proposal_digest, "review_digest": review_digest})
    steps = [
        {"role": "proposer", "input_digests": [source_bundle_digest], "output_digest": proposal_digest},
        {"role": "fresh_adversarial_reviewer", "input_digests": [source_bundle_digest, proposal_digest], "output_digest": review_digest},
        {"role": "revision", "input_digests": [source_bundle_digest, proposal_digest, review_digest], "output_digest": sha256_bytes(canonical_bytes(revision))},
    ]
    for row in steps: row.update({"conversation_state": None, "previous_response_id": None, "background": False})
    if len({id(proposer_receipt), id(reviewer_receipt), id(revision_receipt)}) != 3:
        raise ProvanError("FOUNDRY_ARM_B_CALL_INDEPENDENCE_INVALID", "receipt identity reused")
    return {"schema_id": "provan.internal.foundry_baseline_arm.v1", "arm": "B", "label": "STRONG_FRONTIER_MODEL_MULTI_CALL_BASELINE", "source_bundle_digest": source_bundle_digest, "steps": steps, "output": revision, "receipts": [proposer_receipt, reviewer_receipt, revision_receipt], "budget": budget}


def opaque_outputs(outputs: dict[str, dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    if set(outputs) != {"A", "B", "STANDARD", "DEEP"}:
        raise ProvanError("FOUNDRY_EVALUATION_ARM_SET_INVALID", "arms")
    mapping: dict[str, str] = {}; randomized: dict[str, dict[str, Any]] = {}
    for arm in sorted(outputs):
        opaque = secrets.token_hex(16); mapping[opaque] = arm; randomized[opaque] = json.loads(json.dumps(outputs[arm]))
    return randomized, mapping


def adjudicate(
    *, case_digest: str, opaque: dict[str, dict[str, Any]], adjudicator_a: dict[str, Any], adjudicator_b: dict[str, Any],
    deterministic_metrics: dict[str, dict[str, Any]], protected_reviewer: dict[str, Any] | None,
) -> dict[str, Any]:
    opaque_ids = set(opaque)
    for label, result in (("A", adjudicator_a), ("B", adjudicator_b)):
        if result.get("blind") is not True or result.get("arm_labels_visible") is not False or set(result.get("outputs", {})) != opaque_ids or result.get("saw_other_adjudicator") is not False:
            raise ProvanError("FOUNDRY_ADJUDICATOR_BLINDING_INVALID", label)
    disagreements = []
    dispositions: dict[str, Any] = {}
    for opaque_id in opaque_ids:
        left = adjudicator_a["outputs"][opaque_id]; right = adjudicator_b["outputs"][opaque_id]
        if canonical_bytes(left) != canonical_bytes(right): disagreements.append(opaque_id)
        else: dispositions[opaque_id] = left
    same_family = adjudicator_a.get("model_family") == adjudicator_b.get("model_family")
    if disagreements:
        verdict = "FAIL_MATERIAL_DISAGREEMENT"
    elif same_family and (not protected_reviewer or protected_reviewer.get("verified_all_material_dispositions") is not True):
        verdict = "FAIL_SAME_FAMILY_WITHOUT_PROTECTED_REVIEW"
    else:
        verdict = "PASS"
    return {"schema_id": "provan.internal.semantic_adjudication.v1", "adjudication_id": str(uuid.uuid4()), "case_digest": case_digest, "opaque_output_digests": {key: sha256_bytes(canonical_bytes(value)) for key, value in opaque.items()}, "adjudicators": [{"id": adjudicator_a.get("adjudicator_id"), "provider_family": adjudicator_a.get("provider_family"), "model_family": adjudicator_a.get("model_family")}, {"id": adjudicator_b.get("adjudicator_id"), "provider_family": adjudicator_b.get("provider_family"), "model_family": adjudicator_b.get("model_family")}], "same_family": same_family, "protected_reviewer_required": same_family, "protected_reviewer_ref": protected_reviewer, "disagreements": sorted(disagreements), "agreed_dispositions": dispositions, "deterministic_metrics": deterministic_metrics, "verdict": verdict, "arm_identity_unblinded": False}


def hidden_qualification(cases: list[dict[str, Any]], *, wheel_sha256: str, freeze: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    domains = {row.get("domain") for row in cases}
    required = {"payment_state", "permission_identity", "api_schema", "multi_step_recovery", "ai_tool_authority", "clean_no_friction"}
    if domains != required or len(cases) != 6:
        raise ProvanError("FOUNDRY_HIDDEN_DOMAIN_SET_INVALID", "six exact domains required")
    if freeze.get("wheel_sha256") != wheel_sha256 or freeze.get("one_shot") is not True or freeze.get("implementation_agent_plaintext_access") is not False:
        raise ProvanError("FOUNDRY_HIDDEN_FREEZE_INVALID", wheel_sha256)
    results = []
    for case in cases:
        if case.get("wheel_sha256") != wheel_sha256 or case.get("adjudication", {}).get("verdict") != "PASS":
            raise ProvanError("FOUNDRY_HIDDEN_CASE_BINDING_INVALID", str(case.get("domain")))
        gate = hard_qualification(case["metrics"]); results.append({"case_digest": case["case_digest"], "domain": case["domain"], "hard_gate": gate, "adjudication_digest": sha256_bytes(canonical_bytes(case["adjudication"]))})
    passed = all(row["hard_gate"] == "PASS" for row in results)
    private = {"schema_id": "provan.internal.hidden_qualification.v1", "qualification_id": str(uuid.uuid4()), "wheel_sha256": wheel_sha256, "freeze_digest": sha256_bytes(canonical_bytes(freeze)), "cases": results, "standard": "QUALIFIED_BOUNDED" if passed else "IMPLEMENTED_UNQUALIFIED", "deep": "DEGRADED" if passed and freeze.get("deep_no_material_regression") is True and freeze.get("deep_only_limitation") == "SAME_PROVIDER_MODEL_FAMILY_INDEPENDENCE" else ("IMPLEMENTED_UNQUALIFIED" if freeze.get("deep_available") else "UNAVAILABLE"), "verdict": "PASS" if passed else "MATERIAL_HOLDOUT_FAILURE", "one_shot_consumed": True}
    public = {"schema_id": "provan.session12r_hidden_qualification_projection.v1", "sensitivity": "PUBLIC_SAFE", "private_evaluation_root": sha256_bytes(canonical_bytes(private)), "wheel_sha256": wheel_sha256, "holdout_count": 6, "domains": sorted(required), "standard": private["standard"], "deep": private["deep"], "verdict": private["verdict"], "item_level_feedback_published": False, "execution_available": False, "challenge_available": False}
    return private, public
