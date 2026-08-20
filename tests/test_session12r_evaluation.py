from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from provan.canonical import canonical_bytes, sha256_bytes
from provan.errors import ProvanError
from provan.foundry_evaluation import adjudicate, arm_b, hidden_qualification, opaque_outputs
from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS, ModelProvider, build_envelope, invoke_frozen_public_openai_responses
from provan.session12_validators import validate_model_egress_allowlist_serialized as validate_historical_model_egress_allowlist_serialized
from provan.session12r_validators import validate_model_egress_allowlist_serialized, validate_public_semantic_evidence_serialized


def test_arm_b_is_three_genuine_stateless_calls():
    calls = []
    def invoke(role, payload):
        calls.append((role, copy.deepcopy(payload))); return {"role": role}, {"receipt": len(calls), "calls": 1}
    result = arm_b("sha256:" + "1" * 64, invoke, {"total_tokens": 10000, "relative_to_deep": .9})
    assert [row[0] for row in calls] == ["arm_b_proposer", "arm_b_adversarial_reviewer", "arm_b_revision"]
    assert len(result["steps"]) == 3 and all(row["previous_response_id"] is None and row["conversation_state"] is None and row["background"] is False for row in result["steps"])
    assert calls[1][1]["proposal_digest"] == result["steps"][0]["output_digest"]
    assert calls[2][1]["review_digest"] == result["steps"][1]["output_digest"]


def test_public_semantic_evidence_recomputes_measurements_and_rejects_stale_cost():
    path = Path(__file__).parents[1] / "artifacts/session12/successor_closeout/public/real_use/public_semantic_evidence.v1.public.json"
    raw = path.read_bytes(); validate_public_semantic_evidence_serialized(raw)
    bad = json.loads(raw); bad["runs"][0]["role_receipts"][0]["cost_usd"] += 0.01
    with pytest.raises(ProvanError, match="SESSION12R_PUBLIC_ROLE_COST_MISMATCH"):
        validate_public_semantic_evidence_serialized(canonical_bytes(bad))


def test_historical_and_successor_model_egress_sets_are_exact_and_distinct():
    root = Path(__file__).parents[1]
    historical = (root / "artifacts/session12/public/model_egress_allowlist.v1.public.json").read_bytes()
    successor = (root / "artifacts/session12/successor_closeout/public/model_egress_allowlist.v1.public.json").read_bytes()
    validate_historical_model_egress_allowlist_serialized(historical)
    validate_model_egress_allowlist_serialized(successor)
    mixed = json.loads(successor)
    mixed["cases"][-1]["source_digests"] = ["sha256:" + "f" * 64]
    with pytest.raises(ProvanError, match="SESSION12R_MODEL_EGRESS_ALLOWLIST_INVALID"):
        validate_model_egress_allowlist_serialized(canonical_bytes(mixed))


def test_adjudicators_are_blind_and_disagreement_fails():
    opaque, mapping = opaque_outputs({key: {"value": key} for key in ("A", "B", "STANDARD", "DEEP")})
    assert not set(mapping.values()) & set(opaque)
    outputs = {key: {"material_pass": True} for key in opaque}
    left = {"adjudicator_id": "one", "provider_family": "p1", "model_family": "m1", "blind": True, "arm_labels_visible": False, "saw_other_adjudicator": False, "outputs": outputs}
    right = {**left, "adjudicator_id": "two", "provider_family": "p2", "model_family": "m2", "outputs": copy.deepcopy(outputs)}
    assert adjudicate(case_digest="sha256:" + "2" * 64, opaque=opaque, adjudicator_a=left, adjudicator_b=right, deterministic_metrics={}, protected_reviewer=None)["verdict"] == "PASS"
    right["outputs"][next(iter(opaque))] = {"material_pass": False}
    assert adjudicate(case_digest="sha256:" + "2" * 64, opaque=opaque, adjudicator_a=left, adjudicator_b=right, deterministic_metrics={}, protected_reviewer=None)["verdict"] == "FAIL_MATERIAL_DISAGREEMENT"


def test_same_family_requires_protected_reviewer():
    opaque, _ = opaque_outputs({key: {"value": key} for key in ("A", "B", "STANDARD", "DEEP")}); outputs = {key: {"pass": True} for key in opaque}
    left = {"adjudicator_id": "one", "provider_family": "p", "model_family": "m", "blind": True, "arm_labels_visible": False, "saw_other_adjudicator": False, "outputs": outputs}; right = {**left, "adjudicator_id": "two", "outputs": copy.deepcopy(outputs)}
    assert adjudicate(case_digest="sha256:" + "2" * 64, opaque=opaque, adjudicator_a=left, adjudicator_b=right, deterministic_metrics={}, protected_reviewer=None)["verdict"].startswith("FAIL")
    assert adjudicate(case_digest="sha256:" + "2" * 64, opaque=opaque, adjudicator_a=left, adjudicator_b=right, deterministic_metrics={}, protected_reviewer={"verified_all_material_dispositions": True})["verdict"] == "PASS"


def test_hidden_qualification_requires_six_domains_and_all_hard_gates():
    ones = {key: 1 for key in ("material_explicit_obligation_recall", "valid_acceptance", "near_valid_acceptance", "adversarial_rejection", "material_ambiguity_owner_routing", "material_oracle_disposition_completeness", "material_finding_disposition_coverage", "material_obligation_map_disposition", "material_verification_dimension_disposition", "material_mutation_plan_sensitivity", "non_material_mutation_stability")}; zeros = {key: 0 for key in ("unsupported_material_mandatory_criteria", "material_non_goal_errors", "exact_content_authority_errors", "implementation_authority_errors", "unaccounted_material_source", "wrongly_non_semantic_material_source", "wrongly_ignored_material_source", "unsupported_material_mappings_claimed_supported", "materially_irrelevant_patterns")}; metrics = {**ones, **zeros, "six_run_semantic_stability": True}
    wheel = "sha256:" + "3" * 64; domains = ["payment_state", "permission_identity", "api_schema", "multi_step_recovery", "ai_tool_authority", "clean_no_friction"]
    cases = [{"domain": domain, "case_digest": "sha256:" + str(index) * 64, "wheel_sha256": wheel, "adjudication": {"verdict": "PASS"}, "metrics": copy.deepcopy(metrics)} for index, domain in enumerate(domains, 1)]
    freeze = {"wheel_sha256": wheel, "one_shot": True, "implementation_agent_plaintext_access": False, "deep_available": True, "deep_no_material_regression": True, "deep_only_limitation": "SAME_PROVIDER_MODEL_FAMILY_INDEPENDENCE"}
    private, public = hidden_qualification(cases, wheel_sha256=wheel, freeze=freeze)
    assert private["standard"] == "QUALIFIED_BOUNDED" and private["deep"] == "DEGRADED" and public["holdout_count"] == 6
    cases[0]["metrics"]["material_non_goal_errors"] = 1
    private, _ = hidden_qualification(cases, wheel_sha256=wheel, freeze=freeze)
    assert private["verdict"] == "MATERIAL_HOLDOUT_FAILURE" and private["standard"] == "IMPLEMENTED_UNQUALIFIED"


def test_derived_public_role_block_requires_separate_operator_authorization(monkeypatch: pytest.MonkeyPatch):
    source = "frozen public source"; source_digest = sha256_bytes(source.encode("utf-8"))
    monkeypatch.setitem(FROZEN_PUBLIC_MODEL_EGRESS, "derived-public-fixture", (source_digest,))
    provider = ModelProvider("openai-responses-primary", "gpt-5.6-sol", "semantic-successor-v1", "https://api.openai.com", "high")
    envelope = build_envelope(case_id="sha256:" + "1" * 64, candidate_digest="sha256:" + "2" * 64, provider=provider, instructions="public role prompt", blocks=[{"category": "frozen_public_intent", "content": source}, {"category": "derived_public_audit_input", "content": '{"candidate":"bounded"}'}])
    authorization = {"case_id": "derived-public-fixture", "classification": "PUBLIC_SAFE", "operator_confirmed": True}
    with pytest.raises(ProvanError, match="MODEL_EGRESS_NOT_AUTHORIZED"):
        invoke_frozen_public_openai_responses(provider, envelope, "unused", authorization)
