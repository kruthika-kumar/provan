"""Closed validators for canonical Sessions 6--8 persisted contracts.

These validators are intentionally explicit.  They are production loader
boundaries, not a generic JSON walker, and keep each canonical artifact's
top-level contract closed while the owning loader rederives cross-file
semantics and hashes.
"""
from __future__ import annotations

from typing import Any
import re

from shiproom.workflow_audit import observed_boundary


SHAPES: dict[str, tuple[str | None, frozenset[str]]] = {
    "remediation_source_packet": ("remediation-source-packet.v1", frozenset({"schema_version","preparation_id","authority","issues","contract_schema_hashes"})),
    "remediation_work_orders": ("remediation-work-orders.v1", frozenset({"schema_version","compiler_version","preparation_id","authority","source_packet_hash","contract_schema_hashes","planner_work_order","manifest_hash"})),
    "remediation_active_pointer": ("active-remediation-preparation.v1", frozenset({"schema_version","preparation_id","manifest_hash"})),
    "remediation_current_pointer": ("current-remediation-generation.v1", frozenset({"schema_version","generation","manifest_hash","semantic_bundle_hash"})),
    "remediation_generation_manifest": ("remediation-generation-manifest.v1", frozenset({"schema_version","compiler_version","generation","release_id","release_commit","authority","preparation_id","artifact_hashes","semantic_bundle_hash","bundle_hash"})),
    "remediation_index": ("remediation-index.v1", frozenset({"schema_version","release_id","authority","remediation_ids"})),
    "remediation_plan": ("remediation-plan.v1", frozenset({"schema_version","release_id","packets"})),
    "remediation_overlay": ("remediation-overlay.v1", frozenset({"schema_version","nodes"})),
    "remediation_packet": (None, frozenset({"remediation_id","source_issue_id","source_issue_type","requirement_id","criterion_id","journey_ids","issue_classification","issue_authority","evidence_refs","automation_eligibility","automation_class","allowed_closure_evidence_classes","protected_invariants","execution_modes","root_cause_hypotheses","recommended_changes","test_proposals","instrumentation_implications","rollback_suggestions","complexity","risk","suggested_owner","assumptions","limitations","user_or_business_impact","verification_contract_id"})),
    "remediation_closure_contract": (None, frozenset({"closure_contract_id","remediation_id","original_issue_id","original_criterion_id","original_failure_evidence","required_before_state","required_after_evidence","exact_checks_to_rerun","test_requirements","instrumentation_requirements","regression_checks","protected_invariants","evidence_classes_allowed_to_close","independent_verifier_requirement","owner_decision_requirement","source_generation","release_commit","allowed_repository_commit","allowed_branch","expiry_or_stale_bindings"})),
    "review_generation_manifest": ("review-plan-generation-manifest.v1", frozenset({"schema_version","compiler_version","generation","plan_id","input_vector","artifact_hashes","semantic_bundle_hash","bundle_hash"})),
    "review_current_pointer": ("current-review-plan.v1", frozenset({"schema_version","generation","manifest_hash","semantic_bundle_hash"})),
    "review_plan": ("review-plan.v1", frozenset({"schema_version","plan_id","input_vector","specialists","adaptation_depth","supersedes"})),
    "review_plan_events": ("plan-events.v1", frozenset({"schema_version","events"})),
    "review_revision_ledger": ("revision-ledger.v1", frozenset({"schema_version","entries"})),
    "review_accepted_results": ("accepted-specialist-results.v1", frozenset({"schema_version","results"})),
    "review_execution_summary_initial": ("execution-summary.v1", frozenset({"schema_version","execution_modes"})),
    "review_execution_summary_adapted": ("execution-summary.v1", frozenset({"schema_version","execution_modes","active_specialists","adaptation_event_id"})),
    "review_specialist_work_order": ("specialist-work-order.v1", frozenset({"schema_version","work_order_id","plan_id","specialist_id","role_version","result_schema","input_vector_hash","allowed_files","execution_mode","harness_capability_manifest","revision_policy","native_boundary","native_binding"})),
    "review_submission_validation": ("specialist-submission-validation.v1", frozenset({"schema_version","status","reason","json_pointers","result_snapshot_hash","receipt_snapshot_hash"})),
    "contestation_generation_manifest": ("contestation-generation-manifest.v1", frozenset({"schema_version","compiler_version","generation","release_id","actions_hash","artifact_hashes","semantic_bundle_hash"})),
    "contestation_current_pointer": ("current-contestation-generation.v1", frozenset({"schema_version","generation","manifest_hash","semantic_bundle_hash"})),
    "contestation_ledger": ("contestation-ledger.v1", frozenset({"schema_version","release_id","actions"})),
    "contestation_effects": ("contestation-effects.v1", frozenset({"schema_version","named_risk_effects","remediation_requests","immediate_owner_decisions","overflow_owner_decisions","priority_reason_codes","source_references"})),
    "management_generation_manifest": ("management-generation-manifest.v1", frozenset({"schema_version","compiler_version","generation","release_id","artifact_dependency_vector","artifact_hashes","semantic_bundle_hash","bundle_hash"})),
    "management_current_pointer": ("current-management-generation.v1", frozenset({"schema_version","generation","manifest_hash","semantic_bundle_hash"})),
    "management_executive_release_brief": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","recommendation","verified_blockers","unknowns"})),
    "management_product_release_review": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","matrix"})),
    "management_engineering_release_assessment": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","repository"})),
    "management_measurement_ai_readiness": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","authority_note","canonical_artifacts"})),
    "management_remediation_overview": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","remediation_dependency","canonical_artifacts"})),
    "management_release_packet_index": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","artifacts"})),
    "management_release_recommendation_view": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","computed_recommendation","canonical_finding_state","owner_decision_state","contestation"})),
    "management_github_payload": (None, frozenset({"release_id","artifact_dependency_vector","sections","section_contracts","section_records","recommendation","local_references"})),
}


@observed_boundary
def validate_canonical_contract(contract_id: str, value: Any) -> dict:
    """Validate an exact canonical artifact shape and its local invariants."""
    if contract_id not in SHAPES:
        raise ValueError("session6_8_canonical_contract_unregistered:" + contract_id)
    if not isinstance(value, dict):
        raise ValueError(contract_id + "_contract_invalid")
    version, required = SHAPES[contract_id]
    actual = frozenset(value)
    if contract_id == "remediation_packet":
        # Policy-derived issue fields are a closed optional group because old
        # canonical findings predate the packaged authority policy.
        optional = {"actionable","actionability","permitted_automation_classes","open_state","owner_decision_state","release_freshness"}
        if not required.issubset(actual) or not actual.issubset(required | optional):
            raise ValueError(contract_id + "_contract_invalid")
    elif contract_id == "review_plan":
        if not required.issubset(actual) or not actual.issubset(required | {"last_adaptation"}):
            raise ValueError(contract_id + "_contract_invalid")
    elif contract_id == "review_specialist_work_order":
        optional = {"adaptation_event_id","supersedes_work_order_id","superseded_by"}
        if not required.issubset(actual) or not actual.issubset(required | optional):
            raise ValueError(contract_id + "_contract_invalid")
    elif contract_id == "review_submission_validation":
        if not required.issubset(actual) or not actual.issubset(required | {"native_result_semantic_hash"}):
            raise ValueError(contract_id + "_contract_invalid")
    elif actual != required:
        raise ValueError(contract_id + "_contract_invalid")
    if version is not None and value.get("schema_version") != version:
        raise ValueError(contract_id + "_version_invalid")
    if contract_id.endswith("manifest"):
        hashes = value.get("artifact_hashes")
        if not isinstance(hashes, dict) or not hashes or not all(isinstance(k, str) and isinstance(v, str) and v.startswith("sha256:") for k, v in hashes.items()):
            raise ValueError(contract_id + "_hashes_invalid")
    if contract_id.endswith("pointer"):
        if not isinstance(value.get("manifest_hash"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}",value["manifest_hash"]) is None:
            raise ValueError(contract_id + "_hash_invalid")
    if contract_id == "remediation_index" and (not isinstance(value["remediation_ids"], list) or len(value["remediation_ids"]) != len(set(value["remediation_ids"]))):
        raise ValueError("remediation_index_ids_invalid")
    if contract_id == "remediation_plan" and not isinstance(value["packets"], list):
        raise ValueError("remediation_plan_packets_invalid")
    if contract_id == "remediation_overlay" and not isinstance(value["nodes"], list):
        raise ValueError("remediation_overlay_nodes_invalid")
    if contract_id == "remediation_packet" and (not isinstance(value["remediation_id"], str) or not isinstance(value["verification_contract_id"], str)):
        raise ValueError("remediation_packet_identity_invalid")
    if contract_id == "remediation_closure_contract" and value["remediation_id"] == value["closure_contract_id"]:
        raise ValueError("remediation_closure_contract_identity_invalid")
    if contract_id in {"review_plan_events","review_revision_ledger","review_accepted_results"}:
        field = {"review_plan_events":"events","review_revision_ledger":"entries","review_accepted_results":"results"}[contract_id]
        if not isinstance(value[field], list):
            raise ValueError(contract_id + "_records_invalid")
    if contract_id.startswith("review_execution_summary") and not isinstance(value["execution_modes"], list):
        raise ValueError("review_execution_summary_modes_invalid")
    if contract_id == "contestation_ledger" and not isinstance(value["actions"], list):
        raise ValueError("contestation_ledger_actions_invalid")
    if contract_id == "contestation_effects":
        for field in ("immediate_owner_decisions","overflow_owner_decisions","priority_reason_codes","source_references"):
            if not isinstance(value[field], list):
                raise ValueError("contestation_effects_records_invalid")
    if contract_id in {"management_executive_release_brief","management_product_release_review","management_engineering_release_assessment","management_measurement_ai_readiness","management_remediation_overview","management_release_packet_index","management_release_recommendation_view","management_github_payload"}:
        if not isinstance(value["artifact_dependency_vector"], dict) or not isinstance(value["sections"], list) or not isinstance(value["section_contracts"], list):
            raise ValueError(contract_id + "_records_invalid")
        if contract_id != "management_release_recommendation_view" and not isinstance(value.get("section_records"), list):
            raise ValueError(contract_id + "_records_invalid")
    return value
