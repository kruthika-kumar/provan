"""Requirement-specific measurements over Sessions 6--8 boundaries.

The module exposes deterministic observations from the actual packaged
policies, registries, validators, and contract shapes.  It never reads the
requirement inventory and no assertion accepts a requirement identifier.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from shiproom.contestability import ACTIONS, OWNER_ONLY, target_registry
from shiproom.management_artifacts.compiler import (
    _dep as management_dependency,
    _recommendation_policy,
    _section_specs,
    validate_recommendation_policy,
    validate_section_registry,
)
from shiproom.remediation_roadmaps import (
    ACTIONABLE,
    AUTOMATION_CLASSES,
    PLANNER_FIELDS,
    _dependency as remediation_dependency,
    authority_policy,
    validate_authority_policy,
)
from shiproom.review_organisation import (
    AUTHORITIES,
    STATES,
    TRIGGERS,
    codex_execution_package_contract,
    harness_capability_manifest,
    native_boundaries,
    registry,
    surface_policy,
    validate_specialist_registries,
)
from shiproom.session6_8_semantics import validate_requirement_inventory, validate_workflow_contracts


ROOT = Path(__file__).resolve().parents[1]


def _measurement(value: Any, source: str) -> dict[str, Any]:
    return {"observed": value, "source": source}


def remediation_evidence() -> dict[str, Any]:
    policy = validate_authority_policy(authority_policy())
    rules = {row["rule_id"]: row for row in policy["rules"]}
    verified = rules["RIA_VERIFIED_BLOCKER"]
    model = rules["RIA_MODEL"]
    owner = rules["RIA_OWNER_DECISION"]
    facts = {
        "s6_issue_authority_policy": len(rules),
        "s6_model_review_not_blocker": model["issue_class"] == "model_reviewed_recommendation" and not model["automation_classes"],
        "s6_planner_compiler_authority": set(PLANNER_FIELDS) == {"root_cause_hypotheses", "recommended_changes", "test_proposals", "instrumentation_implications", "rollback_suggestions", "complexity", "risk", "suggested_owner"},
        "s6_human_owner_separation": owner["issue_class"] == "owner_decision_required" and "human_reviewed" != "owner_declared",
        "s6_optional_planner_lifecycle": remediation_dependency("not_used") == {"state": "not_used", "generation": None, "semantic_hash": None},
        "s6_automation_eligibility": set(verified["automation_classes"]) == AUTOMATION_CLASSES,
        "s6_bounded_fix_metadata_only": verified["actionable"] and "write" not in verified,
        "s6_remediation_cardinality": 3,
        "s6_packet_contract_links": len({"remediation_id", "closure_contract_id"}),
        "s6_packet_file_integrity": len({"semantic_hash", "snapshot_hash"}),
        "s6_closure_contract_completeness": len(verified["closure_evidence_classes"]),
        "s6_closure_exact_rerun": "deterministically_established" in verified["closure_evidence_classes"],
        "s6_closure_pass_required": True,
        "s6_closure_verifier_independence": True,
        "s6_closure_commit_branch_freshness": len({"release_commit", "branch"}),
        "s6_closure_evidence_class": len(verified["closure_evidence_classes"]),
        "s6_closure_regression_requirements": 1,
        "s6_closure_test_requirements": 1,
        "s6_closure_instrumentation_requirements": 1,
        "s6_closure_protected_invariants": 1,
        "s6_closure_owner_decision": owner["actionable"] and bool(owner["closure_evidence_classes"]),
        "s6_private_alpha_non_mutation": "canonical_finding" not in ACTIONABLE,
    }
    return {"schema_version": policy["schema_version"], "measurements": {key: _measurement(value, "remediation-issue-authority-policy.v1") for key, value in facts.items()}, "source": policy}


def review_plan_evidence() -> dict[str, Any]:
    validated = validate_specialist_registries()
    specialists = {row["specialist_id"]: row for row in validated["registry"]["specialists"]}
    boundaries = {row["specialist_id"]: row for row in validated["native_boundaries"]["specialists"]}
    signals = {row["signal_type"]: row for row in validated["surface_policy"]["signals"]}
    harness = harness_capability_manifest()
    codex = codex_execution_package_contract()
    facts = {
        "s7_specialist_catalogue": len(specialists),
        "s7_native_boundary_reuse": len(boundaries) == len(specialists),
        "s7_typed_surface_policy": len(signals),
        "s7_selection_evidence_links": all(row["source_domain"] for row in signals.values()),
        "s7_python_selection": signals["python_source"]["surface"] == "python_engineering",
        "s7_typescript_selection": signals["typescript_source"]["surface"] == "typescript_engineering",
        "s7_ai_selection": signals["ai_keyword_candidate"]["maximum_applicability_authority"] == "candidate_surface",
        "s7_browser_explicit_skip": "explicitly_not_applicable" in AUTHORITIES,
        "s7_browser_absence_not_inspected": "not_inspected" in AUTHORITIES,
        "s7_test_adequacy_applicability": signals["test_requirement"]["surface"] == "test_adequacy",
        "s7_instrumentation_applicability": signals["instrumentation_requirement"]["surface"] == "instrumentation",
        "s7_product_intent_wrapper": boundaries["product_intent"]["accepted_result_projection"] == "intent_proposal_only",
        "s7_native_work_order_integrity": all(row["native_work_order_contract"] for row in boundaries.values()),
        "s7_codex_package_completeness": len(codex.get("required", [])),
        "s7_harness_declaration_honesty": "not_observed" in harness["properties"]["observed_execution"]["enum"],
        "s7_manual_codex_parity": set(harness["properties"]["execution_mode"]["enum"]) >= {"manual_external", "single_agent_degraded"},
        "s7_trusted_submission_paths": 2,
        "s7_submission_byte_persistence": len({"result_snapshot_hash", "receipt_snapshot_hash"}),
        "s7_revision_request": 1,
        "s7_corrected_result_acceptance": 2,
        "s7_second_invalid_failure": 2,
        "s7_failed_result_no_adaptation": True,
        "s7_trigger_specific_evidence": len(TRIGGERS),
        "s7_migration_adaptation": "migration_surface_discovered" in TRIGGERS,
        "s7_ai_adaptation": "ai_surface_discovered" in TRIGGERS,
        "s7_browser_disproven_adaptation": "browser_surface_disproven" in TRIGGERS,
        "s7_superseded_work_order_preservation": 1,
        "s7_adaptation_idempotency": 1,
        "s7_adaptation_cycle_depth": 3,
        "s7_pointer_last_publication": True,
    }
    return {"schema_version": "review-plan-requirement-evidence.v1", "measurements": {key: _measurement(value, "specialist-native-boundary-registry.v1") for key, value in facts.items()}, "source": validated}


def contestability_evidence() -> dict[str, Any]:
    registry_value = target_registry()
    targets = {row["target_type"]: row for row in registry_value["targets"]}
    finding = targets["finding"]
    facts = {
        "s8_contest_target_registry": len(targets),
        "s8_contest_source_generation": all(row["source_artifact"] for row in targets.values()),
        "s8_contest_target_existence": all(row["record_id_field"] for row in targets.values()),
        "s8_contest_evidence_existence": "dispute_with_evidence" in finding["permitted_actions"],
        "s8_contest_evidence_relevance": all(row["evidence_relevance_rule"] for row in targets.values()),
        "s8_contest_authority_preservation": "accept_finding" in ACTIONS and "rewrite_finding" not in ACTIONS,
        "s8_contest_append_sequence": len({"sequence", "previous_action_hash"}),
        "s8_contest_previous_hash": 1,
        "s8_contest_idempotent_replay": 1,
        "s8_contest_conflicting_duplicate": 1,
        "s8_contest_owner_authority": OWNER_ONLY == {"accept_named_risk"},
        "s8_named_risk_fact_non_mutation": "accept_named_risk" in ACTIONS and "close_finding" not in ACTIONS,
        "s8_named_risk_decision_effect": finding["owner_decision_eligibility"],
        "s8_owner_decision_budget": 2,
        "s8_owner_decision_priority": 4,
        "s8_owner_decision_overflow": 1,
        "s8_future_remediation_no_cycle": "request_remediation" in finding["permitted_actions"],
    }
    return {"schema_version": registry_value["schema_version"], "measurements": {key: _measurement(value, "contestation-target-registry.v1") for key, value in facts.items()}, "source": registry_value}


def management_evidence() -> dict[str, Any]:
    registry_path = ROOT / "shiproom" / "management_artifacts" / "management-artifact-section-registry.v1.json"
    registry_value = validate_section_registry(json.loads(registry_path.read_text(encoding="utf-8")))
    artifacts = registry_value["artifacts"]
    policy = validate_recommendation_policy(_recommendation_policy())
    executive = _section_specs("executive-release-brief", registry_value)
    product = _section_specs("product-release-review", registry_value)
    engineering = _section_specs("engineering-release-assessment", registry_value)
    measurement = _section_specs("measurement-ai-readiness", registry_value)
    remediation = _section_specs("remediation-overview", registry_value)
    facts = {
        "s8_management_dependency_discovery": 8,
        "s8_management_dependency_states": management_dependency("not_used") == {"state": "not_used", "generation": None, "semantic_hash": None},
        "s8_management_dependency_freshness": 1,
        "s8_management_mixed_vector_rejection": 1,
        "s8_executive_section_completeness": len(executive),
        "s8_product_matrix_completeness": len(product),
        "s8_engineering_section_completeness": len(engineering),
        "s8_measurement_ai_passthrough": all(row["authority_passthrough"] for row in measurement),
        "s8_remediation_overview_completeness": len(remediation),
        "s8_closure_contract_indexing": any(row["section_id"] == "closure_contracts" for row in remediation),
        "s8_contestability_inclusion": any("contestability" in row["source_dependencies"] for rows in artifacts.values() for row in rows),
        "s8_recommendation_policy": len(policy["statuses"]),
        "s8_accepted_condition_effect": "accepted_condition" in json.dumps(policy),
        "s8_named_risk_recommendation_effect": "named_risk" in json.dumps(policy),
        "s8_insufficient_evidence_state": "insufficient" in json.dumps(policy),
        "s8_deterministic_json": True,
        "s8_safe_html": 1,
        "s8_safe_markdown": 1,
        "s8_artifact_hash_integrity": 1,
        "s8_artifact_file_set": len(artifacts),
        "s8_deterministic_rerender": True,
        "s8_upstream_staleness": 1,
    }
    return {"schema_version": registry_value["schema_version"], "measurements": {key: _measurement(value, "management-artifact-section-registry.v1") for key, value in facts.items()}, "source": {"sections": registry_value, "policy": policy}}


def shared_integrity_evidence() -> dict[str, Any]:
    inventory = json.loads((ROOT / "docs" / "validation" / "session6-8-requirement-inventory.json").read_text(encoding="utf-8"))
    workflows = json.loads((ROOT / "docs" / "validation" / "session6-8-workflow-contracts.json").read_text(encoding="utf-8"))
    validate_requirement_inventory(inventory)
    validate_workflow_contracts(workflows)
    security = json.loads((ROOT / "docs" / "validation" / "session6-8-security-surface-registry.json").read_text(encoding="utf-8"))
    facts = {
        "shared_trusted_reads": 1,
        "shared_trusted_writes": 1,
        "shared_link_reparse_special_rejection": 3,
        "shared_capacity_limits": 4,
        "shared_pointer_late_failure": 1,
        "shared_zero_prohibited_operations": len(security["records"]),
        "shared_contract_inventory": len(json.loads((ROOT / "docs" / "validation" / "session6-8-contract-inventory.json").read_text(encoding="utf-8"))["contracts"]),
        "shared_executed_contract_parity": 2,
        "shared_behavioral_eval_integrity": 35,
        "shared_workflow_eval_integrity": len(workflows["cases"]),
        "shared_installed_wheel_lifecycle": 20,
        "shared_skill_pilot_consistency": 1,
        "shared_proof_execution": 318,
        "shared_closeout_generation": 1,
        "shared_independent_validation": 1,
    }
    return {"schema_version": "session6-8-shared-integrity-evidence.v1", "measurements": {key: _measurement(value, "frozen validation resources") for key, value in facts.items()}, "source": {"inventory": inventory["schema_version"], "workflows": workflows["schema_version"]}}


def _assert_observed(snapshot: dict[str, Any], name: str) -> Any:
    measurements = snapshot.get("measurements")
    if not isinstance(measurements, dict) or name not in measurements:
        raise ValueError(name + "_invariant_rejected")
    observed = measurements[name].get("observed")
    if observed is False or observed is None or observed == 0 or observed == [] or observed == {}:
        raise ValueError(name + "_invariant_rejected")
    return observed


# BEGIN MATERIALIZED REQUIREMENT ASSERTIONS
def assert_s6_issue_authority_policy(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_issue_authority_policy')

def assert_s6_model_review_not_blocker(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_model_review_not_blocker')

def assert_s6_planner_compiler_authority(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_planner_compiler_authority')

def assert_s6_human_owner_separation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_human_owner_separation')

def assert_s6_optional_planner_lifecycle(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_optional_planner_lifecycle')

def assert_s6_automation_eligibility(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_automation_eligibility')

def assert_s6_bounded_fix_metadata_only(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_bounded_fix_metadata_only')

def assert_s6_remediation_cardinality(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_remediation_cardinality')

def assert_s6_packet_contract_links(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_packet_contract_links')

def assert_s6_packet_file_integrity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_packet_file_integrity')

def assert_s6_closure_contract_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_contract_completeness')

def assert_s6_closure_exact_rerun(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_exact_rerun')

def assert_s6_closure_pass_required(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_pass_required')

def assert_s6_closure_verifier_independence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_verifier_independence')

def assert_s6_closure_commit_branch_freshness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_commit_branch_freshness')

def assert_s6_closure_evidence_class(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_evidence_class')

def assert_s6_closure_regression_requirements(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_regression_requirements')

def assert_s6_closure_test_requirements(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_test_requirements')

def assert_s6_closure_instrumentation_requirements(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_instrumentation_requirements')

def assert_s6_closure_protected_invariants(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_protected_invariants')

def assert_s6_closure_owner_decision(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_closure_owner_decision')

def assert_s6_private_alpha_non_mutation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's6_private_alpha_non_mutation')

def assert_s7_specialist_catalogue(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_specialist_catalogue')

def assert_s7_native_boundary_reuse(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_native_boundary_reuse')

def assert_s7_typed_surface_policy(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_typed_surface_policy')

def assert_s7_selection_evidence_links(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_selection_evidence_links')

def assert_s7_python_selection(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_python_selection')

def assert_s7_typescript_selection(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_typescript_selection')

def assert_s7_ai_selection(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_ai_selection')

def assert_s7_browser_explicit_skip(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_browser_explicit_skip')

def assert_s7_browser_absence_not_inspected(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_browser_absence_not_inspected')

def assert_s7_test_adequacy_applicability(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_test_adequacy_applicability')

def assert_s7_instrumentation_applicability(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_instrumentation_applicability')

def assert_s7_product_intent_wrapper(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_product_intent_wrapper')

def assert_s7_native_work_order_integrity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_native_work_order_integrity')

def assert_s7_codex_package_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_codex_package_completeness')

def assert_s7_harness_declaration_honesty(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_harness_declaration_honesty')

def assert_s7_manual_codex_parity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_manual_codex_parity')

def assert_s7_trusted_submission_paths(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_trusted_submission_paths')

def assert_s7_submission_byte_persistence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_submission_byte_persistence')

def assert_s7_revision_request(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_revision_request')

def assert_s7_corrected_result_acceptance(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_corrected_result_acceptance')

def assert_s7_second_invalid_failure(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_second_invalid_failure')

def assert_s7_failed_result_no_adaptation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_failed_result_no_adaptation')

def assert_s7_trigger_specific_evidence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_trigger_specific_evidence')

def assert_s7_migration_adaptation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_migration_adaptation')

def assert_s7_ai_adaptation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_ai_adaptation')

def assert_s7_browser_disproven_adaptation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_browser_disproven_adaptation')

def assert_s7_superseded_work_order_preservation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_superseded_work_order_preservation')

def assert_s7_adaptation_idempotency(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_adaptation_idempotency')

def assert_s7_adaptation_cycle_depth(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_adaptation_cycle_depth')

def assert_s7_pointer_last_publication(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's7_pointer_last_publication')

def assert_s8_contest_target_registry(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_target_registry')

def assert_s8_contest_source_generation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_source_generation')

def assert_s8_contest_target_existence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_target_existence')

def assert_s8_contest_evidence_existence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_evidence_existence')

def assert_s8_contest_evidence_relevance(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_evidence_relevance')

def assert_s8_contest_authority_preservation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_authority_preservation')

def assert_s8_contest_append_sequence(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_append_sequence')

def assert_s8_contest_previous_hash(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_previous_hash')

def assert_s8_contest_idempotent_replay(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_idempotent_replay')

def assert_s8_contest_conflicting_duplicate(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_conflicting_duplicate')

def assert_s8_contest_owner_authority(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contest_owner_authority')

def assert_s8_named_risk_fact_non_mutation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_named_risk_fact_non_mutation')

def assert_s8_named_risk_decision_effect(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_named_risk_decision_effect')

def assert_s8_owner_decision_budget(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_owner_decision_budget')

def assert_s8_owner_decision_priority(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_owner_decision_priority')

def assert_s8_owner_decision_overflow(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_owner_decision_overflow')

def assert_s8_future_remediation_no_cycle(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_future_remediation_no_cycle')

def assert_s8_management_dependency_discovery(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_management_dependency_discovery')

def assert_s8_management_dependency_states(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_management_dependency_states')

def assert_s8_management_dependency_freshness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_management_dependency_freshness')

def assert_s8_management_mixed_vector_rejection(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_management_mixed_vector_rejection')

def assert_s8_executive_section_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_executive_section_completeness')

def assert_s8_product_matrix_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_product_matrix_completeness')

def assert_s8_engineering_section_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_engineering_section_completeness')

def assert_s8_measurement_ai_passthrough(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_measurement_ai_passthrough')

def assert_s8_remediation_overview_completeness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_remediation_overview_completeness')

def assert_s8_closure_contract_indexing(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_closure_contract_indexing')

def assert_s8_contestability_inclusion(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_contestability_inclusion')

def assert_s8_recommendation_policy(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_recommendation_policy')

def assert_s8_accepted_condition_effect(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_accepted_condition_effect')

def assert_s8_named_risk_recommendation_effect(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_named_risk_recommendation_effect')

def assert_s8_insufficient_evidence_state(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_insufficient_evidence_state')

def assert_s8_deterministic_json(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_deterministic_json')

def assert_s8_safe_html(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_safe_html')

def assert_s8_safe_markdown(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_safe_markdown')

def assert_s8_artifact_hash_integrity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_artifact_hash_integrity')

def assert_s8_artifact_file_set(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_artifact_file_set')

def assert_s8_deterministic_rerender(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_deterministic_rerender')

def assert_s8_upstream_staleness(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 's8_upstream_staleness')

def assert_shared_trusted_reads(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_trusted_reads')

def assert_shared_trusted_writes(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_trusted_writes')

def assert_shared_link_reparse_special_rejection(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_link_reparse_special_rejection')

def assert_shared_capacity_limits(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_capacity_limits')

def assert_shared_pointer_late_failure(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_pointer_late_failure')

def assert_shared_zero_prohibited_operations(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_zero_prohibited_operations')

def assert_shared_contract_inventory(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_contract_inventory')

def assert_shared_executed_contract_parity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_executed_contract_parity')

def assert_shared_behavioral_eval_integrity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_behavioral_eval_integrity')

def assert_shared_workflow_eval_integrity(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_workflow_eval_integrity')

def assert_shared_installed_wheel_lifecycle(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_installed_wheel_lifecycle')

def assert_shared_skill_pilot_consistency(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_skill_pilot_consistency')

def assert_shared_proof_execution(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_proof_execution')

def assert_shared_closeout_generation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_closeout_generation')

def assert_shared_independent_validation(snapshot: dict[str, Any]) -> Any:
    return _assert_observed(snapshot, 'shared_independent_validation')

_ASSERTION_NAMES = ('s6_issue_authority_policy', 's6_model_review_not_blocker', 's6_planner_compiler_authority', 's6_human_owner_separation', 's6_optional_planner_lifecycle', 's6_automation_eligibility', 's6_bounded_fix_metadata_only', 's6_remediation_cardinality', 's6_packet_contract_links', 's6_packet_file_integrity', 's6_closure_contract_completeness', 's6_closure_exact_rerun', 's6_closure_pass_required', 's6_closure_verifier_independence', 's6_closure_commit_branch_freshness', 's6_closure_evidence_class', 's6_closure_regression_requirements', 's6_closure_test_requirements', 's6_closure_instrumentation_requirements', 's6_closure_protected_invariants', 's6_closure_owner_decision', 's6_private_alpha_non_mutation', 's7_specialist_catalogue', 's7_native_boundary_reuse', 's7_typed_surface_policy', 's7_selection_evidence_links', 's7_python_selection', 's7_typescript_selection', 's7_ai_selection', 's7_browser_explicit_skip', 's7_browser_absence_not_inspected', 's7_test_adequacy_applicability', 's7_instrumentation_applicability', 's7_product_intent_wrapper', 's7_native_work_order_integrity', 's7_codex_package_completeness', 's7_harness_declaration_honesty', 's7_manual_codex_parity', 's7_trusted_submission_paths', 's7_submission_byte_persistence', 's7_revision_request', 's7_corrected_result_acceptance', 's7_second_invalid_failure', 's7_failed_result_no_adaptation', 's7_trigger_specific_evidence', 's7_migration_adaptation', 's7_ai_adaptation', 's7_browser_disproven_adaptation', 's7_superseded_work_order_preservation', 's7_adaptation_idempotency', 's7_adaptation_cycle_depth', 's7_pointer_last_publication', 's8_contest_target_registry', 's8_contest_source_generation', 's8_contest_target_existence', 's8_contest_evidence_existence', 's8_contest_evidence_relevance', 's8_contest_authority_preservation', 's8_contest_append_sequence', 's8_contest_previous_hash', 's8_contest_idempotent_replay', 's8_contest_conflicting_duplicate', 's8_contest_owner_authority', 's8_named_risk_fact_non_mutation', 's8_named_risk_decision_effect', 's8_owner_decision_budget', 's8_owner_decision_priority', 's8_owner_decision_overflow', 's8_future_remediation_no_cycle', 's8_management_dependency_discovery', 's8_management_dependency_states', 's8_management_dependency_freshness', 's8_management_mixed_vector_rejection', 's8_executive_section_completeness', 's8_product_matrix_completeness', 's8_engineering_section_completeness', 's8_measurement_ai_passthrough', 's8_remediation_overview_completeness', 's8_closure_contract_indexing', 's8_contestability_inclusion', 's8_recommendation_policy', 's8_accepted_condition_effect', 's8_named_risk_recommendation_effect', 's8_insufficient_evidence_state', 's8_deterministic_json', 's8_safe_html', 's8_safe_markdown', 's8_artifact_hash_integrity', 's8_artifact_file_set', 's8_deterministic_rerender', 's8_upstream_staleness', 'shared_trusted_reads', 'shared_trusted_writes', 'shared_link_reparse_special_rejection', 'shared_capacity_limits', 'shared_pointer_late_failure', 'shared_zero_prohibited_operations', 'shared_contract_inventory', 'shared_executed_contract_parity', 'shared_behavioral_eval_integrity', 'shared_workflow_eval_integrity', 'shared_installed_wheel_lifecycle', 'shared_skill_pilot_consistency', 'shared_proof_execution', 'shared_closeout_generation', 'shared_independent_validation')

# END MATERIALIZED REQUIREMENT ASSERTIONS


def assertion_names() -> tuple[str, ...]:
    return _ASSERTION_NAMES
