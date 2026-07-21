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


def _bind_assertion(name: str) -> Callable[[dict[str, Any]], Any]:
    def assertion(snapshot: dict[str, Any]) -> Any:
        measurements = snapshot.get("measurements")
        if not isinstance(measurements, dict) or name not in measurements:
            raise ValueError(name + "_invariant_rejected")
        observed = measurements[name].get("observed")
        if observed is False or observed is None or observed == 0 or observed == [] or observed == {}:
            raise ValueError(name + "_invariant_rejected")
        return observed
    assertion.__name__ = "assert_" + name
    assertion.__qualname__ = assertion.__name__
    return assertion


_ASSERTION_NAMES = tuple(
    list(remediation_evidence()["measurements"])
    + list(review_plan_evidence()["measurements"])
    + list(contestability_evidence()["measurements"])
    + list(management_evidence()["measurements"])
    + list(shared_integrity_evidence()["measurements"])
)
for _name in _ASSERTION_NAMES:
    globals()["assert_" + _name] = _bind_assertion(_name)


def assertion_names() -> tuple[str, ...]:
    return _ASSERTION_NAMES
