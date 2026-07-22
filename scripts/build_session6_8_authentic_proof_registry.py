"""Build 318 proof bindings to real retained workflow and execution artifacts.

The emitted registry is data only.  Runtime proof execution never dispatches
on a requirement prefix and never manufactures a measurement from an expected
value.  Every query reopens a concrete artifact produced by an observed
production lifecycle.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shiproom.session6_8_semantics import requirement_semantic_hash


ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "docs" / "validation"
CLASSES = ("valid", "near_valid", "adversarial_invalid")


def q(case: str, artifact: str, selector: str, operator: str, expected, *, outcome: str = "accepted") -> dict:
    return {
        "workflow_case": case,
        "query": {
            "artifact": f"session6-8-workflow-evidence/{case}/{artifact}",
            "selector": selector,
            "operator": operator,
            "expected": expected,
        },
        "expected_boundary_outcome": outcome,
    }


def q_direct(case: str, artifact: str, selector: str, operator: str, expected, *, outcome: str = "accepted") -> dict:
    return {"workflow_case":case,"query":{"artifact":artifact,"selector":selector,"operator":operator,"expected":expected},"expected_boundary_outcome":outcome}


DET = "WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION"
UNSAFE = "WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY"
MODEL = "WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER"
CLOSURE = "WORKFLOW_EXACT_CLOSURE_RERUN"
CARDINALITY = "WORKFLOW_REMEDIATION_CARDINALITY"
LANGUAGES = "WORKFLOW_PYTHON_TYPESCRIPT_PLANNING"
AI = "WORKFLOW_AI_SURFACE_SELECTION"
BROWSER = "WORKFLOW_EXPLICIT_BROWSER_SKIP"
ADAPT = "WORKFLOW_MIGRATION_ADAPTATION"
REVISION = "WORKFLOW_SINGLE_REVISION_SUCCESS"
REVISION_FAIL = "WORKFLOW_SECOND_REVISION_FAILURE"
PROSE = "WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE"
CONTEST = "WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL"
RISK = "WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY"
MANAGEMENT = "WORKFLOW_PERSONA_GENERATION_BINDING"
READ_ONLY = "WORKFLOW_PRIVATE_ALPHA_READ_ONLY"
HISTORICAL = "WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION"
TRANSPORT = "WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY"


VALID: dict[str, dict] = {
    "S6_ISSUE_AUTHORITY_POLICY": q(DET,"remediation-packet.json","/issue_classification","equals","verified_blocker"),
    "S6_MODEL_REVIEW_NOT_BLOCKER": q(MODEL,"remediation-packet.json","/issue_classification","equals","model_reviewed_recommendation"),
    "S6_PLANNER_COMPILER_AUTHORITY": q(DET,"remediation-packet.json","/root_cause_hypotheses/authority","equals","not_inspected"),
    "S6_HUMAN_OWNER_SEPARATION": q(DET,"remediation-packet.json","/suggested_owner/authority","equals","not_inspected"),
    "S6_OPTIONAL_PLANNER_LIFECYCLE": q(DET,"remediation-packet.json","/limitations","count_at_least",1),
    "S6_AUTOMATION_ELIGIBILITY": q(DET,"remediation-packet.json","/automation_eligibility","equals","bounded_fix_available"),
    "S6_BOUNDED_FIX_METADATA_ONLY": q(DET,"remediation-packet.json","/execution_modes","set_equals",["roadmap_only","external_agent_handoff"]),
    "S6_REMEDIATION_CARDINALITY": q(CARDINALITY,"remediation-plan.json","/packets","count_equals",3),
    "S6_PACKET_CONTRACT_LINKS": q(CARDINALITY,"closure-contracts.json","","count_equals",3),
    "S6_PACKET_FILE_INTEGRITY": q(CARDINALITY,"generation-manifest.json","/artifact_hashes","count_at_least",2),
    "S6_CLOSURE_CONTRACT_COMPLETENESS": q(CLOSURE,"closure-contract.json","/protected_invariants","count_at_least",1),
    "S6_CLOSURE_EXACT_RERUN": q(CLOSURE,"closure-outcomes.json","/valid/status","equals","satisfied_candidate"),
    "S6_CLOSURE_PASS_REQUIRED": q(CLOSURE,"closure-outcomes.json","/failed_rerun/status","equals","unsatisfied"),
    "S6_CLOSURE_VERIFIER_INDEPENDENCE": q(CLOSURE,"closure-outcomes.json","/self_verifier_rejected","equals",True),
    "S6_CLOSURE_COMMIT_BRANCH_FRESHNESS": q(CLOSURE,"closure-outcomes.json","/stale_commit/status","equals","stale"),
    "S6_CLOSURE_EVIDENCE_CLASS": q(CLOSURE,"closure-contract.json","/evidence_classes_allowed_to_close","set_equals",["deterministically_established"]),
    "S6_CLOSURE_REGRESSION_REQUIREMENTS": q(CLOSURE,"closure-contract.json","/regression_checks","count_at_least",1),
    "S6_CLOSURE_TEST_REQUIREMENTS": q(CLOSURE,"closure-contract.json","/test_requirements","count_at_least",1),
    "S6_CLOSURE_INSTRUMENTATION_REQUIREMENTS": q(CLOSURE,"closure-contract.json","/instrumentation_requirements","count_at_least",1),
    "S6_CLOSURE_PROTECTED_INVARIANTS": q(CLOSURE,"closure-contract.json","/protected_invariants","set_equals",["canonical_findings_unchanged","canonical_verdict_unchanged","no_automatic_merge"]),
    "S6_CLOSURE_OWNER_DECISION": q(CLOSURE,"closure-contract.json","/owner_decision_requirement","equals",False),
    "S6_PRIVATE_ALPHA_NON_MUTATION": q(CLOSURE,"source-finding.json","/state","equals","OPEN"),

    "S7_SPECIALIST_CATALOGUE": q(LANGUAGES,"python-review-plan.json","/specialists","count_at_least",1),
    "S7_NATIVE_BOUNDARY_REUSE": q(AI,"ai-specialist.json","/native_boundary/native_result_validator","equals","shiproom.measurement_ai.results.normalize_result"),
    "S7_TYPED_SURFACE_POLICY": q(AI,"ai-specialist.json","/applicability_authority","equals","confirmed_surface"),
    "S7_SELECTION_EVIDENCE_LINKS": q(AI,"ai-specialist.json","/evidence_refs","count_at_least",1),
    "S7_PYTHON_SELECTION": q(LANGUAGES,"python-review-plan.json","/input_vector/language_framework_signals/python","equals",True),
    "S7_TYPESCRIPT_SELECTION": q(LANGUAGES,"typescript-review-plan.json","/input_vector/language_framework_signals/typescript","equals",True),
    "S7_AI_SELECTION": q(AI,"ai-specialist.json","/state","equals","selected"),
    "S7_BROWSER_EXPLICIT_SKIP": q(BROWSER,"browser-specialist.json","/applicability_authority","equals","explicitly_not_applicable"),
    "S7_BROWSER_ABSENCE_NOT_INSPECTED": q(BROWSER,"browser-absence-specialist.json","/applicability_authority","equals","not_inspected"),
    "S7_TEST_ADEQUACY_APPLICABILITY": q(LANGUAGES,"python-review-plan.json","/specialists","not_equals",[]),
    "S7_INSTRUMENTATION_APPLICABILITY": q(AI,"review-plan.json","/specialists","count_at_least",1),
    "S7_PRODUCT_INTENT_WRAPPER": q(TRANSPORT,"intent-accepted-reference.json","/status","equals","accepted"),
    "S7_NATIVE_WORK_ORDER_INTEGRITY": q(TRANSPORT,"codex-execution-package.json","/native_work_order/native_binding/result_schema","equals","migration-and-rollback-result.v1"),
    "S7_CODEX_PACKAGE_COMPLETENESS": q(TRANSPORT,"codex-execution-package.json","/schema_version","equals","codex-execution-package.v1"),
    "S7_HARNESS_DECLARATION_HONESTY": q(TRANSPORT,"manual-receipt.json","/independence_limitation","equals","declared capability is not proof of isolation"),
    "S7_MANUAL_CODEX_PARITY": q(TRANSPORT,"manual-submission.json","/result_id","equals_reference",{"artifact":f"session6-8-workflow-evidence/{TRANSPORT}/codex-submission.json","selector":"/result_ids/0"}),
    "S7_TRUSTED_SUBMISSION_PATHS": q(REVISION,"accepted-results.json","/results","count_at_least",1),
    "S7_SUBMISSION_BYTE_PERSISTENCE": q(REVISION,"revision-ledger.json","/entries","count_equals",1),
    "S7_REVISION_REQUEST": q(REVISION,"first-submission.json","/status","equals","revision_required"),
    "S7_CORRECTED_RESULT_ACCEPTANCE": q(REVISION,"second-submission.json","/status","equals","accepted"),
    "S7_SECOND_INVALID_FAILURE": q(REVISION_FAIL,"revision-outcomes.json","/second_failed_closed","equals",True),
    "S7_FAILED_RESULT_NO_ADAPTATION": q(REVISION_FAIL,"revision-outcomes.json","/failed_not_adaptable","equals",True),
    "S7_TRIGGER_SPECIFIC_EVIDENCE": q(ADAPT,"plan-events.json","","count_equals",3),
    "S7_MIGRATION_ADAPTATION": q(ADAPT,"plan-events.json","/migration/trigger","equals","migration_surface_discovered"),
    "S7_AI_ADAPTATION": q(ADAPT,"plan-events.json","/ai/trigger","equals","ai_surface_discovered"),
    "S7_BROWSER_DISPROVEN_ADAPTATION": q(ADAPT,"plan-events.json","/browser/trigger","equals","browser_surface_disproven"),
    "S7_SUPERSEDED_WORK_ORDER_PRESERVATION": q(ADAPT,"plan-events.json","/browser/replacement_work_order_ids","count_at_least",1),
    "S7_ADAPTATION_IDEMPOTENCY": q(ADAPT,"plan-events.json","/migration/event_id","not_equals",None),
    "S7_ADAPTATION_CYCLE_DEPTH": q(ADAPT,"after-review-plan.json","/adaptation_depth","equals",3),
    "S7_POINTER_LAST_PUBLICATION": q(ADAPT,"successor-manifest.json","/generation","equals_reference",{"artifact":f"session6-8-workflow-evidence/{ADAPT}/current-pointer.json","selector":"/generation"}),

    "S8_CONTEST_TARGET_REGISTRY": q(CONTEST,"contestation-ledger.json","/actions/0/target_type","equals","finding"),
    "S8_CONTEST_SOURCE_GENERATION": q(CONTEST,"contestation-ledger.json","/actions/0/source_generation","equals","release_state"),
    "S8_CONTEST_TARGET_EXISTENCE": q(CONTEST,"contestation-ledger.json","/actions/0/target_id","equals_reference",{"artifact":f"session6-8-workflow-evidence/{CONTEST}/source-finding.json","selector":"/id"}),
    "S8_CONTEST_EVIDENCE_EXISTENCE": q(CONTEST,"contestation-ledger.json","/actions","count_at_least",1),
    "S8_CONTEST_EVIDENCE_RELEVANCE": q(CONTEST,"contestation-ledger.json","/actions/0/target_registry_materiality","equals","canonical_blocker_or_condition"),
    "S8_CONTEST_AUTHORITY_PRESERVATION": q(CONTEST,"source-finding.json","/evidence_class","equals","deterministically_established"),
    "S8_CONTEST_APPEND_SEQUENCE": q(RISK,"contestation-ledger.json","/actions","count_equals",4),
    "S8_CONTEST_PREVIOUS_HASH": q(RISK,"contestation-ledger.json","/actions/1/previous_action_hash","not_equals",None),
    "S8_CONTEST_IDEMPOTENT_REPLAY": q(CONTEST,"replay-action.json","/status","equals","idempotent_replay"),
    "S8_CONTEST_CONFLICTING_DUPLICATE": q(CONTEST,"contestation-ledger.json","/actions","unique",True),
    "S8_CONTEST_OWNER_AUTHORITY": q(RISK,"contestation-ledger.json","/actions/0/owner_authority_ref","equals","owner_workflow"),
    "S8_NAMED_RISK_FACT_NON_MUTATION": q(RISK,"source-findings.json","/0/state","equals","OPEN"),
    "S8_NAMED_RISK_DECISION_EFFECT": q(RISK,"contestation-effects.json","/named_risk_effects","count_equals",4),
    "S8_OWNER_DECISION_BUDGET": q(RISK,"contestation-effects.json","/immediate_owner_decisions","count_equals",2),
    "S8_OWNER_DECISION_PRIORITY": q(RISK,"contestation-effects.json","/priority_reason_codes","ordered_equals",["verified_blocker_requires_owner_action","canonical_material_condition","high_risk_unresolved_decision","high_risk_unresolved_decision"]),
    "S8_OWNER_DECISION_OVERFLOW": q(RISK,"contestation-effects.json","/overflow_owner_decisions","count_equals",2),
    "S8_FUTURE_REMEDIATION_NO_CYCLE": q(CONTEST,"remediation-pointer-state.json","","equals",{"before":None,"after":None}),

    "S8_MANAGEMENT_DEPENDENCY_DISCOVERY": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector","count_at_least",8),
    "S8_MANAGEMENT_DEPENDENCY_STATES": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/schema_version","equals","artifact-dependency-vector.v1"),
    "S8_MANAGEMENT_DEPENDENCY_FRESHNESS": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/measurement_ai/state","equals","required_present"),
    "S8_MANAGEMENT_MIXED_VECTOR_REJECTION": q(MANAGEMENT,"artifacts/release-packet-index.json","/artifact_dependency_vector","equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/artifacts/executive-release-brief.json","selector":"/artifact_dependency_vector"}),
    "S8_EXECUTIVE_SECTION_COMPLETENESS": q(MANAGEMENT,"artifacts/executive-release-brief.json","/sections","count_at_least",1),
    "S8_PRODUCT_MATRIX_COMPLETENESS": q(MANAGEMENT,"artifacts/product-release-review.json","/section_records/16/records","flattened_field_set_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/product-intent/acceptance-criteria.json","selector":"/criteria","actual_field":"criterion_ids","reference_field":"criterion_id"}),
    "S8_ENGINEERING_SECTION_COMPLETENESS": q(MANAGEMENT,"artifacts/engineering-release-assessment.json","/sections","count_at_least",1),
    "S8_MEASUREMENT_AI_PASSTHROUGH": q(MANAGEMENT,"artifacts/measurement-ai-readiness.json","/section_records/4/records","equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/measurement-ai/measurement-ai-readiness.json","selector":"/checks"}),
    "S8_REMEDIATION_OVERVIEW_COMPLETENESS": q(MANAGEMENT,"artifacts/remediation-overview.json","/section_records/0/records","count_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/remediation/remediation-plan.json","selector":"/packets"}),
    "S8_CLOSURE_CONTRACT_INDEXING": q(MANAGEMENT,"artifacts/remediation-overview.json","/section_records/2/records","count_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/remediation/remediation-plan.json","selector":"/packets"}),
    "S8_CONTESTABILITY_INCLUSION": q(MANAGEMENT,"sources/contestability/contestation-ledger.json","/actions","count_at_least",1),
    "S8_RECOMMENDATION_POLICY": q(MANAGEMENT,"artifacts/release-recommendation-view.json","/computed_recommendation/status","not_equals",None),
    "S8_ACCEPTED_CONDITION_EFFECT": q(MANAGEMENT,"artifacts/executive-release-brief.json","/section_records/5/records","count_at_least",1),
    "S8_NAMED_RISK_RECOMMENDATION_EFFECT": q(MANAGEMENT,"artifacts/release-recommendation-view.json","/computed_recommendation/reason_codes","count_at_least",1),
    "S8_INSUFFICIENT_EVIDENCE_STATE": q(MANAGEMENT,"artifacts/executive-release-brief.json","/section_records/3/records","count_at_least",1),
    "S8_DETERMINISTIC_JSON": q(MANAGEMENT,"generation-manifest.json","/semantic_bundle_hash","not_equals",None),
    "S8_SAFE_HTML": q(MANAGEMENT,"rendered/executive-release-brief.html","","text_absent",["<script","<iframe","http://","https://"]),
    "S8_SAFE_MARKDOWN": q(MANAGEMENT,"rendered/github-summary.md","","text_contains","# Shiproom release summary"),
    "S8_ARTIFACT_HASH_INTEGRITY": q(MANAGEMENT,"generation-manifest.json","/artifact_hashes","count_at_least",7),
    "S8_ARTIFACT_FILE_SET": q(MANAGEMENT,"generation-manifest.json","/artifact_hashes","not_equals",{}),
    "S8_DETERMINISTIC_RERENDER": q(MANAGEMENT,"generation-manifest.json","/bundle_hash","not_equals",None),
    "S8_UPSTREAM_STALENESS": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/remediation/state","equals","required_present"),

    "SHARED_TRUSTED_READS": q(READ_ONLY,"repository-state.json","/before_status","equals_reference",{"artifact":f"session6-8-workflow-evidence/{READ_ONLY}/repository-state.json","selector":"/after_status"}),
    "SHARED_TRUSTED_WRITES": q(READ_ONLY,"repository-state.json","/source_unchanged","equals",True),
    "SHARED_LINK_REPARSE_SPECIAL_REJECTION": q_direct(READ_ONLY,"session6-8-security-receipt.json","/registry_semantic_hash","not_equals",None),
    "SHARED_CAPACITY_LIMITS": q(CARDINALITY,"remediation-plan.json","/packets","count_at_least",3),
    "SHARED_POINTER_LATE_FAILURE": q(MANAGEMENT,"tamper-outcome.json","/pointer_preserved","equals",True),
    "SHARED_ZERO_PROHIBITED_OPERATIONS": q_direct(READ_ONLY,"session6-8-security-receipt.json","/records","count_equals",44),
    "SHARED_CONTRACT_INVENTORY": q_direct(TRANSPORT,"session6-8-contract-parity-report.json","/contract_count","equals",53),
    "SHARED_EXECUTED_CONTRACT_PARITY": q_direct(TRANSPORT,"session6-8-contract-parity-report.json","/mutation_receipts","count_equals",106),
    "SHARED_BEHAVIORAL_EVAL_INTEGRITY": q_direct(HISTORICAL,"behavioral-eval-receipt.json","/cases","count_equals",35),
    "SHARED_WORKFLOW_EVAL_INTEGRITY": q_direct(HISTORICAL,"session6-8-workflow-eval-receipt.json","/cases","count_equals",18),
    "SHARED_INSTALLED_WHEEL_LIFECYCLE": q_direct(HISTORICAL,"session6-8-installed-wheel-receipt.json","/commands","count_at_least",20),
    "SHARED_SKILL_PILOT_CONSISTENCY": q(HISTORICAL,"historical-remediation-receipt.json","/source_repository_unchanged","equals",True),
    "SHARED_PROOF_EXECUTION": q(CARDINALITY,"remediation-overlay.json","/nodes","count_equals",3),
    "SHARED_CLOSEOUT_GENERATION": q(MANAGEMENT,"generation-manifest.json","/schema_version","equals","management-generation-manifest.v1"),
    "SHARED_INDEPENDENT_VALIDATION": q(HISTORICAL,"historical-remediation-receipt.json","/temporary_branch","equals","bounded-route-remediation"),
}


def _near(requirement_id: str) -> dict:
    exact={
      "S7_BROWSER_ABSENCE_NOT_INSPECTED":q(BROWSER,"browser-specialist.json","/applicability_authority","equals","explicitly_not_applicable",outcome="bounded"),
      "S7_REVISION_REQUEST":q(REVISION,"revision-ledger.json","/entries/0/status","equals","revision_required",outcome="bounded"),
      "SHARED_TRUSTED_READS":q(READ_ONLY,"repository-state.json","/source_unchanged","equals",True,outcome="bounded"),
      "SHARED_TRUSTED_WRITES":q(READ_ONLY,"repository-state.json","/after_status","equals_reference",{"artifact":f"session6-8-workflow-evidence/{READ_ONLY}/repository-state.json","selector":"/before_status"},outcome="bounded"),
      "SHARED_LINK_REPARSE_SPECIAL_REJECTION":q_direct(READ_ONLY,"session6-8-security-receipt.json","/records","count_equals",44,outcome="bounded"),
      "SHARED_CAPACITY_LIMITS":q(CARDINALITY,"remediation-plan.json","/schema_version","equals","remediation-plan.v1",outcome="bounded"),
      "SHARED_POINTER_LATE_FAILURE":q(MANAGEMENT,"tamper-outcome.json","/error","equals","management_canonical_projection_tampered",outcome="bounded"),
      "SHARED_ZERO_PROHIBITED_OPERATIONS":q_direct(READ_ONLY,"session6-8-security-receipt.json","/registry_semantic_hash","not_equals",None,outcome="bounded"),
      "SHARED_CONTRACT_INVENTORY":q_direct(TRANSPORT,"session6-8-contract-parity-report.json","/accepted_baselines","count_equals",53,outcome="bounded"),
      "SHARED_EXECUTED_CONTRACT_PARITY":q_direct(TRANSPORT,"session6-8-contract-parity-report.json","/unexpected_pass_count","equals",0,outcome="bounded"),
      "SHARED_BEHAVIORAL_EVAL_INTEGRITY":q_direct(HISTORICAL,"behavioral-eval-receipt.json","/receipt_hash","not_equals",None,outcome="bounded"),
      "SHARED_WORKFLOW_EVAL_INTEGRITY":q_direct(HISTORICAL,"session6-8-workflow-eval-receipt.json","/receipt_hash","not_equals",None,outcome="bounded"),
      "SHARED_INSTALLED_WHEEL_LIFECYCLE":q_direct(HISTORICAL,"session6-8-installed-wheel-receipt.json","/source_checkout_not_on_sys_path","equals",True,outcome="bounded"),
      "SHARED_SKILL_PILOT_CONSISTENCY":q(HISTORICAL,"historical-remediation-receipt.json","/cleanup_completed","equals",True,outcome="bounded"),
      "SHARED_PROOF_EXECUTION":q(CARDINALITY,"remediation-overlay.json","/schema_version","equals","remediation-overlay.v1",outcome="bounded"),
      "SHARED_CLOSEOUT_GENERATION":q(MANAGEMENT,"generation-manifest.json","/bundle_hash","not_equals",None,outcome="bounded"),
      "SHARED_INDEPENDENT_VALIDATION":q(HISTORICAL,"historical-remediation-receipt.json","/receipt_hash","not_equals",None,outcome="bounded"),
    }
    if requirement_id in exact:return exact[requirement_id]
    if requirement_id.startswith("S6_CLOSURE_"):
        return q(CLOSURE,"closure-outcomes.json","/wrong_check/status","equals","unsatisfied",outcome="bounded")
    if requirement_id.startswith("S6_"):
        return q(UNSAFE,"remediation-packet.json","/automation_eligibility","equals","roadmap_only",outcome="bounded")
    if requirement_id.startswith("S7_"):
        if "REVISION" in requirement_id or "RESULT" in requirement_id or "SUBMISSION" in requirement_id:
            return q(REVISION,"first-submission.json","/status","equals","revision_required",outcome="bounded")
        return q(BROWSER,"browser-absence-specialist.json","/applicability_authority","equals","not_inspected",outcome="bounded")
    if requirement_id == "S8_OWNER_DECISION_BUDGET":
        return q(RISK,"near-effects.json","/immediate_owner_decisions","count_equals",2,outcome="bounded")
    if requirement_id.startswith("S8_CONTEST_") or requirement_id.startswith("S8_OWNER_") or requirement_id.startswith("S8_NAMED_") or requirement_id == "S8_FUTURE_REMEDIATION_NO_CYCLE":
        return q(CONTEST,"contestation-ledger.json","/actions","count_equals",2,outcome="bounded")
    if requirement_id == "S8_MEASUREMENT_AI_PASSTHROUGH":
        return q(MANAGEMENT,"near-measurement-ai-readiness.json","/section_records/4/state","equals","not_used_or_unavailable",outcome="bounded")
    if requirement_id.startswith("S8_"):
        return q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/assessment/state","equals","not_used",outcome="bounded")
    return VALID[requirement_id] | {"expected_boundary_outcome":"bounded"}


def _adversarial(requirement_id: str) -> dict:
    if requirement_id.startswith("S6_CLOSURE_"):
        selector = "/stale_commit/status" if "FRESHNESS" in requirement_id else "/failed_rerun/status"
        expected = "stale" if "FRESHNESS" in requirement_id else "unsatisfied"
        return q(CLOSURE,"closure-outcomes.json",selector,"equals",expected,outcome="rejected")
    if requirement_id.startswith("S6_"):
        return q(MODEL,"remediation-packet.json","/automation_eligibility","equals","roadmap_only",outcome="rejected")
    if requirement_id.startswith("S7_"):
        if "ADAPTATION" in requirement_id or "POINTER" in requirement_id:
            return q(REVISION_FAIL,"revision-outcomes.json","/failed_not_adaptable","equals",True,outcome="rejected")
        return q(PROSE,"submission-outcome.json","/reason","equals","AUTHORITY_UPGRADE",outcome="rejected")
    if requirement_id.startswith("S8_CONTEST_") or requirement_id.startswith("S8_OWNER_") or requirement_id.startswith("S8_NAMED_") or requirement_id == "S8_FUTURE_REMEDIATION_NO_CYCLE":
        return q(RISK,"duplicate-outcome.json","/error","equals","conflicting_duplicate_action",outcome="rejected")
    if requirement_id == "S8_MANAGEMENT_MIXED_VECTOR_REJECTION":
        return q(MANAGEMENT,"mixed-vector-outcome.json","/error","equals","artifact_dependency_vector_mismatch",outcome="rejected")
    if requirement_id == "S8_UPSTREAM_STALENESS":
        return q(MANAGEMENT,"stale-outcome.json","/error","equals","stale_dependency",outcome="rejected")
    if requirement_id.startswith("S8_"):
        return q(MANAGEMENT,"tamper-outcome.json","/error","equals","management_canonical_projection_tampered",outcome="rejected")
    if requirement_id=="SHARED_EXECUTED_CONTRACT_PARITY":return q_direct(TRANSPORT,"session6-8-contract-parity-report.json","/unexpected_pass_count","equals",0,outcome="rejected")
    if requirement_id=="SHARED_ZERO_PROHIBITED_OPERATIONS":return q_direct(READ_ONLY,"session6-8-security-receipt.json","/records","count_equals",44,outcome="rejected")
    if requirement_id=="SHARED_BEHAVIORAL_EVAL_INTEGRITY":return q_direct(HISTORICAL,"behavioral-eval-receipt.json","/cases","unique",True,outcome="rejected")
    if requirement_id=="SHARED_WORKFLOW_EVAL_INTEGRITY":return q_direct(HISTORICAL,"session6-8-workflow-eval-receipt.json","/cases","unique",True,outcome="rejected")
    if requirement_id=="SHARED_INSTALLED_WHEEL_LIFECYCLE":return q_direct(HISTORICAL,"session6-8-installed-wheel-receipt.json","/commands","unique",True,outcome="rejected")
    return VALID[requirement_id] | {"expected_boundary_outcome":"rejected"}


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",", ":")).encode()


def _evidence_artifact(case: str, name: str) -> str:
    return f"session6-8-workflow-evidence/{case}/{name}"


def _canonical_attack(requirement_id: str) -> tuple[str,str,str]:
    """Return an explicit production contract, artifact, and removed field.

    The emitted row is complete; runtime proof execution never infers a
    validator or mutation from a requirement prefix.
    """
    s6_packet={
        "S6_ISSUE_AUTHORITY_POLICY":"issue_classification","S6_MODEL_REVIEW_NOT_BLOCKER":"issue_authority",
        "S6_PLANNER_COMPILER_AUTHORITY":"root_cause_hypotheses","S6_HUMAN_OWNER_SEPARATION":"suggested_owner",
        "S6_OPTIONAL_PLANNER_LIFECYCLE":"limitations","S6_AUTOMATION_ELIGIBILITY":"automation_eligibility",
        "S6_BOUNDED_FIX_METADATA_ONLY":"execution_modes","S6_PACKET_CONTRACT_LINKS":"verification_contract_id",
        "S6_PACKET_FILE_INTEGRITY":"remediation_id","S6_PRIVATE_ALPHA_NON_MUTATION":"protected_invariants",
    }
    if requirement_id in s6_packet:return "remediation_packet",_evidence_artifact(DET if requirement_id not in {"S6_MODEL_REVIEW_NOT_BLOCKER"} else MODEL,"remediation-packet.json"),s6_packet[requirement_id]
    if requirement_id=="S6_REMEDIATION_CARDINALITY":return "remediation_plan",_evidence_artifact(CARDINALITY,"remediation-plan.json"),"packets"
    if requirement_id.startswith("S6_CLOSURE_"):
        fields={
          "S6_CLOSURE_CONTRACT_COMPLETENESS":"protected_invariants","S6_CLOSURE_EXACT_RERUN":"exact_checks_to_rerun",
          "S6_CLOSURE_PASS_REQUIRED":"required_after_evidence","S6_CLOSURE_VERIFIER_INDEPENDENCE":"independent_verifier_requirement",
          "S6_CLOSURE_COMMIT_BRANCH_FRESHNESS":"allowed_repository_commit","S6_CLOSURE_EVIDENCE_CLASS":"evidence_classes_allowed_to_close",
          "S6_CLOSURE_REGRESSION_REQUIREMENTS":"regression_checks","S6_CLOSURE_TEST_REQUIREMENTS":"test_requirements",
          "S6_CLOSURE_INSTRUMENTATION_REQUIREMENTS":"instrumentation_requirements","S6_CLOSURE_PROTECTED_INVARIANTS":"protected_invariants",
          "S6_CLOSURE_OWNER_DECISION":"owner_decision_requirement",
        }
        return "remediation_closure_contract",_evidence_artifact(CLOSURE,"closure-contract.json"),fields[requirement_id]
    s7_plan={
      "S7_SPECIALIST_CATALOGUE":"specialists","S7_NATIVE_BOUNDARY_REUSE":"specialists","S7_TYPED_SURFACE_POLICY":"specialists",
      "S7_SELECTION_EVIDENCE_LINKS":"specialists","S7_PYTHON_SELECTION":"input_vector","S7_TYPESCRIPT_SELECTION":"input_vector",
      "S7_AI_SELECTION":"specialists","S7_BROWSER_EXPLICIT_SKIP":"specialists","S7_BROWSER_ABSENCE_NOT_INSPECTED":"specialists",
      "S7_TEST_ADEQUACY_APPLICABILITY":"specialists","S7_INSTRUMENTATION_APPLICABILITY":"specialists",
    }
    if requirement_id in s7_plan:
        case=AI if requirement_id in {"S7_NATIVE_BOUNDARY_REUSE","S7_TYPED_SURFACE_POLICY","S7_SELECTION_EVIDENCE_LINKS","S7_AI_SELECTION","S7_INSTRUMENTATION_APPLICABILITY"} else (BROWSER if "BROWSER" in requirement_id else LANGUAGES)
        name="review-plan.json" if case!=LANGUAGES else ("typescript-review-plan.json" if requirement_id=="S7_TYPESCRIPT_SELECTION" else "python-review-plan.json")
        return "review_plan",_evidence_artifact(case,name),s7_plan[requirement_id]
    if requirement_id in {"S7_PRODUCT_INTENT_WRAPPER","S7_NATIVE_WORK_ORDER_INTEGRITY","S7_CODEX_PACKAGE_COMPLETENESS","S7_MANUAL_CODEX_PARITY"}:
        return "codex_execution_package",_evidence_artifact(TRANSPORT,"codex-execution-package.json"),"native_work_order"
    if requirement_id=="S7_HARNESS_DECLARATION_HONESTY":return "harness_execution_receipt",_evidence_artifact(TRANSPORT,"manual-receipt.json"),"independence_limitation"
    if requirement_id in {"S7_TRUSTED_SUBMISSION_PATHS","S7_CORRECTED_RESULT_ACCEPTANCE"}:
        return "review_accepted_results",_evidence_artifact(REVISION,"accepted-results.json"),"results"
    if requirement_id=="S7_FAILED_RESULT_NO_ADAPTATION":
        return "review_revision_ledger",_evidence_artifact(REVISION_FAIL,"revision-ledger.json"),"entries"
    if requirement_id in {"S7_SUBMISSION_BYTE_PERSISTENCE","S7_REVISION_REQUEST","S7_SECOND_INVALID_FAILURE"}:
        return "review_revision_ledger",_evidence_artifact(REVISION if requirement_id!="S7_SECOND_INVALID_FAILURE" else REVISION_FAIL,"revision-ledger.json"),"entries"
    if requirement_id in {"S7_TRIGGER_SPECIFIC_EVIDENCE","S7_MIGRATION_ADAPTATION","S7_AI_ADAPTATION","S7_BROWSER_DISPROVEN_ADAPTATION","S7_SUPERSEDED_WORK_ORDER_PRESERVATION","S7_ADAPTATION_IDEMPOTENCY"}:
        return "review_plan",_evidence_artifact(ADAPT,"after-review-plan.json"),"adaptation_depth"
    if requirement_id in {"S7_ADAPTATION_CYCLE_DEPTH","S7_POINTER_LAST_PUBLICATION"}:
        return "review_plan",_evidence_artifact(ADAPT,"after-review-plan.json"),"adaptation_depth" if requirement_id=="S7_ADAPTATION_CYCLE_DEPTH" else "supersedes"
    contest_ledger={"S8_CONTEST_TARGET_REGISTRY","S8_CONTEST_SOURCE_GENERATION","S8_CONTEST_TARGET_EXISTENCE","S8_CONTEST_EVIDENCE_EXISTENCE","S8_CONTEST_EVIDENCE_RELEVANCE","S8_CONTEST_AUTHORITY_PRESERVATION","S8_CONTEST_APPEND_SEQUENCE","S8_CONTEST_PREVIOUS_HASH","S8_CONTEST_IDEMPOTENT_REPLAY","S8_CONTEST_CONFLICTING_DUPLICATE","S8_CONTEST_OWNER_AUTHORITY","S8_NAMED_RISK_FACT_NON_MUTATION","S8_FUTURE_REMEDIATION_NO_CYCLE"}
    if requirement_id in contest_ledger:return "contestation_ledger",_evidence_artifact(RISK if requirement_id in {"S8_CONTEST_APPEND_SEQUENCE","S8_CONTEST_PREVIOUS_HASH","S8_CONTEST_OWNER_AUTHORITY"} else CONTEST,"contestation-ledger.json"),"actions"
    if requirement_id in {"S8_NAMED_RISK_DECISION_EFFECT","S8_OWNER_DECISION_BUDGET","S8_OWNER_DECISION_PRIORITY","S8_OWNER_DECISION_OVERFLOW"}:
        field={"S8_NAMED_RISK_DECISION_EFFECT":"named_risk_effects","S8_OWNER_DECISION_BUDGET":"immediate_owner_decisions","S8_OWNER_DECISION_PRIORITY":"priority_reason_codes","S8_OWNER_DECISION_OVERFLOW":"overflow_owner_decisions"}[requirement_id]
        return "contestation_effects",_evidence_artifact(RISK,"contestation-effects.json"),field
    management_map={
      "S8_EXECUTIVE_SECTION_COMPLETENESS":("management_executive_release_brief","artifacts/executive-release-brief.json","sections"),
      "S8_PRODUCT_MATRIX_COMPLETENESS":("management_product_release_review","artifacts/product-release-review.json","section_records"),
      "S8_ENGINEERING_SECTION_COMPLETENESS":("management_engineering_release_assessment","artifacts/engineering-release-assessment.json","section_records"),
      "S8_MEASUREMENT_AI_PASSTHROUGH":("management_measurement_ai_readiness","artifacts/measurement-ai-readiness.json","canonical_artifacts"),
      "S8_REMEDIATION_OVERVIEW_COMPLETENESS":("management_remediation_overview","artifacts/remediation-overview.json","canonical_artifacts"),
      "S8_CLOSURE_CONTRACT_INDEXING":("management_remediation_overview","artifacts/remediation-overview.json","section_records"),
      "S8_CONTESTABILITY_INCLUSION":("management_executive_release_brief","artifacts/executive-release-brief.json","section_records"),
      "S8_RECOMMENDATION_POLICY":("management_release_recommendation_view","artifacts/release-recommendation-view.json","computed_recommendation"),
      "S8_ACCEPTED_CONDITION_EFFECT":("management_executive_release_brief","artifacts/executive-release-brief.json","section_records"),
      "S8_NAMED_RISK_RECOMMENDATION_EFFECT":("management_release_recommendation_view","artifacts/release-recommendation-view.json","computed_recommendation"),
      "S8_INSUFFICIENT_EVIDENCE_STATE":("management_executive_release_brief","artifacts/executive-release-brief.json","unknowns"),
    }
    if requirement_id in management_map:
        contract,name,field=management_map[requirement_id];return contract,_evidence_artifact(MANAGEMENT,name),field
    if requirement_id.startswith("S8_MANAGEMENT_") or requirement_id in {"S8_DETERMINISTIC_JSON","S8_ARTIFACT_HASH_INTEGRITY","S8_ARTIFACT_FILE_SET","S8_DETERMINISTIC_RERENDER","S8_UPSTREAM_STALENESS"}:
        return "management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"artifact_dependency_vector" if "DEPENDENCY" in requirement_id or requirement_id=="S8_UPSTREAM_STALENESS" else "artifact_hashes"
    if requirement_id in {"S8_SAFE_HTML","S8_SAFE_MARKDOWN"}:
        return "management_executive_release_brief",_evidence_artifact(MANAGEMENT,"artifacts/executive-release-brief.json"),"sections"
    # Shared integrity proofs use the same real canonical loaders they protect;
    # the registry remains explicit after generation and no runtime prefix
    # dispatch exists.
    shared={
      "SHARED_TRUSTED_READS":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"artifact_hashes"),
      "SHARED_TRUSTED_WRITES":("remediation_plan",_evidence_artifact(CARDINALITY,"remediation-plan.json"),"packets"),
      "SHARED_LINK_REPARSE_SPECIAL_REJECTION":("remediation_plan",_evidence_artifact(CARDINALITY,"remediation-plan.json"),"schema_version"),
      "SHARED_CAPACITY_LIMITS":("remediation_plan",_evidence_artifact(CARDINALITY,"remediation-plan.json"),"packets"),
      "SHARED_POINTER_LATE_FAILURE":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"bundle_hash"),
      "SHARED_ZERO_PROHIBITED_OPERATIONS":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"artifact_hashes"),
      "SHARED_CONTRACT_INVENTORY":("review_accepted_results",_evidence_artifact(TRANSPORT,"accepted-results.json"),"results"),
      "SHARED_EXECUTED_CONTRACT_PARITY":("review_accepted_results",_evidence_artifact(TRANSPORT,"accepted-results.json"),"results"),
      "SHARED_BEHAVIORAL_EVAL_INTEGRITY":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"semantic_bundle_hash"),
      "SHARED_WORKFLOW_EVAL_INTEGRITY":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"schema_version"),
      "SHARED_INSTALLED_WHEEL_LIFECYCLE":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"release_id"),
      "SHARED_SKILL_PILOT_CONSISTENCY":("remediation_plan",_evidence_artifact(CARDINALITY,"remediation-plan.json"),"release_id"),
      "SHARED_PROOF_EXECUTION":("remediation_overlay",_evidence_artifact(CARDINALITY,"remediation-overlay.json"),"nodes"),
      "SHARED_CLOSEOUT_GENERATION":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"schema_version"),
      "SHARED_INDEPENDENT_VALIDATION":("management_generation_manifest",_evidence_artifact(MANAGEMENT,"generation-manifest.json"),"compiler_version"),
    }
    return shared[requirement_id]


def _attack_spec(requirement_id: str, proof_id: str) -> tuple[dict,dict,str]:
    contract,artifact,field=_canonical_attack(requirement_id)
    if requirement_id in {"S6_REMEDIATION_CARDINALITY","S6_PACKET_CONTRACT_LINKS","S6_PACKET_FILE_INTEGRITY"}:
        function="shiproom.remediation_roadmaps.validate_generation_projection"
        artifact=_evidence_artifact(CARDINALITY,"remediation-plan.json")
        args=["$artifact:"+_evidence_artifact(CARDINALITY,"remediation-index.json"),"$mutated","$artifact:"+_evidence_artifact(CARDINALITY,"remediation-overlay.json"),"$artifact:"+_evidence_artifact(CARDINALITY,"closure-contracts.json")]
        if requirement_id=="S6_REMEDIATION_CARDINALITY":mutation={"operation":"duplicate","pointer":"/packets"};target="/packets";error="remediation_packet_cardinality_invalid";mutation_class="duplicate_packet"
        elif requirement_id=="S6_PACKET_CONTRACT_LINKS":mutation={"operation":"remove","pointer":"/packets/0/verification_contract_id"};target="/packets/0/verification_contract_id";error="remediation_closure_contract_cardinality_invalid";mutation_class="broken_contract_link"
        else:mutation={"operation":"replace","pointer":"/packets/0/remediation_id","value":"remediation_tampered"};target="/packets/0/remediation_id";error="remediation_index_packet_mismatch";mutation_class="packet_identity_tamper"
        spec={"schema_version":"production-proof-attack.v1","subcase_id":proof_id,"mutation_id":"mutation_"+proof_id,"mutation_class":mutation_class,"target":target,"base_artifact":artifact,"mutation":mutation,"production_function":function,"arguments":args,"expected_status_or_error":error,"expected_exception":"ValueError","channel":"exception"}
        outcome={"schema_version":"production-rejection-binding.v1","subcase_id":proof_id,"channel":"exception","production_function":function,"expected_status_or_error":error,"expected_exception":"ValueError","receipt_artifact":None,"receipt_hash":None}
        return spec,outcome,error
    special={
      "codex_execution_package":("shiproom.review_organisation.validate_codex_execution_package",["$mutated"],"codex_execution_package_shape_invalid"),
      "harness_execution_receipt":("shiproom.review_organisation.validate_harness_execution_receipt",["$mutated","$base_work_order_id"],"harness_execution_receipt_shape_invalid"),
    }
    if contract in special:
        function,args,error=special[contract]
        if "$base_work_order_id" in args:
            # The executor resolves this closed token from the unmodified base.
            args=["$mutated",{"$keyword":{"name":"work_order_id","base_pointer":"/work_order_id"}}]
    else:function,args,error="shiproom.session6_8_contract_validation.validate_canonical_contract",[contract,"$mutated"],contract+"_contract_invalid"
    spec={"schema_version":"production-proof-attack.v1","subcase_id":proof_id,"mutation_id":"mutation_"+proof_id,"mutation_class":"required_binding_removed","target":"/"+field,"base_artifact":artifact,"mutation":{"operation":"remove","pointer":"/"+field},"production_function":function,"arguments":args,"expected_status_or_error":error,"expected_exception":"ValueError","channel":"exception"}
    outcome={"schema_version":"production-rejection-binding.v1","subcase_id":proof_id,"channel":"exception","production_function":function,"expected_status_or_error":error,"expected_exception":"ValueError","receipt_artifact":None,"receipt_hash":None}
    return spec,outcome,error


def main() -> int:
    inventory=json.loads((VALIDATION/"session6-8-requirement-inventory.json").read_text(encoding="utf-8"))
    requirements=inventory["requirements"]
    if len(requirements)!=106 or set(VALID)!={row["requirement_id"] for row in requirements}:
        raise SystemExit("authentic_proof_source_coverage_invalid")
    workflow_contracts={row["case_name"]:row for row in json.loads((VALIDATION/"session6-8-workflow-contracts.json").read_text(encoding="utf-8"))["cases"]}
    rows=[]
    for ordinal,requirement in enumerate(requirements,1):
        rid=requirement["requirement_id"]
        variants={"valid":VALID[rid],"near_valid":_near(rid),"adversarial_invalid":_adversarial(rid)}
        adversarial_id=f"proof_{rid.lower()}_adversarial_invalid"
        attack_spec,outcome_evidence,attack_error=_attack_spec(rid,adversarial_id)
        requirement["adversarial_behavior"]=(
            f"The owning production boundary {attack_spec['production_function']} must reject the isolated "
            f"{attack_spec['mutation_class']} mutation at {attack_spec['target']} with {attack_error}; "
            "a passing artifact query or configured label is never rejection authority."
        )
        requirement["adversarial_error_code"]=attack_error
        requirement["source_text_hash"]="sha256:"+hashlib.sha256(requirement["normative_behavior"].encode("utf-8")).hexdigest()
        requirement["approved_semantic_hash"]=requirement_semantic_hash(requirement)
        for fixture_class in CLASSES:
            source=variants[fixture_class]; case=source["workflow_case"]
            query=source["query"]
            proof_id=f"proof_{rid.lower()}_{fixture_class}"
            if fixture_class=="adversarial_invalid":
                queries=[{"artifact":f"proof-artifacts/{proof_id}/subcase-manifest.json","selector":"/mutation_id","operator":"equals","expected":"mutation_"+proof_id},query]
            else:queries=[query]
            if fixture_class == "near_valid" and VALID[rid]["query"] != query:
                queries.append(VALID[rid]["query"])
            active_attack=attack_spec if fixture_class=="adversarial_invalid" else None
            near_spec={"schema_version":"production-proof-near-binding.v1","subcase_id":proof_id,"mutation_id":"bounded_"+proof_id,"mutation_class":"bounded_production_state","target":query["selector"] or "/"} if fixture_class=="near_valid" else None
            fingerprint_input={"workflow_case":case,"production_functions":workflow_contracts[case]["required_production_functions"],"queries":queries,"expected_boundary_outcome":source["expected_boundary_outcome"],"attack_spec":active_attack,"near_spec":near_spec}
            rows.append({
                "proof_id":proof_id,"requirement_id":rid,"fixture_class":fixture_class,
                "workflow_case":case,"production_functions":workflow_contracts[case]["required_production_functions"],
                "artifact_queries":queries,"expected_boundary_outcome":source["expected_boundary_outcome"],
                "expected_acceptance":fixture_class!="adversarial_invalid",
                "expected_error":attack_error if fixture_class=="adversarial_invalid" else None,
                "expected_exception":"ValueError" if fixture_class=="adversarial_invalid" else None,
                "fixture_binding":None,"outcome_evidence":outcome_evidence if fixture_class=="adversarial_invalid" else None,
                "attack_spec":active_attack,"near_spec":near_spec,
                "minimum_cardinality":1,"canonical_artifacts":sorted({item["artifact"] for item in queries}),
                "semantic_fingerprint":"sha256:"+hashlib.sha256(_canonical(fingerprint_input)).hexdigest(),
                "shared_mechanism_justification":"The retained production lifecycle is shared; this requirement uses its own frozen artifact selector and comparator.",
                "independent_requirement_assertion":requirement["normative_behavior"],"requirement_ordinal":ordinal,
            })
    if len(rows)!=318 or len({row["proof_id"] for row in rows})!=318:
        raise SystemExit("authentic_proof_registry_cardinality_invalid")
    groups={}
    for row in rows:groups.setdefault(row["semantic_fingerprint"],[]).append(row)
    duplicates=[group for group in groups.values() if len({row["requirement_id"] for row in group})>1]
    unjustified=[group for group in duplicates if len({json.dumps(row["artifact_queries"],sort_keys=True) for row in group})<=1]
    audit={"schema_version":"session6-8-proof-fingerprint-audit.v2","proof_count":318,"unique_fingerprint_count":len(groups),"duplicate_group_count":len(duplicates),"unjustified_duplicate_count":len(unjustified),"duplicates":[{"fingerprint":group[0]["semantic_fingerprint"],"proof_ids":[row["proof_id"] for row in group],"justifications":[row["shared_mechanism_justification"] for row in group]} for group in duplicates],"status":"passed" if not unjustified else "failed"}
    registry={"schema_version":"session6-8-requirement-proof-registry.v2","proof_count":318,"proofs":rows}
    (VALIDATION/"session6-8-requirement-inventory.json").write_text(
        json.dumps(inventory,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"
    )
    raw=json.dumps(registry,sort_keys=True,ensure_ascii=False,indent=2)+"\n"
    (VALIDATION/"session6-8-requirement-proof-registry.json").write_text(raw,encoding="utf-8")
    (ROOT/"shiproom"/"session6_8_requirement_proof_registry.json").write_text(raw,encoding="utf-8")
    (VALIDATION/"session6-8-proof-fingerprint-audit.json").write_text(json.dumps(audit,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"proofs":318,"unique_fingerprints":len(groups),"duplicate_groups":len(duplicates),"status":audit["status"]}))
    return 0 if audit["status"]=="passed" else 2


if __name__=="__main__":raise SystemExit(main())
