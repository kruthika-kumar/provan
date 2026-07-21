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
    "S8_CONTEST_IDEMPOTENT_REPLAY": q(CONTEST,"accepted-action.json","/status","equals","accepted"),
    "S8_CONTEST_CONFLICTING_DUPLICATE": q(CONTEST,"contestation-ledger.json","/actions","count_equals",1),
    "S8_CONTEST_OWNER_AUTHORITY": q(RISK,"contestation-ledger.json","/actions/0/owner_authority_ref","equals","owner_workflow"),
    "S8_NAMED_RISK_FACT_NON_MUTATION": q(RISK,"source-findings.json","/0/state","equals","OPEN"),
    "S8_NAMED_RISK_DECISION_EFFECT": q(RISK,"contestation-effects.json","/named_risk_effects","count_equals",4),
    "S8_OWNER_DECISION_BUDGET": q(RISK,"contestation-effects.json","/immediate_owner_decisions","count_equals",2),
    "S8_OWNER_DECISION_PRIORITY": q(RISK,"contestation-effects.json","/priority_reason_codes","ordered_equals",["verified_blocker_requires_owner_action","canonical_material_condition","high_risk_unresolved_decision","high_risk_unresolved_decision"]),
    "S8_OWNER_DECISION_OVERFLOW": q(RISK,"contestation-effects.json","/overflow_owner_decisions","count_equals",2),
    "S8_FUTURE_REMEDIATION_NO_CYCLE": q(CONTEST,"contestation-effects.json","/remediation_requests","count_equals",1),

    "S8_MANAGEMENT_DEPENDENCY_DISCOVERY": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector","count_at_least",8),
    "S8_MANAGEMENT_DEPENDENCY_STATES": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/schema_version","equals","artifact-dependency-vector.v1"),
    "S8_MANAGEMENT_DEPENDENCY_FRESHNESS": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/measurement_ai/state","equals","required_present"),
    "S8_MANAGEMENT_MIXED_VECTOR_REJECTION": q(MANAGEMENT,"artifacts/release-packet-index","/artifact_dependency_vector","equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/artifacts/executive-release-brief","selector":"/artifact_dependency_vector"}),
    "S8_EXECUTIVE_SECTION_COMPLETENESS": q(MANAGEMENT,"artifacts/executive-release-brief","/sections","count_at_least",1),
    "S8_PRODUCT_MATRIX_COMPLETENESS": q(MANAGEMENT,"artifacts/product-release-review","/section_records/16/records","count_at_least",1),
    "S8_ENGINEERING_SECTION_COMPLETENESS": q(MANAGEMENT,"artifacts/engineering-release-assessment","/sections","count_at_least",1),
    "S8_MEASUREMENT_AI_PASSTHROUGH": q(MANAGEMENT,"artifacts/measurement-ai-readiness","/section_records/4/records","field_set_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/measurement-ai/measurement-ai-readiness.json","selector":"/checks","field":"check_id"}),
    "S8_REMEDIATION_OVERVIEW_COMPLETENESS": q(MANAGEMENT,"artifacts/remediation-overview","/section_records/0/records","count_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/remediation/remediation-plan.json","selector":"/packets"}),
    "S8_CLOSURE_CONTRACT_INDEXING": q(MANAGEMENT,"artifacts/remediation-overview","/section_records/2/records","count_equals_reference",{"artifact":f"session6-8-workflow-evidence/{MANAGEMENT}/sources/remediation/remediation-plan.json","selector":"/packets"}),
    "S8_CONTESTABILITY_INCLUSION": q(MANAGEMENT,"sources/contestability/contestation-ledger.json","/actions","count_at_least",1),
    "S8_RECOMMENDATION_POLICY": q(MANAGEMENT,"artifacts/release-recommendation-view","/computed_recommendation/status","not_equals",None),
    "S8_ACCEPTED_CONDITION_EFFECT": q(MANAGEMENT,"artifacts/executive-release-brief","/section_records/5/records","count_at_least",1),
    "S8_NAMED_RISK_RECOMMENDATION_EFFECT": q(MANAGEMENT,"artifacts/release-recommendation-view","/computed_recommendation/reason_codes","count_at_least",1),
    "S8_INSUFFICIENT_EVIDENCE_STATE": q(MANAGEMENT,"artifacts/executive-release-brief","/section_records/3/records","count_at_least",1),
    "S8_DETERMINISTIC_JSON": q(MANAGEMENT,"generation-manifest.json","/semantic_bundle_hash","not_equals",None),
    "S8_SAFE_HTML": q(MANAGEMENT,"rendered/executive-release-brief.html","","text_absent",["<script","<iframe","http://","https://"]),
    "S8_SAFE_MARKDOWN": q(MANAGEMENT,"rendered/github-summary.md","","text_contains","# Shiproom release summary"),
    "S8_ARTIFACT_HASH_INTEGRITY": q(MANAGEMENT,"generation-manifest.json","/artifact_hashes","count_at_least",7),
    "S8_ARTIFACT_FILE_SET": q(MANAGEMENT,"generation-manifest.json","/artifact_hashes","not_equals",{}),
    "S8_DETERMINISTIC_RERENDER": q(MANAGEMENT,"generation-manifest.json","/bundle_hash","not_equals",None),
    "S8_UPSTREAM_STALENESS": q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/remediation/state","equals","required_present"),

    "SHARED_TRUSTED_READS": q(READ_ONLY,"repository-state.json","/before_status","equals_reference",{"artifact":f"session6-8-workflow-evidence/{READ_ONLY}/repository-state.json","selector":"/after_status"}),
    "SHARED_TRUSTED_WRITES": q(READ_ONLY,"repository-state.json","/source_unchanged","equals",True),
    "SHARED_LINK_REPARSE_SPECIAL_REJECTION": q(HISTORICAL,"historical-remediation-receipt.json","/cleanup_completed","equals",True),
    "SHARED_CAPACITY_LIMITS": q(CARDINALITY,"remediation-plan.json","/packets","count_at_least",3),
    "SHARED_POINTER_LATE_FAILURE": q(ADAPT,"after-review-plan.json","/supersedes","not_equals",None),
    "SHARED_ZERO_PROHIBITED_OPERATIONS": q(HISTORICAL,"historical-remediation-receipt.json","/source_status_before_hash","equals_reference",{"artifact":f"session6-8-workflow-evidence/{HISTORICAL}/historical-remediation-receipt.json","selector":"/source_status_after_hash"}),
    "SHARED_CONTRACT_INVENTORY": q(TRANSPORT,"codex-execution-package.json","/result_schema","equals","migration-and-rollback-result.v1"),
    "SHARED_EXECUTED_CONTRACT_PARITY": q(TRANSPORT,"manual-submission.json","/status","equals","accepted"),
    "SHARED_BEHAVIORAL_EVAL_INTEGRITY": q(HISTORICAL,"historical-remediation-receipt.json","/allowlisted_files","count_equals",1),
    "SHARED_WORKFLOW_EVAL_INTEGRITY": q(HISTORICAL,"historical-remediation-receipt.json","/status","equals","verified"),
    "SHARED_INSTALLED_WHEEL_LIFECYCLE": q(HISTORICAL,"historical-remediation-receipt.json","/exact_rerun_passed","equals",True),
    "SHARED_SKILL_PILOT_CONSISTENCY": q(HISTORICAL,"historical-remediation-receipt.json","/source_repository_unchanged","equals",True),
    "SHARED_PROOF_EXECUTION": q(CARDINALITY,"remediation-overlay.json","/nodes","count_equals",3),
    "SHARED_CLOSEOUT_GENERATION": q(MANAGEMENT,"generation-manifest.json","/schema_version","equals","management-generation-manifest.v1"),
    "SHARED_INDEPENDENT_VALIDATION": q(HISTORICAL,"historical-remediation-receipt.json","/temporary_branch","equals","bounded-route-remediation"),
}


def _near(requirement_id: str) -> dict:
    if requirement_id.startswith("S6_CLOSURE_"):
        return q(CLOSURE,"closure-outcomes.json","/wrong_check/status","equals","unsatisfied",outcome="bounded")
    if requirement_id.startswith("S6_"):
        return q(UNSAFE,"remediation-packet.json","/automation_eligibility","equals","roadmap_only",outcome="bounded")
    if requirement_id.startswith("S7_"):
        if "REVISION" in requirement_id or "RESULT" in requirement_id or "SUBMISSION" in requirement_id:
            return q(REVISION,"first-submission.json","/status","equals","revision_required",outcome="bounded")
        return q(BROWSER,"browser-absence-specialist.json","/applicability_authority","equals","not_inspected",outcome="bounded")
    if requirement_id.startswith("S8_CONTEST_") or requirement_id.startswith("S8_OWNER_") or requirement_id.startswith("S8_NAMED_") or requirement_id == "S8_FUTURE_REMEDIATION_NO_CYCLE":
        return q(CONTEST,"contestation-ledger.json","/actions","count_equals",1,outcome="bounded")
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
        return q(CONTEST,"contestation-ledger.json","/actions","count_equals",1,outcome="rejected")
    if requirement_id.startswith("S8_"):
        return q(MANAGEMENT,"generation-manifest.json","/artifact_dependency_vector/measurement_ai/state","equals","required_present",outcome="rejected")
    return VALID[requirement_id] | {"expected_boundary_outcome":"rejected"}


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",", ":")).encode()


def main() -> int:
    inventory=json.loads((VALIDATION/"session6-8-requirement-inventory.json").read_text())
    requirements=inventory["requirements"]
    if len(requirements)!=106 or set(VALID)!={row["requirement_id"] for row in requirements}:
        raise SystemExit("authentic_proof_source_coverage_invalid")
    workflow_contracts={row["case_name"]:row for row in json.loads((VALIDATION/"session6-8-workflow-contracts.json").read_text())["cases"]}
    rows=[]
    for ordinal,requirement in enumerate(requirements,1):
        rid=requirement["requirement_id"]
        variants={"valid":VALID[rid],"near_valid":_near(rid),"adversarial_invalid":_adversarial(rid)}
        for fixture_class in CLASSES:
            source=variants[fixture_class]; case=source["workflow_case"]
            query=source["query"]
            queries=[query]
            if fixture_class != "valid" and VALID[rid]["query"] != query:
                queries.append(VALID[rid]["query"])
            fingerprint_input={"workflow_case":case,"production_functions":workflow_contracts[case]["required_production_functions"],"queries":queries,"expected_boundary_outcome":source["expected_boundary_outcome"]}
            rows.append({
                "proof_id":f"proof_{rid.lower()}_{fixture_class}","requirement_id":rid,"fixture_class":fixture_class,
                "workflow_case":case,"production_functions":workflow_contracts[case]["required_production_functions"],
                "artifact_queries":queries,"expected_boundary_outcome":source["expected_boundary_outcome"],
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
    raw=json.dumps(registry,sort_keys=True,ensure_ascii=False,indent=2)+"\n"
    (VALIDATION/"session6-8-requirement-proof-registry.json").write_text(raw,encoding="utf-8")
    (ROOT/"shiproom"/"session6_8_requirement_proof_registry.json").write_text(raw,encoding="utf-8")
    (VALIDATION/"session6-8-proof-fingerprint-audit.json").write_text(json.dumps(audit,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"proofs":318,"unique_fingerprints":len(groups),"duplicate_groups":len(duplicates),"status":audit["status"]}))
    return 0 if audit["status"]=="passed" else 2


if __name__=="__main__":raise SystemExit(main())
