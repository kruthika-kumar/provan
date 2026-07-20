"""Build the exhaustive Sessions 6--8 inventory and evidence-map skeletons.

The executable proof runner fills proof status from test-time events.  This
builder owns identifiers and immutable expectations only; it never labels a
proof verified.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "docs" / "validation"

GROUPS = {
"6": """S6_ISSUE_AUTHORITY_POLICY S6_MODEL_REVIEW_NOT_BLOCKER S6_PLANNER_COMPILER_AUTHORITY S6_HUMAN_OWNER_SEPARATION S6_OPTIONAL_PLANNER_LIFECYCLE S6_AUTOMATION_ELIGIBILITY S6_BOUNDED_FIX_METADATA_ONLY S6_REMEDIATION_CARDINALITY S6_PACKET_CONTRACT_LINKS S6_PACKET_FILE_INTEGRITY S6_CLOSURE_CONTRACT_COMPLETENESS S6_CLOSURE_EXACT_RERUN S6_CLOSURE_PASS_REQUIRED S6_CLOSURE_VERIFIER_INDEPENDENCE S6_CLOSURE_COMMIT_BRANCH_FRESHNESS S6_CLOSURE_EVIDENCE_CLASS S6_CLOSURE_REGRESSION_REQUIREMENTS S6_CLOSURE_TEST_REQUIREMENTS S6_CLOSURE_INSTRUMENTATION_REQUIREMENTS S6_CLOSURE_PROTECTED_INVARIANTS S6_CLOSURE_OWNER_DECISION S6_PRIVATE_ALPHA_NON_MUTATION""".split(),
"7": """S7_SPECIALIST_CATALOGUE S7_NATIVE_BOUNDARY_REUSE S7_TYPED_SURFACE_POLICY S7_SELECTION_EVIDENCE_LINKS S7_PYTHON_SELECTION S7_TYPESCRIPT_SELECTION S7_AI_SELECTION S7_BROWSER_EXPLICIT_SKIP S7_BROWSER_ABSENCE_NOT_INSPECTED S7_TEST_ADEQUACY_APPLICABILITY S7_INSTRUMENTATION_APPLICABILITY S7_PRODUCT_INTENT_WRAPPER S7_NATIVE_WORK_ORDER_INTEGRITY S7_CODEX_PACKAGE_COMPLETENESS S7_HARNESS_DECLARATION_HONESTY S7_MANUAL_CODEX_PARITY S7_TRUSTED_SUBMISSION_PATHS S7_SUBMISSION_BYTE_PERSISTENCE S7_REVISION_REQUEST S7_CORRECTED_RESULT_ACCEPTANCE S7_SECOND_INVALID_FAILURE S7_FAILED_RESULT_NO_ADAPTATION S7_TRIGGER_SPECIFIC_EVIDENCE S7_MIGRATION_ADAPTATION S7_AI_ADAPTATION S7_BROWSER_DISPROVEN_ADAPTATION S7_SUPERSEDED_WORK_ORDER_PRESERVATION S7_ADAPTATION_IDEMPOTENCY S7_ADAPTATION_CYCLE_DEPTH S7_POINTER_LAST_PUBLICATION""".split(),
"8_contestability": """S8_CONTEST_TARGET_REGISTRY S8_CONTEST_SOURCE_GENERATION S8_CONTEST_TARGET_EXISTENCE S8_CONTEST_EVIDENCE_EXISTENCE S8_CONTEST_EVIDENCE_RELEVANCE S8_CONTEST_AUTHORITY_PRESERVATION S8_CONTEST_APPEND_SEQUENCE S8_CONTEST_PREVIOUS_HASH S8_CONTEST_IDEMPOTENT_REPLAY S8_CONTEST_CONFLICTING_DUPLICATE S8_CONTEST_OWNER_AUTHORITY S8_NAMED_RISK_FACT_NON_MUTATION S8_NAMED_RISK_DECISION_EFFECT S8_OWNER_DECISION_BUDGET S8_OWNER_DECISION_PRIORITY S8_OWNER_DECISION_OVERFLOW S8_FUTURE_REMEDIATION_NO_CYCLE""".split(),
"8_management": """S8_MANAGEMENT_DEPENDENCY_DISCOVERY S8_MANAGEMENT_DEPENDENCY_STATES S8_MANAGEMENT_DEPENDENCY_FRESHNESS S8_MANAGEMENT_MIXED_VECTOR_REJECTION S8_EXECUTIVE_SECTION_COMPLETENESS S8_PRODUCT_MATRIX_COMPLETENESS S8_ENGINEERING_SECTION_COMPLETENESS S8_MEASUREMENT_AI_PASSTHROUGH S8_REMEDIATION_OVERVIEW_COMPLETENESS S8_CLOSURE_CONTRACT_INDEXING S8_CONTESTABILITY_INCLUSION S8_RECOMMENDATION_POLICY S8_ACCEPTED_CONDITION_EFFECT S8_NAMED_RISK_RECOMMENDATION_EFFECT S8_INSUFFICIENT_EVIDENCE_STATE S8_DETERMINISTIC_JSON S8_SAFE_HTML S8_SAFE_MARKDOWN S8_ARTIFACT_HASH_INTEGRITY S8_ARTIFACT_FILE_SET S8_DETERMINISTIC_RERENDER S8_UPSTREAM_STALENESS""".split(),
"shared": """SHARED_TRUSTED_READS SHARED_TRUSTED_WRITES SHARED_LINK_REPARSE_SPECIAL_REJECTION SHARED_CAPACITY_LIMITS SHARED_POINTER_LATE_FAILURE SHARED_ZERO_PROHIBITED_OPERATIONS SHARED_CONTRACT_INVENTORY SHARED_EXECUTED_CONTRACT_PARITY SHARED_BEHAVIORAL_EVAL_INTEGRITY SHARED_WORKFLOW_EVAL_INTEGRITY SHARED_INSTALLED_WHEEL_LIFECYCLE SHARED_SKILL_PILOT_CONSISTENCY SHARED_PROOF_EXECUTION SHARED_CLOSEOUT_GENERATION SHARED_INDEPENDENT_VALIDATION""".split(),
}
EXPECTED = {"6": 22, "7": 30, "8_contestability": 17, "8_management": 22, "shared": 15}

def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()

def _semantic_hash(requirement_id: str, behavior: str, forbidden: list[str], artifacts: list[str], cardinalities: dict[str, int]) -> str:
    approved = {
        "requirement_id": requirement_id,
        "normative_behavior": behavior,
        "forbidden_substitutions": forbidden,
        "required_artifacts": artifacts,
        "minimum_cardinalities": cardinalities,
    }
    return _sha(json.dumps(approved, ensure_ascii=False, sort_keys=True, separators=(",", ":")))

def _metadata(requirement_id: str, group: str) -> tuple[str, str, str]:
    if group == "6": return "shiproom.remediation_roadmaps.closure_verify", "remediation-plan.json", "remediation"
    if group == "7": return "shiproom.review_organisation.prepare", "review-plan.json", "review_plan"
    if group == "8_contestability": return "shiproom.contestability.append_action", "contestation-ledger.json", "contestation"
    if group == "8_management": return "shiproom.management_artifacts.compile", "release-packet-index.json", "management"
    return "scripts.run_workflow_integration_evals.main", "session6-8-workflow-eval-receipt.json", "shared"

def _adversarial_error(requirement_id: str, group: str) -> str:
    if requirement_id in {"S6_ISSUE_AUTHORITY_POLICY","S6_MODEL_REVIEW_NOT_BLOCKER","S6_PLANNER_COMPILER_AUTHORITY","S6_HUMAN_OWNER_SEPARATION","S6_AUTOMATION_ELIGIBILITY","S6_BOUNDED_FIX_METADATA_ONLY"}:
        return "remediation_issue_authority_policy_invalid"
    if group in {"6","8_management","shared"}: return "optional_dependency_must_be_null"
    if group == "7": return "harness_capability_manifest_shape_invalid"
    return "contestation_target_unregistered"

def _approved_behavior(requirement_id: str) -> str:
    words = requirement_id.removeprefix("SHARED_").removeprefix("S8_MANAGEMENT_").removeprefix("S8_CONTEST_").removeprefix("S7_").removeprefix("S6_").lower().replace("_", " ")
    domain = (
        "Remediation" if requirement_id.startswith("S6_") else
        "Review planning" if requirement_id.startswith("S7_") else
        "Contestability" if requirement_id.startswith("S8_CONTEST_") else
        "Management compilation" if requirement_id.startswith("S8_MANAGEMENT_") else
        "Shared integrity"
    )
    return f"{domain} must enforce {words} through its registered production boundary and canonical persisted evidence."

def _approved_forbidden(requirement_id: str) -> list[str]:
    values = ["declared_status_without_executed_proof", "inventory_row_presence_as_proof"]
    if "AUTHORITY" in requirement_id or "EVIDENCE" in requirement_id:
        values.append("weaker_or_unlinked_authority_substitution")
    if "CARDINALITY" in requirement_id or "COMPLETENESS" in requirement_id or "INDEX" in requirement_id:
        values.append("key_presence_or_empty_collection_as_completeness")
    if "ADAPTATION" in requirement_id:
        values.append("event_only_adaptation_without_substantive_plan_delta")
    if "PARITY" in requirement_id:
        values.append("declared_python_rejection_without_boundary_execution")
    if "PROHIBITED" in requirement_id:
        values.append("generic_guard_without_real_route_or_unreachability_proof")
    return values

def main() -> int:
    if {key: len(value) for key, value in GROUPS.items()} != EXPECTED or sum(map(len, GROUPS.values())) != 106:
        raise SystemExit("session6_8_requirement_baseline_count_invalid")
    requirements=[]; completion=[]; execution=[]; proofs=[]; claims=[]
    for group, ids in GROUPS.items():
        for rid in ids:
            behavior=_approved_behavior(rid)
            function, artifact, domain = _metadata(rid, group)
            forbidden = _approved_forbidden(rid)
            cardinalities = {artifact: 3 if rid == "S6_REMEDIATION_CARDINALITY" else 1}
            artifacts = [artifact]
            requirements.append({"requirement_id":rid,"session":group,"source_section":"approved evidence-integrity closeout","source_requirement":rid,"source_text_hash":_sha(rid),"normative_behavior":behavior,"forbidden_substitutions":forbidden,"required_artifacts":artifacts,"minimum_cardinalities":cardinalities,"approved_semantic_hash":_semantic_hash(rid,behavior,forbidden,artifacts,cardinalities),"status":"pending_execution"})
            proof_ids=[]
            for fixture, accepted, error in (("valid",True,None),("near_valid",True,None),("adversarial_invalid",False,_adversarial_error(rid,group))):
                pid=f"proof_{rid.lower()}_{fixture}"; proof_ids.append(pid)
                proofs.append({"proof_id":pid,"requirement_id":rid,"domain":domain,"invariant":behavior,"fixture_class":fixture,"fixture_or_builder":f"proof_fixture_{rid.lower()}","production_function":function,"schema":None,"expected_acceptance":accepted,"expected_python_exception":None if accepted else "ValueError","expected_error_code":error,"expected_schema_rejection":False,"not_applicable_reason":"semantic production boundary","canonical_artifact":artifact,"test_id":f"tests/test_session6_8_proof_execution.py::test_requirement_proof[{pid}]","status":"pending_execution"})
            completion.append({"requirement_id":rid,"phase":group,"current_state":"pending_execution","known_gap":"proof execution required","implementation_files":[artifact],"production_boundary":function,"positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],"canonical_artifacts":[artifact],"status":"pending_execution"})
            execution.append({"requirement_id":rid,"production_boundary":function,"proof_ids":proof_ids,"canonical_artifact":artifact,"status":"pending_execution"})
            claims.append({"claim_id":"claim_"+rid.lower(),"requirement_ids":[rid],"implementation_symbols":[function],"positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],"artifact_assertions":[{"requirement_id":rid,"artifact":artifact,"assertion":"minimum_records"}],"minimum_record_counts":{artifact:3 if rid=="S6_REMEDIATION_CARDINALITY" else 1},"production_invocation_receipts":[],"contract_parity_receipts":[],"security_receipts":[],"installed_wheel_receipts":[],"status":"pending_execution"})
    (VALIDATION/"session6-8-requirement-inventory.json").write_text(_dump({"schema_version":"session6-8-requirement-inventory.v2","expected_requirement_count":106,"requirements":requirements}),encoding="utf-8")
    (VALIDATION/"session6-8-completion-map.json").write_text(_dump({"schema_version":"shiproom.session6-8-completion-map.v4","requirements":completion}),encoding="utf-8")
    (VALIDATION/"session6-8-execution-map.json").write_text(_dump({"schema_version":"shiproom.session6-8-execution-map.v4","requirements":execution}),encoding="utf-8")
    (VALIDATION/"session6-8-proof-manifest.json").write_text(_dump({"schema_version":"shiproom.session6-8-proof-manifest.v5","proofs":proofs}),encoding="utf-8")
    (VALIDATION/"session6-8-claim-registry.json").write_text(_dump({"schema_version":"shiproom.session6-8-claim-registry.v4","claims":claims}),encoding="utf-8")
    print(json.dumps({"requirements":106,"proofs":318,"claims":106,"status":"pending_execution"}))
    return 0

if __name__ == "__main__": raise SystemExit(main())
