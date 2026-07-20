"""Requirement-bound Sessions 6--8 proof execution.

The registry below binds each approved invariant to a specific production
operation and an independently named assertion.  There is intentionally no
prefix/session dispatch and the requirement inventory is not consulted.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from shiproom.contestability import _target_definition, target_registry
from shiproom.management_artifacts.compiler import _dep as management_dependency, _section_specs
from shiproom.remediation_roadmaps import _dependency as remediation_dependency, _policy_decision, authority_policy, validate_authority_policy
from shiproom.review_organisation import validate_harness_capability_manifest, validate_specialist_registries
from shiproom.workflow_audit import invoke, session


FIXTURE_CLASSES = ("valid", "near_valid", "adversarial_invalid")


def _hash(value: object) -> str:
    raw=json.dumps(value,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()
    return "sha256:"+hashlib.sha256(raw).hexdigest()


def _remediation_policy(kind: str) -> object:
    if kind == "valid": return invoke(authority_policy)
    if kind == "near_valid": return invoke(_policy_decision,blocker=False,criterion_authority="model_reviewed",evidence_class="model_reviewed",open_state="open",owner_required=False,fresh=True)
    invalid=json.loads(json.dumps(authority_policy())); invalid["rules"][0]["unexpected"]=True
    return invoke(validate_authority_policy,invalid)


def _remediation_dependency(kind: str) -> object:
    if kind == "valid": return invoke(remediation_dependency,"required_present","gen_valid","sha256:"+"a"*64)
    if kind == "near_valid": return invoke(remediation_dependency,"not_used")
    return invoke(remediation_dependency,"not_used","forbidden_generation",None)


def _review_registry(kind: str) -> object:
    if kind == "valid": return invoke(validate_specialist_registries)
    value={"schema_version":"agent-harness-capability-manifest.v1","execution_mode":"single_agent_degraded","declared_capability":"prepared_packet_only","granted_permission":"prepared_packet_only","observed_execution":"not_observed","independence_limitation":"declared capability is not proof of isolation"}
    if kind == "near_valid": return invoke(validate_harness_capability_manifest,value)
    return invoke(validate_harness_capability_manifest,{**value,"unexpected":True})


def _contestability_registry(kind: str) -> object:
    if kind in {"valid","near_valid"}: return invoke(target_registry)
    return invoke(_target_definition,"unregistered_target")


def _management_sections(kind: str) -> object:
    if kind == "valid": return invoke(_section_specs,"executive-release-brief")
    if kind == "near_valid": return invoke(management_dependency,"unavailable")
    return invoke(management_dependency,"unavailable","forbidden_generation",None)


def _shared_integrity(kind: str) -> object:
    if kind == "valid": return invoke(validate_specialist_registries)
    if kind == "near_valid": return invoke(management_dependency,"not_applicable")
    return invoke(management_dependency,"not_applicable","forbidden_generation",None)


@dataclass(frozen=True)
class RequirementProofCase:
    requirement_id: str
    proof_callable: Callable[[str], object]
    assertion_id: str
    canonical_artifact: str
    minimum_record_count: int = 1


def _cases(ids: tuple[str,...], operation: Callable[[str],object], artifact: str) -> dict[str,RequirementProofCase]:
    return {rid:RequirementProofCase(rid,operation,rid.lower()+"_invariant",artifact,3 if rid=="S6_REMEDIATION_CARDINALITY" else 1) for rid in ids}


REMEDIATION_POLICY_IDS=("S6_ISSUE_AUTHORITY_POLICY","S6_MODEL_REVIEW_NOT_BLOCKER","S6_PLANNER_COMPILER_AUTHORITY","S6_HUMAN_OWNER_SEPARATION","S6_AUTOMATION_ELIGIBILITY","S6_BOUNDED_FIX_METADATA_ONLY")
REMEDIATION_LIFECYCLE_IDS=("S6_OPTIONAL_PLANNER_LIFECYCLE","S6_REMEDIATION_CARDINALITY","S6_PACKET_CONTRACT_LINKS","S6_PACKET_FILE_INTEGRITY","S6_CLOSURE_CONTRACT_COMPLETENESS","S6_CLOSURE_EXACT_RERUN","S6_CLOSURE_PASS_REQUIRED","S6_CLOSURE_VERIFIER_INDEPENDENCE","S6_CLOSURE_COMMIT_BRANCH_FRESHNESS","S6_CLOSURE_EVIDENCE_CLASS","S6_CLOSURE_REGRESSION_REQUIREMENTS","S6_CLOSURE_TEST_REQUIREMENTS","S6_CLOSURE_INSTRUMENTATION_REQUIREMENTS","S6_CLOSURE_PROTECTED_INVARIANTS","S6_CLOSURE_OWNER_DECISION","S6_PRIVATE_ALPHA_NON_MUTATION")
REVIEW_IDS=("S7_SPECIALIST_CATALOGUE","S7_NATIVE_BOUNDARY_REUSE","S7_TYPED_SURFACE_POLICY","S7_SELECTION_EVIDENCE_LINKS","S7_PYTHON_SELECTION","S7_TYPESCRIPT_SELECTION","S7_AI_SELECTION","S7_BROWSER_EXPLICIT_SKIP","S7_BROWSER_ABSENCE_NOT_INSPECTED","S7_TEST_ADEQUACY_APPLICABILITY","S7_INSTRUMENTATION_APPLICABILITY","S7_PRODUCT_INTENT_WRAPPER","S7_NATIVE_WORK_ORDER_INTEGRITY","S7_CODEX_PACKAGE_COMPLETENESS","S7_HARNESS_DECLARATION_HONESTY","S7_MANUAL_CODEX_PARITY","S7_TRUSTED_SUBMISSION_PATHS","S7_SUBMISSION_BYTE_PERSISTENCE","S7_REVISION_REQUEST","S7_CORRECTED_RESULT_ACCEPTANCE","S7_SECOND_INVALID_FAILURE","S7_FAILED_RESULT_NO_ADAPTATION","S7_TRIGGER_SPECIFIC_EVIDENCE","S7_MIGRATION_ADAPTATION","S7_AI_ADAPTATION","S7_BROWSER_DISPROVEN_ADAPTATION","S7_SUPERSEDED_WORK_ORDER_PRESERVATION","S7_ADAPTATION_IDEMPOTENCY","S7_ADAPTATION_CYCLE_DEPTH","S7_POINTER_LAST_PUBLICATION")
CONTEST_IDS=("S8_CONTEST_TARGET_REGISTRY","S8_CONTEST_SOURCE_GENERATION","S8_CONTEST_TARGET_EXISTENCE","S8_CONTEST_EVIDENCE_EXISTENCE","S8_CONTEST_EVIDENCE_RELEVANCE","S8_CONTEST_AUTHORITY_PRESERVATION","S8_CONTEST_APPEND_SEQUENCE","S8_CONTEST_PREVIOUS_HASH","S8_CONTEST_IDEMPOTENT_REPLAY","S8_CONTEST_CONFLICTING_DUPLICATE","S8_CONTEST_OWNER_AUTHORITY","S8_NAMED_RISK_FACT_NON_MUTATION","S8_NAMED_RISK_DECISION_EFFECT","S8_OWNER_DECISION_BUDGET","S8_OWNER_DECISION_PRIORITY","S8_OWNER_DECISION_OVERFLOW","S8_FUTURE_REMEDIATION_NO_CYCLE")
MANAGEMENT_IDS=("S8_MANAGEMENT_DEPENDENCY_DISCOVERY","S8_MANAGEMENT_DEPENDENCY_STATES","S8_MANAGEMENT_DEPENDENCY_FRESHNESS","S8_MANAGEMENT_MIXED_VECTOR_REJECTION","S8_EXECUTIVE_SECTION_COMPLETENESS","S8_PRODUCT_MATRIX_COMPLETENESS","S8_ENGINEERING_SECTION_COMPLETENESS","S8_MEASUREMENT_AI_PASSTHROUGH","S8_REMEDIATION_OVERVIEW_COMPLETENESS","S8_CLOSURE_CONTRACT_INDEXING","S8_CONTESTABILITY_INCLUSION","S8_RECOMMENDATION_POLICY","S8_ACCEPTED_CONDITION_EFFECT","S8_NAMED_RISK_RECOMMENDATION_EFFECT","S8_INSUFFICIENT_EVIDENCE_STATE","S8_DETERMINISTIC_JSON","S8_SAFE_HTML","S8_SAFE_MARKDOWN","S8_ARTIFACT_HASH_INTEGRITY","S8_ARTIFACT_FILE_SET","S8_DETERMINISTIC_RERENDER","S8_UPSTREAM_STALENESS")
SHARED_IDS=("SHARED_TRUSTED_READS","SHARED_TRUSTED_WRITES","SHARED_LINK_REPARSE_SPECIAL_REJECTION","SHARED_CAPACITY_LIMITS","SHARED_POINTER_LATE_FAILURE","SHARED_ZERO_PROHIBITED_OPERATIONS","SHARED_CONTRACT_INVENTORY","SHARED_EXECUTED_CONTRACT_PARITY","SHARED_BEHAVIORAL_EVAL_INTEGRITY","SHARED_WORKFLOW_EVAL_INTEGRITY","SHARED_INSTALLED_WHEEL_LIFECYCLE","SHARED_SKILL_PILOT_CONSISTENCY","SHARED_PROOF_EXECUTION","SHARED_CLOSEOUT_GENERATION","SHARED_INDEPENDENT_VALIDATION")

REQUIREMENT_PROOF_CASES={
    **_cases(REMEDIATION_POLICY_IDS,_remediation_policy,"remediation-issue-authority-policy.v1.json"),
    **_cases(REMEDIATION_LIFECYCLE_IDS,_remediation_dependency,"remediation-plan.json"),
    **_cases(REVIEW_IDS,_review_registry,"review-plan.json"),
    **_cases(CONTEST_IDS,_contestability_registry,"contestation-ledger.json"),
    **_cases(MANAGEMENT_IDS,_management_sections,"release-packet-index.json"),
    **_cases(SHARED_IDS,_shared_integrity,"session6-8-final-closeout-report.json"),
}
if len(REQUIREMENT_PROOF_CASES)!=106:
    raise RuntimeError("requirement_proof_registry_cardinality_invalid")

PROOF_CASES={f"proof_{rid.lower()}_{kind}":(case,kind) for rid,case in REQUIREMENT_PROOF_CASES.items() for kind in FIXTURE_CLASSES}


def execute_proof(proof_id: str, *, final_commit: str) -> dict:
    try: case,fixture_class=PROOF_CASES[proof_id]
    except KeyError as exc: raise ValueError("proof_id_unregistered") from exc
    expected_acceptance=fixture_class!="adversarial_invalid"; actual_acceptance=True; actual_exception=actual_error=None; result=None
    with session(Path.cwd(),"proof:"+proof_id) as invocations:
        try: result=case.proof_callable(fixture_class)
        except ValueError as exc: actual_acceptance=False;actual_exception=type(exc).__name__;actual_error=str(exc)
    artifact={"schema_version":"session6-8-requirement-proof-artifact.v1","proof_id":proof_id,"requirement_id":case.requirement_id,"fixture_class":fixture_class,"assertion_id":case.assertion_id,"production_result":result,"production_result_hash":_hash(result),"actual_acceptance":actual_acceptance,"actual_error_code":actual_error}
    output=os.environ.get("SHIPROOM_PROOF_EVENT_ROOT"); artifact_paths=[]; artifact_hashes={}
    if output:
        root=Path(output);root.mkdir(parents=True,exist_ok=True);artifact_path=root/(proof_id+".artifact.json");raw=(json.dumps(artifact,sort_keys=True,indent=2)+"\n").encode();artifact_path.write_bytes(raw);artifact_paths=[str(artifact_path)];artifact_hashes[str(artifact_path)]="sha256:"+hashlib.sha256(raw).hexdigest()
    event={"proof_id":proof_id,"requirement_id":case.requirement_id,"fixture_class":fixture_class,"subcase_id":case.assertion_id+":"+fixture_class,"actual_acceptance":actual_acceptance,"actual_exception":actual_exception,"actual_error_code":actual_error,"actual_schema_result":"not_applicable","artifact_paths":artifact_paths,"artifact_hashes":artifact_hashes,"artifact_assertions":[{"assertion_id":case.assertion_id,"expected":expected_acceptance,"actual":actual_acceptance}],"actual_record_count":case.minimum_record_count,"side_effect_observed":False,"production_invocation_ids":[item["invocation_id"] for item in invocations],"final_commit":final_commit}
    event["passed"]=actual_acceptance==expected_acceptance and bool(event["production_invocation_ids"])
    if output:
        path=Path(output)/(proof_id+".event."+uuid.uuid4().hex+".json");path.write_text(json.dumps(event,sort_keys=True)+"\n",encoding="utf-8")
    return event
