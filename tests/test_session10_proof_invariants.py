from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import uuid

import jsonschema
import pytest

from provan.canonical import canonical_bytes
from provan.errors import ProvanError
from provan.structural import StructuralValidationError,validate_schema_instance
from provan.session10_validators import (
    validate_acceptance_preparation_serialized,
    validate_acceptance_seed_serialized,
    validate_affected_entity_serialized,
    validate_affected_relationship_serialized,
    validate_cache_fragment_serialized,
    validate_change_brief_serialized,
    validate_context_bundle_serialized,
    validate_context_request_serialized,
    validate_provider_result_serialized,
    validate_error_serialized,
    validate_implementation_binding_serialized,
    validate_model_envelope_serialized,
    validate_model_usage_serialized,
    validate_manifest_serialized,
    validate_previous_export_manifest_serialized,
    validate_promotion_serialized,
    validate_real_use_serialized,
    validate_runtime_invariant_evidence_serialized,
    validate_session_handoff_serialized,
    validate_public_projection_serialized,
    validate_topology_serialized,
    _recompute_analysis_authority,
)

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def fixture_digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(("provan-session10-fixture:" + name).encode()).hexdigest()
HEX = fixture_digest("primary-canonical-artifact")
COMMIT = "22a73b13eee4bac00930c8afe24944286eac2023"
TREE = "14dd7b7ba854ed882c98be4454c0bebb1c30ff8e"
HEAD = "4b9f63e507c4ea75fa59f6bbdfb103e2f014a6f9"
CASE = HEX
ENVELOPE_ID=str(uuid.UUID(bytes=hashlib.sha256(b"provan-session10-fixture:model-envelope-id").digest()[:16],version=4))


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def proof_identity(value):
    if isinstance(value,dict):return {"mapping":[[proof_identity(key),proof_identity(item)] for key,item in sorted(value.items(),key=lambda pair:repr(pair[0]))]}
    if isinstance(value,(list,tuple)):return [proof_identity(item) for item in value]
    if isinstance(value,set):return sorted(proof_identity(item) for item in value)
    if isinstance(value,bytes):return {"bytes_sha256":"sha256:"+hashlib.sha256(value).hexdigest(),"size":len(value)}
    return value


def change_brief():
    candidate = {"repository_identity":"https://github.com/example/example","mode":"immutable","base":COMMIT,"head":HEAD,"working_tree_digest":None}
    candidate["candidate_digest"] = digest({k:candidate.get(k) for k in ("repository_identity","mode","base","head","working_tree_digest")})
    usage={"schema_id":"provan.model_usage_receipt.v1","mode":"NO_MODEL","provider":None,"model":None,"prompt_id":None,"prompt_version":None,"envelope_digest":None,"calls":0,"latency_ms":None,"latency_source":"not-applicable","cost_status":"not-applicable"}
    model_binding={"mode":"NO_MODEL","provider":None,"model":None,"provider_version":None,"prompt_id":"change-brief-synthesis","prompt_version":"1","instructions_digest":digest_text("Identify bounded implications and unresolved questions. Do not assert source facts or Acceptance authority.")}
    binding={"candidate":candidate["candidate_digest"],"brief":digest_text(""),"agent":digest_text(""),"context_request":digest({"file_digests":[],"aliases":[],"journey_digests":[]}),"previous":None,"model":model_binding,"policy":{"id":"community.default.v1","version":"1"},"pr":None};case=digest(binding)
    bundle={"schema_id":"provan.case_context_bundle.v1","case_id":case,"records":[],"aliases":[],"journeys":[],"omissions":[],"limitations":[]};decision={"schema_id":"provan.promotion_decision.v1","case_id":case,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","applied_triggers":[],"unresolved_proposals":[]}
    request={"schema_id":"provan.context_request.v1","case_id":case,"file_digests":[],"aliases":[],"journey_digests":[]}
    seed={"schema_id":"provan.acceptance_seed.v1","seed_id":"seed-proof","case_id":case,"candidate_digest":candidate["candidate_digest"],"status":"proposed","acceptance_eligible":True,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","trigger_refs":[],"context_digest":digest(bundle),"evidence_refs":[],"unresolved_questions":[]}
    return {"schema_id":"provan.change_brief.v1","brief_id":"brief-proof","case_id":case,"case_binding":binding,"case_provenance":{"previous":None,"pr":None},"candidate":candidate,"analysis_evidence":[],"claims":{"agent_reported":[],"source_attributed_product_intent":[],"source_established":[],"model_reviewed_implications":[],"unresolved":[]},"entities":[],"relationships":[],"context_request":request,"context_bundle":bundle,"promotion_decision":decision,"acceptance_seed":seed,"model_usage":usage,"previous_comparison":{"status":"NOT_SUPPLIED"},"limitations":[],"next_action":"Review."}


def digest_text(value):
    return "sha256:"+hashlib.sha256(value.encode()).hexdigest()


def context():
    return {"schema_id":"provan.case_context_bundle.v1","case_id":CASE,"records":[],"aliases":[],"journeys":[],"omissions":[],"limitations":[]}


def analysis_rows():
    empty={"content_digest":None,"symbols":[],"exports":[],"imports":[],"routes":[],"dependencies":[],"schema_contract":None}
    current={**empty,"content_digest":fixture_digest("analysis-src-content"),"symbols":["provan.example"],"imports":["provan.other"]}
    return [{"path":"src.py","status":"M","surface_classes":["python_source"],"static_details":current,"baseline_static_details":dict(empty),"verified_triggers":[]}]


def entity():
    rows=analysis_rows();value={"schema_id":"provan.affected_entity.v1","kind":"symbol","scope":"provan.example","state":"referenced","authority":"source_established","evidence_refs":["src.py"]}
    value["entity_id"]=digest({"kind":value["kind"],"scope":value["scope"]})
    return value,_recompute_analysis_authority(rows)[1]


def relationship():
    rows=analysis_rows();left={"kind":"file","scope":"src.py"};right={"kind":"module","scope":"provan.other"};left["entity_id"]=digest(left);right["entity_id"]=digest(right)
    value={"schema_id":"provan.affected_relationship.v1","source_entity_id":left["entity_id"],"target_entity_id":right["entity_id"],"relation":"imports","authority":"source_established","evidence_refs":["src.py"]}
    value["relationship_id"]=digest({"source":value["source_entity_id"],"target":value["target_entity_id"],"relation":value["relation"]})
    allowed=_recompute_analysis_authority(rows)[2]
    return value,({left["entity_id"],right["entity_id"]},allowed)


def context_request():
    bundle=context();return {"schema_id":"provan.context_request.v1","case_id":CASE,"file_digests":[],"aliases":[],"journey_digests":[]},bundle


def provider():
    bundle=context();return {"schema_id":"provan.context_provider_result.v1","provider_id":"CaseLocalContextProvider","case_id":CASE,"records":[],"omissions":[],"limitations":[],"canonical_proof":False},bundle


def promotion():
    return {"schema_id":"provan.promotion_decision.v1","case_id":CASE,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","applied_triggers":[],"unresolved_proposals":[]},([],[])


def acceptance():
    return {"schema_id":"provan.acceptance_preparation.v1","preparation_id":"prep-proof","brief_id":"brief-proof","case_id":"case-proof","candidate_digest":HEX,"status":"preparation_only","confirmed":False,"executed":False,"verdict":None,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","trigger_refs":[]}


def seed():
    candidate={"repository_identity":"https://github.com/example/example","mode":"immutable","base":COMMIT,"head":HEAD,"working_tree_digest":None};candidate["candidate_digest"]=digest({key:candidate.get(key) for key in ("repository_identity","mode","base","head","working_tree_digest")});promotion_value=promotion()[0];bundle=context()
    value={"schema_id":"provan.acceptance_seed.v1","seed_id":"seed-proof","case_id":CASE,"candidate_digest":candidate["candidate_digest"],"status":"proposed","acceptance_eligible":True,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","trigger_refs":[],"context_digest":digest(bundle),"evidence_refs":[],"unresolved_questions":[]}
    return value,(candidate,CASE,promotion_value,set(),bundle)


def topology():
    return {"schema_id":"provan.change_topology.v1","case_id":CASE,"rendered":False,"threshold_rule":"entities>=8 or relationships>=6","nodes":[],"edges":[],"text_fallback":"No bounded topology required."},([],[])


def model_usage():
    return {"schema_id":"provan.model_usage_receipt.v1","mode":"NO_MODEL","provider":None,"model":None,"prompt_id":None,"prompt_version":None,"envelope_digest":None,"calls":0,"latency_ms":None,"latency_source":"not-applicable","cost_status":"not-applicable"},None


def cache():
    analysis={"changed_files":[],"index_changes":[],"excluded_sensitive_surfaces":[],"limitations":[],"analysis_bytes":0,"target_state_before":{},"target_state_after":{}}
    keys={"repository_identity":"https://github.com/example/example","base":COMMIT,"head":TREE,"working_tree_digest":None,"target_state_digest":digest({"before":analysis["target_state_before"],"after":analysis["target_state_after"]}),"schema_registry":HEX,"mapper_version":"1"}
    value={"schema_id":"provan.repository_analysis_cache_fragment.v1","cache_key":digest(keys),"key_inputs":keys,"case_id":None,"analysis":analysis,"analysis_digest":digest(analysis)}
    return value,(keys,analysis)


def model():
    block={"category":"selected_source","content":"bounded public source"};block["sha256"]="sha256:"+hashlib.sha256(block["content"].encode()).hexdigest()
    return {"schema_id":"provan.model_input_envelope.v1","envelope_id":ENVELOPE_ID,"case_id":fixture_digest("model-envelope-case"),"candidate_digest":HEX,"provider":"spy","model":"local-spy","provider_version":"1","prompt_id":"bounded-synthesis","prompt_version":"1","instructions":"Return only unresolved implications.","selected_blocks":[block],"limits":{"max_input_bytes":262144,"max_output_tokens":2048},"permitted_output_classes":["model_reviewed_implications","unresolved"]}


def previous():
    return {"schema_id":"provan.change_brief_export_manifest.v1","repository_identity":"https://github.com/example/example","previous_head":COMMIT,"artifacts":[{"path":"brief.json","role":"change_brief","schema_id":"provan.change_brief.v1","sensitivity":"LOCAL_NON_PUBLIC","sha256":HEX,"size":100}]}


def implementation():
    return {"schema_id":"provan.session10_implementation_binding.v1","implementation_commit":COMMIT,"implementation_tree":TREE,"package_version":"0.3.0","wheel_sha256":HEX,"schema_registry_digest":HEX,"maturity":"QUALIFIED_BOUNDED","published":False}


def real_use():
    return {"schema_id":"provan.session10_real_use_evidence.v1","case":"HTTPX_PR_3699","predeclared":True,"implementation_binding":implementation(),"brief_digest":HEX,"comparator":{"kind":"authentic_pr_body_and_review","digest":HEX},"latency_ms":1,"cost_status":"not_applicable","engineer_feedback":"not_obtained","production_changed_after_run":False}


def handoff():
    brief=change_brief();candidate=brief["candidate"];bundle=brief["context_bundle"];decision=brief["promotion_decision"];seed=brief["acceptance_seed"]
    wheel=b"bounded-wheel";schema_registry={"schema_id":"provan.schema_registry.v1","registry_digest":digest({"schemas":[]}),"schemas":[]};binding=implementation();binding["wheel_sha256"]="sha256:"+hashlib.sha256(wheel).hexdigest();binding["schema_registry_digest"]=schema_registry["registry_digest"]
    projection={"schema_id":"provan.change_brief_public_projection.v1","sensitivity":"PUBLIC_SAFE","brief_id":"brief-proof","candidate_digest":candidate["candidate_digest"],"mode":"immutable","changed_surface_counts":{},"promotion":"explain_only","limitations":[],"model_audit":{"calls":0},"summary":"Deterministically sanitised bounded projection."}
    brief_raw=canonical_bytes(brief);real={"schema_id":"provan.session10_real_use_evidence.v1","case":"HTTPX_PR_3699","predeclared":True,"implementation_binding":binding,"brief_digest":"sha256:"+hashlib.sha256(brief_raw).hexdigest(),"comparator":{},"latency_ms":1,"cost_status":"not_applicable","engineer_feedback":"not_obtained","production_changed_after_run":False}
    proof_ids=[f"proof-{index}" for index in range(1,214)];matrix={"schema_id":"provan.session10_layer4_matrix.v1","claims":[{"Claim":f"G10-{index:02d} claim","Positive proof":proof_ids[(index-1)*3],"Near-valid proof":proof_ids[(index-1)*3+1],"Negative proof":proof_ids[(index-1)*3+2]} for index in range(1,72)]};registry={"schema_id":"provan.session10_proof_registry.v1","implementation_commit":binding["implementation_commit"],"implementation_tree":binding["implementation_tree"],"entries":[{"proof_id":item} for item in proof_ids]}
    values={"canonical_brief":brief,"public_projection":projection,"real_use":real,"layer4_matrix":matrix,"proof_registry":registry,"implementation_binding":binding,"schema_registry":schema_registry};artifacts={name:canonical_bytes(item) for name,item in values.items()};artifacts["authoritative_wheel"]=wheel;refs={name:{"path":name+(".whl" if name=="authoritative_wheel" else ".json"),"sha256":"sha256:"+hashlib.sha256(raw).hexdigest()} for name,raw in artifacts.items()};root=digest([{"name":name,"sha256":row["sha256"]} for name,row in sorted(refs.items())])
    value={"schema_id":"provan.session_handoff.v1","candidate":candidate,"brief":{"brief_id":"brief-proof","sha256":"sha256:"+hashlib.sha256(brief_raw).hexdigest(),"storage":"EXTERNAL_OPERATOR_STATE","public_projection":refs["public_projection"]},"analysis_evidence":brief["analysis_evidence"],"source_established_claims":brief["claims"]["source_established"],"entities":[],"relationships":[],"context_bundle":bundle,"promotion_decision":decision,"acceptance_seed":seed,"addressing_rules":{"canonical_bytes":"json","digest":"sha256","artifact_references":"relative","reviewer_receipt":"external"},"projection_rules":{"internal":"LOCAL_NON_PUBLIC","public":"PUBLIC_SAFE","client_safe":"deterministically_sanitised"},"limitations":[],"session11_prerequisites":["one","two","three","four","five"],"layer4_matrix":refs["layer4_matrix"],"proof_root":root,"reviewer_receipt":{"state":"PENDING_EXTERNAL_NON_RECURSIVE","receipts":[]},"implementation_binding":binding,"schema_registry":{"reference":refs["schema_registry"],"registry_digest":schema_registry["registry_digest"]},"wheel":{"reference":refs["authoritative_wheel"],"package_version":"0.3.0","sha256":refs["authoritative_wheel"]["sha256"]},"provider_binding":{"status":"NOT_APPLICABLE","reason":"no model","authority":"policy"},"artifact_references":refs}
    return value,artifacts


def error():
    return {"schema_id":"provan.error.v1","error":"INPUT_FILE_PATH_UNSAFE","message":"Explicit input path is not a bounded regular file."}


def manifest():
    artifacts={f"artifact-{index}.json":f"artifact-{index}".encode() for index in range(7)}
    return {"schema_id":"provan.change_brief_manifest.v1","brief_id":"brief-proof","case_id":"case-proof","artifacts":{name:"sha256:"+hashlib.sha256(raw).hexdigest() for name,raw in artifacts.items()},"canonicalization":"UTF8_JSON_SORTED_KEYS_COMPACT_LF","digest":"SHA-256"},artifacts


def projection():
    return {"schema_id":"provan.change_brief_public_projection.v1","sensitivity":"PUBLIC_SAFE","brief_id":"brief-proof","candidate_digest":HEX,"mode":"immutable","changed_surface_counts":{"python_source":1},"promotion":"explain_only","limitations":[],"model_audit":{"calls":0},"summary":"Deterministically sanitised bounded projection."}


GROUPS = ["change_brief","entity","relationship","context","context_request","provider","promotion","seed","acceptance","topology","model_usage","cache","model","previous","implementation","real_use","handoff","error","manifest","projection"]
CLASSES = ["valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid"]
RUNTIME_CLASSES = ["valid","near-valid","adversarial","schema-invalid"]

RUNTIME_TEST_IDS={
    "context_record_semantics":["tests/test_session10_change_brief.py::test_context_record_and_bundle_valid_controlled_case"],
    "context_bundle_case_binding":["tests/test_session10_change_brief.py::test_context_record_and_bundle_valid_controlled_case"],
    "independent_semantic_recomputation":["tests/test_session10_proof_invariants.py::test_all_major_semantic_invalid_cases_are_observed"],
    "immutable_full_commit_identity":["tests/test_session10_change_brief.py::test_immutable_full_commit_identities_valid"],
    "challenge_private_eval_projection_exclusion":["tests/test_session10_change_brief.py::test_public_projection_rejects_challenge_and_private_eval_material"],
    "verifier_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[verifier]"],
    "challenge_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[challenge]"],
    "enterprise_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[enterprise]"],
    "authentic_predeclared_comparator":["tests/test_session10_change_brief.py::test_authentic_comparator_matches_predeclared_case_and_commits"],
    "consequential_range_dogfood_completeness":["tests/test_session10_change_brief.py::test_consequential_range_dogfood_semantics_use_real_controlled_replay"],
    "mutable_candidate_coverage_and_nonread":["tests/test_session10_change_brief.py::test_mutable_sensitive_classes_are_excluded_without_opening"],
    "credential_free_remote_and_pr_resolution":["tests/test_session10_change_brief.py::test_pr_metadata_transport_spy_and_adversarial_boundaries","tests/test_session10_change_brief.py::test_remote_fetch_rechecks_bounds_after_fast_completion"],
    "source_only_target_immutability":["tests/test_session10_change_brief.py::test_local_analysis_never_runs_git_in_the_inspected_target"],
    "claim_classes_and_renderer_fidelity":["tests/test_session10_change_brief.py::test_renderers_preserve_all_claim_classes_and_entity_evidence"],
    "bounded_noncoverage_reporting":["tests/test_session10_change_brief.py::test_global_entity_and_relationship_caps_report_noncoverage"],
    "zero_or_single_model_execution":["tests/test_session10_change_brief.py::test_model_envelope_transport_spy_receives_exact_semantics"],
    "authoritative_wheel_maturity_and_dependency_boundary":["tests/test_session9.py::test_wheel_configuration_excludes_historical_packages"],
    "session9_successor_preservation":["tests/test_session9_correction.py::test_c9f_resolves_immutable_historical_registry_without_rewriting_it"],
    "private_planning_authority_absence":["tests/test_session9.py::test_public_projection_leakage_gate"],
    "literal_file_disambiguation_and_safe_reader":["tests/test_session10_change_brief.py::test_common_safe_reader_rejects_type_size_encoding_and_link","tests/test_session10_change_brief.py::test_safe_reader_reparse_detection_is_deterministic","tests/test_session10_change_brief.py::test_safe_reader_symlink_detection_without_platform_privilege","tests/test_session10_change_brief.py::test_safe_reader_revalidates_parent_components_after_open"],
}
RUNTIME_NEAR_TEST_IDS={
    "context_record_semantics":["tests/test_session10_runtime_near_cases.py::test_near_context_record_semantics"],
    "context_bundle_case_binding":["tests/test_session10_runtime_near_cases.py::test_near_context_bundle_case_binding"],
    "independent_semantic_recomputation":["tests/test_session10_runtime_near_cases.py::test_near_independent_semantic_recomputation"],
    "immutable_full_commit_identity":["tests/test_session10_runtime_near_cases.py::test_near_immutable_full_commit_identity"],
    "challenge_private_eval_projection_exclusion":["tests/test_session10_runtime_near_cases.py::test_near_public_projection_boundary"],
    "verifier_capability_absence":["tests/test_session10_runtime_near_cases.py::test_near_forbidden_capability_absence[verifier_capability_absence-verify]"],
    "challenge_capability_absence":["tests/test_session10_runtime_near_cases.py::test_near_forbidden_capability_absence[challenge_capability_absence-challenge]"],
    "enterprise_capability_absence":["tests/test_session10_runtime_near_cases.py::test_near_forbidden_capability_absence[enterprise_capability_absence-enterprise]"],
    "authentic_predeclared_comparator":["tests/test_session10_runtime_near_cases.py::test_near_authentic_comparator"],
    "consequential_range_dogfood_completeness":["tests/test_session10_runtime_near_cases.py::test_near_dogfood_complete_range"],
    "mutable_candidate_coverage_and_nonread":["tests/test_session10_runtime_near_cases.py::test_near_mutable_candidate_noncoverage"],
    "credential_free_remote_and_pr_resolution":["tests/test_session10_runtime_near_cases.py::test_near_credential_free_pr_transport"],
    "source_only_target_immutability":["tests/test_session10_runtime_near_cases.py::test_near_source_only_target_immutability"],
    "claim_classes_and_renderer_fidelity":["tests/test_session10_runtime_near_cases.py::test_near_renderer_fidelity"],
    "bounded_noncoverage_reporting":["tests/test_session10_runtime_near_cases.py::test_near_bounded_noncoverage"],
    "zero_or_single_model_execution":["tests/test_session10_runtime_near_cases.py::test_near_zero_model_default_fallback"],
    "authoritative_wheel_maturity_and_dependency_boundary":["tests/test_session10_runtime_near_cases.py::test_near_wheel_dependency_boundary"],
    "session9_successor_preservation":["tests/test_session10_runtime_near_cases.py::test_near_session9_successor_preservation"],
    "private_planning_authority_absence":["tests/test_session10_runtime_near_cases.py::test_near_private_planning_absence"],
    "literal_file_disambiguation_and_safe_reader":["tests/test_session10_runtime_near_cases.py::test_near_safe_reader_exact_limit"],
}
RUNTIME_ADVERSARIAL_TEST_IDS={
    "context_record_semantics":["tests/test_session10_change_brief.py::test_context_record_and_bundle_semantics_from_controlled_case"],
    "context_bundle_case_binding":["tests/test_session10_change_brief.py::test_context_record_and_bundle_semantics_from_controlled_case"],
    "independent_semantic_recomputation":["tests/test_session10_proof_invariants.py::test_all_major_semantic_invalid_cases_are_observed"],
    "immutable_full_commit_identity":["tests/test_session10_change_brief.py::test_immutable_candidate_requires_exact_full_commit_identities"],
    "challenge_private_eval_projection_exclusion":["tests/test_session10_change_brief.py::test_public_projection_rejects_challenge_and_private_eval_material"],
    "verifier_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[verifier]"],
    "challenge_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[challenge]"],
    "enterprise_capability_absence":["tests/test_session10_change_brief.py::test_forbidden_session10_capability_is_unreachable[enterprise]"],
    "authentic_predeclared_comparator":["tests/test_session10_change_brief.py::test_authentic_comparator_independently_recomputes_component_and_aggregate_digests"],
    "consequential_range_dogfood_completeness":["tests/test_session10_change_brief.py::test_consequential_range_dogfood_semantics_use_real_controlled_replay"],
    "mutable_candidate_coverage_and_nonread":["tests/test_session10_change_brief.py::test_mutable_sensitive_classes_are_excluded_without_opening"],
    "credential_free_remote_and_pr_resolution":["tests/test_session10_change_brief.py::test_pr_metadata_transport_spy_and_adversarial_boundaries"],
    "source_only_target_immutability":["tests/test_session10_change_brief.py::test_local_analysis_never_runs_git_in_the_inspected_target"],
    "claim_classes_and_renderer_fidelity":["tests/test_session10_change_brief.py::test_claim_class_conflation_is_rejected_by_serialized_semantics"],
    "bounded_noncoverage_reporting":["tests/test_session10_change_brief.py::test_remote_fetch_enforces_storage_bound_before_completion"],
    "zero_or_single_model_execution":["tests/test_session10_change_brief.py::test_model_envelope_rejects_credentials_and_undeclared_output"],
    "authoritative_wheel_maturity_and_dependency_boundary":["tests/test_session9.py::test_wheel_configuration_excludes_historical_packages"],
    "session9_successor_preservation":["tests/test_session9_correction.py::test_c9f_rejects_self_consistent_unrelated_family_against_tracked_authority"],
    "private_planning_authority_absence":["tests/test_session9.py::test_leakage_rejects_json_escaped_windows_user_path"],
    "literal_file_disambiguation_and_safe_reader":["tests/test_session10_change_brief.py::test_safe_reader_symlink_detection_without_platform_privilege"],
}
RUNTIME_ADVERSARIAL_ERRORS={
    "context_record_semantics":"CONTEXT_RECORD_SEMANTICS_INVALID",
    "context_bundle_case_binding":"CONTEXT_CASE_BINDING_INVALID",
    "independent_semantic_recomputation":"ALL_MAJOR_SEMANTIC_INVALID_CASES_REJECTED",
    "immutable_full_commit_identity":"PINNED_COMMIT_REQUIRED",
    "challenge_private_eval_projection_exclusion":"PUBLIC_PROJECTION_CHALLENGE_MATERIAL_FORBIDDEN",
    "verifier_capability_absence":"ARGPARSE_EXIT_2",
    "challenge_capability_absence":"ARGPARSE_EXIT_2",
    "enterprise_capability_absence":"ARGPARSE_EXIT_2",
    "authentic_predeclared_comparator":"REAL_USE_COMPARATOR_UNRESOLVED",
    "consequential_range_dogfood_completeness":"SESSION10_DOGFOOD_RANGE_INCOMPLETE",
    "claim_classes_and_renderer_fidelity":"CHANGE_BRIEF_CLAIM_CLASS_CONFLATION",
    "mutable_candidate_coverage_and_nonread":"MUTABLE_SENSITIVE_CONTENT_NOT_READ",
    "credential_free_remote_and_pr_resolution":"PR_TRANSPORT_BOUNDARIES_REJECTED",
    "source_only_target_immutability":"TARGET_STATE_UNCHANGED",
    "bounded_noncoverage_reporting":"REMOTE_FETCH_BOUND_EXCEEDED",
    "zero_or_single_model_execution":"MODEL_OUTPUT_AUTHORITY_INVALID",
    "authoritative_wheel_maturity_and_dependency_boundary":"HISTORICAL_RUNTIME_EXCLUDED_FROM_WHEEL_CONFIG",
    "session9_successor_preservation":"LAYER4_UNRELATED_PROOF_FAMILY",
    "private_planning_authority_absence":"COMMUNITY_PRIVATE_LEAKAGE",
    "literal_file_disambiguation_and_safe_reader":"INPUT_FILE_PATH_UNSAFE",
}
_RUNTIME_MEASUREMENTS={}


def runtime_payload(invariant,fixture_class):
    tests=(RUNTIME_NEAR_TEST_IDS if fixture_class=="near-valid" else RUNTIME_ADVERSARIAL_TEST_IDS if fixture_class=="adversarial" else RUNTIME_TEST_IDS)[invariant]
    measurement=(invariant,fixture_class)
    if measurement not in _RUNTIME_MEASUREMENTS:
        command=[sys.executable,"-m","pytest","-vv","-s",*tests];done=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
        _RUNTIME_MEASUREMENTS[measurement]=(done.returncode," ".join(command),done.stdout+done.stderr)
    exit_code,command,transcript=_RUNTIME_MEASUREMENTS[measurement]
    scenario="supported_success" if fixture_class in {"valid","schema-invalid","schema-valid-python-invalid"} else "bounded_limitation" if fixture_class=="near-valid" else "prohibited_or_invalid_input_rejected"
    expected=RUNTIME_ADVERSARIAL_ERRORS.get(invariant) if fixture_class=="adversarial" else None
    marker=re.search(rf"ADVERSARIAL_REJECTION_OBSERVED:{re.escape(invariant)}:([A-Z0-9_]+)",transcript) if fixture_class=="adversarial" else None
    observed=marker.group(1) if marker else None
    value={"schema_id":"provan.session10_runtime_invariant_evidence.v1","invariant":invariant,"fixture_class":fixture_class,"scenario":scenario,"adversarial_operation":";".join(tests) if fixture_class=="adversarial" else None,"expected_error":expected,"observed_error":observed,"command":command,"exit_code":exit_code,"transcript":transcript,"transcript_sha256":"sha256:"+hashlib.sha256(transcript.encode()).hexdigest(),"production_test_ids":tests,"artifact_evidence":[],"limitations":[]}
    if fixture_class=="near-valid":
        marker=re.search(rf"NEAR_VALID_OBSERVED:{re.escape(invariant)}:([A-Z0-9_]+)",transcript)
        value["limitations"]=[marker.group(1)] if marker else []
    if fixture_class=="schema-valid-python-invalid":value["scenario"]="bounded_limitation"
    if fixture_class=="schema-invalid":value.pop("schema_id")
    return value,None


def payload(group, fixture_class, invariant=None):
    if group=="runtime_evidence":return runtime_payload(invariant,fixture_class)
    value = globals()[group]()
    extra = None
    if group in {"entity","relationship","context_request","provider","promotion","seed","topology","model_usage","cache","handoff","manifest"}: value,extra=value
    if fixture_class == "near-valid":
        if group=="change_brief": value["limitations"]=["UNSUPPORTED_RUNTIME_SURFACE"]
        elif group=="entity": value["state"]="M"
        elif group=="relationship": value["authority"]="unresolved"
        elif group=="context": value["limitations"]=["owner confirmation unavailable"]
        elif group=="context_request":
            proposal={"proposal":"service=svc","authority":"case_local_identity_proposal"};extra["aliases"]=[proposal];value["aliases"]=[proposal["proposal"]]
        elif group=="provider": value["limitations"]=["EXPLICIT_CONTEXT_OMISSION"]
        elif group=="promotion": value["unresolved_proposals"]=[{"reason":"OWNER_REQUESTED","authority":"unresolved_proposal","source":"case_supplied_text"}]
        elif group=="seed": value["unresolved_questions"]=["OWNER_CONFIRMATION_REQUIRED"]
        elif group=="acceptance": value["preparation_id"]="prep-proof-near-boundary"
        elif group=="topology": value["text_fallback"]="No bounded topology required; text fallback remains explicit."
        elif group=="model_usage": value["mode"]="DETERMINISTIC_FALLBACK"
        elif group=="cache":
            value["analysis"]["limitations"]=["UNSUPPORTED_DYNAMIC_SURFACE"];value["analysis_digest"]=digest(value["analysis"]);extra=(extra[0],value["analysis"])
        elif group=="model": value["limits"]["max_output_tokens"]=1
        elif group=="previous": value["artifacts"][0]["size"]=8*1024*1024
        elif group=="implementation": value["wheel_sha256"]=fixture_digest("near-valid-wheel")
        elif group=="real_use": value["latency_ms"]=0
        elif group=="handoff": value["limitations"]=["OWNER_CONFIRMATION_UNAVAILABLE"]
        elif group=="error": value["message"]="Explicit input path is outside the bounded state root."
        elif group=="manifest":
            extra["artifact-near.json"]=b"near-boundary";value["artifacts"]["artifact-near.json"]="sha256:"+hashlib.sha256(extra["artifact-near.json"]).hexdigest()
        elif group=="projection": value["limitations"]=["UNSUPPORTED_DYNAMIC_SURFACE"]
    elif fixture_class == "schema-invalid": value.pop("schema_id",None)
    elif fixture_class == "adversarial":
        if group=="change_brief":value["acceptance_seed"]["status"]="confirmed"
        elif group=="entity":value["entity_id"]=fixture_digest("adversarial-entity-identity")
        elif group=="relationship":value["relationship_id"]=fixture_digest("adversarial-relationship-identity")
        elif group=="context":value["aliases"]=[{"entity":"service","alias":"owner","authority":"owner_confirmed","proposal":True}]
        elif group=="context_request":value["aliases"]=["unbound=alias"]
        elif group=="provider":value["case_id"]="unrelated-case"
        elif group=="promotion":value.update(decision="acceptance_recommended",applied_triggers=[])
        elif group=="acceptance":value["policy_id"]=""
        elif group=="seed":value["context_digest"]=fixture_digest("adversarial-seed-context")
        elif group=="topology":value.update(rendered=True,text_fallback="")
        elif group=="model_usage":value.update(calls=1,latency_ms=1,latency_source="provan_monotonic_elapsed")
        elif group=="cache":value["analysis_digest"]=fixture_digest("adversarial-cache-analysis")
        elif group=="model":value["selected_blocks"][0]["sha256"]=fixture_digest("adversarial-model-block")
        elif group=="previous":value["artifacts"][0]["path"]="C:/brief.json"
        elif group=="implementation":value.update(implementation_tree=value["implementation_commit"],wheel_sha256="sha256:"+"0"*64)
        elif group=="real_use":value["brief_digest"]="sha256:"+"0"*64
        elif group=="handoff":extra={key:item for key,item in extra.items() if key!="public_projection"}
        elif group=="error":value["message"]="Authorization: secret"
        elif group=="manifest":value["artifacts"]["unbound.json"]=fixture_digest("adversarial-unbound-manifest-artifact")
        elif group=="projection":value["summary"]="C:"+"\\Users\\example\\raw projection"
    elif fixture_class == "schema-valid-python-invalid":
        if group=="change_brief":
            value["candidate"]["candidate_digest"]=fixture_digest("semantic-invalid-candidate")
        elif group=="entity": value["evidence_refs"]=[]
        elif group=="relationship": value["target_entity_id"]="missing"
        elif group=="context": value["records"]=[{"case_id":"case-proof","authority":"owner_confirmed","content_digest":HEX}]
        elif group=="context_request": value["file_digests"]=[HEX]
        elif group=="provider": value["records"]=[{"unbound":True}]
        elif group=="promotion": value.update(decision="acceptance_recommended",applied_triggers=[{"reason":"HIGH_BLAST_RADIUS","authority":"source_verified"}])
        elif group=="acceptance": value["candidate_digest"]=""
        elif group=="seed": value["candidate_digest"]=fixture_digest("semantic-invalid-seed-candidate")
        elif group=="topology": value["rendered"]=True
        elif group=="model_usage": value.update(mode="EXECUTED",provider="spy",model="local",prompt_id="p",prompt_version="1",envelope_digest=HEX,calls=1,latency_ms=1,latency_source="unavailable");extra=HEX
        elif group=="cache": value["cache_key"]=fixture_digest("semantic-invalid-cache-key")
        elif group=="model": value["selected_blocks"][0]["content"]="undigested addition"
        elif group=="previous": value["artifacts"][0]["path"]="../brief.json"
        elif group=="implementation": value["implementation_tree"]=value["implementation_commit"]
        elif group=="real_use": value["implementation_binding"]={}
        elif group=="handoff": extra={}
        elif group=="error": value["message"]="TOKEN=secret"
        elif group=="manifest": value["artifacts"]["artifact-0.json"]=fixture_digest("semantic-invalid-manifest-artifact-zero")
        elif group=="projection": value["summary"]="Raw unsanitized projection."
    return value,extra


def schema_path(group):
    names={"change_brief":"change-brief.v1.json","entity":"affected-entity.v1.json","relationship":"affected-relationship.v1.json","context":"case-context-bundle.v1.json","context_request":"context-request.v1.json","provider":"context-provider-result.v1.json","promotion":"promotion-decision.v1.json","seed":"acceptance-seed.v1.json","acceptance":"acceptance-preparation.v1.json","topology":"change-topology.v1.json","model_usage":"model-usage-receipt.v1.json","cache":"repository-analysis-cache-fragment.v1.json","model":"model-input-envelope.v1.json","previous":"change-brief-export-manifest.v1.json","implementation":"implementation-binding.v1.json","real_use":"real-use-evidence.v1.json","handoff":"session-handoff.v1.json","error":"error.v1.json","manifest":"change-brief-manifest.v1.json","projection":"change-brief-public-projection.v1.json"}
    if group=="runtime_evidence":return ROOT/"provan/schemas/session10-runtime-invariant-evidence.v1.json"
    return ROOT/"provan/schemas"/names[group]


def semantic(group,value,extra):
    raw=canonical_bytes(value)
    if group=="change_brief": return validate_change_brief_serialized(raw)
    if group=="entity": return validate_affected_entity_serialized(raw,extra)
    if group=="relationship": return validate_affected_relationship_serialized(raw,*extra)
    if group=="context": return validate_context_bundle_serialized(raw)
    if group=="context_request": return validate_context_request_serialized(raw,extra)
    if group=="provider": return validate_provider_result_serialized(raw,extra)
    if group=="promotion": return validate_promotion_serialized(raw,source_claims=extra[0],analysis_evidence=extra[1])
    if group=="acceptance": return validate_acceptance_preparation_serialized(raw)
    if group=="seed": return validate_acceptance_seed_serialized(raw,*extra)
    if group=="topology": return validate_topology_serialized(raw,*extra)
    if group=="model_usage": return validate_model_usage_serialized(raw,extra)
    if group=="cache": return validate_cache_fragment_serialized(raw,*extra)
    if group=="model": return validate_model_envelope_serialized(raw)
    if group=="previous": return validate_previous_export_manifest_serialized(raw)
    if group=="implementation": return validate_implementation_binding_serialized(raw)
    if group=="real_use": return validate_real_use_serialized(raw,{"HTTPX_PR_3699","CLICK_PR_3721","OFFLINE_SESSION9_FALLBACK"})
    if group=="handoff": return validate_session_handoff_serialized(raw,extra)
    if group=="manifest": return validate_manifest_serialized(raw,extra)
    if group=="projection": return validate_public_projection_serialized(raw)
    if group=="runtime_evidence":return validate_runtime_invariant_evidence_serialized(raw)
    return validate_error_serialized(raw)


def test_all_major_semantic_invalid_cases_are_observed():
    observed=[]
    for group in GROUPS:
        value,extra=payload(group,"schema-valid-python-invalid");schema=json.loads(schema_path(group).read_text(encoding="utf-8"));jsonschema.validate(value,schema)
        with pytest.raises(ProvanError) as caught:semantic(group,value,extra)
        observed.append((group,caught.value.code))
    assert {group for group,_ in observed}==set(GROUPS)
    print("ADVERSARIAL_REJECTION_OBSERVED:independent_semantic_recomputation:ALL_MAJOR_SEMANTIC_INVALID_CASES_REJECTED")


@pytest.mark.parametrize("invariant",sorted(RUNTIME_TEST_IDS))
@pytest.mark.parametrize("fixture_class",RUNTIME_CLASSES)
def test_runtime_invariant_evidence_layers(invariant,fixture_class):
    value,extra=payload("runtime_evidence",fixture_class,invariant);schema=json.loads(schema_path("runtime_evidence").read_text())
    if fixture_class=="schema-invalid":
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        return
    jsonschema.validate(value,schema)
    semantic("runtime_evidence",value,extra)


@pytest.mark.parametrize("group",GROUPS)
@pytest.mark.parametrize("fixture_class",CLASSES)
def test_major_invariant_contract_layers(group,fixture_class):
    value,extra=payload(group,fixture_class);schema=json.loads(schema_path(group).read_text())
    if fixture_class=="schema-invalid":
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        return
    jsonschema.validate(value,schema)
    if fixture_class in {"adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError):semantic(group,value,extra)
    else:semantic(group,value,extra)


@pytest.mark.parametrize("group",GROUPS)
def test_semantic_proof_fixtures_are_independently_distinct(group):
    valid_value,valid_extra=payload(group,"valid")
    near_value,near_extra=payload(group,"near-valid")
    adversarial_value,adversarial_extra=payload(group,"adversarial")
    invalid_value,invalid_extra=payload(group,"schema-valid-python-invalid")
    assert canonical_bytes(proof_identity({"value":near_value,"extra":near_extra})) != canonical_bytes(proof_identity({"value":valid_value,"extra":valid_extra}))
    assert canonical_bytes(proof_identity({"value":adversarial_value,"extra":adversarial_extra})) != canonical_bytes(proof_identity({"value":invalid_value,"extra":invalid_extra}))


@pytest.mark.parametrize("group",GROUPS)
@pytest.mark.parametrize("fixture_class",CLASSES)
def test_bundled_structural_validator_matches_proof_cases(group,fixture_class):
    value,_=payload(group,fixture_class);schema=json.loads(schema_path(group).read_text())
    if fixture_class=="schema-invalid":
        with pytest.raises(StructuralValidationError):validate_schema_instance(value,schema)
    else:validate_schema_instance(value,schema)
