from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/"artifacts/session11";PROOFS=OUT/"proofs"

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()
def write(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(value))
def support_nodes(kind):return {cls:f"test_proof_support_contract_layers[{kind}-{cls}]" for cls in ("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")}
def final_nodes(kind):return {cls:f"test_proof_final_artifact_binding[{kind}-{cls}]" for cls in ("valid","near-valid","adversarial")}

# Every class below is an independently executed pytest parameter. Runtime
# invariants use three genuine behavioral cases because a schema layer is not
# applicable to target mutation/leakage behavior.
INVARIANTS=[
 ("S11A","seed_disposition_contract","seed-disposition.v1.json",support_nodes("seed"),{"adversarial":"SEED_DISPOSITION_ACTOR_AUTHORITY_INVALID","schema-valid-python-invalid":"SEED_DISPOSITION_ACTOR_AUTHORITY_INVALID"}),
 ("S11A","contract_surface","acceptance-contract.v1.json","test_proof_contract_layers",{"adversarial":"CONTRACT_CANDIDATE_NOT_IMMUTABLE","schema-valid-python-invalid":"CHALLENGE_NOT_REQUIRED_CAP_NONZERO"}),
 ("S11B","conditional_activation","candidate-freeze.v1.json",{"valid":"test_proof_freeze_layers[valid]","near-valid":"test_conditional_activation_states_and_clearance_ceiling","adversarial":"test_conditional_activation_mismatch_fails","schema-invalid":"test_proof_freeze_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_freeze_layers[schema-valid-python-invalid]"},{"adversarial":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH","schema-valid-python-invalid":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH"}),
 ("S11C","contract_supersession","candidate-freeze.v1.json",{"valid":"test_proof_freeze_layers[valid]","near-valid":"test_proof_freeze_layers[near-valid]","adversarial":"test_superseding_contract_requires_new_freeze","schema-invalid":"test_proof_freeze_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_freeze_layers[schema-valid-python-invalid]"},{"adversarial":"CONTRACT_FREEZE_BINDING_MISMATCH","schema-valid-python-invalid":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH"}),
 ("S11C","verifier_work_order_contract","verifier-work-order.v1.json",support_nodes("work-order"),{"adversarial":"VERIFIER_WORK_ORDER_PROHIBITIONS_INCOMPLETE","schema-valid-python-invalid":"VERIFIER_WORK_ORDER_PROHIBITIONS_INCOMPLETE"}),
 ("S11C","verifier_capability_contract","verifier-capability-request.v1.json",support_nodes("capability"),{"adversarial":"VERIFIER_CAPABILITY_STATE_INVALID","schema-valid-python-invalid":"VERIFIER_CAPABILITY_STATE_INVALID"}),
 ("S11C","verification_result_contract","verification-result.v1.json",support_nodes("verification"),{"adversarial":"VERIFICATION_RESULT_EVIDENCE_MISSING","schema-valid-python-invalid":"VERIFICATION_RESULT_EVIDENCE_MISSING"}),
 ("S11C","environment_receipt_contract","environment-receipt.v1.json",support_nodes("environment"),{"adversarial":"RECEIPT_PRODUCER_QUALIFICATION_UNRESOLVED","schema-valid-python-invalid":"RECEIPT_PRODUCER_QUALIFICATION_UNRESOLVED"}),
 ("S11C","command_receipt_contract","command-receipt.v1.json",support_nodes("command"),{"adversarial":"COMMAND_EXECUTION_AUTHORITY_UNRESOLVED","schema-valid-python-invalid":"COMMAND_EXECUTION_AUTHORITY_UNRESOLVED"}),
 ("S11C","external_change_receipt_contract","external-change-receipt.v1.json",support_nodes("external"),{"adversarial":"EXTERNAL_CHANGE_RECEIPT_CLOSURE_AUTHORITY_FORBIDDEN","schema-valid-python-invalid":"EXTERNAL_CHANGE_RECEIPT_CLOSURE_AUTHORITY_FORBIDDEN"}),
 ("S11C","semantic_validator_coverage","session10-runtime-invariant-evidence.v1.json",{"valid":"test_proof_semantic_validator_coverage[valid]","near-valid":"test_proof_semantic_validator_coverage[near-valid]","adversarial":"test_proof_semantic_validator_coverage[adversarial]"},{"adversarial":"SEMANTIC_VALIDATOR_COVERAGE_INCOMPLETE"}),
 ("S11D","typed_closure_checks","closure-requirement.v1.json",{"valid":"test_proof_closure_layers[valid]","near-valid":"test_proof_closure_layers[near-valid]","adversarial":"test_static_python_export_check_does_not_execute","schema-invalid":"test_proof_closure_layers[schema-invalid]","schema-valid-python-invalid":"test_schema_valid_python_invalid_closure"},{"adversarial":"TARGET_EXECUTION_FORBIDDEN","schema-valid-python-invalid":"CLOSURE_SOURCE_CHECK_UNSUPPORTED"}),
 ("S11E","human_confirmation","closure-requirement.v1.json",{"valid":"test_proof_closure_layers[valid]","near-valid":"test_proof_closure_layers[near-valid]","adversarial":"test_human_confirmation_not_satisfied_by_arbitrary_text","schema-invalid":"test_proof_closure_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_closure_layers[schema-valid-python-invalid]"},{"adversarial":"HUMAN_CONFIRMATION_UNABLE_TO_ESTABLISH","schema-valid-python-invalid":"CLOSURE_SOURCE_PATH_UNSAFE"}),
 ("S11F","attestation_chain","acceptance-attestation.v1.json","test_proof_attestation_layers",{"adversarial":"SESSION11_EXECUTION_STATE_FABRICATED","schema-valid-python-invalid":"ATTESTATION_RECOMMENDATION_MISMATCH"}),
 ("S11G","evidence_ingestion_authority","evidence-settlement.v1.json",{"valid":"test_proof_settlement_layers[valid]","near-valid":"test_proof_settlement_layers[near-valid]","adversarial":"test_imported_file_cannot_self_declare_authority","schema-invalid":"test_proof_settlement_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_settlement_layers[schema-valid-python-invalid]"},{"adversarial":"EVIDENCE_AUTHORITY_PROVENANCE_INVALID","schema-valid-python-invalid":"EVIDENCE_SETTLEMENT_STATE_INVALID"}),
 ("S11H","settlement_recommendation","evidence-settlement.v1.json",{"valid":"test_proof_settlement_layers[valid]","near-valid":"test_proof_settlement_layers[near-valid]","adversarial":"test_settlement_recomputes_complete_coverage_and_recommendation","schema-invalid":"test_proof_settlement_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_settlement_layers[schema-valid-python-invalid]"},{"adversarial":"SETTLEMENT_RECOMMENDATION_MISMATCH","schema-valid-python-invalid":"EVIDENCE_SETTLEMENT_STATE_INVALID"}),
 ("S11I","disputed_derivation","evidence-settlement.v1.json",{"valid":"test_proof_disputed_derivation_layers[valid]","near-valid":"test_proof_disputed_derivation_layers[near-valid]","adversarial":"test_proof_disputed_derivation_layers[adversarial]"},{"adversarial":"OWNER_DISAGREEMENT_NOT_EVIDENCE_CONFLICT"}),
 ("S11J","owner_decision_compatibility","owner-decision.v1.json","test_proof_owner_decision_layers",{"adversarial":"OWNER_DECISION_INCOMPATIBLE","schema-valid-python-invalid":"OWNER_DECISION_INCOMPATIBLE"}),
 ("S11K","protected_invariant_contract","protected-invariant.v1.json","test_proof_protected_invariant_layers",{"adversarial":"PROTECTED_INVARIANT_FREEFORM_EVALUATOR_FORBIDDEN","schema-valid-python-invalid":"PROTECTED_INVARIANT_CHECK_UNSUPPORTED"}),
 ("S11L","reinspection_lineage","reinspection-record.v1.json",{"valid":"test_full_lifecycle_and_exact_reinspection","near-valid":"test_near_fix_and_unrelated_descendant_do_not_close","adversarial":"test_reinspection_lineage_and_same_head_reject"},{"adversarial":"REINSPECTION_LINEAGE_INVALID"}),
 ("S11M","reinspection_aggregate","reinspection-record.v1.json",{"valid":"test_full_lifecycle_and_exact_reinspection","near-valid":"test_reinspection_aggregate_precedence","adversarial":"test_proof_reinspection_layers[adversarial]","schema-invalid":"test_proof_reinspection_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_reinspection_layers[schema-valid-python-invalid]"},{"adversarial":"REINSPECTION_MATERIAL_REQUIREMENT_SET_MISMATCH","schema-valid-python-invalid":"REINSPECTION_AGGREGATE_STATUS_INVALID"}),
 ("S11N","protected_invariant_closure","reinspection-record.v1.json",{"valid":"test_full_lifecycle_and_exact_reinspection","near-valid":"test_reinspection_aggregate_precedence","adversarial":"test_protected_invariant_failure_prevents_closure","schema-invalid":"test_proof_reinspection_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_reinspection_layers[schema-valid-python-invalid]"},{"adversarial":"PROTECTED_INVARIANT_PREVENTS_CLOSURE","schema-valid-python-invalid":"REINSPECTION_AGGREGATE_STATUS_INVALID"}),
 ("S11O","expiry_effective_status","acceptance-attestation.v1.json",{"valid":"test_expiry_is_computed_with_injectable_clock","near-valid":"test_proof_attestation_layers[near-valid]","adversarial":"test_attestation_schema_valid_semantic_chain_mismatch","schema-invalid":"test_proof_attestation_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_attestation_layers[schema-valid-python-invalid]"},{"adversarial":"ATTESTATION_RECOMMENDATION_MISMATCH","schema-valid-python-invalid":"ATTESTATION_RECOMMENDATION_MISMATCH"}),
 ("S11P","future_capability_ceiling","acceptance-attestation.v1.json","test_proof_attestation_layers",{"adversarial":"SESSION11_EXECUTION_STATE_FABRICATED","schema-valid-python-invalid":"ATTESTATION_RECOMMENDATION_MISMATCH"}),
 ("S11Q","session12_handoff_completeness","session12-handoff.v1.json","test_proof_session12_handoff_layers",{"adversarial":"SESSION12_HANDOFF_DUPLICATE_ARTIFACT_REF","schema-valid-python-invalid":"SESSION12_HANDOFF_PROJECTION_RULES_INVALID"}),
 ("S11R","pr_history_safety","session10-runtime-invariant-evidence.v1.json",{"valid":"test_proof_pr_history_layers[valid]","near-valid":"test_pr_synthetic_merge_metadata_is_not_candidate_history","adversarial":"test_real_candidate_history_leakage_still_rejects"},{"adversarial":"COMMUNITY_PRIVATE_LEAKAGE"}),
 ("S11S","record_projection_authority","session10-runtime-invariant-evidence.v1.json",{"valid":"test_record_bundle_identity_is_renderer_independent","near-valid":"test_proof_record_projection_layers[near-valid]","adversarial":"test_record_locator_rejects_redirected_authoritative_chain"},{"adversarial":"RECORD_CHAIN_REDIRECTED"}),
 ("S11S","candidate_freeze_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("candidate-freeze"),{"adversarial":"CANDIDATE_FREEZE_ANALYSIS_DIGEST_MISMATCH"}),
 ("S11S","candidate_target_immutability","session10-runtime-invariant-evidence.v1.json","test_proof_candidate_target_immutability",{"adversarial":"TARGET_EXECUTION_AND_MUTATION_UNREACHABLE"}),
 ("S11S","attestation_complete_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("attestation-complete"),{"adversarial":"ATTESTATION_RECOMMENDATION_MISMATCH"}),
 ("S11S","attestation_projection_artifacts","session10-runtime-invariant-evidence.v1.json",{"valid":"test_attestation_materializes_bound_internal_and_client_safe_projections","near-valid":"test_proof_record_projection_layers[near-valid]","adversarial":"test_tampered_attestation_projection_prevents_record_render"},{"adversarial":"ATTESTATION_PROJECTION_PAYLOAD_INVALID"}),
 ("S11S","record_rendering_surface","session10-runtime-invariant-evidence.v1.json","test_proof_record_projection_layers",{"adversarial":"RECORD_PROJECTION_TAMPERED"}),
 ("S11S","external_real_use_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("external-real-use"),{"adversarial":"UPSTREAM_OWNER_AUTHORITY_FABRICATED"}),
 ("S11S","internal_real_use_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("internal-real-use"),{"adversarial":"ORGANISATION_IDENTITY_FABRICATED"}),
 ("S11S","installed_wheel_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("installed-wheel"),{"adversarial":"INSTALLED_WHEEL_ORIGIN_INVALID"}),
 ("S11S","package_implementation_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("package-binding"),{"adversarial":"PACKAGE_WHEEL_BINDING_INVALID"}),
 ("S11S","final_session12_handoff_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("session12-handoff"),{"adversarial":"SESSION12_HANDOFF_TRANSITIVE_BINDING_INVALID"}),
 ("S11S","controlled_reinspection_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("controlled-reinspection"),{"adversarial":"CONTROLLED_REINSPECTION_PROOF_BINDING_INVALID"}),
 ("S11S","predecessor_preservation","session10-runtime-invariant-evidence.v1.json","test_proof_predecessor_preservation",{"adversarial":"SESSION10_HISTORICAL_ARTIFACT_CHANGED"}),
 ("S11S","generic_absence_binding","session10-runtime-invariant-evidence.v1.json",final_nodes("successor-safety"),{"adversarial":"PRIVATE_PLANNING_AUTHORITY_PRESENT"}),
]
RUNTIME={"pr_history_safety","record_projection_authority","reinspection_lineage","disputed_derivation","semantic_validator_coverage","candidate_freeze_binding","candidate_target_immutability","attestation_complete_binding","attestation_projection_artifacts","record_rendering_surface","external_real_use_binding","internal_real_use_binding","installed_wheel_binding","package_implementation_binding","final_session12_handoff_binding","controlled_reinspection_binding","predecessor_preservation","generic_absence_binding"}
FINAL_EVIDENCE={
 "candidate_freeze_binding":"artifacts/session11/real_use/httpx/candidate_freeze.v1.public.json",
 "attestation_complete_binding":"artifacts/session11/real_use/httpx/acceptance_attestation.v1.public.json",
 "external_real_use_binding":"artifacts/session11/real_use/httpx_pr3699.acceptance_lifecycle.v1.public.json",
 "internal_real_use_binding":"artifacts/session11/real_use/provan_internal_lifecycle.v1.public.json",
 "installed_wheel_binding":"artifacts/session11/real_use/installed_wheel_origin.v1.public.json",
 "package_implementation_binding":"artifacts/session11/implementation_binding.v1.public.json",
 "generic_absence_binding":"artifacts/session11/generic_absence_receipt.v1.public.json",
}

CLAIM_INVARIANTS={"contract_surface":{1,2,16,17,18,19,20,21,66,79},"conditional_activation":{3,22,23,68,69,81},"contract_supersession":{70},"verifier_work_order_contract":{4,27},"verifier_capability_contract":{5,28},"verification_result_contract":{6,29},"environment_receipt_contract":{7},"command_receipt_contract":{8,30},"external_change_receipt_contract":{12,51},"semantic_validator_coverage":{14},"typed_closure_checks":{24,25,26,55,56,57,83},"human_confirmation":{84},"attestation_chain":{37,38,39,40,80},"evidence_ingestion_authority":{31,32,33,34,35,36,71,82},"settlement_recommendation":{9,41},"disputed_derivation":{72},"owner_decision_compatibility":{11,42,43,44,73},"protected_invariant_contract":{10,67},"reinspection_lineage":{13,52,53,54,74,75},"reinspection_aggregate":{86},"protected_invariant_closure":{87},"expiry_effective_status":{77},"future_capability_ceiling":{45,60},"session12_handoff_completeness":{15,58,59,61,62,63,64,65},"pr_history_safety":{78},"record_projection_authority":{46,47,48,49,50,76,85}}
SUPPLEMENTAL_CLAIM_INVARIANTS={
 1:{"seed_disposition_contract"},16:{"seed_disposition_contract"},17:{"seed_disposition_contract"},18:{"seed_disposition_contract"},
 3:{"candidate_freeze_binding"},22:{"candidate_freeze_binding"},23:{"candidate_freeze_binding"},24:{"candidate_freeze_binding"},25:{"candidate_freeze_binding"},26:{"candidate_target_immutability"},
 10:{"attestation_complete_binding"},15:{"predecessor_preservation"},
 37:{"attestation_complete_binding"},38:{"attestation_complete_binding"},39:{"attestation_complete_binding"},40:{"attestation_complete_binding"},
 45:{"record_rendering_surface"},46:{"record_rendering_surface"},47:{"record_rendering_surface"},48:{"record_rendering_surface"},49:{"record_rendering_surface"},50:{"attestation_projection_artifacts"},
 58:{"external_real_use_binding"},59:{"internal_real_use_binding"},60:{"controlled_reinspection_binding"},61:{"installed_wheel_binding"},62:{"package_implementation_binding"},63:{"final_session12_handoff_binding"},64:{"predecessor_preservation"},65:{"generic_absence_binding"},
 75:{"controlled_reinspection_binding"},76:{"record_rendering_surface"},80:{"attestation_complete_binding"},85:{"record_projection_authority"},
}
def invariants_for(number):
    primary=[name for name,numbers in CLAIM_INVARIANTS.items() if number in numbers]
    if len(primary)!=1:raise ValueError(f"claim {number} has {len(primary)} primary invariants")
    return primary+sorted(SUPPLEMENTAL_CLAIM_INVARIANTS.get(number,set())-set(primary))
def primary_invariant_for(number):return invariants_for(number)[0]

def main():
    p=argparse.ArgumentParser();p.add_argument("--implementation-commit",required=True);p.add_argument("--implementation-tree",required=True);p.add_argument("--wheel-sha256",required=True);a=p.parse_args()
    authority_path=OUT/"claim_registry.v1.public.json";authority=json.loads(authority_path.read_text(encoding="utf-8"));authority_digest=digest(authority_path.read_bytes())
    schema_registry=json.loads((OUT/"schema_registry.v1.public.json").read_text(encoding="utf-8"));binding={"schema_id":"provan.session11_implementation_binding.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"package_version":"0.4.0","extension_api_major":1,"wheel_sha256":a.wheel_sha256,"schema_registry_digest":schema_registry["registry_digest"],"claim_registry_digest":authority_digest,"maturity":"QUALIFIED_BOUNDED","published":False};write(OUT/"implementation_binding.v1.public.json",binding)
    entries=[];test_rel="tests/test_session11_acceptance.py";validator_rel="provan/session11_validators.py"
    for family,invariant,schema_name,test_spec,errors in INVARIANTS:
        classes=("valid","near-valid","adversarial") if invariant in RUNTIME else ("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")
        schema_rel="provan/schemas/"+schema_name;schema_id=json.loads((ROOT/schema_rel).read_text(encoding="utf-8"))["$id"]
        for fixture_class in classes:
            node=test_spec[fixture_class] if isinstance(test_spec,dict) else f"{test_spec}[{fixture_class}]"
            test_id=f"{test_rel}::{node}";command=["python","-m","pytest","-q","-s","-p","no:cacheprovider",test_id]
            run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding="utf-8",errors="strict");transcript=("COMMAND: "+" ".join(command)+f"\nEXIT_CODE: {run.returncode}\n"+run.stdout+run.stderr).replace("\r\n","\n")
            if run.returncode:raise SystemExit(transcript)
            transcript_path=PROOFS/"transcripts"/f"{family}-{invariant.replace('_','-')}-{fixture_class}.public.txt";transcript_path.parent.mkdir(parents=True,exist_ok=True);transcript_path.write_text(transcript,encoding="utf-8",newline="\n");transcript_hash=digest(transcript_path.read_bytes())
            locations=[test_rel,schema_rel,validator_rel,transcript_path.relative_to(ROOT).as_posix()]
            if invariant in FINAL_EVIDENCE:locations.append(FINAL_EVIDENCE[invariant])
            if invariant in RUNTIME:schema_result="NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"
            elif fixture_class=="schema-invalid":
                marker=next((line.split("PROOF_SCHEMA_ERROR:",1)[1] for line in transcript.splitlines() if "PROOF_SCHEMA_ERROR:" in line),None)
                if marker is None:raise SystemExit("SCHEMA_ERROR_NOT_OBSERVED:"+test_id)
                schema_result="FAIL:jsonschema.ValidationError:"+marker
            else:schema_result="PASS:Draft202012 asserted by executed test"
            python_result="PASS" if fixture_class in {"valid","near-valid"} else "NOT_RUN_AFTER_STRUCTURAL_FAILURE" if fixture_class=="schema-invalid" else "FAIL:"+errors[fixture_class]
            entries.append({"proof_id":f"{family}-{invariant.replace('_','-')}-{fixture_class}","family":family,"invariant":invariant,"fixture_class":fixture_class,"fixture_path":test_id,"schema_id":schema_id,"schema_result":schema_result,"python_validator":"provan.session11_validators independent serialized recomputation" if invariant not in RUNTIME else "direct production behavioral invariant with monitored state","python_result":python_result,"production_function":"provan.acceptance and provan.session11_validators" if invariant not in RUNTIME else "claim-specific Session 11 runtime and canonical artifact resolver","test_id":test_id,"artifact_locations":locations,"artifact_hashes":[digest((ROOT/path).read_bytes()) for path in locations],"command":" ".join(command),"exit_code":run.returncode,"transcript_hash":transcript_hash,"sensitivity":"PUBLIC_SAFE"})
    registry={"schema_id":"provan.session11_proof_registry.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"claim_registry_digest":authority_digest,"entries":entries};write(PROOFS/"proof_registry.v1.public.json",registry)
    by_inv={name:[row for row in entries if row["invariant"]==name] for _,name,*_ in INVARIANTS};claims=[];crosswalk=[]
    for invariant,proofs in by_inv.items():crosswalk.append({"major_invariant":invariant,"proof_ids":[row["proof_id"] for row in proofs],"claim_ids":[row["claim_id"] for row in authority["claims"] if primary_invariant_for(int(row["claim_id"].split("-")[1]))==invariant],"supplemental_claim_ids":[row["claim_id"] for row in authority["claims"] if invariant in invariants_for(int(row["claim_id"].split("-")[1])) and primary_invariant_for(int(row["claim_id"].split("-")[1]))!=invariant],"schema_layer":"NOT_APPLICABLE_RUNTIME_BEHAVIOR" if invariant in RUNTIME else "REQUIRED_AND_EXECUTED"})
    for row in authority["claims"]:
        number=int(row["claim_id"].split("-")[1]);invariants=invariants_for(number);proof_sets=[{item["fixture_class"]:item["proof_id"] for item in by_inv[invariant]} for invariant in invariants]
        proofs={fixture:[proof_set.get(fixture,"NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT") for proof_set in proof_sets] for fixture in ("valid","near-valid","adversarial","schema-valid-python-invalid","schema-invalid")}
        claims.append({"Claim":f"{row['claim_id']} — {row['normative_claim']}","Implemented in":"provan/acceptance.py; provan/session11_validators.py; provan/schemas; docs/acceptance-lifecycle.md","Positive proof":proofs["valid"],"Near-valid proof":proofs["near-valid"],"Negative proof":proofs["adversarial"],"Python result":proofs.get("schema-valid-python-invalid","NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"),"Schema result":proofs.get("schema-invalid","NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"),"Artifact evidence":"artifacts/session11/proofs/proof_registry.v1.public.json","Reviewer result":"PENDING","Status":"READY_FOR_REVIEW"})
    write(PROOFS/"claim_crosswalk.v1.public.json",{"schema_id":"provan.session11_claim_crosswalk.v1","claim_registry_digest":authority_digest,"entries":crosswalk});write(OUT/"layer4_claim_matrix.v1.public.json",{"schema_id":"provan.session11_layer4_matrix.v1","claim_registry_digest":authority_digest,"claims":claims})
    print(f"SESSION11_PROOFS_VALID entries={len(entries)} claims={len(claims)}")
if __name__=="__main__":main()
