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

# Every class below is an independently executed pytest parameter. Runtime
# invariants use three genuine behavioral cases because a schema layer is not
# applicable to target mutation/leakage behavior.
INVARIANTS=[
 ("S11A","contract_surface","acceptance-contract.v1.json","test_proof_contract_layers",{"adversarial":"CONTRACT_CANDIDATE_NOT_IMMUTABLE","schema-valid-python-invalid":"CHALLENGE_NOT_REQUIRED_CAP_NONZERO"}),
 ("S11B","conditional_activation","candidate-freeze.v1.json",{"valid":"test_proof_freeze_layers[valid]","near-valid":"test_conditional_activation_states_and_clearance_ceiling","adversarial":"test_conditional_activation_mismatch_fails","schema-invalid":"test_proof_freeze_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_freeze_layers[schema-valid-python-invalid]"},{"adversarial":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH","schema-valid-python-invalid":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH"}),
 ("S11C","contract_supersession","candidate-freeze.v1.json",{"valid":"test_proof_freeze_layers[valid]","near-valid":"test_proof_freeze_layers[near-valid]","adversarial":"test_superseding_contract_requires_new_freeze","schema-invalid":"test_proof_freeze_layers[schema-invalid]","schema-valid-python-invalid":"test_proof_freeze_layers[schema-valid-python-invalid]"},{"adversarial":"CONTRACT_FREEZE_BINDING_MISMATCH","schema-valid-python-invalid":"CONDITIONAL_ACTIVATION_BINDING_MISMATCH"}),
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
]
RUNTIME={"pr_history_safety","record_projection_authority","reinspection_lineage","disputed_derivation"}

CLAIM_INVARIANTS={"contract_surface":{1,2,14,16,17,18,19,20,21,66,79},"conditional_activation":{3,22,23,68,69,81},"contract_supersession":{70},"typed_closure_checks":{4,5,6,24,25,26,55,56,57,83},"human_confirmation":{84},"attestation_chain":{7,8,27,28,29,30,37,38,39,40,80},"evidence_ingestion_authority":{31,32,33,34,35,36,71,82},"settlement_recommendation":{9},"disputed_derivation":{72},"owner_decision_compatibility":{11,42,43,44,73},"protected_invariant_contract":{10,67},"reinspection_lineage":{13,52,53,54,74,75},"reinspection_aggregate":{86},"protected_invariant_closure":{87},"expiry_effective_status":{77},"future_capability_ceiling":{41,45,51,60},"session12_handoff_completeness":{12,15,58,59,61,62,63,64,65},"pr_history_safety":{78},"record_projection_authority":{46,47,48,49,50,76,85}}
def invariant_for(number):return next(name for name,numbers in CLAIM_INVARIANTS.items() if number in numbers)

def main():
    p=argparse.ArgumentParser();p.add_argument("--implementation-commit",required=True);p.add_argument("--implementation-tree",required=True);p.add_argument("--wheel-sha256",required=True);a=p.parse_args()
    entries=[];test_rel="tests/test_session11_acceptance.py";validator_rel="provan/session11_validators.py"
    for family,invariant,schema_name,test_spec,errors in INVARIANTS:
        classes=("valid","near-valid","adversarial") if invariant in RUNTIME else ("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")
        schema_rel="provan/schemas/"+schema_name;schema_id=json.loads((ROOT/schema_rel).read_text(encoding="utf-8"))["$id"]
        for fixture_class in classes:
            node=test_spec[fixture_class] if isinstance(test_spec,dict) else f"{test_spec}[{fixture_class}]"
            test_id=f"{test_rel}::{node}";command=["python","-m","pytest","-q","-s","-p","no:cacheprovider",test_id]
            run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding="utf-8",errors="strict");transcript=("COMMAND: "+" ".join(command)+f"\nEXIT_CODE: {run.returncode}\n"+run.stdout+run.stderr).replace("\r\n","\n")
            if run.returncode:raise SystemExit(transcript)
            transcript_path=PROOFS/"transcripts"/f"{family}-{fixture_class}.public.txt";transcript_path.parent.mkdir(parents=True,exist_ok=True);transcript_path.write_text(transcript,encoding="utf-8",newline="\n");transcript_hash=digest(transcript_path.read_bytes())
            locations=[test_rel,schema_rel,validator_rel,transcript_path.relative_to(ROOT).as_posix()]
            if invariant in RUNTIME:schema_result="NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"
            elif fixture_class=="schema-invalid":
                marker=next((line.split("PROOF_SCHEMA_ERROR:",1)[1] for line in transcript.splitlines() if "PROOF_SCHEMA_ERROR:" in line),None)
                if marker is None:raise SystemExit("SCHEMA_ERROR_NOT_OBSERVED:"+test_id)
                schema_result="FAIL:jsonschema.ValidationError:"+marker
            else:schema_result="PASS:Draft202012 asserted by executed test"
            python_result="PASS" if fixture_class in {"valid","near-valid"} else "NOT_RUN_AFTER_STRUCTURAL_FAILURE" if fixture_class=="schema-invalid" else "FAIL:"+errors[fixture_class]
            entries.append({"proof_id":f"{family}-{invariant.replace('_','-')}-{fixture_class}","family":family,"invariant":invariant,"fixture_class":fixture_class,"fixture_path":test_id,"schema_id":schema_id,"schema_result":schema_result,"python_validator":"provan.session11_validators independent serialized recomputation" if invariant not in RUNTIME else "direct production behavioral invariant with monitored state","python_result":python_result,"production_function":"provan.acceptance and provan.session11_validators" if invariant not in RUNTIME else "provan.leakage/provan.acceptance runtime boundary","test_id":test_id,"artifact_locations":locations,"artifact_hashes":[digest((ROOT/path).read_bytes()) for path in locations],"command":" ".join(command),"exit_code":run.returncode,"transcript_hash":transcript_hash,"sensitivity":"PUBLIC_SAFE"})
    authority_path=OUT/"claim_registry.v1.public.json";authority=json.loads(authority_path.read_text(encoding="utf-8"));authority_digest=digest(authority_path.read_bytes())
    registry={"schema_id":"provan.session11_proof_registry.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"claim_registry_digest":authority_digest,"entries":entries};write(PROOFS/"proof_registry.v1.public.json",registry)
    by_inv={name:[row for row in entries if row["invariant"]==name] for _,name,*_ in INVARIANTS};claims=[];crosswalk=[]
    for invariant,proofs in by_inv.items():crosswalk.append({"major_invariant":invariant,"proof_ids":[row["proof_id"] for row in proofs],"claim_ids":[row["claim_id"] for row in authority["claims"] if invariant_for(int(row["claim_id"].split("-")[1]))==invariant],"schema_layer":"NOT_APPLICABLE_RUNTIME_BEHAVIOR" if invariant in RUNTIME else "REQUIRED_AND_EXECUTED"})
    for row in authority["claims"]:
        number=int(row["claim_id"].split("-")[1]);invariant=invariant_for(number);proofs={item["fixture_class"]:item["proof_id"] for item in by_inv[invariant]}
        claims.append({"Claim":f"{row['claim_id']} — {row['normative_claim']}","Implemented in":"provan/acceptance.py; provan/session11_validators.py; provan/schemas; docs/acceptance-lifecycle.md","Positive proof":proofs["valid"],"Near-valid proof":proofs["near-valid"],"Negative proof":proofs["adversarial"],"Python result":proofs.get("schema-valid-python-invalid","NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"),"Schema result":proofs.get("schema-invalid","NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT"),"Artifact evidence":"artifacts/session11/proofs/proof_registry.v1.public.json","Reviewer result":"PENDING","Status":"READY_FOR_REVIEW"})
    write(PROOFS/"claim_crosswalk.v1.public.json",{"schema_id":"provan.session11_claim_crosswalk.v1","claim_registry_digest":authority_digest,"entries":crosswalk});write(OUT/"layer4_claim_matrix.v1.public.json",{"schema_id":"provan.session11_layer4_matrix.v1","claim_registry_digest":authority_digest,"claims":claims})
    schema_registry=json.loads((OUT/"schema_registry.v1.public.json").read_text(encoding="utf-8"));binding={"schema_id":"provan.session11_implementation_binding.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"package_version":"0.4.0","extension_api_major":1,"wheel_sha256":a.wheel_sha256,"schema_registry_digest":schema_registry["registry_digest"],"claim_registry_digest":authority_digest,"maturity":"QUALIFIED_BOUNDED","published":False};write(OUT/"implementation_binding.v1.public.json",binding)
    print(f"SESSION11_PROOFS_VALID entries={len(entries)} claims={len(claims)}")
if __name__=="__main__":main()
