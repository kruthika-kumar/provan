from __future__ import annotations

import copy
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import jsonschema

from provan.acceptance import (attest, create_contract, decide, derive_evidence_state,
                               disposition_items, freeze_contract, reinspect, render_record)
from provan.canonical import canonical_bytes, sha256_bytes
from provan.change_brief import explain, promote
from provan.errors import ProvanError
from provan.leakage import validate_candidate_surfaces
from provan.session11_validators import (derive_reinspection_overall,
    SEMANTIC_VALIDATORS,
    effective_status, validate_attestation_serialized,
    validate_closure_requirement_serialized, validate_contract_serialized, validate_freeze_serialized,
    validate_command_receipt_serialized, validate_environment_receipt_serialized,
    validate_external_change_receipt_serialized, validate_seed_disposition_serialized,
    validate_verification_result_serialized, validate_verifier_capability_request_serialized,
    validate_verifier_work_order_serialized,
    validate_owner_decision_serialized, validate_protected_invariant_serialized,
    validate_reinspection_serialized, validate_session12_handoff_serialized,
    validate_settlement_serialized)
from provan.state import secure_read

FIXED=lambda:datetime(2026,8,10,12,0,0,tzinfo=timezone.utc)


def git(repo:Path,*args:str,env:dict|None=None)->str:
    merged=os.environ.copy();merged.update(env or {})
    return subprocess.run(["git",*args],cwd=repo,check=True,capture_output=True,text=True,encoding="utf-8",env=merged).stdout.strip()


def commit(repo:Path,message:str)->str:
    env={"GIT_AUTHOR_NAME":"Fixture","GIT_AUTHOR_EMAIL":"noreply","GIT_COMMITTER_NAME":"Fixture","GIT_COMMITTER_EMAIL":"noreply"}
    git(repo,"add","-A",env=env);git(repo,"commit","-m",message,env=env);return git(repo,"rev-parse","HEAD")


def new_contract(patient,terms:dict,*,supersedes:str|None=None):
    surface=disposition_items(patient["preparation"]["preparation_id"]);rows=[{"item_id":item["item_id"],"action":"unresolved" if item["kind"]=="unresolved_question" else "confirm","rationale":"bounded fixture"} for item in surface["items"]]
    return create_contract(patient["preparation"]["preparation_id"],{"items":rows,"contract_terms":terms},"fixture-operator",supersedes=supersedes,now=FIXED)


def patient_criterion(**overrides):
    value={"criterion_id":"patient.acceptance_record_available.v1","statement":"Acceptance Record capability is available.","class":"mandatory","material":True,"required_evidence_classes":["source_verified"],"challenge_requirement":"not_required","closure_requirement":{"check_mode":"source_only","required_evidence_class":"source_verified","check":{"type":"canonical_field_equals","path":"patient/public-contract.json","json_pointer":"/capabilities/acceptance_record","expected_value":"available"}}}
    value.update(overrides);return value


@pytest.fixture
def patient(tmp_path:Path,monkeypatch):
    home=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(home));repo=tmp_path/"patient";repo.mkdir();git(repo,"init");git(repo,"config","user.name","Fixture");git(repo,"config","user.email","noreply");git(repo,"remote","add","origin","https://github.com/provan-test/acceptance-patient.git")
    (repo/"README.md").write_text("patient\n",encoding="utf-8");base=commit(repo,"base")
    (repo/"patient").mkdir();(repo/"patient"/"public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"absent"}}\n',encoding="utf-8");original=commit(repo,"original")
    brief=explain(repo=str(repo),base=base,head=original,working_tree=False,brief_text="Acceptance Record capability must become available.",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    prep=promote(brief["brief_id"]);surface=disposition_items(prep["preparation_id"]);rows=[]
    for item in surface["items"]:rows.append({"item_id":item["item_id"],"action":"unresolved" if item["kind"]=="unresolved_question" else "confirm","rationale":"fixture authority"})
    terms={"criteria":[{"criterion_id":"patient.acceptance_record_available.v1","statement":"Acceptance Record capability is available.","class":"mandatory","material":True,"required_evidence_classes":["source_verified"],"challenge_requirement":"not_required","closure_requirement":{"check_mode":"source_only","required_evidence_class":"source_verified","check":{"type":"canonical_field_equals","path":"patient/public-contract.json","json_pointer":"/capabilities/acceptance_record","expected_value":"available"}}}],"risk":{"tier":{"value":"medium","authority":"owner_confirmed","provenance_refs":[prep["preparation_id"]]},"reversibility":{"value":"bounded","authority":"owner_confirmed","provenance_refs":[prep["preparation_id"]]}},"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}}
    contract=create_contract(prep["preparation_id"],{"items":rows,"contract_terms":terms},"fixture-operator",now=FIXED);freeze=freeze_contract(contract["contract_id"],str(repo),now=FIXED);att=attest(freeze["freeze_id"],[],now=FIXED)
    return {"repo":repo,"base":base,"original":original,"brief":brief,"preparation":prep,"contract":contract,"freeze":freeze,"attestation":att,"home":home}


def test_full_lifecycle_and_exact_reinspection(patient):
    att=patient["attestation"];assert att["recommendation"]=="held"
    decision=decide(att["attestation_id"],{"decision":"override_accept_risk","rationale":"controlled fixture"},"fixture-operator",now=FIXED)
    record_id,text=render_record(att["attestation_id"],decision["decision_id"],"markdown");assert "Recommendation: `held`" in text
    repo=patient["repo"];(repo/"patient"/"public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"available"}}\n',encoding="utf-8");later=commit(repo,"correct fix")
    result=reinspect(record_id,str(repo),later,None,now=FIXED);assert result["overall_status"]=="closed" and result["items"][0]["status"]=="closed"


def test_near_fix_and_unrelated_descendant_do_not_close(patient):
    att=patient["attestation"];record_id,_=render_record(att["attestation_id"],None,"json");repo=patient["repo"]
    (repo/"patient"/"public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"planned"}}\n',encoding="utf-8");near=commit(repo,"near fix");assert reinspect(record_id,str(repo),near,None,now=FIXED)["overall_status"]=="open"
    git(repo,"checkout",patient["original"]);(repo/"patient"/"notes.txt").write_text("unrelated\n",encoding="utf-8");unrelated=commit(repo,"unrelated descendant");assert reinspect(record_id,str(repo),unrelated,None,now=FIXED)["overall_status"]=="open"


def test_reinspection_lineage_and_same_head_reject(patient,tmp_path):
    record_id,_=render_record(patient["attestation"]["attestation_id"],None,"json")
    with pytest.raises(ProvanError) as same:reinspect(record_id,str(patient["repo"]),patient["original"],None,now=FIXED)
    assert same.value.code=="REINSPECTION_NOT_LATER_CANDIDATE"
    other=tmp_path/"other";other.mkdir();git(other,"init");(other/"x").write_text("x");head=commit(other,"other")
    with pytest.raises(ProvanError) as exc:reinspect(record_id,str(other),head,None,now=FIXED)
    assert exc.value.code=="REINSPECTION_REPOSITORY_MISMATCH"


def test_tampered_projection_cannot_drive_reinspection(patient):
    record_id,_=render_record(patient["attestation"]["attestation_id"],None,"json");root=Path(os.environ["PROVAN_HOME"])/"outputs"/"acceptance"/"records"/record_id.removeprefix("sha256:");(root/"record.markdown").write_text("tampered",encoding="utf-8")
    with pytest.raises(ProvanError) as exc:reinspect(record_id,str(patient["repo"]),patient["original"],None,now=FIXED)
    assert exc.value.code in {"RECORD_PROJECTION_TAMPERED","REINSPECTION_NOT_LATER_CANDIDATE"}


def test_record_bundle_identity_is_renderer_independent(patient):
    ids=[]
    for fmt in ("json","markdown","html","terminal"):ids.append(render_record(patient["attestation"]["attestation_id"],None,fmt)[0])
    assert len(set(ids))==1


def test_record_locator_rejects_redirected_authoritative_chain(patient):
    first=patient["attestation"]
    record_id,_=render_record(first["attestation_id"],None,"json")
    second=attest(patient["freeze"]["freeze_id"],[],now=FIXED)
    second_raw=secure_read(Path("outputs/acceptance/attestations")/f"{second['attestation_id']}.json")
    second_settlement=secure_read(Path("outputs/acceptance/settlements")/f"{second['settlement_ref']['id']}.json")
    root=Path(os.environ["PROVAN_HOME"])/"outputs/acceptance/records"/record_id.removeprefix("sha256:")
    bundle=json.loads((root/"bundle.json").read_bytes())
    bundle["authoritative_chain"]["attestation_ref"]={"id":second["attestation_id"],"sha256":sha256_bytes(second_raw)}
    bundle["authoritative_chain"]["settlement_ref"]={"id":second["settlement_ref"]["id"],"sha256":sha256_bytes(second_settlement)}
    (root/"bundle.json").write_bytes(canonical_bytes(bundle))
    repo=patient["repo"]
    (repo/"patient/notes.txt").write_text("later\n",encoding="utf-8")
    later=commit(repo,"later for redirected chain")
    with pytest.raises(ProvanError) as exc:reinspect(record_id,str(repo),later,None,now=FIXED)
    assert exc.value.code=="RECORD_ID_BINDING_MISMATCH"


def test_invalid_owner_decision_compatibility(patient):
    att=patient["attestation"]
    with pytest.raises(ProvanError) as exc:decide(att["attestation_id"],{"decision":"accept"},"operator",now=FIXED)
    assert exc.value.code=="OWNER_DECISION_INCOMPATIBLE"


def test_settlement_recomputes_complete_coverage_and_recommendation(patient):
    att=patient["attestation"]
    settlement_path=Path(os.environ["PROVAN_HOME"])/"outputs/acceptance/settlements"/f"{att['settlement_ref']['id']}.json"
    contract_path=Path(os.environ["PROVAN_HOME"])/"outputs/acceptance/contracts"/f"{patient['contract']['contract_id']}.json"
    freeze_path=Path(os.environ["PROVAN_HOME"])/"outputs/acceptance/freezes"/f"{patient['freeze']['freeze_id']}.json"
    settlement=json.loads(settlement_path.read_bytes());contract_raw=contract_path.read_bytes();freeze_raw=freeze_path.read_bytes()
    missing=copy.deepcopy(settlement);missing["criteria"]=[]
    with pytest.raises(ProvanError) as coverage:validate_settlement_serialized(canonical_bytes(missing),contract_raw,freeze_raw,now=FIXED)
    assert coverage.value.code=="SETTLEMENT_CRITERION_COVERAGE_MISMATCH"
    false_clearance=copy.deepcopy(settlement);false_clearance["recommendation"]="cleared"
    with pytest.raises(ProvanError) as recommendation:validate_settlement_serialized(canonical_bytes(false_clearance),contract_raw,freeze_raw,now=FIXED)
    assert recommendation.value.code=="SETTLEMENT_RECOMMENDATION_MISMATCH"
    omitted=copy.deepcopy(settlement);omitted["criteria"][0]["eligible_evidence"]=[];omitted["criteria"][0]["state"]="not_established";omitted["criteria"][0]["missing_evidence"]=[omitted["criteria"][0]["required_evidence_class"]]
    with pytest.raises(ProvanError) as eligible:validate_settlement_serialized(canonical_bytes(omitted),contract_raw,freeze_raw,now=FIXED)
    assert eligible.value.code=="SETTLEMENT_ELIGIBLE_EVIDENCE_MISMATCH"


def test_schema_valid_python_invalid_closure():
    value={"schema_id":"provan.closure_requirement.v1","artifact_id":"00000000-0000-4000-8000-000000000001","closure_requirement_id":"00000000-0000-4000-8000-000000000002","version":1,"criterion_ref":"c","required_evidence_class":"source_verified","check_mode":"source_only","check":{"type":"source_contract_present","pattern":"anything"},"subject_refs":["x"],"protected_invariant_refs":[],"limitations":[]}
    with pytest.raises(ProvanError) as exc:validate_closure_requirement_serialized(canonical_bytes(value))
    assert exc.value.code=="CLOSURE_SOURCE_CHECK_UNSUPPORTED"


def test_protected_invariant_freeform_evaluator_rejected():
    value={"schema_id":"provan.protected_invariant.v1","artifact_id":"00000000-0000-4000-8000-000000000001","protected_invariant_id":"p","version":1,"statement":"p","scope":"candidate","authority":{},"source_refs":[],"required_evidence_class":"source_verified","check_mode":"source_only","check":{"type":"artifact_exists","path":"x","command":"run"},"prohibited_actions":[],"closure_requirement_refs":[],"limitations":[],"sensitivity":"PUBLIC_SAFE"}
    with pytest.raises(ProvanError) as exc:validate_protected_invariant_serialized(canonical_bytes(value))
    assert exc.value.code=="PROTECTED_INVARIANT_FREEFORM_EVALUATOR_FORBIDDEN"


def test_conditional_activation_mismatch_fails(patient):
    freeze=patient["freeze"].copy();freeze["conditional_activation"]=[{"criterion_ref":"x","state":"active"}];raw=canonical_bytes(freeze);contract_raw=secure_read(Path("outputs/acceptance/contracts")/f"{patient['contract']['contract_id']}.json")
    with pytest.raises(ProvanError) as exc:validate_freeze_serialized(raw,contract_raw)
    assert exc.value.code=="CONDITIONAL_ACTIVATION_BINDING_MISMATCH"


def test_imported_file_cannot_self_declare_authority(patient,tmp_path):
    fake=canonical_bytes({"schema_id":"fake","evidence_class":"source_verified","state":"PASS","producer":"self-qualified"});att=attest(patient["freeze"]["freeze_id"],[('fake.json',fake)],now=FIXED);settlement=json.loads(secure_read(Path("outputs/acceptance/settlements")/f"{att['settlement_ref']['id']}.json"));assert settlement["criteria"][0]["supporting_ineligible_evidence"][0]["evidence_class"]=="imported_unverified"


def test_reinspection_aggregate_precedence():
    assert derive_reinspection_overall([{"status":"closed"},{"status":"open"}],[])=="partially_closed"
    assert derive_reinspection_overall([{"status":"unable_to_establish"}],[])=="unable_to_establish"
    assert derive_reinspection_overall([{"status":"closed"}],[{"status":"open"}])=="partially_closed"
    assert derive_reinspection_overall([{"status":"closed"}],[{"status":"disputed"}])=="disputed"


def test_disputed_settlement_is_exact_conflicting_eligible_evidence_rule():
    support={"predicate_result":"supports","evidence_class":"source_verified"}
    falsify={"predicate_result":"falsifies","evidence_class":"source_verified"}
    assert derive_evidence_state([support])=="established"
    assert derive_evidence_state([falsify])=="falsified"
    assert derive_evidence_state([support,falsify])=="disputed"
    assert derive_evidence_state([])=="not_established"


@pytest.mark.parametrize("fixture_class",PROOF_RUNTIME_CLASSES if 'PROOF_RUNTIME_CLASSES' in globals() else ("valid","near-valid","adversarial"))
def test_proof_disputed_derivation_layers(fixture_class):
    support={"predicate_result":"supports","evidence_class":"source_verified"}
    falsify={"predicate_result":"falsifies","evidence_class":"source_verified"}
    if fixture_class=="valid":assert derive_evidence_state([support,falsify])=="disputed"
    elif fixture_class=="near-valid":assert derive_evidence_state([support])=="established"
    else:
        owner_disagreement={"decision":"reject","predicate_result":"owner_disagreement"}
        assert derive_evidence_state([support,owner_disagreement])=="established"


def test_pr_synthetic_merge_metadata_is_not_candidate_history(tmp_path):
    repo=tmp_path/"repo";repo.mkdir();git(repo,"init");(repo/"a.txt").write_text("base\n");base=commit(repo,"base");git(repo,"checkout","-b","candidate");(repo/"a.txt").write_text("candidate\n");candidate=commit(repo,"candidate");git(repo,"checkout","-b","main",base)
    synthetic_email="synthetic"+"@"+"example.com";env={"GIT_AUTHOR_NAME":"GitHub","GIT_AUTHOR_EMAIL":synthetic_email,"GIT_COMMITTER_NAME":"GitHub","GIT_COMMITTER_EMAIL":synthetic_email};git(repo,"merge","--no-ff","candidate","-m","synthetic merge",env=env);merge=git(repo,"rev-parse","HEAD")
    validate_candidate_surfaces(repo,history_base=base,history_head=candidate,integration_head=merge)
    with pytest.raises(ProvanError):validate_candidate_surfaces(repo,history_base=base,history_head=merge,integration_head=merge)


def test_superseding_contract_requires_new_freeze(patient):
    terms={"criteria":[patient_criterion()],"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}}
    successor=new_contract(patient,terms,supersedes=patient["contract"]["contract_id"])
    assert successor["version"]==2 and successor["supersedes"]["id"]==patient["contract"]["contract_id"]
    with pytest.raises(ProvanError) as exc:validate_freeze_serialized(canonical_bytes(patient["freeze"]),canonical_bytes(successor))
    assert exc.value.code=="CONTRACT_FREEZE_BINDING_MISMATCH"


def test_conditional_activation_states_and_clearance_ceiling(patient):
    active=patient_criterion(criterion_id="conditional.present",**{"class":"conditional","activation_rule":{"type":"source_artifact_exists","path":"patient/public-contract.json"},"activation_provenance":{"authority":"source_verified","source_refs":["candidate-tree"]}})
    unresolved=patient_criterion(criterion_id="conditional.operator",**{"class":"conditional","activation_rule":{"type":"operator_confirmation"},"activation_provenance":{"authority":"unresolved","source_refs":[]}})
    contract=new_contract(patient,{"criteria":[active,unresolved],"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}});freeze=freeze_contract(contract["contract_id"],str(patient["repo"]),now=FIXED)
    assert {r["criterion_ref"]:r["state"] for r in freeze["conditional_activation"]}=={"conditional.present":"active","conditional.operator":"unresolved"}
    att=attest(freeze["freeze_id"],[],now=FIXED);assert att["recommendation"]=="held"


def test_expiry_is_computed_with_injectable_clock(patient):
    assert effective_status("2026-08-10T11:59:59Z",FIXED)=="expired"
    assert effective_status("2026-08-10T12:00:01Z",FIXED)=="active"
    contract=new_contract(patient,{"criteria":[patient_criterion()],"expires_at":"2026-08-10T11:59:59Z","challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}});freeze=freeze_contract(contract["contract_id"],str(patient["repo"]),now=FIXED);att=attest(freeze["freeze_id"],[],now=FIXED)
    record_id,text=render_record(att["attestation_id"],None,"json",now=FIXED)
    assert record_id.startswith("sha256:") and json.loads(text)["effective_status"]=="expired"


def test_attestation_schema_valid_semantic_chain_mismatch(patient):
    att=copy.deepcopy(patient["attestation"]);att["recommendation"]="cleared"
    schema=json.loads((Path(__file__).parents[1]/"provan/schemas/acceptance-attestation.v1.json").read_text(encoding="utf-8"));jsonschema.validate(att,schema)
    contract_raw=canonical_bytes(patient["contract"])
    settlement_raw=secure_read(Path("outputs/acceptance/settlements")/f"{patient['attestation']['settlement_ref']['id']}.json")
    with pytest.raises(ProvanError) as exc:validate_attestation_serialized(canonical_bytes(att),contract_raw,canonical_bytes(patient["freeze"]),settlement_raw,now=FIXED)
    assert exc.value.code=="ATTESTATION_RECOMMENDATION_MISMATCH"


def test_human_confirmation_not_satisfied_by_arbitrary_text(patient):
    criterion=patient_criterion(criterion_id="human.confirmation",required_evidence_classes=["owner_confirmed"],closure_requirement={"check_mode":"human_confirmation","required_evidence_class":"owner_confirmed","check":{"type":"canonical_case_operator_action"}})
    contract=new_contract(patient,{"criteria":[criterion],"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}});freeze=freeze_contract(contract["contract_id"],str(patient["repo"]),now=FIXED)
    att=attest(freeze["freeze_id"],[('claim.txt',b'owner_confirmed: true')],now=FIXED);settlement=json.loads(secure_read(Path("outputs/acceptance/settlements")/f"{att['settlement_ref']['id']}.json"))
    assert settlement["criteria"][0]["state"]=="not_established" and att["evidence_refs"]["operator"]==[]


def test_protected_invariant_failure_prevents_closure(patient):
    invariant={"protected_invariant_id":"patient.required-marker.v1","statement":"Required marker remains present.","authority":{"class":"source_verified","source_refs":["contract"]},"source_refs":["contract"],"check_mode":"source_only","check":{"type":"artifact_exists","path":"patient/required-marker.txt"}}
    criterion=patient_criterion();criterion["closure_requirement"]["protected_invariant_ids"]=["patient.required-marker.v1"]
    contract=new_contract(patient,{"criteria":[criterion],"protected_invariants":[invariant],"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}});freeze=freeze_contract(contract["contract_id"],str(patient["repo"]),now=FIXED);att=attest(freeze["freeze_id"],[],now=FIXED);record_id,_=render_record(att["attestation_id"],None,"json")
    (patient["repo"]/"patient/public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"available"}}\n',encoding="utf-8");later=commit(patient["repo"],"criterion only")
    result=reinspect(record_id,str(patient["repo"]),later,None,now=FIXED);assert result["overall_status"]!="closed" and result["protected_invariant_results"][0]["status"]=="open"


def test_static_python_export_check_does_not_execute(patient):
    criterion=patient_criterion(criterion_id="python.export",closure_requirement={"check_mode":"source_only","required_evidence_class":"source_verified","check":{"type":"python_public_export_exists","path":"patient/export.py","symbol":"public_api"}})
    contract=new_contract(patient,{"criteria":[criterion],"challenge_budget":{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0}});freeze=freeze_contract(contract["contract_id"],str(patient["repo"]),now=FIXED);att=attest(freeze["freeze_id"],[],now=FIXED);record_id,_=render_record(att["attestation_id"],None,"json")
    (patient["repo"]/"patient/export.py").write_text("raise RuntimeError('must not execute')\n__all__ = ['public_api']\ndef public_api(): pass\n",encoding="utf-8");later=commit(patient["repo"],"static export")
    assert reinspect(record_id,str(patient["repo"]),later,None,now=FIXED)["overall_status"]=="closed"


def test_real_candidate_history_leakage_still_rejects(tmp_path):
    repo=tmp_path/"real-history";repo.mkdir();git(repo,"init");(repo/"a").write_text("base");base=commit(repo,"base");(repo/"a").write_text("candidate")
    private_email="private"+"@"+"example.com";env={"GIT_AUTHOR_NAME":"Fixture","GIT_AUTHOR_EMAIL":private_email,"GIT_COMMITTER_NAME":"Fixture","GIT_COMMITTER_EMAIL":private_email};git(repo,"add","-A",env=env);git(repo,"commit","-m","candidate",env=env);head=git(repo,"rev-parse","HEAD")
    with pytest.raises(ProvanError):validate_candidate_surfaces(repo,history_base=base,history_head=head,integration_head=head)


def test_session11_public_artifact_scan_includes_untracked_absolute_paths(tmp_path,monkeypatch):
    import scripts.validate_session11 as gate
    root=tmp_path;artifact=root/"artifacts/session11/proposed.json";artifact.parent.mkdir(parents=True)
    adversarial_path=str(Path.home()/"private")
    artifact.write_text(json.dumps({"path":adversarial_path}),encoding="utf-8")
    monkeypatch.setattr(gate,"ROOT",root)
    with pytest.raises(SystemExit) as exc:gate.validate_public_artifact_safety()
    assert str(exc.value)=="SESSION11_PUBLIC_PROOF_ABSOLUTE_USER_PATH_LEAK"


def test_session11_validator_direct_invocation_imports_runtime():
    root=Path(__file__).resolve().parents[1]
    result=subprocess.run([os.sys.executable,"scripts/validate_session11.py","--help"],cwd=root,capture_output=True,text=True,encoding="utf-8")
    assert result.returncode==0 and "--phase" in result.stdout


PROOF_CLASSES=("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")
PROOF_RUNTIME_CLASSES=("valid","near-valid","adversarial")

def assert_schema_invalid(value,schema):
    with pytest.raises(jsonschema.ValidationError) as caught:jsonschema.validate(value,schema)
    path="/"+"/".join(str(part) for part in caught.value.absolute_path)
    print(f"PROOF_SCHEMA_ERROR:{caught.value.message}:path={path}")


def contract_dependencies(contract):
    closures={ref["id"]:secure_read(Path("outputs/acceptance/closure-requirements")/f"{ref['id']}.json") for ref in contract["closure_requirement_refs"]}
    invariants={ref["id"]:secure_read(Path("outputs/acceptance/protected-invariants")/f"{ref['id']}.json") for ref in contract["protected_invariant_refs"]}
    return closures,invariants


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_contract_layers(patient,fixture_class):
    value=copy.deepcopy(patient["contract"]);closures,invariants=contract_dependencies(value);schema=json.loads((Path(__file__).parents[1]/"provan/schemas/acceptance-contract.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="near-valid":value["risk"]["tier"]={"value":"unresolved","authority":"unresolved","provenance_refs":[value["disposition_refs"][0]["id"]]}
    elif fixture_class=="adversarial":value["candidate"]["mode"]="mutable"
    elif fixture_class=="schema-invalid":del value["execution_policy"]
    elif fixture_class=="schema-valid-python-invalid":value["challenge_policy"]["challenge_budget"]["max_instances"]=1
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_contract_serialized(canonical_bytes(value),closures,invariants)
            assert exc.value.code==("CONTRACT_CANDIDATE_NOT_IMMUTABLE" if fixture_class=="adversarial" else "CHALLENGE_NOT_REQUIRED_CAP_NONZERO")
        else:validate_contract_serialized(canonical_bytes(value),closures,invariants)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_freeze_layers(patient,fixture_class):
    value=copy.deepcopy(patient["freeze"]);schema=json.loads((Path(__file__).parents[1]/"provan/schemas/candidate-freeze.v1.json").read_text(encoding="utf-8"));contract_raw=canonical_bytes(patient["contract"])
    if fixture_class=="near-valid":value["limitations"]=["BOUNDED_STATIC_ANALYSIS_NONCOVERAGE"]
    elif fixture_class=="adversarial":value["repository_identity"]="https://github.com/example/different"
    elif fixture_class=="schema-invalid":del value["head"]
    elif fixture_class=="schema-valid-python-invalid":value["conditional_activation"]=[{"criterion_ref":"invented","state":"active","basis":"invented","evidence_refs":[],"reason_code":"INVENTED"}]
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_freeze_serialized(canonical_bytes(value),contract_raw)
            assert exc.value.code==("CANDIDATE_CONTRACT_MISMATCH" if fixture_class=="adversarial" else "CONDITIONAL_ACTIVATION_BINDING_MISMATCH")
        else:validate_freeze_serialized(canonical_bytes(value),contract_raw)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_closure_layers(patient,fixture_class):
    ref=patient["contract"]["closure_requirement_refs"][0];value=json.loads(secure_read(Path("outputs/acceptance/closure-requirements")/f"{ref['id']}.json"));schema=json.loads((Path(__file__).parents[1]/"provan/schemas/closure-requirement.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="near-valid":value["summary"]="Exact bounded source predicate."
    elif fixture_class=="adversarial":value["check"]={"type":"source_contract_present","pattern":"PASS"}
    elif fixture_class=="schema-invalid":del value["check"]
    elif fixture_class=="schema-valid-python-invalid":value["check"]={"type":"artifact_exists","path":"../escape"}
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_closure_requirement_serialized(canonical_bytes(value))
            assert exc.value.code==("CLOSURE_SOURCE_CHECK_UNSUPPORTED" if fixture_class=="adversarial" else "CLOSURE_SOURCE_PATH_UNSAFE")
        else:validate_closure_requirement_serialized(canonical_bytes(value))


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_attestation_layers(patient,fixture_class):
    value=copy.deepcopy(patient["attestation"]);schema=json.loads((Path(__file__).parents[1]/"provan/schemas/acceptance-attestation.v1.json").read_text(encoding="utf-8"));contract_raw=canonical_bytes(patient["contract"]);freeze_raw=canonical_bytes(patient["freeze"]);settlement_raw=secure_read(Path("outputs/acceptance/settlements")/f"{value['settlement_ref']['id']}.json")
    if fixture_class=="near-valid":value["created_at"]="2026-08-11T12:00:00+00:00"
    elif fixture_class=="adversarial":value["verifier_state"]["execution"]="executed"
    elif fixture_class=="schema-invalid":del value["subject"]
    elif fixture_class=="schema-valid-python-invalid":value["recommendation"]="cleared"
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_attestation_serialized(canonical_bytes(value),contract_raw,freeze_raw,settlement_raw,now=FIXED)
            assert exc.value.code==("SESSION11_EXECUTION_STATE_FABRICATED" if fixture_class=="adversarial" else "ATTESTATION_RECOMMENDATION_MISMATCH")
        else:validate_attestation_serialized(canonical_bytes(value),contract_raw,freeze_raw,settlement_raw,now=FIXED)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_reinspection_layers(patient,fixture_class):
    record_id,_=render_record(patient["attestation"]["attestation_id"],None,"json");repo=patient["repo"];(repo/"patient/public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"available"}}\n',encoding="utf-8");later=commit(repo,"proof later candidate");value=reinspect(record_id,str(repo),later,None,now=FIXED)
    schema=json.loads((Path(__file__).parents[1]/"provan/schemas/reinspection-record.v1.json").read_text(encoding="utf-8"));att_raw=canonical_bytes(patient["attestation"]);contract_raw=canonical_bytes(patient["contract"]);original_raw=canonical_bytes(patient["freeze"]);later_raw=secure_read(Path("outputs/acceptance/freezes")/f"{value['later_freeze_ref']['id']}.json");settlement_raw=secure_read(Path("outputs/acceptance/settlements")/f"{patient['attestation']['settlement_ref']['id']}.json")
    if fixture_class=="near-valid":value["external_change_receipt_ref"]=None
    elif fixture_class=="adversarial":value["items"]=[{"criterion_ref":"invented.omission","closure_requirement_ref":value["items"][0]["closure_requirement_ref"],"status":"closed","material":True,"reason_code":"INVENTED_SUBSET"}]
    elif fixture_class=="schema-invalid":del value["overall_status"]
    elif fixture_class=="schema-valid-python-invalid":value["overall_status"]="open"
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        kwargs={"attestation_raw":att_raw,"contract_raw":contract_raw,"original_freeze_raw":original_raw,"later_freeze_raw":later_raw,"settlement_raw":settlement_raw}
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_reinspection_serialized(canonical_bytes(value),**kwargs)
            assert exc.value.code==("REINSPECTION_MATERIAL_REQUIREMENT_SET_MISMATCH" if fixture_class=="adversarial" else "REINSPECTION_AGGREGATE_STATUS_INVALID")
        else:validate_reinspection_serialized(canonical_bytes(value),**kwargs)


@pytest.mark.parametrize("fixture_class",PROOF_RUNTIME_CLASSES)
def test_proof_pr_history_layers(tmp_path,fixture_class):
    repo=tmp_path/fixture_class;repo.mkdir();git(repo,"init");(repo/"a").write_text("base");base=commit(repo,"base");(repo/"a").write_text("candidate")
    email="private"+"@"+"example.com" if fixture_class=="adversarial" else "noreply"
    env={"GIT_AUTHOR_NAME":"Fixture","GIT_AUTHOR_EMAIL":email,"GIT_COMMITTER_NAME":"Fixture","GIT_COMMITTER_EMAIL":email};git(repo,"add","-A",env=env);git(repo,"commit","-m","candidate",env=env);head=git(repo,"rev-parse","HEAD");integration=head
    if fixture_class=="valid":
        git(repo,"checkout","-b","integration",base);synthetic_email="synthetic"+"@"+"example.com";merge_env={"GIT_AUTHOR_NAME":"GitHub","GIT_AUTHOR_EMAIL":synthetic_email,"GIT_COMMITTER_NAME":"GitHub","GIT_COMMITTER_EMAIL":synthetic_email};git(repo,"merge","--no-ff",head,"-m","synthetic merge",env=merge_env);integration=git(repo,"rev-parse","HEAD")
    if fixture_class=="adversarial":
        with pytest.raises(ProvanError):validate_candidate_surfaces(repo,history_base=base,history_head=head,integration_head=integration)
    else:validate_candidate_surfaces(repo,history_base=base,history_head=head,integration_head=integration)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_settlement_layers(patient,fixture_class):
    att=patient["attestation"]
    if fixture_class=="near-valid":att=attest(patient["freeze"]["freeze_id"],[('support.json',canonical_bytes({"state":"PASS"}))],now=FIXED)
    value=json.loads(secure_read(Path("outputs/acceptance/settlements")/f"{att['settlement_ref']['id']}.json"));schema=json.loads((Path(__file__).parents[1]/"provan/schemas/evidence-settlement.v1.json").read_text(encoding="utf-8"));contract_raw=canonical_bytes(patient["contract"]);freeze_raw=canonical_bytes(patient["freeze"])
    if fixture_class=="adversarial":
        source=value["criteria"][0]["eligible_evidence"][0].copy();source["evidence_id"]="sha256:"+"1"*64;value["criteria"][0]["eligible_evidence"]=[source]
    elif fixture_class=="schema-invalid":del value["recommendation"]
    elif fixture_class=="schema-valid-python-invalid":value["criteria"][0]["state"]="established"
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_settlement_serialized(canonical_bytes(value),contract_raw,freeze_raw,now=FIXED)
            assert exc.value.code==("EVIDENCE_AUTHORITY_PROVENANCE_INVALID" if fixture_class=="adversarial" else "EVIDENCE_SETTLEMENT_STATE_INVALID")
        else:validate_settlement_serialized(canonical_bytes(value),contract_raw,freeze_raw,now=FIXED)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_owner_decision_layers(patient,fixture_class):
    base=decide(patient["attestation"]["attestation_id"],{"decision":"hold","rationale":"bounded"},"operator",now=FIXED);value=copy.deepcopy(base);schema=json.loads((Path(__file__).parents[1]/"provan/schemas/owner-decision.v1.json").read_text(encoding="utf-8"));att_raw=canonical_bytes(patient["attestation"])
    if fixture_class=="near-valid":value["decision"]="override_accept_risk"
    elif fixture_class=="adversarial":value["decision"]="accept"
    elif fixture_class=="schema-invalid":del value["actor"]
    elif fixture_class=="schema-valid-python-invalid":value["provan_recommendation"]="cleared"
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_owner_decision_serialized(canonical_bytes(value),att_raw)
            assert exc.value.code=="OWNER_DECISION_INCOMPATIBLE"
        else:validate_owner_decision_serialized(canonical_bytes(value),att_raw)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_protected_invariant_layers(fixture_class):
    value={"schema_id":"provan.protected_invariant.v1","artifact_id":"00000000-0000-4000-8000-000000000001","protected_invariant_id":"patient.invariant.v1","version":1,"statement":"A bounded invariant.","scope":"candidate","authority":{"class":"source_verified","source_refs":["contract"]},"source_refs":["contract"],"required_evidence_class":"source_verified","check_mode":"source_only","check":{"type":"artifact_exists","path":"patient/marker"},"prohibited_actions":["target_execution"],"closure_requirement_refs":[],"limitations":[],"sensitivity":"PUBLIC_SAFE"};schema=json.loads((Path(__file__).parents[1]/"provan/schemas/protected-invariant.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="near-valid":value["limitations"]=["SOURCE_ONLY"]
    elif fixture_class=="adversarial":value["check"]["callable"]="run_target"
    elif fixture_class=="schema-invalid":del value["statement"]
    elif fixture_class=="schema-valid-python-invalid":value["check"]={"type":"protected_invariant_satisfied","protected_invariant_ref":{"id":"self","sha256":"sha256:"+"0"*64}}
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_protected_invariant_serialized(canonical_bytes(value))
            assert exc.value.code==("PROTECTED_INVARIANT_FREEFORM_EVALUATOR_FORBIDDEN" if fixture_class=="adversarial" else "PROTECTED_INVARIANT_CHECK_UNSUPPORTED")
        else:validate_protected_invariant_serialized(canonical_bytes(value))


@pytest.mark.parametrize("fixture_class",PROOF_RUNTIME_CLASSES)
def test_proof_record_projection_layers(patient,fixture_class):
    record_id,_=render_record(patient["attestation"]["attestation_id"],None,"json")
    if fixture_class=="valid":
        assert {render_record(patient["attestation"]["attestation_id"],None,fmt)[0] for fmt in ("json","markdown","html","terminal")}=={record_id}
    elif fixture_class=="near-valid":assert record_id.startswith("sha256:")
    else:
        root=Path(os.environ["PROVAN_HOME"])/"outputs/acceptance/records"/record_id.removeprefix("sha256:");(root/"record.markdown").write_text("tampered",encoding="utf-8")
        with pytest.raises(ProvanError):reinspect(record_id,str(patient["repo"]),patient["original"],None,now=FIXED)


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
def test_proof_session12_handoff_layers(fixture_class):
    names=["brief","preparation","disposition","contract","closure","freeze","work-order","capability","verification","environment","command","settlement","attestation","reinspection","matrix","schema","proof-evidence"]
    artifacts={f"artifacts/{name}.json":canonical_bytes({"artifact":name}) for name in names};refs={name:{"path":f"artifacts/{name}.json","sha256":sha256_bytes(artifacts[f"artifacts/{name}.json"])} for name in names}
    closure_ref={"id":"closure-1",**refs["closure"]};artifacts["artifacts/contract.json"]=canonical_bytes({"artifact":"contract","closure_requirement_refs":[{"id":"closure-1","sha256":closure_ref["sha256"]}]});refs["contract"]["sha256"]=sha256_bytes(artifacts["artifacts/contract.json"])
    evidence_entries=[refs["proof-evidence"]];artifacts["artifacts/proof-manifest.json"]=canonical_bytes({"entries":evidence_entries,"proof_root":sha256_bytes(canonical_bytes(evidence_entries))});proof_manifest={"path":"artifacts/proof-manifest.json","sha256":sha256_bytes(artifacts["artifacts/proof-manifest.json"])}
    value={"schema_id":"provan.session12_handoff.v1","candidate":{"repository_identity":"https://github.com/example/repo","mode":"immutable","base":"1"*40,"head":"2"*40,"candidate_digest":"sha256:"+"3"*64},"brief":refs["brief"],"preparation":refs["preparation"],"seed_dispositions":[refs["disposition"]],"acceptance_contract":refs["contract"],"candidate_freeze":refs["freeze"],"closure_requirements":[closure_ref],"verifier_contracts":[refs[name] for name in ("work-order","capability","verification")],"receipt_contracts":[refs["environment"],refs["command"]],"evidence_policy":{"target_access":"read_only","execution_available":False,"challenge_available":False},"protected_invariants":[],"evidence_settlement":refs["settlement"],"attestation":refs["attestation"],"projection_rules":{"internal":"LOCAL_NON_PUBLIC","client_safe":"DETERMINISTICALLY_SANITISED","record_locator":"RESOLVE_CANONICAL_CHAIN_NOT_RENDERED_PROSE"},"reinspection":refs["reinspection"],"limitations":["SESSION12_EXECUTION_NOT_IMPLEMENTED"],"session12_prerequisites":["qualified sandbox","qualified producer","environment authority","command authority","read-only capability"],"layer4_matrix":refs["matrix"],"proof_manifest":proof_manifest,"proof_root":sha256_bytes(canonical_bytes(evidence_entries)),"reviewer_receipts":[],"implementation_binding":{"implementation_commit":"5"*40,"implementation_tree":"6"*40,"package_version":"0.4.0","wheel_sha256":"sha256:"+"7"*64,"schema_registry_digest":"sha256:"+"8"*64,"maturity":"QUALIFIED_BOUNDED","published":False,"extension_api_major":1},"schema_registry":refs["schema"],"claim_registry_digest":"sha256:"+"9"*64}
    schema=json.loads((Path(__file__).parents[1]/"provan/schemas/session12-handoff.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="near-valid":value["limitations"].append("CHALLENGE_NOT_IMPLEMENTED")
    elif fixture_class=="adversarial":value["verifier_contracts"][1]=value["verifier_contracts"][0]
    elif fixture_class=="schema-invalid":del value["candidate_freeze"]
    elif fixture_class=="schema-valid-python-invalid":value["projection_rules"]["record_locator"]="TRUST_RENDERED_PROSE"
    if fixture_class=="schema-invalid":
        assert_schema_invalid(value,schema)
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError) as exc:validate_session12_handoff_serialized(canonical_bytes(value),artifacts)
            assert exc.value.code==("SESSION12_HANDOFF_DUPLICATE_ARTIFACT_REF" if fixture_class=="adversarial" else "SESSION12_HANDOFF_PROJECTION_RULES_INVALID")
        else:validate_session12_handoff_serialized(canonical_bytes(value),artifacts)


SUPPORT_CONTRACTS={
    "work-order":("verifier-work-order.v1.json",validate_verifier_work_order_serialized,{"schema_id":"provan.verifier_work_order.v1","work_order_id":"00000000-0000-4000-8000-000000000101","contract_ref":{"id":"contract","sha256":"sha256:"+"1"*64},"freeze_ref":{"id":"freeze","sha256":"sha256:"+"2"*64},"criterion_refs":["criterion"],"protected_invariant_refs":[],"required_evidence_class":"source_verified","requested_capabilities":["verifier_runtime"],"target_policy":"read_only","network_policy":"none","allowed_tool_classes":[],"prohibited_actions":["target_mutation","target_execution","remediation","deployment"],"environment_requirements":[],"completion_requirements":[{"id":"closure","sha256":"sha256:"+"3"*64}],"remediation_allowed":False}),
    "capability":("verifier-capability-request.v1.json",validate_verifier_capability_request_serialized,{"schema_id":"provan.verifier_capability_request.v1","request_id":"00000000-0000-4000-8000-000000000102","work_order_ref":{"id":"work","sha256":"sha256:"+"4"*64},"capability":"verifier_runtime","state":"unavailable","reason_code":"CAPABILITY_UNAVAILABLE"}),
    "verification":("verification-result.v1.json",validate_verification_result_serialized,{"schema_id":"provan.verification_result.v1","result_id":"00000000-0000-4000-8000-000000000103","work_order_ref":{"id":"work","sha256":"sha256:"+"4"*64},"criterion_ref":"criterion","state":"not_run","evidence_refs":[]}),
    "environment":("environment-receipt.v1.json",validate_environment_receipt_serialized,{"schema_id":"provan.environment_receipt.v1","receipt_id":"00000000-0000-4000-8000-000000000104","producer":{},"candidate_ref":{"id":"freeze","sha256":"sha256:"+"2"*64},"state":"not_run","qualified":False,"details":{}}),
    "command":("command-receipt.v1.json",validate_command_receipt_serialized,{"schema_id":"provan.command_receipt.v1","receipt_id":"00000000-0000-4000-8000-000000000105","producer":{},"candidate_ref":{"id":"freeze","sha256":"sha256:"+"2"*64},"command_class":"future_verifier","state":"not_run","executed":False,"details":{}}),
    "external":("external-change-receipt.v1.json",validate_external_change_receipt_serialized,{"schema_id":"provan.external_change_receipt.v1","receipt_id":"00000000-0000-4000-8000-000000000106","repository_identity":"https://github.com/example/repo","original_head":"1"*40,"claimed_later_head":"2"*40,"claims":[],"provenance":{"establishes_closure":False}}),
}


@pytest.mark.parametrize("fixture_class",PROOF_CLASSES)
@pytest.mark.parametrize("contract_kind",sorted(SUPPORT_CONTRACTS))
def test_proof_support_contract_layers(contract_kind,fixture_class):
    schema_name,validator,base=SUPPORT_CONTRACTS[contract_kind];value=copy.deepcopy(base);schema=json.loads((Path(__file__).parents[1]/"provan/schemas"/schema_name).read_text(encoding="utf-8"))
    if fixture_class=="near-valid":value[next(key for key in value if key.endswith("_id"))]=str(value[next(key for key in value if key.endswith("_id"))])
    elif fixture_class=="schema-invalid":del value["schema_id"]
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:
        if contract_kind=="work-order":value["prohibited_actions"]=[]
        elif contract_kind=="capability":value["reason_code"]="INVENTED"
        elif contract_kind=="verification":value["state"]="passed";value["evidence_refs"]=[]
        elif contract_kind=="environment":value["state"]="qualified";value["qualified"]=True
        elif contract_kind=="command":value["state"]="passed";value["executed"]=True
        else:value["provenance"]["establishes_closure"]=True
    if fixture_class=="schema-invalid":assert_schema_invalid(value,schema);return
    jsonschema.validate(value,schema)
    if fixture_class in {"adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError):validator(canonical_bytes(value))
    else:validator(canonical_bytes(value))


@pytest.mark.parametrize("fixture_class",PROOF_RUNTIME_CLASSES)
def test_proof_semantic_validator_coverage(fixture_class):
    required={"provan.seed_disposition.v1","provan.acceptance_contract.v1","provan.closure_requirement.v1","provan.protected_invariant.v1","provan.candidate_freeze.v1","provan.verifier_work_order.v1","provan.verifier_capability_request.v1","provan.verification_result.v1","provan.environment_receipt.v1","provan.command_receipt.v1","provan.evidence_settlement.v1","provan.acceptance_attestation.v1","provan.owner_decision.v1","provan.external_change_receipt.v1","provan.reinspection_record.v1","provan.session12_handoff.v1"}
    if fixture_class=="valid":assert set(SEMANTIC_VALIDATORS)==required
    elif fixture_class=="near-valid":assert all(callable(value) for value in SEMANTIC_VALIDATORS.values())
    else:
        incomplete=dict(SEMANTIC_VALIDATORS);incomplete.pop("provan.command_receipt.v1")
        assert set(incomplete)!=required


def test_contract_rejects_invented_risk_authority(patient):
    value=copy.deepcopy(patient["contract"]);value["risk"]["tier"]={"value":"high","authority":"owner_confirmed","provenance_refs":["invented"]}
    closures={ref["id"]:secure_read(Path("outputs/acceptance/closure-requirements")/f"{ref['id']}.json") for ref in value["closure_requirement_refs"]};invariants={ref["id"]:secure_read(Path("outputs/acceptance/protected-invariants")/f"{ref['id']}.json") for ref in value["protected_invariant_refs"]}
    with pytest.raises(ProvanError) as exc:validate_contract_serialized(canonical_bytes(value),closures,invariants)
    assert exc.value.code=="RISK_AUTHORITY_INVALID"


def test_freeze_rejects_coordinated_analysis_digest_mutation(patient):
    value=copy.deepcopy(patient["freeze"]);value["workspace_digest"]="sha256:"+"f"*64
    with pytest.raises(ProvanError) as exc:validate_freeze_serialized(canonical_bytes(value),canonical_bytes(patient["contract"]))
    assert exc.value.code=="CANDIDATE_FREEZE_ANALYSIS_DIGEST_MISMATCH"


def test_attestation_rejects_fake_evidence_and_policy(patient):
    value=copy.deepcopy(patient["attestation"]);value["evidence_refs"]["source"]=["sha256:"+"f"*64];value["builder_provenance"]["policy_id"]="invented"
    settlement_raw=secure_read(Path("outputs/acceptance/settlements")/f"{value['settlement_ref']['id']}.json")
    with pytest.raises(ProvanError) as exc:validate_attestation_serialized(canonical_bytes(value),canonical_bytes(patient["contract"]),canonical_bytes(patient["freeze"]),settlement_raw,now=FIXED)
    assert exc.value.code in {"ATTESTATION_BUILDER_PROVENANCE_MISMATCH","ATTESTATION_EVIDENCE_BINDING_MISMATCH"}


def test_reinspection_rejects_coordinated_item_and_aggregate_mutation(patient):
    record_id,_=render_record(patient["attestation"]["attestation_id"],None,"json");repo=patient["repo"]
    (repo/"patient/public-contract.json").write_text('{"schema_version":1,"capabilities":{"acceptance_record":"available"}}\n',encoding="utf-8");later=commit(repo,"validator later")
    value=reinspect(record_id,str(repo),later,None,now=FIXED);value["items"][0]["status"]="open";value["overall_status"]="open"
    later_raw=secure_read(Path("outputs/acceptance/freezes")/f"{value['later_freeze_ref']['id']}.json");settlement_raw=secure_read(Path("outputs/acceptance/settlements")/f"{patient['attestation']['settlement_ref']['id']}.json")
    with pytest.raises(ProvanError) as exc:validate_reinspection_serialized(canonical_bytes(value),attestation_raw=canonical_bytes(patient["attestation"]),contract_raw=canonical_bytes(patient["contract"]),original_freeze_raw=canonical_bytes(patient["freeze"]),later_freeze_raw=later_raw,settlement_raw=settlement_raw)
    assert exc.value.code=="REINSPECTION_ITEM_RESULT_MISMATCH"
