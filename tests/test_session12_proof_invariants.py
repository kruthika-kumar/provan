from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from provan.canonical import canonical_bytes,sha256_bytes
from provan.errors import ProvanError
from provan.foundry import foundry
from provan.session12_validators import (validate_adjudication_projection_serialized,
    validate_claim_registry_serialized,validate_pattern_library_serialized,
    validate_model_egress_allowlist_serialized,validate_run_serialized,validate_work_order_serialized)
from provan.state import secure_read,secure_write

ROOT=Path(__file__).parents[1]
CLASSES=("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")
RUN_INVARIANTS=("run_descriptor","readiness_eligibility","stage_order","router","provider_binding","spend_cap","stage_artifacts","pattern_selection","audit_coverage","capability_ceiling")


def _brief()->dict:
    value={"schema_id":"provan.change_brief.v1","brief_id":"21111111-1111-4111-8111-111111111111","case_id":"sha256:"+"2"*64,"candidate":{"repository_identity":"https://github.com/example/proof","mode":"immutable","base":"3"*40,"head":"4"*40,"working_tree_digest":None,"candidate_digest":"sha256:"+"5"*64}}
    secure_write(Path("outputs/change-brief")/value["brief_id"]/"change-brief.json",canonical_bytes(value));return value


def _manifest(tmp_path:Path)->Path:
    (tmp_path/"intent.md").write_text("Preserve a stable public response contract.",encoding="utf-8")
    value={"sources":[{"path":"intent.md","role":"intent"}],"routing_inputs":{"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"}}
    path=tmp_path/"sources.json";path.write_text(json.dumps(value),encoding="utf-8");return path


def _run_bundle(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,near:bool=False):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief();run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),interpretation="clarifying" if near else "faithful",no_model=True)
    root=Path("outputs/contract-foundry")/run["run_id"];projection=secure_read(root/"foundry-acceptance-projection.json");artifacts={run["source_ledger"]["path"]:secure_read(root/run["source_ledger"]["path"])}
    for name,ref in run["stage_artifacts"].items():
        if name!="revisions":artifacts[ref["path"]]=secure_read(root/ref["path"])
    return run,projection,artifacts


def _replace_artifact(run:dict,artifacts:dict,name:str,mutate):
    ref=run["stage_artifacts"][name];value=json.loads(artifacts[ref["path"]]);mutate(value);raw=canonical_bytes(value);artifacts[ref["path"]]=raw;ref["sha256"]=sha256_bytes(raw)


@pytest.mark.parametrize("fixture_class",CLASSES)
@pytest.mark.parametrize("invariant",RUN_INVARIANTS)
def test_proof_session12_run_layers(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,invariant:str,fixture_class:str):
    run,projection,artifacts=_run_bundle(tmp_path,monkeypatch,fixture_class=="near-valid");schema=json.loads((ROOT/"provan/schemas/contract-foundry-run.v1.json").read_text(encoding="utf-8"));value=copy.deepcopy(run);deps=dict(artifacts)
    if fixture_class=="near-valid":
        if invariant=="spend_cap":value["spend"]["spent"]=75
        elif invariant=="stage_order":assert value["stage_execution"][5]["stage"]=="revision" and value["stage_execution"][5]["status"]=="NOT_APPLICABLE"
        elif invariant=="router":assert value["routing_receipt"]["tier"]==0 and value["routing_receipt"]["roles"]==[]
        elif invariant=="provider_binding":assert value["provider_receipts"]==[] and value["routing_receipt"]["tier"]==0
        elif invariant=="stage_artifacts":assert set(value["stage_artifacts"])-{"revisions"}=={"intent","goal_obstacle","pre_mortem","contract_candidate","audit","witnesses","pattern_selection","readiness"}
        elif invariant=="pattern_selection":assert value["pattern_selection"]["execution_implied"] is False
        elif invariant=="audit_coverage":assert json.loads(deps[value["stage_artifacts"]["audit"]["path"]])["finding_coverage"]=={"total":2,"addressed":0,"preserved_unresolved":2}
        elif invariant=="readiness_eligibility":assert value["contract_readiness"]=="READY_WITH_MATERIAL_QUESTIONS" and value["run_eligibility"]=="ELIGIBLE"
        elif invariant=="capability_ceiling":assert value["mode_qualification"]=="IMPLEMENTED_UNQUALIFIED"
        elif invariant=="run_descriptor":value["limitations"].append("NEAR_VALID_ADDITIONAL_LIMITATION")
    elif fixture_class=="schema-invalid":del value["run_id"]
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:
        if invariant=="run_descriptor":value["case_id"]="sha256:"+"9"*64
        elif invariant=="readiness_eligibility":value["contract_readiness"]="READY_FOR_OWNER_CONFIRMATION"
        elif invariant=="stage_order":
            if fixture_class=="adversarial":value["stages"]=list(reversed(value["stages"]))
            else:value["stage_execution"][0]["output_digests"]=["sha256:"+"f"*64]
        elif invariant=="router":
            if fixture_class=="adversarial":value["routing_receipt"]["tier"]=3
            else:value["routing_receipt"]["inputs"]["risk"]="INVALID"
        elif invariant=="provider_binding":value["provider_receipts"]=[{"provider":"openai-responses-primary","origin":"https://example.invalid","model":"gpt-5.6-sol","kind":"configured_provider_unavailable","semantic_qualification":False,"calls":0,"store_requested":False,"provider_retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED"}]
        elif invariant=="spend_cap":
            if fixture_class=="adversarial":value["spend"]["spent"]=76
            else:value["spend"]["reserved"]=1
        elif invariant=="stage_artifacts":_replace_artifact(value,deps,"contract_candidate",lambda row:row.update({"goal_obstacle_ref":{**row["goal_obstacle_ref"],"sha256":"sha256:"+"f"*64}}))
        elif invariant=="pattern_selection":_replace_artifact(value,deps,"pattern_selection",lambda row:row.update({"execution_implied":True}))
        elif invariant=="audit_coverage":_replace_artifact(value,deps,"audit",lambda row:row["finding_coverage"].update({"total":99}))
        elif invariant=="capability_ceiling":value["mode_qualification"]="QUALIFIED_BOUNDED"
    if fixture_class=="schema-invalid":
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        print("PROOF_SCHEMA_ERROR:required-property")
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError):validate_run_serialized(canonical_bytes(value),projection,deps)
        else:validate_run_serialized(canonical_bytes(value),projection,deps)


PUBLIC_CASES={
    "work_order":("artifacts/session12/authority/work_order.v1.public.json","validate_work_order_serialized"),
    "claim_registry":("artifacts/session12/authority/claim_registry.v1.public.json","validate_claim_registry_serialized"),
    "pattern_library":("artifacts/session12/public/verification_pattern_library.v1.public.json","validate_pattern_library_serialized"),
    "adjudication":("artifacts/session12/public/adjudication_projection.v1.public.json","validate_adjudication_projection_serialized"),
    "model_egress":("artifacts/session12/public/model_egress_allowlist.v1.public.json","validate_model_egress_allowlist_serialized"),
}


@pytest.mark.parametrize("fixture_class",CLASSES)
@pytest.mark.parametrize("invariant",tuple(PUBLIC_CASES))
def test_proof_session12_public_contract_layers(invariant:str,fixture_class:str):
    path,validator_name=PUBLIC_CASES[invariant];raw=(ROOT/path).read_bytes();value=json.loads(raw);validator=globals()[validator_name]
    if fixture_class=="near-valid":
        if invariant=="work_order":value.setdefault("limitations",[]).append("NEAR_VALID_ADDITIONAL_LIMITATION")
        elif invariant=="claim_registry":
            number=len(value["claims"])+1;value["claims"].append({"claim_id":f"G12-{number:02d}","normative_claim":"Documented additive near-valid claim."});value["registry_digest"]=sha256_bytes(canonical_bytes(value["claims"]))
        elif invariant=="pattern_library":
            for row in value["patterns"]:row["limitations"].append("NEAR_VALID_ADDITIONAL_LIMITATION")
        elif invariant=="adjudication":
            value.setdefault("limitations",[]).append("NEAR_VALID_ADDITIONAL_LIMITATION");core=dict(value);core.pop("projection_digest",None);value["projection_digest"]=sha256_bytes(canonical_bytes(core))
        elif invariant=="model_egress":value.setdefault("limitations",[]).append("NEAR_VALID_ADDITIONAL_LIMITATION")
    elif fixture_class=="schema-invalid":del value["schema_id"]
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:
        if invariant=="work_order":value["provider_pin"]["tier_2_model"]="dynamic-model"
        elif invariant=="claim_registry":value["claims"][0]["normative_claim"]="weakened"
        elif invariant=="pattern_library":value["patterns"]=value["patterns"][:-1]
        elif invariant=="adjudication":value["case_summary"]["reserve_cases"]=0
        elif invariant=="model_egress":
            if fixture_class=="adversarial":value["cases"][0]["selected_source_digests"]=["sha256:"+"f"*64]
            else:value["arbitrary_manifest_egress"]=True
    mutated=canonical_bytes(value)
    if fixture_class=="schema-invalid":
        with pytest.raises(ProvanError):validator(mutated)
        print("PROOF_SCHEMA_ERROR:canonical-contract-required-property")
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError):validator(mutated)
    else:validator(mutated)


@pytest.mark.parametrize("fixture_class",CLASSES)
def test_proof_deep_isolation_layers(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,fixture_class:str):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));monkeypatch.setenv("PROVAN_ALLOW_SCRIPTED_PROVIDER","1");brief=_brief();run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),depth="deep",provider_id="scripted-test");root=Path("outputs/contract-foundry")/run["run_id"];projection=secure_read(root/"foundry-acceptance-projection.json");artifacts={run["source_ledger"]["path"]:secure_read(root/run["source_ledger"]["path"])}
    for name,ref in run["stage_artifacts"].items():
        if name!="revisions":artifacts[ref["path"]]=secure_read(root/ref["path"])
    for ref in run["model_envelope_refs"]:artifacts[ref["path"]]=secure_read(root/ref["path"])
    value=copy.deepcopy(run);schema=json.loads((ROOT/"provan/schemas/contract-foundry-run.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="schema-invalid":del value["blind_paths"]
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:value["blind_paths"][1]["path"]="A"
    if fixture_class=="schema-invalid":
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        print("PROOF_SCHEMA_ERROR:blind-paths-required")
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError,match="FOUNDRY_DEEP_ISOLATION_INVALID"):validate_run_serialized(canonical_bytes(value),projection,artifacts)
        else:validate_run_serialized(canonical_bytes(value),projection,artifacts)


@pytest.mark.parametrize("fixture_class",CLASSES)
def test_proof_owner_projection_layers(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,fixture_class:str):
    run,projection,artifacts=_run_bundle(tmp_path,monkeypatch,fixture_class=="near-valid");value=json.loads(projection);schema=json.loads((ROOT/"provan/schemas/foundry-acceptance-projection.v1.json").read_text(encoding="utf-8"))
    if fixture_class=="schema-invalid":del value["projection_id"]
    elif fixture_class in {"adversarial","schema-valid-python-invalid"}:value["proposed_contract_terms"]["conditions"]=["invented authority"]
    raw=canonical_bytes(value)
    if fixture_class=="schema-invalid":
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        print("PROOF_SCHEMA_ERROR:projection-id-required")
    else:
        jsonschema.validate(value,schema)
        if fixture_class in {"adversarial","schema-valid-python-invalid"}:
            with pytest.raises(ProvanError,match="FOUNDRY_PROJECTION_BINDING_MISMATCH"):validate_run_serialized(canonical_bytes(run),raw,artifacts)
        else:validate_run_serialized(canonical_bytes(run),raw,artifacts)


@pytest.mark.parametrize("fixture_class",("valid","near-valid","adversarial"))
def test_proof_source_boundary_layers(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,fixture_class:str):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief();source=tmp_path/"intent.md";source.write_text("bounded intent",encoding="utf-8")
    count=32 if fixture_class=="near-valid" else 1;sources=[{"path":"intent.md","role":"intent"} for _ in range(count)]
    if fixture_class=="adversarial":sources=[{"path":"../outside.md","role":"intent"}]
    manifest=tmp_path/"manifest.json";manifest.write_text(json.dumps({"sources":sources,"routing_inputs":{"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"}}),encoding="utf-8")
    if fixture_class=="adversarial":
        with pytest.raises(ProvanError,match="FOUNDRY_SOURCE_PATH_UNSAFE"):foundry(brief_id=brief["brief_id"],source_manifest=manifest,no_model=True)
    else:
        run,_=foundry(brief_id=brief["brief_id"],source_manifest=manifest,no_model=True);assert len(run["blind_boundary"]["source_ids"])==count
