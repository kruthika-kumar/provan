"""Independently replay Session 6--8 parity fixtures through production validators."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import jsonschema

from shiproom.contestability import target_registry,validate_action_contract
from shiproom.management_artifacts.compiler import validate_generation_manifest,validate_recommendation_policy,validate_section_registry
from shiproom.remediation_roadmaps import validate_authority_policy,validate_closure_evidence,validate_closure_verification,validate_closure_verifier_receipt,validate_planner_receipt,validate_planner_result,validate_planner_role,validate_planner_work_order
from shiproom.review_organisation import native_boundaries,registry
from shiproom.review_organisation import surface_policy,validate_codex_execution_package,validate_harness_capability_manifest,validate_harness_execution_receipt,validate_migration_result,validate_review_plan_artifact,validate_specialist_registries

ROOT=Path(__file__).resolve().parents[1]
def _sha(path:Path)->str:return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()

def _validate(cid:str,value:dict,valid:dict)->None:
    if cid=="remediation_closure_evidence": validate_closure_evidence(value)
    elif cid=="remediation_closure_verifier_receipt": validate_closure_verifier_receipt(value,closure_contract_id=valid["closure_contract_id"])
    elif cid=="remediation_closure_verification": validate_closure_verification(value)
    elif cid=="remediation_issue_authority_policy": validate_authority_policy(value)
    elif cid=="remediation_planner_result": validate_planner_result(value,work_order_id=valid["work_order_id"],preparation_id=valid["preparation_id"])
    elif cid=="remediation_planner_role": validate_planner_role(value)
    elif cid=="remediation_planner_work_order":
        validate_planner_work_order(value)
        if value["work_order_id"]!=valid["work_order_id"] or value["preparation_id"]!=valid["preparation_id"]:raise ValueError("remediation_planner_work_order_binding_invalid")
    elif cid=="remediation_planner_completion_receipt": validate_planner_receipt(value,work_order_id=valid["work_order_id"])
    elif cid=="review_plan":
        validate_review_plan_artifact(value)
        if value["plan_id"]!=valid["plan_id"]:raise ValueError("review_plan_binding_invalid")
    elif cid=="agent_harness_capability_manifest": validate_harness_capability_manifest(value)
    elif cid=="harness_execution_receipt": validate_harness_execution_receipt(value,work_order_id=valid["work_order_id"])
    elif cid=="codex_execution_package": validate_codex_execution_package(value)
    elif cid=="migration_result":
        validate_migration_result(value)
        if value["work_order_id"]!=valid["work_order_id"]:raise ValueError("migration_result_work_order_mismatch")
    elif cid in {"review_surface_policy","specialist_result_registry","specialist_native_boundary_registry"}:
        result=registry();native=native_boundaries();policy=surface_policy()
        if cid=="review_surface_policy":policy=value
        elif cid=="specialist_result_registry":result=value
        else:native=value
        validate_specialist_registries(result,native,policy)
    elif cid=="contestation_action":validate_action_contract(value)
    elif cid=="contestation_target_registry":target_registry(value)
    elif cid=="management_section_registry":validate_section_registry(value)
    elif cid=="release_recommendation_policy":validate_recommendation_policy(value)
    elif cid=="management_generation":validate_generation_manifest(value)
    else:raise ValueError("contract_parity_boundary_unregistered:"+cid)
    if cid=="remediation_closure_evidence" and value["closure_contract_id"]!=valid["closure_contract_id"]:raise ValueError("closure_evidence_binding_invalid")
    if cid=="remediation_closure_verification" and value["closure_contract_id"]!=valid["closure_contract_id"]:raise ValueError("closure_verification_binding_invalid")
    if cid=="remediation_issue_authority_policy" and value!=valid:raise ValueError("remediation_issue_authority_policy_semantic_tamper")

def validate(path:Path):
    report=json.loads(path.read_text());inventory={r["contract_id"]:r for r in json.loads((ROOT/"docs/validation/session6-8-contract-inventory.json").read_text())["contracts"]};baselines={r["contract_id"]:r for r in report.get("accepted_baselines",[])};seen={}
    if set(baselines)!=set(inventory):raise ValueError("contract_parity_accepted_baseline_incomplete")
    for cid,row in baselines.items():
        valid_path=Path(row["valid_fixture_path"])
        if _sha(valid_path)!=row["valid_fixture_hash"]:raise ValueError("contract_parity_valid_fixture_hash_mismatch")
        valid=json.loads(valid_path.read_text());schema_path=ROOT/inventory[cid]["path"]
        if schema_path.is_file():
            schema=json.loads(schema_path.read_text())
            if "$schema" in schema:jsonschema.Draft202012Validator(schema).validate(valid)
        _validate(cid,valid,valid)
        state=Path(row["state_snapshot_path"])
        if _sha(state)!=row["state_snapshot_hash"]:raise ValueError("contract_parity_accepted_state_hash_mismatch")
    for row in report.get("mutation_receipts",[]):
        cid=row["contract_id"];seen.setdefault(cid,set()).add(row["mutation_operation"]);valid_path=Path(row["valid_fixture_path"]);mutated_path=Path(row["mutated_fixture_path"]);before=Path(row["state_snapshot_before_path"]);after=Path(row["state_snapshot_after_path"])
        if any((_sha(candidate)!=expected) for candidate,expected in ((valid_path,row["valid_fixture_hash"]),(mutated_path,row["mutated_fixture_hash"]),(before,row["state_snapshot_before_hash"]),(after,row["state_snapshot_after_hash"]))):raise ValueError("contract_parity_fixture_hash_mismatch")
        valid=json.loads(valid_path.read_text());mutated=json.loads(mutated_path.read_text());schema_path=ROOT/inventory[cid]["path"];actual_schema="not_applicable"
        if schema_path.is_file():
            schema=json.loads(schema_path.read_text())
            if "$schema" in schema:
                try:jsonschema.Draft202012Validator(schema).validate(mutated);actual_schema="accepted"
                except jsonschema.ValidationError:actual_schema="rejected"
        if actual_schema!=row["actual_schema_result"]:raise ValueError("contract_parity_schema_replay_mismatch")
        try:_validate(cid,mutated,valid)
        except ValueError as exc:actual_python="rejected";actual_error=str(exc)
        else:actual_python="accepted";actual_error=None
        if actual_python!="rejected" or actual_python!=row["actual_python_result"] or actual_error!=row["actual_typed_error"]:raise ValueError("contract_parity_python_replay_mismatch:"+cid+":"+row["mutation_operation"]+":"+str(actual_error)+":"+str(row["actual_typed_error"]))
        if json.loads(before.read_text())!=json.loads(after.read_text()):raise ValueError("contract_parity_state_mutated")
    if set(seen)!=set(inventory) or any(kinds!={"structural_mutation","semantic_mutation"} for kinds in seen.values()):raise ValueError("contract_parity_coverage_incomplete")
    return {"schema_version":"session6-8-contract-parity-validation.v2","contract_count":len(seen),"mutation_count":sum(map(len,seen.values())),"unexpected_pass_count":0,"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--report",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.report),sort_keys=True))
if __name__=="__main__":main()
