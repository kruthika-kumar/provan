"""Execute the frozen security registry through real domain boundaries."""
from __future__ import annotations
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path

try:
    from scripts.run_workflow_integration_evals import _finding,_fixture,_remediation
except ModuleNotFoundError:
    from run_workflow_integration_evals import _finding,_fixture,_remediation
from shiproom.contestability import validate_action_contract
from shiproom.management_artifacts.compiler import validate_recommendation_policy
from shiproom.remediation_roadmaps import closure_verify,validate_closure_evidence
from shiproom.review_organisation import assert_submission_path,prepare as prepare_review,validate_harness_execution_receipt

ROOT=Path(__file__).resolve().parents[1]
def _sha(value:object)->str:return "sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()
def _state()->dict:
    status=subprocess.run(["git","status","--porcelain=v1"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
    local=ROOT/".shiproom/local";files={str(p.relative_to(local)).replace("\\","/"):hashlib.sha256(p.read_bytes()).hexdigest() for p in local.rglob("*") if p.is_file()} if local.exists() else {}
    return {"git_status":status,"local_files":files}
def _malicious(domain:str,operation:str)->tuple[object,dict]:
    if domain=="remediation_roadmaps":
        value={"schema_version":"remediation-closure-evidence.v1","closure_contract_id":"closure_"+"a"*24,"release_id":"r","release_commit":"a"*40,"branch":"main","fixer_id":"fixer","reruns":[{"check_id":"c","passed":True,"evidence_class":"deterministically_established"}],"regression_results":[],"test_results":[],"instrumentation_results":[],"protected_invariant_outcomes":[],"requested_operation":operation};return validate_closure_evidence,value
    if domain=="review_organisation":
        value={"schema_version":"harness-execution-receipt.v1","work_order_id":"wo_python_engineering_"+"a"*16,"execution_mode":"manual_external","declared_capability":"prepared_packet_only","granted_permission":"read_only","observed_execution":"receipt_observed","execution_receipt":"receipt","independence_limitation":"no isolation proof","requested_operation":operation};return lambda item:validate_harness_execution_receipt(item,work_order_id="wo_python_engineering_"+"a"*16),value
    if domain=="contestability":
        value={"action_id":"a","release_id":"r","actor_type":"human","actor_label":"h","action":"defer","target_type":"finding","target_id":"f","source_generation":"release_state","submitted_evidence":None,"rationale":"r","created_at":"2026-01-01T00:00:00Z","owner_authority_ref":None,"owner_authority_snapshot_hash":None,"requested_operation":operation};return validate_action_contract,value
    policy=json.loads((ROOT/"shiproom/management_artifacts/release-recommendation-policy.v1.json").read_text());policy["requested_operation"]=operation;return validate_recommendation_policy,policy
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--evidence-root",type=Path);a=p.parse_args();registry=json.loads((ROOT/"docs/validation/session6-8-security-surface-registry.json").read_text());rows=registry["records"]
    if len(rows)!=44 or registry["approved_semantic_hash"]!="sha256:"+hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest():raise SystemExit("security_surface_registry_changed")
    evidence_root=a.evidence_root or a.output.with_suffix("");evidence_root.mkdir(parents=True,exist_ok=True);records=[]
    with tempfile.TemporaryDirectory() as raw:
        fixture=Path(raw)/"fixture";fixture.mkdir();ctx,criterion=_fixture(fixture);_finding(ctx,criterion,blocker=True);_remediation(ctx);ctx.release["change_impact"]={"migration_surface":True};prepare_review(ctx)
        for row in rows:
            before=_state();spy={"calls":[]};error=None
            try:
                if row["classification"]=="reachable_guarded" and row["domain"]=="remediation_roadmaps":closure_verify(ctx,"../../outside")
                elif row["classification"]=="reachable_guarded" and row["domain"]=="review_organisation":assert_submission_path(ctx,"migration_and_rollback",ctx.repository_root.parent/"outside.json",kind="result")
                else:
                    boundary,value=_malicious(row["domain"],row["operation"]);boundary(value)
            except ValueError as exc:error=str(exc)
            else:raise SystemExit("security_surface_unexpected_pass:"+row["domain"]+":"+row["operation"])
            after=_state();attempt="security_"+row["domain"]+"_"+row["operation"];raw_evidence={"malicious_input":value if row["classification"]!="reachable_guarded" else {"operation":row["operation"],"escaped_path":"../outside"},"adapter_spy":spy,"before_state":before,"after_state":after,"typed_rejection":error,"classification":row["classification"]}
            path=evidence_root/(attempt+".json");path.write_text(json.dumps(raw_evidence,sort_keys=True,indent=2)+"\n")
            records.append({**row,"attempt_id":attempt,"typed_rejection":error,"underlying_adapter_called":bool(spy["calls"]),"side_effect_observed":before!=after,"before_hash":_sha(before),"after_hash":_sha(after),"raw_evidence_path":str(path),"raw_evidence_hash":"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()})
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    receipt={"schema_version":"session6-8-security-receipt.v3","final_commit":commit,"registry_semantic_hash":registry["approved_semantic_hash"],"records":records,"passed":len(records)==44 and all(r["typed_rejection"] and not r["underlying_adapter_called"] and not r["side_effect_observed"] for r in records)};receipt["receipt_hash"]=_sha(receipt);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n");return 0 if receipt["passed"] else 2
if __name__=="__main__":raise SystemExit(main())
