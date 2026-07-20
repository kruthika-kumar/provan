"""Independently replay the frozen Sessions 6--8 security surface."""
from __future__ import annotations
import argparse,hashlib,json,tempfile
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
def _sha(path:Path)->str:return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def _replay_unreachable(domain:str,value:dict)->None:
    if domain=="remediation_roadmaps":validate_closure_evidence(value)
    elif domain=="review_organisation":validate_harness_execution_receipt(value,work_order_id="wo_python_engineering_"+"a"*16)
    elif domain=="contestability":validate_action_contract(value)
    else:validate_recommendation_policy(value)
def validate(receipt_path:Path):
    registry=json.loads((ROOT/"docs/validation/session6-8-security-surface-registry.json").read_text());rows=registry["records"];receipt=json.loads(receipt_path.read_text());actual={(r["domain"],r["operation"]):r for r in receipt["records"]}
    expected_hash="sha256:"+hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if len(rows)!=44 or registry.get("row_count")!=44 or registry.get("approved_semantic_hash")!=expected_hash or receipt.get("registry_semantic_hash")!=expected_hash:raise ValueError("security_surface_registry_changed")
    if set(actual)!={(r["domain"],r["operation"]) for r in rows}:raise ValueError("security_surface_coverage_mismatch")
    with tempfile.TemporaryDirectory() as raw:
        fixture=Path(raw)/"fixture";fixture.mkdir();ctx,criterion=_fixture(fixture);_finding(ctx,criterion,blocker=True);_remediation(ctx);ctx.release["change_impact"]={"migration_surface":True};prepare_review(ctx)
        for row in rows:
            recorded=actual[(row["domain"],row["operation"])];evidence_path=Path(recorded["raw_evidence_path"])
            if not evidence_path.is_file() or _sha(evidence_path)!=recorded["raw_evidence_hash"]:raise ValueError("security_raw_evidence_hash_mismatch")
            evidence=json.loads(evidence_path.read_text())
            if evidence.get("classification")!=row["classification"] or evidence.get("adapter_spy",{}).get("calls")!=[] or evidence.get("before_state")!=evidence.get("after_state"):raise ValueError("security_raw_evidence_invalid")
            try:
                if row["classification"]=="reachable_guarded" and row["domain"]=="remediation_roadmaps":closure_verify(ctx,"../../outside")
                elif row["classification"]=="reachable_guarded" and row["domain"]=="review_organisation":assert_submission_path(ctx,"migration_and_rollback",ctx.repository_root.parent/"outside.json",kind="result")
                elif row["classification"]=="unreachable_by_design":_replay_unreachable(row["domain"],evidence["malicious_input"])
                elif row["classification"]=="not_applicable":
                    if not row.get("not_applicable_reason"):raise ValueError("security_not_applicable_reason_missing")
                    continue
                else:raise ValueError("security_surface_classification_invalid")
            except ValueError as exc:error=str(exc)
            else:raise ValueError("security_surface_unexpected_pass")
            if error!=recorded["typed_rejection"] or recorded["underlying_adapter_called"] or recorded["side_effect_observed"] or recorded["before_hash"]!=recorded["after_hash"]:raise ValueError("security_surface_replay_mismatch")
    return {"schema_version":"session6-8-security-validation.v2","record_count":44,"classification_totals":{kind:sum(r["classification"]==kind for r in rows) for kind in ("reachable_guarded","unreachable_by_design","not_applicable")},"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.receipt),sort_keys=True))
if __name__=="__main__":main()
