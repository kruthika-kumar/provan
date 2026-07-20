"""Join proof manifest rows to final JUnit and in-test proof events."""
from __future__ import annotations
import argparse,json,subprocess,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument("--junit",type=Path,required=True);p.add_argument("--events",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    manifest=json.loads((ROOT/"docs/validation/session6-8-proof-manifest.json").read_text())["proofs"]
    events={}
    for path in a.events.glob("*.event.*.json"):
        value=json.loads(path.read_text());events.setdefault(value["proof_id"],[]).append(value)
    junit=ET.parse(a.junit).getroot(); passed_names={case.attrib.get("name","") for case in junit.iter("testcase") if not any(child.tag in {"failure","error","skipped"} for child in case)}
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip();rows=[]
    for proof in manifest:
        matching=events.get(proof["proof_id"],[])
        if len(matching)!=1:raise SystemExit("proof_event_cardinality_invalid:"+proof["proof_id"])
        event=matching[0]; suffix="["+proof["proof_id"]+"]"
        junit_ok=any(name.endswith(suffix) for name in passed_names)
        expected=proof["expected_acceptance"]
        row={"proof_id":proof["proof_id"],"requirement_id":proof["requirement_id"],"fixture_class":proof["fixture_class"],"pytest_nodeid":proof["test_id"],"subcase_id":event["subcase_id"],"production_invocation_ids":event["production_invocation_ids"],"expected_acceptance":expected,"actual_acceptance":event["actual_acceptance"],"expected_exception":proof["expected_python_exception"],"actual_exception":event["actual_exception"],"expected_error_code":proof["expected_error_code"],"actual_error_code":event["actual_error_code"],"expected_schema_result":"rejected" if proof["expected_schema_rejection"] else "not_applicable","actual_schema_result":event["actual_schema_result"],"canonical_artifact":proof["canonical_artifact"],"artifact_paths":event["artifact_paths"],"artifact_hashes":event["artifact_hashes"],"artifact_assertions":event["artifact_assertions"],"actual_record_count":event["actual_record_count"],"minimum_record_count":3 if proof["requirement_id"]=="S6_REMEDIATION_CARDINALITY" else 1,"side_effect_expected":False,"side_effect_observed":event["side_effect_observed"],"passed":bool(event["passed"] and junit_ok and event["actual_acceptance"]==expected and event["actual_record_count"]>=(3 if proof["requirement_id"]=="S6_REMEDIATION_CARDINALITY" else 1)),"final_commit":commit}
        rows.append(row)
    result={"schema_version":"session6-8-proof-execution-receipt.v1","final_commit":commit,"proof_count":len(rows),"proofs":rows,"passed":len(rows)>=318 and all(r["passed"] for r in rows)}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");return 0 if result["passed"] else 2
if __name__=="__main__":raise SystemExit(main())
