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
        minimum=proof.get("minimum_record_count",1)
        cardinality_ok=(not expected) or event["actual_record_count"]>=minimum
        row={"proof_id":proof["proof_id"],"requirement_id":proof["requirement_id"],"fixture_class":proof["fixture_class"],"pytest_nodeid":proof["test_id"],"subcase_id":event["subcase_id"],"semantic_fingerprint":event["semantic_fingerprint"],"production_invocation_ids":event["production_invocation_ids"],"production_invocations":event["production_invocations"],"expected_acceptance":expected,"actual_acceptance":event["actual_acceptance"],"expected_exception":proof["expected_python_exception"],"actual_exception":event["actual_exception"],"expected_error_code":proof["expected_error_code"],"actual_error_code":event["actual_error_code"],"expected_schema_result":"rejected" if proof["expected_schema_rejection"] else "not_applicable","actual_schema_result":event["actual_schema_result"],"canonical_artifact":proof["canonical_artifact"],"artifact_paths":event["artifact_paths"],"artifact_hashes":event["artifact_hashes"],"artifact_assertions":event["artifact_assertions"],"actual_record_count":event["actual_record_count"],"minimum_record_count":minimum,"side_effect_expected":False,"side_effect_observed":event["side_effect_observed"],"fixture_binding":event.get("fixture_binding"),"outcome_evidence":event.get("outcome_evidence"),"rejection_invocation_id":event.get("rejection_invocation_id"),"passed":bool(event["passed"] and junit_ok and event["actual_acceptance"]==expected and cardinality_ok),"final_commit":commit}
        rows.append(row)
    adversarial=[row for row in rows if row["fixture_class"]=="adversarial_invalid"]
    matching=[]
    for row in adversarial:
        matches=[item for item in row["production_invocations"] if item.get("invocation_id")==row.get("rejection_invocation_id") and item.get("typed_status_or_error")==row.get("actual_error_code") and item.get("exception_type")==row.get("actual_exception")]
        if len(matches)==1:matching.append(row["proof_id"])
    by_requirement={}
    for row in rows:by_requirement.setdefault(row["requirement_id"],{})[row["fixture_class"]]=json.dumps([item["query"] for item in row["artifact_assertions"]],sort_keys=True,separators=(",",":"))
    valid_near_duplicates=sum(1 for grouped in by_requirement.values() if grouped.get("valid")==grouped.get("near_valid"))
    valid_adversarial_duplicates=sum(1 for grouped in by_requirement.values() if grouped.get("valid")==grouped.get("adversarial_invalid"))
    rejection_audit={"adversarial_proof_count":len(adversarial),"matching_production_rejection_count":len(matching),"selector_or_value_derived_error_count":len(adversarial)-len(matching),"missing_controlled_mutation_count":sum(1 for row in adversarial if not row.get("fixture_binding")),"unjustified_valid_near_duplicate_count":valid_near_duplicates,"unjustified_valid_adversarial_duplicate_count":valid_adversarial_duplicates,"unexpected_adversarial_acceptance_count":sum(1 for row in adversarial if row.get("actual_acceptance") is not False)}
    result={"schema_version":"session6-8-proof-execution-receipt.v1","final_commit":commit,"proof_count":len(rows),"rejection_audit":rejection_audit,"proofs":rows,"passed":len(rows)==318 and len(adversarial)==len(matching)==106 and not any(rejection_audit[key] for key in rejection_audit if key.endswith("_count") and key not in {"adversarial_proof_count","matching_production_rejection_count"}) and all(r["passed"] for r in rows)}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");return 0 if result["passed"] else 2
if __name__=="__main__":raise SystemExit(main())
