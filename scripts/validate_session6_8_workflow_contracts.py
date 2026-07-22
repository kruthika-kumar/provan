"""Independently recompute workflow assertions from persisted evidence."""
from __future__ import annotations
import json
from pathlib import Path
from shiproom.session6_8_evidence_query import evaluate

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE_ROOT=ROOT/".shiproom"/"local"

def validate() -> dict:
    registry=json.loads((ROOT/"docs/validation/session6-8-workflow-contracts.json").read_text())
    receipt=json.loads((ROOT/".shiproom/local/session6-8-workflow-eval-receipt.json").read_text())
    actual={row["name"]:row for row in receipt["cases"]}; resolved=[]
    if {row["case_name"] for row in registry["cases"]}!={row["name"] for row in receipt["cases"]}: raise ValueError("workflow_contract_case_set_mismatch")
    for case in registry["cases"]:
        observed=actual[case["case_name"]]; functions={row["qualified_function"] for row in observed["production_invocations"]}
        if not set(case["required_production_functions"])<=functions: raise ValueError("workflow_required_production_function_unobserved")
        for assertion in case["assertions"]:
            if assertion["assertion_type"]!="artifact_query" or assertion["named_assertion_function"] is not None: raise ValueError("workflow_assertion_contract_invalid")
            artifact=assertion["artifact_path"].replace("\\","/")
            prefix=".shiproom/local/"
            if not artifact.startswith(prefix):raise ValueError("workflow_assertion_artifact_root_invalid")
            query={"artifact":artifact.removeprefix(prefix),"selector":assertion["json_pointer"],"operator":assertion["comparator"],"expected":assertion["expected_value"]}
            if not evaluate(EVIDENCE_ROOT,query).passed: raise ValueError("workflow_assertion_recomputation_failed")
            resolved.append(assertion["assertion_id"])
    return {"schema_version":"session6-8-workflow-contract-validation.v1","case_count":len(actual),"assertion_count":len(resolved),"status":"passed"}

if __name__=="__main__": print(json.dumps(validate(),sort_keys=True))
