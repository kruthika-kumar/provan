"""Independently recompute workflow assertions from persisted evidence."""
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def _pointer(value, pointer: str):
    current=value
    for token in pointer.lstrip("/").split("/") if pointer else []: current=current[token.replace("~1","/").replace("~0","~")]
    return current

def validate() -> dict:
    registry=json.loads((ROOT/"docs/validation/session6-8-workflow-contracts.json").read_text())
    receipt=json.loads((ROOT/".shiproom/local/session6-8-workflow-eval-receipt.json").read_text())
    actual={row["name"]:row for row in receipt["cases"]}; resolved=[]
    if {row["case_name"] for row in registry["cases"]}!={row["name"] for row in receipt["cases"]}: raise ValueError("workflow_contract_case_set_mismatch")
    for case in registry["cases"]:
        observed=actual[case["case_name"]]; functions={row["qualified_function"] for row in observed["production_invocations"]}
        if not set(case["required_production_functions"])<=functions: raise ValueError("workflow_required_production_function_unobserved")
        for assertion in case["assertions"]:
            if assertion["assertion_type"]!="artifact_pointer" or assertion["named_assertion_function"] is not None: raise ValueError("workflow_assertion_contract_invalid")
            actual_value=_pointer(json.loads((ROOT/assertion["artifact_path"]).read_text()),assertion["json_pointer"])
            if assertion["comparator"]!="equals" or actual_value!=assertion["expected_value"]: raise ValueError("workflow_assertion_recomputation_failed")
            resolved.append(assertion["assertion_id"])
    return {"schema_version":"session6-8-workflow-contract-validation.v1","case_count":len(actual),"assertion_count":len(resolved),"status":"passed"}

if __name__=="__main__": print(json.dumps(validate(),sort_keys=True))
