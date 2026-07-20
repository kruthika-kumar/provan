"""Independently validate proof execution coverage and joins."""
from __future__ import annotations
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def validate(path:Path):
    receipt=json.loads(path.read_text());manifest=json.loads((ROOT/"docs/validation/session6-8-proof-manifest.json").read_text())["proofs"]; requirements={r["requirement_id"] for r in json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text())["requirements"]}
    rows=receipt["proofs"]; by_id={r["proof_id"]:r for r in rows}
    if len(by_id)!=len(rows) or set(by_id)!={p["proof_id"] for p in manifest}:raise ValueError("proof_execution_id_mismatch")
    for proof in manifest:
        row=by_id[proof["proof_id"]]
        if not row["passed"] or not row["production_invocation_ids"] or row["actual_record_count"]<row["minimum_record_count"] or row["side_effect_observed"]:raise ValueError("proof_execution_row_invalid")
    for rid in requirements:
        if {r["fixture_class"] for r in rows if r["requirement_id"]==rid}!={"valid","near_valid","adversarial_invalid"}:raise ValueError("proof_execution_class_incomplete")
    return {"schema_version":"session6-8-proof-execution-validation.v1","requirement_count":len(requirements),"proof_count":len(rows),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.receipt),sort_keys=True))
if __name__=="__main__":main()
