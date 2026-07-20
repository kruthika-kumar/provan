"""Independently replay recorded Session 6--8 parity mutations."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import jsonschema

ROOT=Path(__file__).resolve().parents[1]
def _sha(path):return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def validate(path:Path):
    report=json.loads(path.read_text()); inventory={r["contract_id"]:r for r in json.loads((ROOT/"docs/validation/session6-8-contract-inventory.json").read_text())["contracts"]}; seen={}
    for row in report["mutation_receipts"]:
        cid=row["contract_id"]; seen.setdefault(cid,set()).add(row["mutation_operation"])
        valid=Path(row["valid_fixture_path"]);mutated=Path(row["mutated_fixture_path"]);before=Path(row["state_snapshot_before_path"]);after=Path(row["state_snapshot_after_path"])
        if _sha(valid)!=row["valid_fixture_hash"] or _sha(mutated)!=row["mutated_fixture_hash"] or _sha(before)!=row["state_snapshot_before_hash"] or _sha(after)!=row["state_snapshot_after_hash"]:raise ValueError("contract_parity_fixture_hash_mismatch")
        resource=ROOT/inventory[cid]["path"]
        actual="not_applicable"
        if resource.is_file():
            schema=json.loads(resource.read_text())
            if "$schema" in schema:
                try:jsonschema.Draft202012Validator(schema).validate(json.loads(mutated.read_text()));actual="accepted"
                except jsonschema.ValidationError:actual="rejected"
        if actual!=row["expected_schema_result"]:raise ValueError("contract_parity_schema_replay_mismatch")
        if json.loads(valid.read_text())==json.loads(mutated.read_text()) or row["actual_python_result"]!="rejected":raise ValueError("contract_parity_python_rejection_missing")
        if row["state_snapshot_before_hash"]!=row["state_snapshot_after_hash"]:raise ValueError("contract_parity_state_mutated")
    if set(seen)!=set(inventory) or any(kinds!={"structural_mutation","semantic_mutation"} for kinds in seen.values()):raise ValueError("contract_parity_coverage_incomplete")
    return {"schema_version":"session6-8-contract-parity-validation.v1","contract_count":len(seen),"mutation_count":sum(map(len,seen.values())),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--report",type=Path,required=True);args=p.parse_args();print(json.dumps(validate(args.report),sort_keys=True))
if __name__=="__main__":main()
