"""Independently validate proof execution coverage and joins."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from shiproom.session6_8_evidence_query import evaluate
ROOT=Path(__file__).resolve().parents[1]
def validate(path:Path):
    receipt=json.loads(path.read_text());manifest=json.loads((ROOT/"docs/validation/session6-8-proof-manifest.json").read_text())["proofs"]; requirements={r["requirement_id"] for r in json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text())["requirements"]}
    rows=receipt["proofs"]; by_id={r["proof_id"]:r for r in rows}
    if len(by_id)!=len(rows) or set(by_id)!={p["proof_id"] for p in manifest}:raise ValueError("proof_execution_id_mismatch")
    for proof in manifest:
        row=by_id[proof["proof_id"]]
        if row.get("requirement_id")!=proof["requirement_id"] or row.get("fixture_class")!=proof["fixture_class"]:raise ValueError("proof_execution_binding_mismatch")
        if not row["production_invocation_ids"] or row["side_effect_observed"]:raise ValueError("proof_execution_row_invalid")
        if proof["expected_acceptance"] and row["actual_record_count"]<row["minimum_record_count"]:raise ValueError("proof_execution_cardinality_invalid")
        if row.get("actual_acceptance")!=proof["expected_acceptance"]:raise ValueError("proof_execution_acceptance_mismatch")
        if proof["fixture_class"]=="adversarial_invalid" and (row.get("actual_exception")!=proof["expected_python_exception"] or row.get("actual_error_code")!=proof["expected_error_code"]):raise ValueError("proof_execution_typed_rejection_mismatch")
        if row.get("semantic_fingerprint")!=proof.get("semantic_fingerprint"):raise ValueError("proof_execution_fingerprint_mismatch")
        invocations=row.get("production_invocations")
        if not isinstance(invocations,list) or {item.get("invocation_id") for item in invocations}!={*row["production_invocation_ids"]}:raise ValueError("proof_execution_invocation_binding_invalid")
        assertions=row.get("artifact_assertions")
        if not isinstance(assertions,list) or not assertions or any(item.get("passed") is not True for item in assertions):raise ValueError("proof_execution_artifact_assertion_failed")
        paths=row.get("artifact_paths");hashes=row.get("artifact_hashes")
        if not isinstance(paths,list) or not paths or not isinstance(hashes,dict):raise ValueError("proof_execution_artifact_missing")
        evidence_root=path.parent
        for artifact in paths:
            artifact_path=evidence_root/artifact
            if not artifact_path.is_file() or hashes.get(artifact)!="sha256:"+hashlib.sha256(artifact_path.read_bytes()).hexdigest():raise ValueError("proof_execution_artifact_hash_mismatch")
        for assertion in assertions:
            replay=evaluate(evidence_root,assertion["query"])
            if replay.actual!=assertion["actual"] or replay.expected!=assertion["expected"] or not replay.passed or replay.cardinality!=assertion["cardinality"]:raise ValueError("proof_execution_artifact_replay_mismatch")
    for rid in requirements:
        if {r["fixture_class"] for r in rows if r["requirement_id"]==rid}!={"valid","near_valid","adversarial_invalid"}:raise ValueError("proof_execution_class_incomplete")
    return {"schema_version":"session6-8-proof-execution-validation.v1","requirement_count":len(requirements),"proof_count":len(rows),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.receipt),sort_keys=True))
if __name__=="__main__":main()
