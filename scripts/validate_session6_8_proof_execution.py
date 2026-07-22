"""Independently validate proof execution coverage and joins."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from shiproom.session6_8_evidence_query import evaluate
from shiproom.workflow_audit import observed_boundary
ROOT=Path(__file__).resolve().parents[1]
def _sha(path:Path)->str:return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def _semantic(value)->str:return "sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
def _validate_rejection(row,registered,evidence_root):
    if row["fixture_class"]!="adversarial_invalid":
        if row.get("rejection_invocation_id") is not None or row.get("outcome_evidence") is not None:raise ValueError("proof_execution_spurious_rejection")
        if row["fixture_class"]=="near_valid":
            binding=row.get("fixture_binding")
            if not isinstance(binding,dict):raise ValueError("proof_execution_near_binding_missing")
            manifest_path=evidence_root/binding["manifest_artifact"];manifest=json.loads(manifest_path.read_text());base=evidence_root/manifest["base_artifact"];bounded=evidence_root/manifest["mutated_artifact"]
            if manifest.get("mutation_class")!="bounded_production_state" or _sha(base)!=manifest.get("base_hash") or _sha(bounded)!=manifest.get("mutated_hash") or manifest.get("base_semantic_hash")==manifest.get("mutated_semantic_hash"):raise ValueError("proof_execution_near_binding_invalid")
            baselines=[item for item in row.get("production_invocations",[]) if item.get("invocation_id")==manifest.get("baseline_invocation_id")]
            if len(baselines)!=1 or baselines[0].get("exception_type") is not None:raise ValueError("proof_execution_near_invocation_missing")
        return
    outcome=row.get("outcome_evidence");binding=row.get("fixture_binding")
    if outcome!=registered.get("outcome_evidence") or not isinstance(binding,dict):raise ValueError("proof_execution_rejection_binding_missing")
    invocations=row.get("production_invocations",[]);matches=[item for item in invocations if item.get("invocation_id")==row.get("rejection_invocation_id") and item.get("subcase_id")==outcome["subcase_id"] and item.get("qualified_function")==outcome["production_function"]]
    if len(matches)!=1:raise ValueError("proof_execution_rejection_invocation_missing")
    invocation=matches[0]
    if outcome["channel"]=="exception":
        if invocation.get("exception_type")!=outcome["expected_exception"] or invocation.get("typed_status_or_error")!=outcome["expected_status_or_error"]:raise ValueError("proof_execution_rejection_status_mismatch")
    elif outcome["channel"]=="returned_status":
        if invocation.get("exception_type") is not None or invocation.get("typed_status_or_error")!=outcome["expected_status_or_error"]:raise ValueError("proof_execution_rejection_status_mismatch")
    else:raise ValueError("proof_execution_rejection_channel_invalid")
    manifest_path=evidence_root/binding["manifest_artifact"]
    if not manifest_path.is_file():raise ValueError("proof_execution_mutation_manifest_missing")
    manifest=json.loads(manifest_path.read_text());base=evidence_root/manifest["base_artifact"];mutated=evidence_root/manifest["mutated_artifact"]
    if not base.is_file() or not mutated.is_file() or _sha(base)!=manifest["base_hash"] or _sha(mutated)!=manifest["mutated_hash"] or manifest["base_hash"]==manifest["mutated_hash"]:raise ValueError("proof_execution_mutation_hash_invalid")
    if _semantic(json.loads(base.read_text()))!=manifest["base_semantic_hash"] or _semantic(json.loads(mutated.read_text()))!=manifest["mutated_semantic_hash"]:raise ValueError("proof_execution_mutation_semantics_invalid")
    if manifest["mutated_semantic_hash"] not in set(invocation.get("input_component_hashes",[])):raise ValueError("proof_execution_mutation_invocation_unbound")
    baselines=[item for item in invocations if item.get("invocation_id")==manifest.get("baseline_invocation_id") and item.get("subcase_id")==outcome["subcase_id"]+":baseline" and item.get("qualified_function")==outcome["production_function"]]
    if len(baselines)!=1 or baselines[0].get("exception_type") is not None or manifest["base_semantic_hash"] not in set(baselines[0].get("input_component_hashes",[])):raise ValueError("proof_execution_valid_baseline_missing")
@observed_boundary
def validate(path:Path):
    receipt=json.loads(path.read_text());manifest=json.loads((ROOT/"docs/validation/session6-8-proof-manifest.json").read_text())["proofs"]; requirements={r["requirement_id"] for r in json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text())["requirements"]};registry={r["proof_id"]:r for r in json.loads((ROOT/"docs/validation/session6-8-requirement-proof-registry.json").read_text())["proofs"]}
    rows=receipt["proofs"]; by_id={r["proof_id"]:r for r in rows}
    if len(by_id)!=len(rows) or set(by_id)!={p["proof_id"] for p in manifest}:raise ValueError("proof_execution_id_mismatch")
    for proof in manifest:
        row=by_id[proof["proof_id"]]
        if row.get("requirement_id")!=proof["requirement_id"] or row.get("fixture_class")!=proof["fixture_class"]:raise ValueError("proof_execution_binding_mismatch")
        if not row["production_invocation_ids"] or row["side_effect_observed"]:raise ValueError("proof_execution_row_invalid")
        if proof["expected_acceptance"] and row["actual_record_count"]<row["minimum_record_count"]:raise ValueError("proof_execution_cardinality_invalid")
        if row.get("actual_acceptance")!=proof["expected_acceptance"]:raise ValueError("proof_execution_acceptance_mismatch")
        if proof["fixture_class"]=="adversarial_invalid" and (row.get("actual_exception")!=proof["expected_python_exception"] or row.get("actual_error_code")!=proof["expected_error_code"]):raise ValueError("proof_execution_typed_rejection_mismatch")
        _validate_rejection(row,registry[proof["proof_id"]],path.parent)
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
