"""Reconstruct Sessions 6--8 closure from a self-contained evidence bundle.

This module intentionally imports no closeout generator, claim resolver,
workflow runner, proof runner, parity outcome logic, or security summary logic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


class CloseoutValidationError(ValueError): pass


def _sha(raw: bytes) -> str: return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> dict:
    try: value=json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc: raise CloseoutValidationError("closeout_json_invalid") from exc
    if not isinstance(value,dict): raise CloseoutValidationError("closeout_object_invalid")
    return value


def _semantic_hash(row: dict) -> str:
    fields={key:row[key] for key in ("requirement_id","normative_behavior","forbidden_substitutions","required_artifacts","minimum_cardinalities")}
    return _sha(json.dumps(fields,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode())


def _workflow_hash(row: dict) -> str:
    fields={key:row[key] for key in ("preconditions","required_production_functions","assertions","required_artifacts","minimum_record_counts","forbidden_substitutions")}
    return _sha(json.dumps(fields,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode())


def validate_bundle(bundle: Path, *, expected_commit: str, expected_receipt_hash: str) -> dict:
    manifest=_load(bundle/"session6-8-evidence-bundle-manifest.json")
    if manifest.get("final_evidence_commit")!=expected_commit: raise CloseoutValidationError("closeout_final_commit_mismatch")
    manifest_body={**manifest,"manifest_hash":""}
    if manifest.get("manifest_hash")!=_sha(json.dumps(manifest_body,sort_keys=True,separators=(",",":")).encode()):raise CloseoutValidationError("closeout_bundle_manifest_hash_mismatch")
    listed=set()
    for row in manifest.get("files",[]):
        relative=row.get("relative_path")
        if not isinstance(relative,str) or relative.startswith("/") or ".." in Path(relative).parts or relative in listed:raise CloseoutValidationError("closeout_bundle_path_invalid")
        listed.add(relative);path=bundle/relative
        if not path.is_file() or _sha(path.read_bytes())!=row.get("sha256") or path.stat().st_size!=row.get("size_bytes") or row.get("final_evidence_commit")!=expected_commit:raise CloseoutValidationError("closeout_bundle_file_hash_mismatch")
    actual={path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}-{"session6-8-evidence-bundle-manifest.json"}
    if listed!=actual:raise CloseoutValidationError("closeout_bundle_file_set_mismatch")
    report_path=bundle/"session6-8-final-closeout-report.json";receipt_path=bundle/"session6-8-final-closeout-receipt.json"
    report=_load(report_path);receipt=_load(receipt_path)
    if _sha(receipt_path.read_bytes())!=expected_receipt_hash:raise CloseoutValidationError("closeout_detached_receipt_hash_mismatch")
    if receipt.get("report_hash")!=_sha(report_path.read_bytes()):raise CloseoutValidationError("closeout_report_hash_mismatch")
    expected_receipt={key:value for key,value in receipt.items() if key!="receipt_hash"}
    if receipt.get("receipt_hash")!=_sha(json.dumps(expected_receipt,sort_keys=True,separators=(",",":")).encode()):raise CloseoutValidationError("closeout_receipt_hash_mismatch")
    if report.get("final_commit")!=expected_commit or receipt.get("final_commit")!=expected_commit:raise CloseoutValidationError("closeout_report_commit_mismatch")
    expected_report={**report,"report_self_hash":""}
    if report.get("report_self_hash")!=_sha(json.dumps(expected_report,sort_keys=True,separators=(",",":")).encode()):raise CloseoutValidationError("closeout_report_self_hash_mismatch")
    requirements=_load(bundle/"session6-8-requirement-inventory.json").get("requirements",[])
    if len(requirements)!=106 or len({row.get("requirement_id") for row in requirements})!=106:raise CloseoutValidationError("closeout_requirement_cardinality_invalid")
    if any(row.get("approved_semantic_hash")!=_semantic_hash(row) for row in requirements):raise CloseoutValidationError("closeout_requirement_semantics_tampered")
    rid={row["requirement_id"] for row in requirements}
    completion={row["requirement_id"] for row in _load(bundle/"session6-8-completion-map.json").get("requirements",[])}
    execution={row["requirement_id"] for row in _load(bundle/"session6-8-execution-map.json").get("requirements",[])}
    proof_manifest=_load(bundle/"session6-8-proof-manifest.json").get("proofs",[])
    proof_registry=_load(bundle/"session6-8-requirement-proof-registry.json").get("proofs",[])
    fingerprint_audit=_load(bundle/"session6-8-proof-fingerprint-audit.json")
    claims=_load(bundle/"session6-8-claim-registry.json").get("claims",[])
    claim_rids=[tuple(row.get("requirement_ids",[])) for row in claims]
    if rid!=completion or rid!=execution or rid!={row.get("requirement_id") for row in proof_manifest} or set(claim_rids)!={(x,) for x in rid} or len(claims)!=106:raise CloseoutValidationError("closeout_requirement_coverage_mismatch")
    if len(proof_manifest)!=318 or len(proof_registry)!=318 or len({row.get("proof_id") for row in proof_registry})!=318:raise CloseoutValidationError("closeout_proof_registry_cardinality_invalid")
    if {row["proof_id"] for row in proof_manifest}!={row["proof_id"] for row in proof_registry}:raise CloseoutValidationError("closeout_proof_registry_mismatch")
    classes={requirement:{row.get("fixture_class") for row in proof_registry if row.get("requirement_id")==requirement} for requirement in rid}
    if any(value!={"valid","near_valid","adversarial_invalid"} for value in classes.values()):raise CloseoutValidationError("closeout_proof_fixture_class_reuse")
    recomputed=[]
    for row in proof_registry:
        fields={key:row[key] for key in ("production_functions","fixture_builder","fixture_mutation","artifact_selectors","comparators","expected_acceptance","expected_error","expected_schema_result","side_effect_assertions")}
        fingerprint=_sha(json.dumps(fields,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode())
        if row.get("semantic_fingerprint")!=fingerprint:raise CloseoutValidationError("closeout_proof_fingerprint_tampered")
        recomputed.append(fingerprint)
    if len(set(recomputed))!=318 or fingerprint_audit.get("unjustified_duplicate_count")!=0 or fingerprint_audit.get("unique_fingerprint_count")!=318:raise CloseoutValidationError("closeout_proof_fingerprint_duplicate")
    workflows=_load(bundle/"session6-8-workflow-contracts.json").get("cases",[])
    if len(workflows)!=18 or any(row.get("approved_semantic_hash")!=_workflow_hash(row) for row in workflows):raise CloseoutValidationError("closeout_workflow_semantics_tampered")
    junit=ET.parse(bundle/"final-session6-8-junit.xml").getroot()
    if any(child.tag in {"failure","error"} for case in junit.iter("testcase") for child in case):raise CloseoutValidationError("closeout_junit_not_clean")
    behavioral=_load(bundle/"behavioral-eval-receipt.json").get("cases",[])
    workflow_receipt=_load(bundle/"session6-8-workflow-eval-receipt.json").get("cases",[])
    if len(behavioral)!=35 or not all(row.get("passed") for row in behavioral):raise CloseoutValidationError("closeout_behavioral_evidence_incomplete")
    if len(workflow_receipt)!=18:raise CloseoutValidationError("closeout_workflow_evidence_incomplete")
    by_workflow={row["name"]:row for row in workflow_receipt}
    for contract in workflows:
        case=by_workflow.get(contract["case_name"])
        if case is None:raise CloseoutValidationError("closeout_workflow_case_missing")
        observed={row.get("qualified_function") for row in case.get("production_invocations",[])}
        if not set(contract["required_production_functions"]).issubset(observed):raise CloseoutValidationError("closeout_workflow_invocation_missing")
        artifact=bundle/"canonical-artifacts/workflow-evidence"/(contract["case_name"]+".json")
        evidence=_load(artifact)
        for assertion in contract["assertions"]:
            actual=evidence.get("assertions",{}).get(assertion["assertion_id"])
            if assertion["comparator"]!="equals" or actual!=assertion["expected_value"]:raise CloseoutValidationError("closeout_workflow_assertion_failed")
    registry_by={row["proof_id"]:row for row in proof_registry}
    proof_receipt=_load(bundle/"session6-8-proof-execution-receipt.json")
    proof_rows=proof_receipt.get("proofs",[]);manifest_by={row["proof_id"]:row for row in proof_manifest}
    if len(proof_rows)<318 or len({row.get("proof_id") for row in proof_rows})!=len(proof_manifest):raise CloseoutValidationError("closeout_proof_execution_incomplete")
    for row in proof_rows:
        expected=manifest_by.get(row["proof_id"])
        if expected is None or row.get("requirement_id")!=expected["requirement_id"] or row.get("fixture_class")!=expected["fixture_class"]:raise CloseoutValidationError("closeout_proof_binding_invalid")
        if row.get("actual_acceptance")!=expected["expected_acceptance"] or not row.get("production_invocation_ids"):raise CloseoutValidationError("closeout_proof_outcome_invalid")
        if expected["expected_acceptance"] and row.get("actual_record_count",0)<row.get("minimum_record_count",1):raise CloseoutValidationError("closeout_proof_cardinality_invalid")
        if expected["fixture_class"]=="adversarial_invalid" and (row.get("actual_exception")!=expected["expected_python_exception"] or row.get("actual_error_code")!=expected["expected_error_code"]):raise CloseoutValidationError("closeout_proof_rejection_mismatch")
        registered=registry_by[row["proof_id"]]
        if row.get("semantic_fingerprint")!=registered.get("semantic_fingerprint"):raise CloseoutValidationError("closeout_proof_receipt_fingerprint_mismatch")
        invocations=row.get("production_invocations",[])
        if not invocations or {item.get("invocation_id") for item in invocations}!={*row.get("production_invocation_ids",[])}:raise CloseoutValidationError("closeout_proof_invocation_missing")
        artifact=bundle/"canonical-artifacts/proof-events"/(row["proof_id"]+".artifact.json")
        if not artifact.is_file() or _sha(artifact.read_bytes()) not in row.get("artifact_hashes",{}).values():raise CloseoutValidationError("closeout_proof_artifact_mismatch")
        artifact_value=_load(artifact)
        if artifact_value.get("artifact_selector")!=registered["artifact_selectors"][0]:raise CloseoutValidationError("closeout_proof_selector_mismatch")
        measured=artifact_value.get("measured_value")
        measured_count=(1 if measured else 0) if isinstance(measured,bool) else (max(measured,0) if isinstance(measured,int) else len(measured) if isinstance(measured,(list,dict,str)) else 1 if measured is not None else 0)
        if artifact_value.get("measured_cardinality")!=measured_count or row.get("actual_record_count")!=measured_count:raise CloseoutValidationError("closeout_proof_configured_minimum_substitution")
    parity=_load(bundle/"session6-8-contract-parity-report.json")
    if len(parity.get("accepted_baselines",[]))!=parity.get("contract_count") or len(parity.get("mutation_receipts",[]))<2*parity.get("contract_count",0):raise CloseoutValidationError("closeout_parity_incomplete")
    for row in parity["mutation_receipts"]:
        valid=bundle/"parity-fixtures"/Path(row["valid_fixture_path"]).name;mutated=bundle/"parity-fixtures"/Path(row["mutated_fixture_path"]).name
        if not valid.is_file() or _sha(valid.read_bytes())!=row["valid_fixture_hash"]:raise CloseoutValidationError("closeout_parity_baseline_invalid")
        if not mutated.is_file() or _sha(mutated.read_bytes())!=row["mutated_fixture_hash"]:raise CloseoutValidationError("closeout_parity_mutation_invalid")
        if row.get("actual_python_result")!="rejected" or row.get("unexpected_pass"):raise CloseoutValidationError("closeout_parity_unexpected_pass")
    security_registry=_load(bundle/"session6-8-security-surface-registry.json").get("records",[])
    security=_load(bundle/"session6-8-security-receipt.json").get("records",[])
    if len(security_registry)!=44 or len(security)!=44:raise CloseoutValidationError("closeout_security_cardinality_invalid")
    for row in security:
        raw=bundle/"security-evidence"/Path(row["raw_evidence_path"]).name
        if not raw.is_file() or _sha(raw.read_bytes())!=row["raw_evidence_hash"]:raise CloseoutValidationError("closeout_security_raw_evidence_invalid")
        evidence=_load(raw)
        if evidence.get("adapter_spy",{}).get("called") or evidence.get("before_hash")!=evidence.get("after_hash"):raise CloseoutValidationError("closeout_security_side_effect")
    wheel=_load(bundle/"session6-8-installed-wheel-receipt.json")
    if wheel.get("final_commit")!=expected_commit or len(wheel.get("commands",[]))<20 or not wheel.get("source_checkout_not_on_sys_path"):raise CloseoutValidationError("closeout_wheel_lifecycle_incomplete")
    for index,row in enumerate(wheel["commands"]):
        for stream in ("stdout","stderr"):
            raw=bundle/"wheel-logs"/(f"{index:02d}.{stream}.txt")
            if not raw.is_file() or _sha(raw.read_bytes())!=row[stream+"_hash"]:raise CloseoutValidationError("closeout_wheel_log_invalid")
        if row.get("exit_code")!=0:raise CloseoutValidationError("closeout_wheel_command_failed")
    for row in wheel.get("artifacts",[]):
        artifact=bundle/"canonical-artifacts/wheel"/row["relative_path"]
        if not artifact.is_file() or _sha(artifact.read_bytes())!=row["sha256"]:raise CloseoutValidationError("closeout_wheel_artifact_invalid")
    bundled_wheel=bundle/"final-session6-8.whl"
    if not bundled_wheel.is_file() or _sha(bundled_wheel.read_bytes())!=wheel.get("wheel_sha256"):raise CloseoutValidationError("closeout_bundled_wheel_invalid")
    validator_source=bundle/"independent-validator-entrypoint.py"
    if not validator_source.is_file():raise CloseoutValidationError("closeout_validator_source_missing")
    if len(claims)!=len({row.get("claim_id") for row in claims}):raise CloseoutValidationError("closeout_claim_duplicate")
    resolution=_load(bundle/"session6-8-claim-resolution-receipt.json")
    if resolution.get("claim_count")!=106 or resolution.get("resolved_claim_count")!=106 or resolution.get("final_commit")!=expected_commit:raise CloseoutValidationError("closeout_claim_resolution_incomplete")
    resolved_by={row.get("requirement_id"):row for row in resolution.get("claims",[])}
    if len(resolved_by)!=106 or set(resolved_by)!=rid:raise CloseoutValidationError("closeout_claim_resolution_binding_invalid")
    for claim in claims:
        requirement=claim["requirement_ids"][0];resolved=resolved_by[requirement]
        expected_ids=set(claim["positive_proof_ids"]+claim["near_valid_proof_ids"]+claim["adversarial_proof_ids"])
        if set(resolved.get("proof_ids",[]))!=expected_ids:raise CloseoutValidationError("closeout_claim_proof_substitution")
        measured=resolved.get("measured_evidence",[])
        if len(measured)!=3 or {row.get("proof_id") for row in measured}!=expected_ids:raise CloseoutValidationError("closeout_claim_measured_evidence_incomplete")
    matrix=_load(bundle/"session6-8-requirement-evidence-matrix.json")
    matrix_rows=matrix.get("rows",[])
    if matrix.get("requirement_count")!=106 or len(matrix_rows)!=106 or {row.get("requirement_id") for row in matrix_rows}!=rid:raise CloseoutValidationError("closeout_evidence_matrix_incomplete")
    if any(row.get("claim_status")!="resolved" or not row.get("production_invocations") or any(value<0 for value in row.get("measured_cardinalities",{}).values()) for row in matrix_rows):raise CloseoutValidationError("closeout_evidence_matrix_invalid")
    if report.get("resolved") is not True or not isinstance(report.get("prerequisites"),dict) or not all(report["prerequisites"].values()):raise CloseoutValidationError("closeout_report_not_resolved")
    return {"status":"verified","final_commit":expected_commit,"requirement_count":106,"claim_count":106,"proof_count":len(proof_rows),"workflow_count":18,"security_count":44,"parity_mutation_count":len(parity["mutation_receipts"]),"wheel_command_count":len(wheel["commands"]),"bundle_manifest_hash":manifest["manifest_hash"]}


def main() -> int:
    parser=argparse.ArgumentParser();parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--expected-commit",required=True);parser.add_argument("--expected-receipt-hash",required=True);parser.add_argument("--require-installed-wheel",action="store_true");args=parser.parse_args()
    if args.require_installed_wheel:
        try:
            import shiproom
            module=Path(shiproom.__file__).resolve();prefix=Path(sys.prefix).resolve()
            module.relative_to(prefix)
        except Exception: print("closeout_external_wheel_origin_invalid");return 2
        checkout=Path(__file__).resolve().parents[1]
        if any(str(checkout).lower()==str(Path(item).resolve()).lower() for item in sys.path if item):print("closeout_source_checkout_on_sys_path");return 2
    try: result=validate_bundle(args.bundle,expected_commit=args.expected_commit,expected_receipt_hash=args.expected_receipt_hash)
    except CloseoutValidationError as exc: print(str(exc));return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=="__main__":raise SystemExit(main())
