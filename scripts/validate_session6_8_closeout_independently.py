"""Independent integrity check for the final Sessions 6--8 closeout pair.

This intentionally does not import the report generator.  It shares only
canonical JSON parsing and SHA-256, so a defect in report prerequisite
calculation cannot certify its own output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


class CloseoutValidationError(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # exact type is intentionally not a trusted input API
        raise CloseoutValidationError("closeout_json_invalid") from exc
    if not isinstance(value, dict):
        raise CloseoutValidationError("closeout_object_invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--validation-root", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--workflow-receipt", type=Path, required=True)
    parser.add_argument("--behavioral-receipt", type=Path, required=True)
    parser.add_argument("--proof-receipt", type=Path, required=True)
    parser.add_argument("--parity-report", type=Path, required=True)
    parser.add_argument("--security-receipt", type=Path, required=True)
    parser.add_argument("--wheel-receipt", type=Path, required=True)
    parser.add_argument("--workflow-validation", type=Path, required=True)
    args = parser.parse_args()
    report_raw = args.report.read_bytes(); receipt_raw = args.receipt.read_bytes()
    report = _load(args.report); receipt = _load(args.receipt)
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True).stdout.strip()
    if report.get("final_commit") != commit or receipt.get("final_commit") != commit:
        raise CloseoutValidationError("closeout_final_commit_mismatch")
    if receipt.get("report_hash") != _sha(report_raw):
        raise CloseoutValidationError("closeout_report_hash_mismatch")
    expected_receipt = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if receipt.get("receipt_hash") != _sha(json.dumps(expected_receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")):
        raise CloseoutValidationError("closeout_receipt_hash_mismatch")
    inventory = _load(args.validation_root / "session6-8-requirement-inventory.json").get("requirements")
    if not isinstance(inventory, list) or not inventory:
        raise CloseoutValidationError("closeout_requirement_inventory_invalid")
    inventory_hash = _sha((args.validation_root / "session6-8-requirement-inventory.json").read_bytes())
    if report.get("inputs", {}).get("requirement_inventory_hash") != inventory_hash:
        raise CloseoutValidationError("closeout_requirement_inventory_hash_mismatch")
    inputs=report.get("inputs",{})
    expected_inputs={"junit_hash":args.junit,"workflow_receipt_hash":args.workflow_receipt,"behavioral_receipt_hash":args.behavioral_receipt,"proof_execution_receipt_hash":args.proof_receipt,"contract_parity_report_hash":args.parity_report,"security_receipt_hash":args.security_receipt,"wheel_receipt_hash":args.wheel_receipt,"workflow_validation_hash":args.workflow_validation,"workflow_contracts_hash":args.validation_root/"session6-8-workflow-contracts.json","security_surface_registry_hash":args.validation_root/"session6-8-security-surface-registry.json"}
    for key,path in expected_inputs.items():
        if inputs.get(key)!=_sha(path.read_bytes()):raise CloseoutValidationError("closeout_input_hash_mismatch:"+key)
    workflow=_load(args.workflow_receipt);behavioral=_load(args.behavioral_receipt);proof=_load(args.proof_receipt);parity=_load(args.parity_report);security=_load(args.security_receipt);wheel=_load(args.wheel_receipt);workflow_validation=_load(args.workflow_validation)
    if len(workflow.get("cases",[]))!=18 or not all(row.get("passed") for row in workflow["cases"]) or workflow_validation.get("status")!="passed":raise CloseoutValidationError("closeout_workflow_evidence_incomplete")
    if len(behavioral.get("cases",[]))!=35 or not all(row.get("passed") for row in behavioral["cases"]):raise CloseoutValidationError("closeout_behavioral_evidence_incomplete")
    if proof.get("proof_count",0)<318 or not proof.get("passed"):raise CloseoutValidationError("closeout_proof_execution_incomplete")
    if not parity.get("passed") or len(parity.get("mutation_receipts",[]))<42:raise CloseoutValidationError("closeout_parity_incomplete")
    if not security.get("passed") or not security.get("records") or any(row.get("side_effect_observed") or row.get("underlying_adapter_called") for row in security["records"]):raise CloseoutValidationError("closeout_security_incomplete")
    if not wheel.get("passed") or len(wheel.get("commands",[]))<20 or wheel.get("final_commit")!=commit:raise CloseoutValidationError("closeout_wheel_lifecycle_incomplete")
    prerequisites = report.get("prerequisites")
    if not isinstance(prerequisites, dict) or not prerequisites or not all(value is True for value in prerequisites.values()):
        raise CloseoutValidationError("closeout_prerequisites_unresolved")
    if report.get("resolved") is not True:
        raise CloseoutValidationError("closeout_report_not_resolved")
    expected_report = dict(report); expected_report["report_self_hash"] = ""
    if report.get("report_self_hash") != _sha(json.dumps(expected_report, sort_keys=True, separators=(",", ":")).encode("utf-8")):
        raise CloseoutValidationError("closeout_report_self_hash_mismatch")
    print(json.dumps({"status":"verified","final_commit":commit,"report_hash":_sha(report_raw),"receipt_hash":_sha(receipt_raw),"requirement_count":len(inventory)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CloseoutValidationError as exc:
        print(str(exc))
        raise SystemExit(2)
