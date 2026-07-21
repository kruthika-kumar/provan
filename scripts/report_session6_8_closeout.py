"""Generate a non-self-certifying Sessions 6--8 closeout report."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _junit_passed_ids(raw: bytes) -> set[str]:
    root = ET.fromstring(raw)
    passed = set()
    for case in root.iter("testcase"):
        if any(child.tag in {"failure", "error", "skipped"} for child in case):
            continue
        name = case.attrib.get("name", "")
        classname = case.attrib.get("classname", "")
        passed.add(name)
        passed.add(classname + "::" + name)
        passed.add(classname.replace(".", "/") + ".py::" + name)
    return passed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--workflow-receipt", type=Path, required=True)
    parser.add_argument("--behavioral-receipt", type=Path, required=True)
    parser.add_argument("--security-receipt", type=Path, required=True)
    parser.add_argument("--contract-parity-report", type=Path, required=True)
    parser.add_argument("--wheel-receipt", type=Path, required=True)
    parser.add_argument("--proof-receipt", type=Path, required=True)
    parser.add_argument("--workflow-validation", type=Path, required=True)
    parser.add_argument("--claim-resolution", type=Path, required=True)
    parser.add_argument("--evidence-matrix", type=Path, required=False)
    parser.add_argument("--receipt", type=Path, required=False)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    validation = root / "docs" / "validation"
    requirement_inventory = _load(validation / "session6-8-requirement-inventory.json")["requirements"]
    completion = _load(validation / "session6-8-completion-map.json")["requirements"]
    execution = _load(validation / "session6-8-execution-map.json")["requirements"]
    proofs = _load(validation / "session6-8-proof-manifest.json")["proofs"]
    claims = _load(validation / "session6-8-claim-registry.json")["claims"]
    inventory = _load(validation / "session6-8-contract-inventory.json")["contracts"]
    contracts = _load(validation / "session6-8-contract-registry.json")["contracts"]
    junit = args.junit.read_bytes()
    passed_tests = _junit_passed_ids(junit)
    workflow = _load(args.workflow_receipt)
    behavioral = _load(args.behavioral_receipt)
    security = _load(args.security_receipt)
    parity = _load(args.contract_parity_report)
    wheel = _load(args.wheel_receipt)
    proof_execution = _load(args.proof_receipt)
    workflow_validation = _load(args.workflow_validation)
    claim_resolution = _load(args.claim_resolution)
    evidence_matrix = _load(args.evidence_matrix) if args.evidence_matrix else None
    proof_ids = {item["proof_id"] for item in proofs}
    inventory_requirements = {item["requirement_id"] for item in requirement_inventory}
    requirements = {item["requirement_id"] for item in completion}
    execution_requirements = {item["requirement_id"] for item in execution}
    covered = {item for claim in claims for item in claim["requirement_ids"]}
    workflow_cases = workflow.get("cases", [])
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    valid_fixture_classes = {"valid", "near_valid", "adversarial_invalid"}
    prerequisites = {
        "requirement_inventory_exhaustive": len(inventory_requirements) == len(requirement_inventory) and requirements == inventory_requirements == {item["requirement_id"] for item in proofs} == covered == execution_requirements,
        "source_text_hashes_bound": all(item.get("source_text_hash") == _sha(item["source_requirement"].encode("utf-8")) for item in requirement_inventory),
        "execution_map_bound": all(item.get("production_boundary") and item.get("proof_ids") for item in execution),
        "all_proofs_executed": all(item["fixture_class"] in valid_fixture_classes and item["test_id"] in passed_tests and bool(item.get("production_function")) and bool(item.get("canonical_artifact")) for item in proofs),
        "all_requirements_executed": len(requirement_inventory) == 106 and len(completion) == 106,
        "all_claims_bound": all(set(claim["positive_proof_ids"] + claim["near_valid_proof_ids"] + claim["adversarial_proof_ids"]) <= proof_ids for claim in claims),
        "proof_execution_complete": proof_execution.get("passed") is True and proof_execution.get("proof_count") >= 318 and len({row["requirement_id"] for row in proof_execution.get("proofs",[])}) == 106,
        "workflow_assertions_recomputed": workflow_validation.get("status") == "passed" and workflow_validation.get("case_count") == 18 and workflow_validation.get("assertion_count",0) > 18,
        "junit_present": bool(junit),
        "workflow_receipt_complete": len(workflow_cases) == 18 and all(item.get("passed") for item in workflow_cases),
        "behavioral_receipt_complete": len(behavioral.get("cases", [])) == 35 and all(item.get("passed") for item in behavioral["cases"]),
        "receipts_match_final_commit": workflow.get("final_commit") == commit and behavioral.get("final_commit") == commit,
        "contract_inventory_bound": {item["contract_id"] for item in inventory if item.get("parity_required")} == {item["contract_name"] for item in contracts} and all(item.get("requirement_ids") for item in contracts),
        "security_receipt_complete": bool(security.get("passed")) and len(security.get("records", [])) == 44 and all(item.get("typed_rejection") and not item.get("underlying_adapter_called") and not item.get("side_effect_observed") and item.get("before_hash") == item.get("after_hash") for item in security["records"]),
        "contract_parity_complete": bool(parity.get("passed")) and parity.get("unexpected_pass_count") == 0 and len(parity.get("accepted_baselines", [])) == parity.get("contract_count") and len(parity.get("mutation_receipts", [])) >= 2 * parity.get("contract_count", 0),
        "wheel_receipt_complete": bool(wheel.get("passed")) and wheel.get("final_commit") == commit and wheel.get("exit_code") == 0 and len(wheel.get("commands",[])) >= 20,
        "all_claims_resolved": claim_resolution.get("claim_count") == 106 and claim_resolution.get("resolved_claim_count") == 106 and claim_resolution.get("final_commit") == commit,
        "requirement_evidence_matrix_complete": isinstance(evidence_matrix,dict) and evidence_matrix.get("requirement_count")==106 and len(evidence_matrix.get("rows",[]))==106,
    }
    report = {"schema_version": "session6-8-closeout-report.v2", "final_commit": commit,
              "inputs": {"requirement_inventory_hash": _sha((validation / "session6-8-requirement-inventory.json").read_bytes()),
                         "completion_map_hash": _sha((validation / "session6-8-completion-map.json").read_bytes()),
                         "execution_map_hash": _sha((validation / "session6-8-execution-map.json").read_bytes()),
                         "proof_manifest_hash": _sha((validation / "session6-8-proof-manifest.json").read_bytes()),
                         "requirement_proof_registry_hash": _sha((validation / "session6-8-requirement-proof-registry.json").read_bytes()),
                         "proof_fingerprint_audit_hash": _sha((validation / "session6-8-proof-fingerprint-audit.json").read_bytes()),
                         "claim_registry_hash": _sha((validation / "session6-8-claim-registry.json").read_bytes()),
                         "contract_inventory_hash": _sha((validation / "session6-8-contract-inventory.json").read_bytes()),
                         "workflow_contracts_hash": _sha((validation / "session6-8-workflow-contracts.json").read_bytes()),
                         "security_surface_registry_hash": _sha((validation / "session6-8-security-surface-registry.json").read_bytes()),
                         "junit_hash": _sha(junit), "workflow_receipt_hash": _sha(args.workflow_receipt.read_bytes()),
                         "behavioral_receipt_hash": _sha(args.behavioral_receipt.read_bytes()),
                         "security_receipt_hash": _sha(args.security_receipt.read_bytes()),
                         "contract_parity_report_hash": _sha(args.contract_parity_report.read_bytes()),
                         "wheel_receipt_hash": _sha(args.wheel_receipt.read_bytes()),
                         "proof_execution_receipt_hash": _sha(args.proof_receipt.read_bytes()),
                         "workflow_validation_hash": _sha(args.workflow_validation.read_bytes())},
              "claim_resolution_hash": _sha(args.claim_resolution.read_bytes()),
              "requirement_evidence_matrix_hash": _sha(args.evidence_matrix.read_bytes()) if args.evidence_matrix else None,
              "prerequisites": prerequisites, "resolved": all(prerequisites.values()), "report_self_hash": ""}
    report["report_self_hash"] = _sha(json.dumps({**report, "report_self_hash": ""}, sort_keys=True, separators=(",", ":")).encode())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if args.receipt is not None:
        receipt = {"schema_version": "session6-8-final-closeout-receipt.v1", "final_commit": commit,
                   "report_hash": _sha(args.output.read_bytes()), "report_self_hash": report["report_self_hash"]}
        receipt["receipt_hash"] = _sha(json.dumps({key: value for key, value in receipt.items() if key != "receipt_hash"}, sort_keys=True, separators=(",", ":")).encode())
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["resolved"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
