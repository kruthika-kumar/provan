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
    return passed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--workflow-receipt", type=Path, required=True)
    parser.add_argument("--behavioral-receipt", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    validation = root / "docs" / "validation"
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
    proof_ids = {item["proof_id"] for item in proofs}
    requirements = {item["requirement_id"] for item in completion}
    execution_requirements = {item["requirement_id"] for item in execution}
    covered = {item for claim in claims for item in claim["requirement_ids"]}
    workflow_cases = workflow.get("cases", [])
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    valid_fixture_classes = {"valid", "near_valid", "adversarial_invalid"}
    prerequisites = {
        "completion_map_exhaustive": requirements == {item["requirement_id"] for item in proofs} == covered == execution_requirements,
        "execution_map_bound": all(item.get("status") == "verified" and item.get("production_boundary") and item.get("proof_ids") for item in execution),
        "all_proofs_verified": all(item["status"] == "verified" and item["fixture_class"] in valid_fixture_classes and item["test_id"] in passed_tests and bool(item.get("production_function")) and bool(item.get("canonical_artifact")) for item in proofs),
        "all_requirements_verified": all(item.get("status") == "verified" for item in completion),
        "all_claims_bound": all(set(claim["positive_proof_ids"] + claim["near_valid_proof_ids"] + claim["adversarial_proof_ids"]) <= proof_ids for claim in claims),
        "junit_present": bool(junit),
        "workflow_receipt_complete": len(workflow_cases) == 18 and all(item.get("passed") for item in workflow_cases),
        "behavioral_receipt_complete": len(behavioral.get("cases", [])) == 35 and all(item.get("passed") for item in behavioral["cases"]),
        "receipts_match_final_commit": workflow.get("final_commit") == commit and behavioral.get("final_commit") == commit,
        "contract_inventory_bound": {item["contract_id"] for item in inventory if item.get("parity_required")} == {item["contract_name"] for item in contracts} and all(item.get("requirement_ids") for item in contracts),
    }
    report = {"schema_version": "session6-8-closeout-report.v2", "final_commit": commit,
              "inputs": {"completion_map_hash": _sha((validation / "session6-8-completion-map.json").read_bytes()),
                         "execution_map_hash": _sha((validation / "session6-8-execution-map.json").read_bytes()),
                         "proof_manifest_hash": _sha((validation / "session6-8-proof-manifest.json").read_bytes()),
                         "claim_registry_hash": _sha((validation / "session6-8-claim-registry.json").read_bytes()),
                         "contract_inventory_hash": _sha((validation / "session6-8-contract-inventory.json").read_bytes()),
                         "junit_hash": _sha(junit), "workflow_receipt_hash": _sha(args.workflow_receipt.read_bytes()),
                         "behavioral_receipt_hash": _sha(args.behavioral_receipt.read_bytes())},
              "prerequisites": prerequisites, "resolved": all(prerequisites.values()), "report_self_hash": ""}
    report["report_self_hash"] = _sha(json.dumps({**report, "report_self_hash": ""}, sort_keys=True, separators=(",", ":")).encode())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["resolved"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
