"""Resolve one Sessions 6--8 claim per approved requirement from raw receipts."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from pathlib import Path
from shiproom.session6_8_evidence_query import evaluate

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from scripts.validate_session6_8_contract_parity import validate as validate_parity
    from scripts.validate_session6_8_proof_execution import validate as validate_proofs
    from scripts.validate_session6_8_security_receipt import validate as validate_security
    from scripts.validate_session6_8_wheel_receipt import validate as validate_wheel
    from scripts.validate_session6_8_workflows import validate as validate_workflows
except ModuleNotFoundError:
    from validate_session6_8_contract_parity import validate as validate_parity
    from validate_session6_8_proof_execution import validate as validate_proofs
    from validate_session6_8_security_receipt import validate as validate_security
    from validate_session6_8_wheel_receipt import validate as validate_wheel
    from validate_session6_8_workflows import validate as validate_workflows


ROOT = Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_symbol(reference: str) -> None:
    module_name, _, attribute = reference.rpartition(".")
    if not module_name or not attribute:
        raise ValueError("claim_implementation_symbol_invalid")
    module = importlib.import_module(module_name)
    if not hasattr(module, attribute):
        raise ValueError("claim_implementation_symbol_missing")


def _measured_count(value: object) -> int:
    if isinstance(value,bool): return 1 if value else 0
    if isinstance(value,int): return max(value,0)
    if isinstance(value,(list,dict,str)): return len(value)
    return 1 if value is not None else 0


def resolve(*, proof_path: Path, workflow_path: Path, parity_path: Path,
            security_path: Path, wheel_path: Path, output: Path) -> dict:
    requirements = json.loads((ROOT / "docs/validation/session6-8-requirement-inventory.json").read_text(encoding="utf-8"))["requirements"]
    claims = json.loads((ROOT / "docs/validation/session6-8-claim-registry.json").read_text(encoding="utf-8"))["claims"]
    if len(requirements) != 106 or len(claims) != 106:
        raise ValueError("claim_requirement_cardinality_invalid")
    requirement_ids = {row["requirement_id"] for row in requirements}
    claim_ids = [row["claim_id"] for row in claims]
    if len(set(claim_ids)) != 106:
        raise ValueError("claim_id_duplicate")
    if {tuple(row.get("requirement_ids", [])) for row in claims} != {(rid,) for rid in requirement_ids}:
        raise ValueError("claim_requirement_bijection_invalid")
    validate_proofs(proof_path)
    workflow_validation = validate_workflows(workflow_path)
    parity_validation = validate_parity(parity_path)
    security_validation = validate_security(security_path)
    wheel_validation = validate_wheel(wheel_path)
    proof_value = json.loads(proof_path.read_text(encoding="utf-8"))
    proof_rows = {row["proof_id"]: row for row in proof_value["proofs"]}
    resolved = []
    for claim in claims:
        rid = claim["requirement_ids"][0]
        if not claim.get("implementation_symbols"):
            raise ValueError("claim_implementation_symbol_missing")
        for symbol in claim["implementation_symbols"]:
            _resolve_symbol(symbol)
        groups = (claim["positive_proof_ids"], claim["near_valid_proof_ids"], claim["adversarial_proof_ids"])
        if any(len(group) < 1 for group in groups):
            raise ValueError("claim_proof_class_missing")
        selected = [proof_rows[pid] for group in groups for pid in group]
        if any(row["requirement_id"] != rid for row in selected):
            raise ValueError("claim_proof_binding_invalid")
        if {row["fixture_class"] for row in selected} != {"valid", "near_valid", "adversarial_invalid"}:
            raise ValueError("claim_proof_class_incomplete")
        configured_assertions = claim.get("artifact_queries")
        counts = claim.get("minimum_record_counts")
        if not configured_assertions or not counts or any(value < 1 for value in counts.values()):
            raise ValueError("claim_evidence_assertion_vacuous")
        measured=[]; invocation_ids=[]; measured_assertions=[]
        for row in selected:
            expected=row["fixture_class"]!="adversarial_invalid"
            if row.get("actual_acceptance")!=expected:
                raise ValueError("claim_proof_outcome_invalid")
            if not expected and not row.get("actual_error_code"):
                raise ValueError("claim_proof_rejection_invalid")
            paths=row.get("artifact_paths",[])
            if not paths:
                raise ValueError("claim_proof_artifact_cardinality_invalid")
            for relative in paths:
                artifact_path=proof_path.parent/relative
                if not artifact_path.is_file() or row.get("artifact_hashes",{}).get(relative)!=_sha(artifact_path):
                    raise ValueError("claim_proof_artifact_hash_invalid")
            proof_assertions=row.get("artifact_assertions",[])
            if not proof_assertions: raise ValueError("claim_proof_artifact_binding_invalid")
            replayed=[]
            for assertion in proof_assertions:
                replay=evaluate(proof_path.parent,assertion["query"])
                if not replay.passed or replay.actual!=assertion["actual"] or replay.cardinality!=assertion["cardinality"]:
                    raise ValueError("claim_proof_artifact_assertion_invalid")
                replayed.append({"selector":assertion["query"]["selector"],"operator":assertion["query"]["operator"],"actual":replay.actual,"cardinality":replay.cardinality})
            measured_assertions.extend({"proof_id":row["proof_id"],**item} for item in replayed)
            count=max(item["cardinality"] for item in replayed)
            if expected and count<row["minimum_record_count"]:
                raise ValueError("claim_measured_cardinality_invalid")
            if count!=row.get("actual_record_count"):
                raise ValueError("claim_configured_minimum_substitution")
            measured.append({"proof_id":row["proof_id"],"artifact_hashes":row["artifact_hashes"],"artifact_assertions":replayed,"measured_cardinality":count,"actual_error_code":row.get("actual_error_code")})
            invocation_ids.extend(row.get("production_invocation_ids",[]))
        expected_functions=set(claim.get("production_invocation_receipts",[]))
        observed_functions={item.get("qualified_function") for row in selected for item in row.get("production_invocations",[])}
        if expected_functions and not expected_functions.issubset(observed_functions):
            raise ValueError("claim_production_invocation_missing")
        resolved.append({"claim_id": claim["claim_id"], "requirement_id": rid,
                         "proof_ids": [row["proof_id"] for row in selected],
                         "evidence_assertions": measured_assertions, "minimum_record_counts": counts,
                         "measured_evidence":measured,"production_invocation_ids":sorted(set(invocation_ids)),
                         "resolved": True})
    commit = proof_value["final_commit"]
    if json.loads(wheel_path.read_text(encoding="utf-8")).get("final_commit") != commit:
        raise ValueError("claim_evidence_commit_mismatch")
    result = {"schema_version": "session6-8-claim-resolution-receipt.v1", "final_commit": commit,
              "requirement_count": 106, "claim_count": 106, "resolved_claim_count": len(resolved),
              "supporting_validations": {"workflow": workflow_validation, "parity": parity_validation,
                                          "security": security_validation, "wheel": wheel_validation},
              "input_hashes": {"proof": _sha(proof_path), "workflow": _sha(workflow_path),
                               "parity": _sha(parity_path), "security": _sha(security_path), "wheel": _sha(wheel_path)},
              "claims": resolved, "receipt_hash": ""}
    result["receipt_hash"] = "sha256:" + hashlib.sha256(json.dumps({k: v for k, v in result.items() if k != "receipt_hash"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--parity", type=Path, required=True)
    parser.add_argument("--security", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = resolve(proof_path=args.proof, workflow_path=args.workflow, parity_path=args.parity,
                     security_path=args.security, wheel_path=args.wheel, output=args.output)
    print(json.dumps({"claim_count": result["claim_count"], "status": "passed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
