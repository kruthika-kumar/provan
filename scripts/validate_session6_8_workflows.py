"""Independently replay the frozen Sessions 6--8 workflow contracts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pointer(value: object, pointer: str) -> object:
    current = value
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise ValueError("workflow_assertion_pointer_unresolved")
    return current


def _compare(actual: object, comparator: str, expected: object) -> bool:
    if comparator == "equals":
        return actual == expected
    if comparator == "minimum":
        return isinstance(actual, (int, float)) and actual >= expected
    if comparator == "contains":
        return expected in actual
    raise ValueError("workflow_assertion_comparator_unregistered")


def validate(receipt_path: Path, *, root: Path = ROOT) -> dict:
    contracts_value = json.loads((root / "docs/validation/session6-8-workflow-contracts.json").read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    cases = receipt.get("cases")
    contracts = contracts_value.get("cases")
    if not isinstance(cases, list) or not isinstance(contracts, list) or len(cases) != 18 or len(contracts) != 18:
        raise ValueError("workflow_contract_cardinality_invalid")
    by_name = {row.get("name"): row for row in cases}
    if set(by_name) != {row.get("case_name") for row in contracts}:
        raise ValueError("workflow_contract_names_mismatch")
    assertion_count = 0
    for contract in contracts:
        case = by_name[contract["case_name"]]
        observed = {row.get("qualified_function") for row in case.get("production_invocations", [])}
        if not set(contract["required_production_functions"]).issubset(observed):
            raise ValueError("workflow_required_invocation_missing")
        for assertion in contract["assertions"]:
            if assertion["assertion_type"] != "artifact_pointer" or assertion["named_assertion_function"] is not None:
                raise ValueError("workflow_assertion_contract_invalid")
            artifact = root / assertion["artifact_path"]
            if not artifact.is_file():
                raise ValueError("workflow_assertion_artifact_missing")
            value = json.loads(artifact.read_text(encoding="utf-8"))
            actual = _pointer(value, assertion["json_pointer"])
            if not _compare(actual, assertion["comparator"], assertion["expected_value"]):
                raise ValueError("workflow_assertion_replay_failed")
            expected_hash = case.get("generated_artifact_hashes", {}).get("workflow_evidence")
            if expected_hash != _sha(artifact.read_bytes()):
                raise ValueError("workflow_assertion_artifact_hash_mismatch")
            assertion_count += 1
        if not case.get("generated_artifact_hashes") or any(value in (None, "") for value in case["generated_artifact_hashes"].values()):
            raise ValueError("workflow_artifact_binding_missing")
    return {"schema_version": "session6-8-workflow-validation.v1", "case_count": 18,
            "assertion_count": assertion_count, "status": "passed"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.receipt), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
