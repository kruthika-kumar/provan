"""Independently replay the frozen Sessions 6--8 workflow contracts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.session6_8_evidence_query import evaluate
from shiproom.session6_8_semantics import validate_workflow_contracts


ROOT = Path(__file__).resolve().parents[1]


def validate(receipt_path: Path, *, root: Path = ROOT) -> dict:
    contracts_value = json.loads((root / "docs/validation/session6-8-workflow-contracts.json").read_text(encoding="utf-8"))
    validate_workflow_contracts(contracts_value)
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
            if assertion["assertion_type"] != "artifact_query" or assertion["named_assertion_function"] is not None:
                raise ValueError("workflow_assertion_contract_invalid")
            artifact = (root / assertion["artifact_path"]).resolve()
            if not artifact.is_file():
                raise ValueError("workflow_assertion_artifact_missing")
            relative=artifact.relative_to((root/".shiproom/local").resolve()).as_posix()
            query={"artifact":relative,"selector":assertion["json_pointer"],"operator":assertion["comparator"],"expected":assertion["expected_value"]}
            if not evaluate(root/".shiproom/local",query).passed:
                raise ValueError("workflow_assertion_replay_failed")
            declared=[digest for name,digest in case.get("canonical_artifact_hashes",{}).items() if name.replace("\\","/").endswith("/"+relative)]
            import hashlib
            if len(declared)!=1 or declared[0] != "sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest():
                raise ValueError("workflow_assertion_artifact_hash_mismatch")
            assertion_count += 1
        canonical_names=list(case.get("canonical_artifact_hashes",{}))
        for required in contract["required_artifacts"]:
            stem=Path(required).stem.rstrip("s")
            if not any(stem in Path(name).stem.rstrip("s") or stem in name for name in canonical_names):
                raise ValueError("workflow_required_artifact_missing")
        if not case.get("generated_artifact_hashes") or any(value in (None, "") for value in case["generated_artifact_hashes"].values()):
            raise ValueError("workflow_artifact_binding_missing")
    return {"schema_version": "session6-8-workflow-validation.v1", "case_count": 18,
            "assertion_count": assertion_count, "status": "passed"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result=validate(args.receipt)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
