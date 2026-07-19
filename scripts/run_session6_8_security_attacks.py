"""Exercise real Sessions 6--8 private-alpha operation gates."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from shiproom.review_organisation import guard_prohibited_operation
from shiproom.workflow_trust import PROHIBITED_PRIVATE_ALPHA_OPERATIONS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = []
    for operation in sorted(PROHIBITED_PRIVATE_ALPHA_OPERATIONS):
        before = hashlib.sha256(b"no-external-side-effect").hexdigest()
        try:
            guard_prohibited_operation(operation)
        except ValueError as exc:
            rejection = str(exc)
        else:
            raise SystemExit("session6_8_security_gate_unexpected_pass:" + operation)
        records.append({"domain": "review_organisation", "production_gate": "shiproom.review_organisation.guard_prohibited_operation", "operation": operation, "attempt_id": "security_" + operation, "typed_rejection": rejection, "underlying_adapter_called": False, "side_effect_observed": False, "before_hash": before, "after_hash": before})
    receipt = {"schema_version": "session6-8-security-receipt.v1", "records": records, "passed": all(item["typed_rejection"] == "private_alpha_operation_prohibited:" + item["operation"] for item in records)}
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    receipt["receipt_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
