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
