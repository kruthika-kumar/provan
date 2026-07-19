"""Independently validate a hash-bound Sessions 6--8 closeout report."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True).stdout.strip()
    expected = _hash({**report, "report_self_hash": ""})
    if report.get("final_commit") != commit or report.get("report_self_hash") != expected or not report.get("resolved"):
        raise SystemExit("session6_8_closeout_report_invalid")
    if receipt.get("report_hash") != "sha256:" + hashlib.sha256(args.report.read_bytes()).hexdigest() or receipt.get("final_commit") != commit:
        raise SystemExit("session6_8_closeout_receipt_invalid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
