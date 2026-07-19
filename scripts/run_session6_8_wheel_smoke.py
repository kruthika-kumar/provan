"""Record an installed-wheel Sessions 6--8 lifecycle proof.

The exercised pytest scenario builds a wheel in a clean temporary directory,
installs it, and runs the connected local prepare/compile/load/show commands.
This wrapper produces a hash-bound receipt rather than treating console output
as the wheel closeout evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    command = ["pytest", "-q", "tests/test_assessment.py::test_installed_wheel_prepares_assessment_outside_source_checkout"]
    completed = subprocess.run(command, cwd=root, text=True, capture_output=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    receipt = {
        "schema_version": "session6-8-installed-wheel-receipt.v1",
        "final_commit": commit,
        "commands": [
            "assessment prepare",
            "measurement-ai prepare/compile/show",
            "remediation-roadmap prepare/compile/show",
            "review-plan prepare/render-package/show",
            "management-artifacts compile/show",
        ],
        "test_id": "test_installed_wheel_prepares_assessment_outside_source_checkout",
        "exit_code": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout_hash": _sha(completed.stdout.encode("utf-8")),
        "stderr_hash": _sha(completed.stderr.encode("utf-8")),
        "receipt_hash": "",
    }
    receipt["receipt_hash"] = _sha(json.dumps({key: value for key, value in receipt.items() if key != "receipt_hash"}, sort_keys=True, separators=(",", ":")).encode())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
