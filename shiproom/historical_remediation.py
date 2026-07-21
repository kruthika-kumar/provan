"""Disposable historical controlled-remediation patient.

This module is intentionally separate from private-alpha roadmaps: it creates
an isolated temporary Git repository, applies one allowlisted deterministic
fixture correction, reruns the exact fixture check, and destroys the patient.
It never merges, pushes, or writes to the Shiproom checkout.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from shiproom.workflow_audit import observed_boundary


def _run(directory: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=directory, text=True, capture_output=True, check=True).stdout.strip()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@observed_boundary
def run_controlled_patient(shiproom_root: Path) -> dict:
    before = _run(shiproom_root, "status", "--porcelain=v1")
    original_branch = _run(shiproom_root, "branch", "--show-current")
    with tempfile.TemporaryDirectory(prefix="shiproom-historical-remediation-") as raw:
        patient = Path(raw) / "patient"; patient.mkdir()
        _run(patient, "init")
        _run(patient, "config", "user.email", "shiproom@example.invalid")
        _run(patient, "config", "user.name", "Shiproom controlled patient")
        target = patient / "route.txt"; target.write_text("BROKEN_ROUTE\n", encoding="utf-8")
        _run(patient, "add", "route.txt"); _run(patient, "commit", "-m", "baseline broken route")
        base = _run(patient, "rev-parse", "HEAD")
        _run(patient, "switch", "-c", "bounded-route-remediation")
        failed_check_before = target.read_text(encoding="utf-8") == "HEALTHY_ROUTE\n"
        target.write_text("HEALTHY_ROUTE\n", encoding="utf-8")
        changed = _run(patient, "diff", "--name-only").splitlines()
        if changed != ["route.txt"]:
            raise ValueError("historical_remediation_allowlist_violation")
        exact_rerun_passed = target.read_text(encoding="utf-8") == "HEALTHY_ROUTE\n"
        if failed_check_before or not exact_rerun_passed:
            raise ValueError("historical_remediation_exact_rerun_invalid")
        # There is deliberately no commit, merge, remote, or push.  Resetting
        # the disposable patient proves cleanup and leaves it clean before the
        # temporary directory is removed.
        _run(patient, "reset", "--hard", base)
        if _run(patient, "status", "--porcelain=v1"):
            raise ValueError("historical_remediation_cleanup_failed")
    after = _run(shiproom_root, "status", "--porcelain=v1")
    receipt = {
        "schema_version": "historical-remediation-receipt.v1",
        "status": "verified",
        "original_branch": original_branch,
        "temporary_branch": "bounded-route-remediation",
        "allowlisted_files": ["route.txt"],
        "exact_failed_check_before": not failed_check_before,
        "exact_rerun_passed": exact_rerun_passed,
        "merge_performed": False,
        "cleanup_completed": True,
        "source_repository_unchanged": before == after,
        "source_status_before_hash": _sha(before.encode("utf-8")),
        "source_status_after_hash": _sha(after.encode("utf-8")),
        "receipt_hash": "",
    }
    receipt["receipt_hash"] = _sha(json.dumps({key: value for key, value in receipt.items() if key != "receipt_hash"}, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return receipt
