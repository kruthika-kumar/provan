"""Capability-scoped, fail-closed Docker qualification for receipt v2."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import uuid

from .proof_v2 import run_five_arm_v2_proof
from .runner import docker_available
from .runner_v2 import ExecutionPolicyV2, create_argv, validate_create_argv


DETECTION_CONTROLS = (
    "linux_engine", "immutable_runner", "effective_inspect", "non_root_identities",
    "capabilities_and_no_new_privileges", "network", "readonly_mounts", "secret_oracle_control",
    "resources", "timeout_cleanup", "residual_absence", "transfer_protocol", "bounded_logs", "cache_isolation",
    "five_arm_parity", "supervisor_corpus",
)
REMEDIATION_CONTROLS = ("isolated_worktree", "detection_write_denied", "controlled_write", "real_diff", "hard_worktree_quota")


def _profile(status: str, controls: tuple[str, ...], reason: str | None = None) -> dict:
    value = {"status": status, "controls": {name: "inconclusive" for name in controls}}
    if reason: value["reason"] = reason
    return value


def _base_result(status: str, reason: str, *, failed: bool = False) -> dict:
    return {"detection_profile": _profile("FAILED" if failed else status, DETECTION_CONTROLS, reason),
            "remediation_profile": _profile("BLOCKED", REMEDIATION_CONTROLS, "hard_writable_worktree_quota_not_qualified"),
            "overall_status": "FAILED" if failed else "PARTIALLY_QUALIFIED"}


def _clean_commit(repository: Path) -> tuple[str, str]:
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=repository, capture_output=True, text=True, check=True).stdout
    if dirty.strip(): raise RuntimeError("qualification_worktree_not_clean")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, text=True, check=True).stdout.strip()
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository, capture_output=True, text=True, check=True).stdout.strip()
    return commit, tree


def qualification(*, run_dynamic: bool = True) -> dict:
    """Qualify detection only from a clean source tree and real v2 receipts.

    Writable remediation deliberately remains blocked until a host proves a
    hard worktree quota.  A successful detection result authorizes no writes.
    """
    if not docker_available(): return _base_result("BLOCKED", "docker_linux_engine_unavailable")
    image, seccomp = os.environ.get("SHIPROOM_DOCKER_V2_IMAGE"), os.environ.get("SHIPROOM_DOCKER_V2_SECCOMP")
    if not image or "@sha256:" not in image or not seccomp: return _base_result("BLOCKED", "pinned_runner_image_or_seccomp_not_configured")
    repository = Path.cwd().resolve()
    try:
        commit, tree = _clean_commit(repository)
        policy = ExecutionPolicyV2(image_digest=image, runner_image_digest=image, security_policy_hash="sha256:" + "0" * 64,
            resource_policy_hash="sha256:" + "1" * 64, seccomp_profile=Path(seccomp).resolve(), wall_seconds=30)
        # This rejects dangerous argv before asking Docker to construct a canary.
        validate_create_argv(create_argv(policy, name="shiproom-doctor-static", cidfile=(repository / ".doctor.cid").resolve(), patient=repository, packet=repository, backend_label="doctor"))
    except Exception as exc:
        return _base_result("FAILED", f"static_policy_or_clean_tree_failed:{type(exc).__name__}", failed=True)
    if not run_dynamic:
        return _base_result("BLOCKED", "dynamic_v2_canary_matrix_not_recorded")
    configured_root = os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT")
    if not configured_root: return _base_result("BLOCKED", "external_validation_root_not_configured")
    parent = Path(configured_root).resolve()
    if not parent.exists() or parent == repository or repository in parent.parents or parent in repository.parents:
        return _base_result("FAILED", "external_validation_root_invalid", failed=True)
    proof_root = parent / ("doctor-v2-" + uuid.uuid4().hex)
    old_root = os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT")
    os.environ["SHIPROOM_EXTERNAL_VALIDATION_ROOT"] = str(proof_root)
    try:
        proof = run_five_arm_v2_proof(proof_root, policy, repository)
        if proof["implementation_commit"] != commit or proof["corpus"]["receipt_count"] != 5:
            raise RuntimeError("doctor_proof_commit_or_corpus_mismatch")
    except Exception as exc:
        return _base_result("FAILED", f"dynamic_v2_canary_failed:{type(exc).__name__}", failed=True)
    finally:
        os.environ["SHIPROOM_EXTERNAL_VALIDATION_ROOT"] = old_root
    detection = _profile("QUALIFIED", DETECTION_CONTROLS)
    detection["controls"] = {control: "proven" for control in DETECTION_CONTROLS}
    detection.update({"implementation_commit": commit, "source_tree": tree, "private_proof_index": proof["index"], "receipt_ids": proof["receipt_ids"]})
    remediation = _profile("BLOCKED", REMEDIATION_CONTROLS, "hard_writable_worktree_quota_not_qualified")
    return {"detection_profile": detection, "remediation_profile": remediation, "overall_status": "PARTIALLY_QUALIFIED"}


def main() -> int:
    result = qualification(); print(json.dumps(result, sort_keys=True))
    return 0 if result["overall_status"] == "QUALIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
