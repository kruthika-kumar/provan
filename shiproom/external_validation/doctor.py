"""Capability-scoped Docker qualification for the reopened Session 1 substrate."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from .runner import docker_available, docker_executable
from .runner_v2 import ExecutionPolicyV2, create_argv, validate_create_argv


DETECTION_CONTROLS = (
    "linux_engine", "immutable_runner", "effective_inspect", "non_root_identities",
    "capabilities_and_no_new_privileges", "network", "readonly_mounts", "secret_oracle_control",
    "resources", "timeout_cleanup", "residual_absence", "transfer_protocol", "bounded_logs", "cache_isolation",
)
REMEDIATION_CONTROLS = ("isolated_worktree", "detection_write_denied", "controlled_write", "real_diff", "hard_worktree_quota")


def _profile(status: str, controls: tuple[str, ...], reason: str | None = None) -> dict:
    value = {"status": status, "controls": {name: "inconclusive" for name in controls}}
    if reason: value["reason"] = reason
    return value


def qualification() -> dict:
    """Never return qualified from static argv validation or a partial canary."""
    if not docker_available():
        return {"detection_profile": _profile("BLOCKED", DETECTION_CONTROLS, "docker_linux_engine_unavailable"),
                "remediation_profile": _profile("BLOCKED", REMEDIATION_CONTROLS, "docker_linux_engine_unavailable"),
                "overall_status": "PARTIALLY_QUALIFIED"}
    image = os.environ.get("SHIPROOM_DOCKER_V2_IMAGE")
    seccomp = os.environ.get("SHIPROOM_DOCKER_V2_SECCOMP")
    if not image or "@sha256:" not in image or not seccomp:
        return {"detection_profile": _profile("BLOCKED", DETECTION_CONTROLS, "pinned_runner_image_or_seccomp_not_configured"),
                "remediation_profile": _profile("BLOCKED", REMEDIATION_CONTROLS, "quota_capability_not_configured"),
                "overall_status": "PARTIALLY_QUALIFIED"}
    policy = ExecutionPolicyV2(image_digest=image, runner_image_digest=image, security_policy_hash="sha256:" + "0" * 64,
                               resource_policy_hash="sha256:" + "1" * 64, seccomp_profile=Path(seccomp), wall_seconds=20)
    try:
        # A static failure is a failed doctor, not a qualified substitute.
        argv = create_argv(policy, name="shiproom-doctor-static", cidfile=Path.cwd() / ".doctor.cid", patient=Path.cwd(), packet=Path.cwd().parent, backend_label="doctor")
        validate_create_argv(argv)
    except Exception as exc:
        return {"detection_profile": _profile("FAILED", DETECTION_CONTROLS, type(exc).__name__),
                "remediation_profile": _profile("BLOCKED", REMEDIATION_CONTROLS, "detection_policy_failed"), "overall_status": "FAILED"}
    # Dynamic canaries are deliberately delegated to the runner/proof module.
    # Until every listed control has a persisted v2 proof receipt, qualification
    # remains blocked instead of treating an argv check as runtime evidence.
    return {"detection_profile": _profile("BLOCKED", DETECTION_CONTROLS, "dynamic_v2_canary_matrix_not_recorded"),
            "remediation_profile": _profile("BLOCKED", REMEDIATION_CONTROLS, "quota_capability_not_recorded"),
            "overall_status": "PARTIALLY_QUALIFIED"}


def main() -> int:
    result = qualification(); print(json.dumps(result, sort_keys=True))
    return 0 if result["overall_status"] == "QUALIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
