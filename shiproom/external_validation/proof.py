"""Canonical v2 five-arm proof entry point.

The former v1 lifecycle remains readable historical material only.  This
module deliberately delegates to the supervisor-owned v2 pipeline so there is
no alternate, less-hardened public proof path.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .doctor import qualification
from .proof_v2 import run_five_arm_v2_proof
from .runner_v2 import ExecutionPolicyV2


def run_docker_five_arm_proof(evidence_root: Path, patient_root: Path, shiproom_root: Path) -> dict:
    if patient_root.exists():
        raise ValueError("v2_proof_patient_root_is_supervisor_materialized")
    qualified = qualification()
    if qualified["detection_profile"]["status"] != "QUALIFIED":
        raise RuntimeError("docker_detection_profile_not_qualified")
    image = os.environ["SHIPROOM_DOCKER_V2_IMAGE"]
    seccomp = Path(os.environ["SHIPROOM_DOCKER_V2_SECCOMP"])
    policy = ExecutionPolicyV2(image_digest=image, runner_image_digest=image,
        security_policy_hash="sha256:" + "0" * 64, resource_policy_hash="sha256:" + "1" * 64,
        seccomp_profile=seccomp, wall_seconds=60)
    original = os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT")
    os.environ["SHIPROOM_EXTERNAL_VALIDATION_ROOT"] = str(evidence_root.resolve())
    try:
        return run_five_arm_v2_proof(evidence_root, policy, shiproom_root)
    finally:
        if original is None: os.environ.pop("SHIPROOM_EXTERNAL_VALIDATION_ROOT", None)
        else: os.environ["SHIPROOM_EXTERNAL_VALIDATION_ROOT"] = original


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--patient-root", required=True, type=Path)
    parser.add_argument("--shiproom-root", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    result = run_docker_five_arm_proof(args.evidence_root, args.patient_root, args.shiproom_root)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    print(json.dumps({"proof": "docker_five_arm_v2", "receipt_count": result["corpus"]["receipt_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
