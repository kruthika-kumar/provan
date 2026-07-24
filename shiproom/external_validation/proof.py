from __future__ import annotations

"""Explicit synthetic proof runner; artifacts remain under the configured private root."""
import argparse
import json
import os
from pathlib import Path

from .adapters import ArmContext
from .corpus import validate_corpus
from .doctor import qualification
from .identity import canonical_json, case_id
from .lifecycle import run_five_arm_lifecycle
from .runner import DockerPolicy, tree_snapshot
from .scheduler import RunScheduler
from .security import sha256_file


def run_docker_five_arm_proof(evidence_root: Path, patient_root: Path, shiproom_root: Path) -> dict:
    """Create one disposable synthetic beta case and execute every arm in Docker."""
    if evidence_root.exists() or patient_root.exists():
        raise FileExistsError("proof_roots_must_be_fresh")
    qualified = qualification()
    if qualified.get("qualification_status") != "QUALIFIED":
        raise RuntimeError("docker_runtime_not_qualified")
    evidence_root.mkdir(parents=True)
    patient_root.mkdir(parents=True)
    (patient_root / "README.synthetic").write_text("synthetic Session 1 lifecycle fixture\n", encoding="utf-8")
    source = evidence_root / "source-snapshot.json"
    source.write_bytes(canonical_json(tree_snapshot(patient_root)))
    packet = evidence_root / "release-packet.json"
    packet.write_bytes(canonical_json({"release": "synthetic-v1", "network": "none", "tools": "none"}))
    snapshot = sha256_file(source)
    applicability = {name: "not_applicable" for name in ("ENGINEERING_EXECUTION", "PRODUCT_JOURNEY", "PRODUCT_MEASUREMENT", "DATA_CONTRACT_PIPELINE", "AI_EVAL")}
    authority = {"dataset": "beta", "snapshot": snapshot, "repository": "synthetic/session1", "commit_sha": "a" * 40,
                 "manifest_version": "1", "release_surfaces": ["ENGINEERING_EXECUTION"], "applicability": applicability}
    case = {"schema_id": "external_validation.beta_case", "schema_version": "1", "case_id": case_id(authority),
            "case_authority": authority, "repository": "synthetic/session1", "commit_sha": "a" * 40,
            "snapshot_hash": snapshot, "release_surfaces": ["ENGINEERING_EXECUTION"], "applicability": applicability,
            "visible_patient_root": str(patient_root.resolve())}
    context = ArmContext(case["case_id"], snapshot, sha256_file(packet), "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64, "sha256:" + "4" * 64)
    policy = DockerPolicy("busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028", timeout_seconds=60)
    scheduler = RunScheduler(evidence_root / "scheduler.sqlite")
    receipt_ids = run_five_arm_lifecycle(case=case, context=context, patient=patient_root, packet=packet, source_artifact=source,
                                          evidence_root=evidence_root, shiproom_root=shiproom_root, scheduler=scheduler, policy=policy,
                                          command={arm: ["sh", "-c", f"printf {arm} > /output/result.txt"] for arm in ("NATIVE_CHECKS_ONLY", "SHIPROOM_DETERMINISTIC_ONLY", "SHIPROOM_FULL", "SOTA_AGENT", "SHIPROOM_NO_DETERMINISTIC_CORE")})
    corpus = validate_corpus(evidence_root, shiproom_root, patient_root, case_manifest_ledger={case["case_id"]: case})
    return {"proof": "docker_five_arm_lifecycle", "qualification": qualified, "receipt_ids": receipt_ids, "corpus": corpus,
            "run_index": scheduler.index()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--patient-root", required=True, type=Path)
    parser.add_argument("--shiproom-root", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    os.environ["SHIPROOM_EXTERNAL_VALIDATION_ROOT"] = str(args.evidence_root.resolve())
    result = run_docker_five_arm_proof(args.evidence_root, args.patient_root, args.shiproom_root)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_bytes(canonical_json(result))
    print(json.dumps({"proof": result["proof"], "receipt_count": result["corpus"]["receipt_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
