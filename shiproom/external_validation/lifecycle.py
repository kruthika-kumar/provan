from __future__ import annotations

"""Host-supervised five-arm lifecycle used for synthetic qualification proofs."""
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import ARMS, ArmContext, DockerArmAdapter, assert_context_equivalence
from .identity import attempt_id, observation_key
from .receipts import finalize_receipt
from .runner import DockerPolicy
from .scheduler import RunScheduler
from .security import sha256_file


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _raw_receipt(case: dict[str, Any], arm: str, observation_inputs: dict[str, Any], lineage: int, result: dict[str, Any], source: Path, packet: Path, output_record: Path, command_log: Path, policy: DockerPolicy) -> dict[str, Any]:
    started = _now()
    receipt = {
        "schema_id": "external_validation.run_receipt", "schema_version": "1", "receipt_id": "",
        "observation_key": observation_key(observation_inputs), "observation_inputs": observation_inputs,
        "attempt_id": "", "attempt_lineage": lineage, "case_id": case["case_id"],
        "dataset": "beta", "snapshot_type": "buggy", "arm": arm,
        "repository": case["repository"], "pr_number": None, "maturity_band": "beta",
        "base_sha": case["commit_sha"], "target_sha": case["commit_sha"], "commit_sha": case["commit_sha"],
        "release_surfaces": case["release_surfaces"], "applicability": case["applicability"],
        "hashes": {"source": sha256_file(source), "release_packet": sha256_file(packet), "output": sha256_file(output_record), "receipt": ""},
        "versions": {"shiproom_commit": observation_inputs["system_version"], "container_image": policy.image_digest,
                     "model": "none", "model_version": "none", "prompt_version": observation_inputs["prompt_version"],
                     "policy_version": observation_inputs["policy_version"], "execution_policy_version": observation_inputs["execution_policy_version"],
                     "tool_policy_version": observation_inputs["tool_policy_version"], "price_version": "not_applicable"},
        "started_at": started, "completed_at": _now(), "terminal_state": result["terminal_state"], "termination": result["terminal_state"],
        "checks": {"attempted": [], "passed": [], "failed": [], "skipped": [], "skip_reasons": {}, "duration_seconds": result["wall_time_seconds"]},
        "model_usage": {"state": "not_applicable"}, "cost": {"state": "not_applicable"},
        "totals": {"wall_time_seconds": result["wall_time_seconds"], "local_compute_seconds": result["wall_time_seconds"], "model_cost_usd": 0, "external_tool_cost_usd": 0},
        "findings": [], "logs": {"command_log": sha256_file(command_log)}, "supervisor": "host_supervisor",
    }
    receipt["attempt_id"] = attempt_id(receipt["observation_key"], lineage)
    return receipt


def run_five_arm_lifecycle(*, case: dict[str, Any], context: ArmContext, patient: Path, packet: Path, source_artifact: Path,
                           evidence_root: Path, shiproom_root: Path, scheduler: RunScheduler, policy: DockerPolicy,
                           command: list[str] | dict[str, list[str]], system_version: str = "session1") -> dict[str, str]:
    """Run all arms through Docker, finalize a receipt per run, and index them durably.

    This function is intentionally for synthetic/proof cases only.  It does not
    select benchmark cases, models, or outcomes.
    """
    assert_context_equivalence({arm: context for arm in ARMS})
    if isinstance(command, dict) and set(command) != set(ARMS):
        raise ValueError("arm_command_set_incomplete")
    packet_hash = sha256_file(packet)
    if context.source_hash != sha256_file(source_artifact) or context.release_packet_hash != packet_hash:
        raise ValueError("lifecycle_context_artifact_mismatch")
    planned: dict[str, tuple[str, dict[str, Any]]] = {}
    for arm in ARMS:
        inputs = {"case_id": case["case_id"], "snapshot_hash": case["snapshot_hash"], "arm": arm,
                  "system_version": system_version, "prompt_version": "synthetic-v1", "policy_version": "synthetic-v1",
                  "model": "none", "model_settings": {}, "model_sampling_seed": None,
                  "tool_policy_version": "synthetic-v1", "execution_policy_version": "docker-v1", "cache_mode": "cold"}
        key = observation_key(inputs)
        planned[key] = (arm, inputs)
        scheduler.enqueue(key, attempt_id(key, 1))
    # Scheduling is a separate, persisted public-seed concern, never an observation identity.
    order = scheduler.freeze_schedule(list(planned), "synthetic-public-seed-v1")
    receipt_ids: dict[str, str] = {}
    for key in order:
        arm, inputs = planned[key]
        operation = "container_" + key.removeprefix("observation_")
        scheduler.begin_operation(key, operation)
        output = evidence_root / "outputs" / key
        arm_command = command[arm] if isinstance(command, dict) else command
        result = DockerArmAdapter(arm, policy, arm_command).run(context, patient=patient, packet=packet, output=output, shiproom_root=shiproom_root)
        output_record = evidence_root / "raw" / f"{key}.json"
        output_record.parent.mkdir(parents=True, exist_ok=True)
        from .identity import canonical_json
        output_record.write_bytes(canonical_json(result))
        command_log = Path(result["command_audit"]["host_log"])
        raw = _raw_receipt(case, arm, inputs, 1, result, source_artifact, packet, output_record, command_log, policy)
        finalized = finalize_receipt(raw, evidence_root / "receipts" / f"{key}.json", evidence_root, shiproom_root,
                                     patient, artifact_paths={"source": source_artifact, "release_packet": packet, "output": output_record}, case_manifest=case)
        scheduler.finalize(key, finalized["receipt_id"])
        receipt_ids[arm] = finalized["receipt_id"]
    return receipt_ids
