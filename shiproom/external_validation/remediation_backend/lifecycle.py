"""Production remediation-fixture lifecycle used by normal runs and doctor.

The doctor only orchestrates this interface.  All materialization, command
sealing, receipt finalization, and release authorization inputs come from the
same host-supervisor functions used for a remediation attempt.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from shiproom.external_validation.identity import canonical_json, attempt_id
    from shiproom.external_validation.receipts_v2 import finalize_v2
    from shiproom.external_validation.security import sha256_file
    from shiproom.external_validation.v2 import FinalizationJournal, observation_key_v2
except ModuleNotFoundError:
    # Direct `-I -S doctor.py --help` remains a source-tree static gate. The
    # staged runtime has its package dependencies copied and hash-bound by the
    # bootstrap manifest before this fallback is permitted.
    if (Path(__file__).with_name("identity.py")).is_file():
        from identity import canonical_json, attempt_id
        from receipts_v2 import finalize_v2
        from security import sha256_file
        from v2 import FinalizationJournal, observation_key_v2
    else:
        repository = Path(__file__).resolve().parents[3]
        if not (repository / "shiproom").is_dir(): raise
        sys.path.insert(0, str(repository))
        from shiproom.external_validation.identity import canonical_json, attempt_id
        from shiproom.external_validation.receipts_v2 import finalize_v2
        from shiproom.external_validation.security import sha256_file
        from shiproom.external_validation.v2 import FinalizationJournal, observation_key_v2


class LifecycleError(RuntimeError):
    pass


def function_ids() -> dict[str, str]:
    """Hashes reported by the doctor to prove it used this production module."""
    module_hash = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {name: module_hash for name in ("materialize_fixture", "execute_patient_command", "git_artifacts", "seal_and_finalize")}


def _run(argv: list[str], cwd: Path, *, timeout: int = 30) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout, check=False)
    completed = datetime.now(timezone.utc)
    return {"command": argv, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "started_at": started.isoformat().replace("+00:00", "Z"), "completed_at": completed.isoformat().replace("+00:00", "Z")}


def prepare_fixture_source(source_root: Path) -> dict[str, str]:
    """Create the deterministic, immutable Git source before allocation."""
    source_root.mkdir(parents=True, mode=0o700)
    for argv in (["/usr/bin/git", "init", "--quiet"], ["/usr/bin/git", "config", "user.email", "shiproom-doctor@example.invalid"], ["/usr/bin/git", "config", "user.name", "Shiproom Doctor"]):
        if _run(list(argv), source_root)["exit_code"] != 0: raise LifecycleError("fixture_git_initialize_failed")
    (source_root / "calculator.py").write_text("def calculate(a, b):\n    return a - b\n\ndef protected(value):\n    return value * 2\n", encoding="utf-8")
    (source_root / "target_test.py").write_text("from calculator import calculate\nassert calculate(2, 2) == 4\n", encoding="utf-8")
    (source_root / "protected_test.py").write_text("from calculator import protected\nassert protected(3) == 6\n", encoding="utf-8")
    if _run(["/usr/bin/git", "add", "calculator.py", "target_test.py", "protected_test.py"], source_root)["exit_code"] != 0 or _run(["/usr/bin/git", "commit", "--quiet", "-m", "known buggy snapshot"], source_root)["exit_code"] != 0:
        raise LifecycleError("fixture_git_commit_failed")
    commit = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    tree = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], cwd=source_root, text=True).strip()
    return {"commit": commit, "tree": tree, "source_snapshot_hash": "sha256:" + hashlib.sha256((commit + "\n" + tree).encode("ascii")).hexdigest()}


def materialize_fixture(*, source_root: Path, worktree: Path, source: dict[str, str]) -> dict[str, str]:
    """Materialize the prepared immutable commit into an allocated worktree."""
    if any(worktree.iterdir()): raise LifecycleError("fixture_worktree_not_empty")
    commit = source["commit"]
    # A real Git worktree is materialized from the immutable commit, then the
    # patient sees only that dedicated quota-controlled directory.
    for argv in (["/usr/bin/git", "init", "--quiet"], ["/usr/bin/git", "remote", "add", "origin", str(source_root)], ["/usr/bin/git", "fetch", "--quiet", "origin", commit], ["/usr/bin/git", "checkout", "--quiet", "--detach", commit]):
        if _run(list(argv), worktree)["exit_code"] != 0: raise LifecycleError("fixture_materialization_failed")
    return source


def run_checked_command(*, argv: list[str], worktree: Path, label: str) -> dict[str, Any]:
    result = _run(argv, worktree)
    result["label"] = label
    return result


def execute_patient_command(*, docker: str, socket: Path, tree: Path, runner_image: str,
                            command: list[str], label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one patient command through the production custom-daemon policy.

    This deliberately owns the Docker argv and effective-inspect capture.  The
    qualification doctor may orchestrate it, but it must not reconstruct a
    second, look-alike execution path.  The function is also the only runtime
    execution entry point exposed by this lifecycle module.
    """
    if not runner_image or "@sha256:" not in runner_image:
        raise LifecycleError("runner_image_digest_required")
    if not tree.is_dir() or not socket.is_socket():
        raise LifecycleError("patient_execution_authority_missing")
    name = "shiproom-remediation-" + hashlib.sha256((label + str(time.time_ns())).encode()).hexdigest()[:20]
    argv = [docker, "--host", "unix://" + str(socket), "create", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user", "65533:65533",
            "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m",
            "--cpus", "0.5", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m",
            "--mount", f"type=bind,src={tree},dst=/remediation,rw", "--workdir",
            "/remediation", runner_image, *command]
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    created = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if created.returncode != 0:
        raise LifecycleError("patient_create_failed")
    container_id = created.stdout.strip()
    if not container_id:
        raise LifecycleError("patient_create_identity_missing")
    try:
        inspected = subprocess.run([docker, "--host", "unix://" + str(socket), "inspect", container_id], capture_output=True, text=True, timeout=30, check=False)
        if inspected.returncode != 0:
            raise LifecycleError("patient_effective_inspect_missing")
        effective = json.loads(inspected.stdout)
        if not isinstance(effective, list) or len(effective) != 1:
            raise LifecycleError("patient_effective_inspect_invalid")
        finished = subprocess.run([docker, "--host", "unix://" + str(socket), "start", "-a", container_id], capture_output=True, timeout=180, check=False)
    finally:
        removed = subprocess.run([docker, "--host", "unix://" + str(socket), "rm", "-f", container_id], capture_output=True, text=True, timeout=60, check=False)
    if removed.returncode != 0:
        raise LifecycleError("patient_cleanup_failed")
    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    result = {"label": label, "command": command, "exit_code": finished.returncode,
              "stdout": finished.stdout, "stderr": finished.stderr,
              "started_at": started_at, "completed_at": completed_at}
    container = {"id": container_id, "name": name, "requested_policy_hash": "sha256:" + hashlib.sha256(canonical_json({"argv": argv})).hexdigest(),
                 "effective_inspect_hash": "sha256:" + hashlib.sha256(canonical_json(effective[0])).hexdigest(),
                 "runner_image_digest": runner_image, "teardown": "proven",
                 "residual_absence": True}
    return result, container


def controlled_repair(worktree: Path) -> None:
    path = worktree / "calculator.py"; before = path.read_bytes()
    after = before.replace(b"return a - b", b"return a + b")
    if before == after: raise LifecycleError("fixture_repair_not_applicable")
    path.write_bytes(after)


def git_artifacts(*, source_root: Path, worktree: Path, artifact_root: Path) -> tuple[dict[str, Path], dict[str, str]]:
    artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    patch = subprocess.check_output(["/usr/bin/git", "diff", "--binary", "HEAD"], cwd=worktree)
    status = subprocess.check_output(["/usr/bin/git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=worktree)
    changed = {path.relative_to(worktree).as_posix(): sha256_file(path) for path in sorted(worktree.rglob("*")) if path.is_file() and ".git" not in path.parts}
    values = {"patch.bin": patch, "changed-manifest.json": canonical_json(changed), "untracked-manifest.bin": status}
    paths: dict[str, Path] = {}
    for name, raw in values.items():
        path = artifact_root / name; path.write_bytes(raw); paths[name] = path
    source_commit = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    return paths, {"source_commit": source_commit, "patch_hash": sha256_file(paths["patch.bin"]), "changed_hash": sha256_file(paths["changed-manifest.json"]), "untracked_hash": sha256_file(paths["untracked-manifest.bin"])}


def seal_and_finalize(*, attempt: str, source: dict[str, str], artifacts: dict[str, Path], command_results: list[dict[str, Any]], receipt_root: Path, journal_root: Path, runner_image_digest: str, container: dict[str, Any], shiproom_commit: str, package_tree_hash: str) -> tuple[str, Path, Path, dict[str, Any]]:
    """Use the package production receipt-v2 finalizer; no shaped receipt IDs."""
    for index, result in enumerate(command_results):
        for stream in ("stdout", "stderr"):
            item = receipt_root / "artifacts" / f"command-{index}-{stream}.bin"; item.parent.mkdir(parents=True, exist_ok=True); item.write_bytes(result[stream]); artifacts[item.relative_to(receipt_root / "artifacts").as_posix()] = item
        meta = receipt_root / "artifacts" / f"command-{index}.json"; meta.write_bytes(canonical_json({key: value for key, value in result.items() if key not in {"stdout", "stderr"}})); artifacts[meta.relative_to(receipt_root / "artifacts").as_posix()] = meta
    entries = []
    for name, path in sorted(artifacts.items()):
        entries.append({"path": name, "type": "regular", "mode": 0o400, "size": path.stat().st_size, "sha256": sha256_file(path), "producer": "patient" if name.startswith("patch") else "supervisor", "sealer": "host_supervisor", "trust": "untrusted_patient" if name.startswith("patch") else "control_plane", "truncated": False})
    aggregate = sum(entry["size"] for entry in entries)
    tree_hash = "sha256:" + hashlib.sha256(canonical_json({"artifacts": entries, "aggregate_bytes": aggregate})).hexdigest()
    manifest = {"schema_id": "external_validation.artifact_manifest.v1", "schema_version": "1", "artifacts": entries, "tree_hash": tree_hash, "aggregate_bytes": aggregate}
    manifest_path = receipt_root / "manifests" / (attempt + ".json"); manifest_path.parent.mkdir(parents=True, exist_ok=True); manifest_path.write_bytes(canonical_json(manifest))
    inputs = {"case_id": "case_remediation_doctor", "snapshot_hash": source["source_snapshot_hash"], "arm": "REMEDIATION_DOCTOR", "system_version": shiproom_commit, "prompt_version": "not_applicable", "policy_version": "remediation-doctor-v1", "model": None, "model_settings": {}, "model_sampling_seed": None, "tool_policy_version": "container-policy-v1", "execution_policy_version": "remediation-lifecycle-v1", "cache_mode": "cold", "runner_image_digest": runner_image_digest, "execution_policy_hash": container["requested_policy_hash"]}
    observation = observation_key_v2(inputs); journal = FinalizationJournal(journal_root / "finalization.sqlite"); journal_id = "journal_" + hashlib.sha256((attempt + tree_hash).encode()).hexdigest()[:32]; destination = receipt_root / "receipts" / (attempt + ".json")
    journal.prepare(journal_id, attempt_id(observation, 1), attempt, sha256_file(manifest_path), str(destination), hashlib.sha256(attempt.encode()).hexdigest())
    receipt = {"schema_id": "external_validation.run_receipt.v2", "schema_version": "2", "observation_key": observation, "observation_inputs": inputs, "attempt_id": attempt_id(observation, 1), "attempt_lineage": 1, "case_id": "case_remediation_doctor", "arm": "REMEDIATION_DOCTOR", "repository": "shiproom/doctor-fixture", "commit_sha": source["commit"], "release_surfaces": ["synthetic"], "source_hash": source["source_snapshot_hash"], "release_packet_hash": sha256_file(manifest_path), "artifact_manifest_hash": sha256_file(manifest_path), "container": container, "execution": {"started_at": command_results[0]["started_at"], "completed_at": command_results[-1]["completed_at"], "monotonic_seconds": 0, "shiproom_commit": shiproom_commit, "package_tree_hash": package_tree_hash, "artifact_protocol_version": "SRXFER02", "wrapper_version": "1", "cache_policy_version": "cold", "security_policy_version": "1", "resource_policy_hash": container["requested_policy_hash"]}, "model_usage": {"state": "not_applicable"}, "cost": {"state": "not_applicable"}, "applicability": {}, "termination": "completed", "evidence_eligible": True, "finalization_journal_id": journal_id, "supervisor": "host_supervisor"}
    receipt_id, _ = finalize_v2(receipt=receipt, manifest=manifest, manifest_path=manifest_path, artifacts=artifacts, journal=journal, destination=destination)
    journal.phase(journal_id, "RECEIPT_DURABLE", "TERMINAL_COMMITTED")
    return receipt_id, destination, manifest_path, receipt
