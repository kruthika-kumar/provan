"""Run one Session 2 qualification command through the production supervisor.

This is intentionally a narrow host-supervisor entry point.  It accepts no
worker-authored result fields: the immutable environment receipt selects the
runner image, a canonical release packet binds the argv and expected exit
contract, and :mod:`session2_execution` seals the supervisor-captured result.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from hashlib import sha256
try:  # The production entry point rejects non-Linux before it needs this.
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows unit tests
    fcntl = None  # type: ignore[assignment]
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Iterator

from .identity import canonical_json
from .runner_v2 import DockerSupervisorV2, ExecutionPolicyV2
from .session2_execution import Session2ExecutionError, execute_contract
from .v2 import BackendLock


ROOT = Path("/var/lib/shiproom-external-validation")
# Do not inherit the older shared staging directory's world-readable mode.
# This entry point owns a separate root-only subtree; only its deliberately
# visible release-packet leaves become patient-readable.
STAGING = Path("/mnt/shiproom-remediation/session2-supervisor/case-runner")
BACKEND_LOCK = Path("/run/lock/shiproom-remediation.backend.lock")
SECCOMP = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
OPAQUE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class CaseRunnerError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise CaseRunnerError(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _canonical(path: Path, digest: str, *, code: str) -> dict[str, Any]:
    if not SECCOMP.fullmatch(digest) or not path.is_file() or path.is_symlink():
        _fail(code)
    raw = path.read_bytes()
    if _sha(raw) != digest:
        _fail(code)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseRunnerError(code) from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail(code)
    return value


def _root() -> None:
    if os.name != "posix" or os.geteuid() != 0 or not ROOT.is_dir() or ROOT.is_symlink():
        _fail("session2_case_runner_root_invalid")
    value = ROOT.stat(follow_symlinks=False)
    if value.st_uid != 0 or value.st_gid != 0 or stat.S_IMODE(value.st_mode) != 0o700:
        _fail("session2_case_runner_root_invalid")


def _directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_gid != 0 or stat.S_IMODE(value.st_mode) & 0o077:
        _fail("session2_case_runner_staging_invalid")


def _release_directory(path: Path) -> None:
    """Create a patient-readable, immutable release-packet directory.

    The release packet intentionally contains only declared visible authority.
    Its confidentiality is therefore not a security control; patient read
    access is required for an upstream target test supplied by the packet.
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    value = path.stat(follow_symlinks=False)
    if (path.is_symlink() or not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
            or value.st_gid != 0 or stat.S_IMODE(value.st_mode) != 0o755):
        _fail("session2_case_runner_release_packet_invalid")


def _environment(receipt_hash: str) -> dict[str, Any]:
    value = _canonical(ROOT / "session2" / "receipts" / "environments" / (receipt_hash[7:] + ".environment-build.json"), receipt_hash, code="session2_case_runner_environment_invalid")
    required = {"schema_id", "schema_version", "materialization_hash", "image_ref", "runner_image_digest", "dependency_authority_hash"}
    if value.get("schema_id") != "external_validation.session2_environment_build_receipt.v1" or not required.issubset(value):
        _fail("session2_case_runner_environment_invalid")
    if not isinstance(value["image_ref"], str) or not SECCOMP.fullmatch(value["runner_image_digest"]) or not SECCOMP.fullmatch(value["materialization_hash"]):
        _fail("session2_case_runner_environment_invalid")
    return value


def _write_once(path: Path, raw: bytes, *, mode: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != raw:
            _fail("session2_case_runner_packet_collision")
        return
    try:
        # The production entry point has already required Linux/root.  The
        # conditional keeps semantic unit tests portable without changing the
        # production authority boundary.
        if hasattr(os, "fchown"):
            os.fchown(descriptor, 0, 0)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        if os.write(descriptor, raw) != len(raw):
            _fail("session2_case_runner_packet_short_write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix":
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def _target_artifact(
    *, snapshot: Path | None, materialization_hash: str | None, relative_path: str | None,
) -> tuple[dict[str, Any] | None, bytes | None, Path | None]:
    if (snapshot is None) != (materialization_hash is None) or (snapshot is None) != (relative_path is None):
        _fail("session2_case_runner_target_artifact_incomplete")
    if snapshot is None:
        return None, None, None
    if (not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink()
            or not SECCOMP.fullmatch(materialization_hash or "")
            or not isinstance(relative_path, str) or not relative_path
            or Path(relative_path).is_absolute() or ".." in Path(relative_path).parts):
        _fail("session2_case_runner_target_artifact_invalid")
    source = snapshot / relative_path
    try:
        resolved = source.resolve(strict=True)
        snapshot_resolved = snapshot.resolve(strict=True)
        resolved.relative_to(snapshot_resolved)
    except (OSError, ValueError) as exc:
        raise CaseRunnerError("session2_case_runner_target_artifact_invalid") from exc
    item = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(item.st_mode) or item.st_size <= 0 or item.st_size > 1_048_576:
        _fail("session2_case_runner_target_artifact_invalid")
    raw = source.read_bytes()
    release_path = "targets/" + sha256(canonical_json({"path": relative_path, "sha256": _sha(raw)})).hexdigest() + ".py"
    return {
        "source_materialization_hash": materialization_hash,
        "source_relative_path": relative_path,
        "release_path": release_path,
        "sha256": _sha(raw),
        "bytes": len(raw),
    }, raw, Path(release_path)


def _packet(*, case_id: str, materialization_hash: str, environment_hash: str, command: list[str], result_contract_id: str, expected_exit_code: int, target_artifact: dict[str, Any] | None, target_bytes: bytes | None, target_path: Path | None) -> tuple[Path, str]:
    if not OPAQUE.fullmatch(case_id) or not OPAQUE.fullmatch(result_contract_id) or not isinstance(expected_exit_code, int):
        _fail("session2_case_runner_contract_invalid")
    if not isinstance(command, list) or not command or any(not isinstance(item, str) or not item for item in command):
        _fail("session2_case_runner_contract_invalid")
    if target_artifact is not None and (target_bytes is None or target_path is None or "/release/" + target_artifact["release_path"] not in command):
        _fail("session2_case_runner_target_artifact_not_executed")
    record = {
        "schema_id": "external_validation.session2_command_contract.v1", "schema_version": "1",
        "case_id": case_id, "materialization_hash": materialization_hash,
        "environment_receipt_hash": environment_hash, "argv": command,
        "result_contract_id": result_contract_id, "expected_exit_code": expected_exit_code,
        "network_policy": "none", "patient_tree_write_policy": "readonly",
        "target_artifact": target_artifact,
    }
    raw = canonical_json(record); digest = _sha(raw)
    _directory(STAGING)
    _release_directory(STAGING / "release-packets")
    directory = STAGING / "release-packets" / digest[7:]
    _release_directory(directory)
    target = directory / "release.json"; _write_once(target, raw, mode=0o444)
    if target_artifact is not None and target_bytes is not None and target_path is not None:
        artifact_directory = directory / target_path.parent
        _release_directory(artifact_directory)
        _write_once(directory / target_path, target_bytes, mode=0o444)
    return directory, digest


@contextmanager
def _backend_lock() -> Iterator[None]:
    if fcntl is None:
        _fail("session2_case_runner_requires_linux_wsl")
    if not BACKEND_LOCK.is_file() or BACKEND_LOCK.is_symlink():
        _fail("session2_case_runner_backend_lock_missing")
    descriptor = os.open(BACKEND_LOCK, os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        value = os.fstat(descriptor)
        if value.st_uid != 0 or value.st_gid != 0 or stat.S_IMODE(value.st_mode) & 0o022:
            _fail("session2_case_runner_backend_lock_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaseRunnerError("session2_case_runner_backend_busy") from exc
        yield
    finally:
        os.close(descriptor)


def run_case(
    repository_root: Path, *, case_id: str, snapshot: Path, environment_receipt_hash: str,
    command: list[str], result_contract_id: str, expected_exit_code: int,
    seccomp_profile: Path, seccomp_hash: str, wall_seconds: int = 900,
    target_source_snapshot: Path | None = None,
    target_source_materialization_hash: str | None = None,
    target_source_relative_path: str | None = None,
) -> dict[str, Any]:
    """Run a single frozen command and return its supervisor-authored receipt."""
    _root()
    if not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink() or not 1 <= wall_seconds <= 900:
        _fail("session2_case_runner_input_invalid")
    environment = _environment(environment_receipt_hash)
    if environment["materialization_hash"] == "":
        _fail("session2_case_runner_environment_invalid")
    if not seccomp_profile.is_absolute() or not seccomp_profile.is_file() or not SECCOMP.fullmatch(seccomp_hash) or _sha(seccomp_profile.read_bytes()) != seccomp_hash:
        _fail("session2_case_runner_seccomp_invalid")
    artifact, artifact_bytes, artifact_path = _target_artifact(
        snapshot=target_source_snapshot,
        materialization_hash=target_source_materialization_hash,
        relative_path=target_source_relative_path,
    )
    packet, packet_hash = _packet(case_id=case_id, materialization_hash=environment["materialization_hash"], environment_hash=environment_receipt_hash, command=command, result_contract_id=result_contract_id, expected_exit_code=expected_exit_code, target_artifact=artifact, target_bytes=artifact_bytes, target_path=artifact_path)
    run_id = uuid.uuid4().hex
    cidfiles = STAGING / "cidfiles"; sealed = STAGING / "sealed-output" / run_id
    _directory(cidfiles); _directory(sealed)
    policy_input = {"seccomp_hash": seccomp_hash, "network": "none", "readonly": True, "cpus": 1.0, "memory": "1g", "pids": 128, "output_tmpfs_bytes": 64 * 1024 * 1024, "stdout_limit_bytes": 1024 * 1024, "stderr_limit_bytes": 1024 * 1024, "wall_seconds": wall_seconds}
    security_hash = _sha(canonical_json({"seccomp_hash": seccomp_hash, "network": "none", "readonly": True, "cap_drop": "ALL", "no_new_privileges": True}))
    resource_hash = _sha(canonical_json(policy_input))
    policy = ExecutionPolicyV2(image_digest=environment["runner_image_digest"], runner_image_digest=environment["runner_image_digest"], image_ref=environment["image_ref"], security_policy_hash=security_hash, resource_policy_hash=resource_hash, seccomp_profile=seccomp_profile, docker_socket=Path("/run/shiproom-remediation-docker/docker.sock"), wall_seconds=wall_seconds)
    lock_database = ROOT / "session2" / "receipts" / "execution-backend-locks.sqlite"
    _directory(lock_database.parent)
    with _backend_lock():
        runner = DockerSupervisorV2(policy, "shiproom-remediation", BackendLock(lock_database))
        receipt = execute_contract(repository_root, runner=runner, owner="session2-" + run_id, name="shiproom-s2-" + run_id[:20], cidfile=cidfiles / (run_id + ".cid"), patient=snapshot, packet=packet, command=command, seal_root=sealed, source_record_hash=environment["materialization_hash"], result_contract_id=result_contract_id, expected_exit_code=expected_exit_code)
    return {"receipt_id": receipt["receipt_id"], "receipt_hash": _sha(canonical_json(receipt)), "packet_hash": packet_hash, "target_artifact": artifact, "contract_satisfied": receipt["contract_satisfied"], "exit_code": receipt["exit_code"]}


def _command(encoded: str) -> list[str]:
    try:
        raw = base64.urlsafe_b64decode(encoded.encode("ascii") + b"=" * (-len(encoded) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise CaseRunnerError("session2_case_runner_command_invalid") from exc
    if not isinstance(value, list):
        _fail("session2_case_runner_command_invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one frozen Session 2 qualification command.")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--case-id", required=True); parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--environment-receipt-hash", required=True); parser.add_argument("--command-base64", required=True)
    parser.add_argument("--result-contract-id", required=True); parser.add_argument("--expected-exit-code", required=True, type=int)
    parser.add_argument("--seccomp-profile", required=True, type=Path); parser.add_argument("--seccomp-hash", required=True)
    parser.add_argument("--target-source-snapshot", type=Path)
    parser.add_argument("--target-source-materialization-hash")
    parser.add_argument("--target-source-relative-path")
    parser.add_argument("--wall-seconds", type=int, default=900)
    parsed = parser.parse_args(argv)
    try:
        print(json.dumps(run_case(parsed.repository_root, case_id=parsed.case_id, snapshot=parsed.snapshot, environment_receipt_hash=parsed.environment_receipt_hash, command=_command(parsed.command_base64), result_contract_id=parsed.result_contract_id, expected_exit_code=parsed.expected_exit_code, seccomp_profile=parsed.seccomp_profile, seccomp_hash=parsed.seccomp_hash, wall_seconds=parsed.wall_seconds, target_source_snapshot=parsed.target_source_snapshot, target_source_materialization_hash=parsed.target_source_materialization_hash, target_source_relative_path=parsed.target_source_relative_path), sort_keys=True, separators=(",", ":")))
    except (CaseRunnerError, Session2ExecutionError, RuntimeError, ValueError) as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
