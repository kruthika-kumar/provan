"""Supervisor-authored Session 2 execution receipts.

This is the sole bridge between a real :class:`DockerSupervisorV2` execution
and case-qualification evidence.  The worker supplies only a frozen command
contract; container identity, time, raw streams, exit status and result are
captured from the supervisor outcome and sealed beneath the configured Linux
external root.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import platform
import re
import stat
from typing import Any

from .identity import canonical_json
from .runner_v2 import DockerSupervisorV2
from .security import _is_reparse, external_root
from .session2 import validate_qualifying_artifact

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class Session2ExecutionError(RuntimeError):
    """Stable production execution rejection code."""


def _fail(code: str) -> None:
    raise Session2ExecutionError(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _store(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_execution_linux_root_required")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise Session2ExecutionError("session2_execution_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_execution_external_root_invalid")
    store = root / "session2" / "receipts" / "executions"
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = store.lstat()
    if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode)
            or value.st_uid != 0 or stat.S_IMODE(value.st_mode) & 0o022):
        _fail("session2_execution_store_invalid")
    return store


def _write_once(directory: Path, suffix: str, raw: bytes) -> dict[str, Any]:
    digest = _sha(raw)
    path = directory / (digest[7:] + suffix)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw:
            _fail("session2_execution_evidence_collision")
    else:
        try:
            os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400)
            written = os.write(descriptor, raw)
            if written != len(raw): _fail("session2_execution_short_write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(parent)
        finally: os.close(parent)
    return {"opaque_id": path.name, "bytes": len(raw), "sha256": digest}


def _command_text(command: list[str]) -> str:
    if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
        _fail("session2_execution_command_contract_invalid")
    # This field is evidence, not a shell command: exact argv is retained
    # separately, therefore a hostile string cannot alter host execution.
    return "argv:" + canonical_json(command).decode("utf-8")


def execute_contract(
    repository_root: Path, *, runner: DockerSupervisorV2, owner: str, name: str,
    cidfile: Path, patient: Path, packet: Path, command: list[str], seal_root: Path,
    source_record_hash: str, result_contract_id: str, expected_exit_code: int,
) -> dict[str, Any]:
    """Execute and seal a real command under a frozen exit-code contract.

    ``expected_exit_code`` is a qualification policy input, never an authored
    pass flag.  The derived ``contract_satisfied`` is based only on the
    supervisor-captured process result.
    """
    if not _HASH.fullmatch(source_record_hash) or not isinstance(result_contract_id, str) or not result_contract_id:
        _fail("session2_execution_authority_invalid")
    if not isinstance(expected_exit_code, int): _fail("session2_execution_contract_invalid")
    store = _store(repository_root)
    before = datetime.now(timezone.utc)
    outcome = runner.execute(owner=owner, name=name, cidfile=cidfile, patient=patient, packet=packet, command=command, seal_root=seal_root)
    after = datetime.now(timezone.utc)
    if not outcome.get("evidence_eligible") or outcome.get("teardown") != "proven":
        _fail("session2_execution_evidence_ineligible")
    if not isinstance(outcome.get("returncode"), int) or not isinstance(outcome.get("stdout"), bytes) or not isinstance(outcome.get("stderr"), bytes):
        _fail("session2_execution_supervisor_outcome_invalid")
    stdout = _write_once(store, ".patient.stdout", outcome["stdout"])
    stderr = _write_once(store, ".patient.stderr", outcome["stderr"])
    raw = {
        "classification": "QUALIFYING_PRIVATE_ARTIFACT",
        "artifact_id": "execution_" + sha256(canonical_json({"source": source_record_hash, "command": command, "start": before.isoformat()})).hexdigest(),
        "source_record_hash": source_record_hash,
        "command": _command_text(command),
        "argv": command,
        "started_at": _utc(float(outcome.get("started_at", before.timestamp()))),
        "completed_at": _utc(float(outcome.get("completed_at", after.timestamp()))),
        "exit_code": outcome["returncode"],
        "stdout": stdout,
        "stderr": stderr,
        "container_digest": runner.policy.runner_image_digest,
        "supervisor_run_id": outcome["container_id"],
        "result_contract_id": result_contract_id,
        "expected_exit_code": expected_exit_code,
        "contract_satisfied": outcome["returncode"] == expected_exit_code,
        "termination": outcome.get("termination"),
        "network_policy": "none",
        "requested_policy_hash": outcome.get("requested_policy_hash"),
        "effective_inspect_hash": outcome.get("effective_inspect_hash"),
        "resource_usage": {"stdout_observed": outcome.get("stdout_observed"), "stderr_observed": outcome.get("stderr_observed"), "stdout_discarded": outcome.get("stdout_discarded"), "stderr_discarded": outcome.get("stderr_discarded")},
    }
    # Re-use the separately authored public semantic validator on its
    # authoritative subset.  It cannot author a result, only reject it.
    validate_qualifying_artifact({key: raw[key] for key in ("classification", "artifact_id", "source_record_hash", "command", "started_at", "completed_at", "exit_code", "stdout", "stderr", "container_digest", "supervisor_run_id", "result_contract_id")})
    receipt_payload = dict(raw)
    receipt_payload["schema_id"] = "external_validation.session2_execution_receipt.v1"
    receipt_payload["schema_version"] = "1"
    # The receipt's identity deliberately excludes its own field; it is not
    # a self-referential assertion.
    receipt_id = _sha(canonical_json(receipt_payload))
    receipt_payload["receipt_id"] = receipt_id
    _write_once(store, ".execution-receipt.json", canonical_json(receipt_payload))
    return receipt_payload
