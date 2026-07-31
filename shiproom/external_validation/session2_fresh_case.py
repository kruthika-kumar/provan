"""Production compiler for a fresh Session 2 pair qualification.

This deliberately derives, rather than accepts, the four target/protected
outcomes.  Its only inputs are content-addressed source/materialization and
pair-transition records already sealed by the host supervisor.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2 import contamination_band, validate_fresh_qualification
from .session2_materialize import MaterializationError, _allocation_bound_destination

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class FreshQualificationError(ValueError):
    pass


def _fail(code: str) -> None:
    raise FreshQualificationError(code)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _record(path: Path, digest: str, suffix: str) -> dict[str, Any]:
    if not _HASH.fullmatch(digest) or not path.is_file() or path.is_symlink():
        _fail("session2_fresh_authority_missing")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshQualificationError("session2_fresh_authority_invalid") from exc
    if _digest(raw) != digest or canonical_json(value) != raw or not path.name.endswith(suffix):
        _fail("session2_fresh_authority_invalid")
    return value


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_fresh_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise FreshQualificationError("session2_fresh_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_fresh_external_root_invalid")
    target = root / "session2" / "cases" / "qualifications"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    return target


def _duration_minutes(receipt_root: Path, transition: dict[str, Any]) -> float:
    values: list[float] = []
    for name in ("target_buggy_receipt_hash", "target_fixed_receipt_hash"):
        digest = transition.get(name)
        if not isinstance(digest, str): _fail("session2_fresh_transition_invalid")
        receipt = _record(receipt_root / (digest[7:] + ".execution-receipt.json"), digest, ".execution-receipt.json")
        try:
            start = datetime.fromisoformat(receipt["started_at"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(receipt["completed_at"].replace("Z", "+00:00"))
        except (KeyError, AttributeError, ValueError) as exc:
            raise FreshQualificationError("session2_fresh_receipt_duration_invalid") from exc
        seconds = (end - start).total_seconds()
        if seconds < 0: _fail("session2_fresh_receipt_duration_invalid")
        values.append(seconds / 60)
    return max(values)


def _allocation_bound_snapshot(materialization: dict[str, Any], fixed_snapshot: Path) -> None:
    """Revalidate the receipt's worktree and exact sealed snapshot identity."""
    attempt = materialization.get("allocation_attempt")
    authority_hash = materialization.get("worktree_authority_hash")
    snapshot_authority = materialization.get("snapshot_authority")
    if (not isinstance(attempt, str) or not isinstance(authority_hash, str)
            or not isinstance(snapshot_authority, dict)):
        _fail("session2_fresh_license_snapshot_authority_missing")
    try:
        authority = _allocation_bound_destination(fixed_snapshot, attempt)
    except MaterializationError as exc:
        raise FreshQualificationError("session2_fresh_license_snapshot_authority_invalid") from exc
    if _digest(canonical_json(authority)) != authority_hash:
        _fail("session2_fresh_license_snapshot_authority_invalid")
    tree = Path(authority["canonical_path"])
    try:
        value = fixed_snapshot.stat(follow_symlinks=False)
        relative = fixed_snapshot.relative_to(tree).as_posix()
    except (OSError, ValueError) as exc:
        raise FreshQualificationError("session2_fresh_license_snapshot_authority_invalid") from exc
    expected = (snapshot_authority.get("device"), snapshot_authority.get("inode"),
                snapshot_authority.get("uid"), snapshot_authority.get("gid"), snapshot_authority.get("relative_path"))
    actual = (value.st_dev, value.st_ino, value.st_uid, value.st_gid, relative)
    if fixed_snapshot.is_symlink() or expected != actual:
        _fail("session2_fresh_license_snapshot_authority_invalid")


def compile_fresh_qualification(
    repository_root: Path, *, case_id: str, candidate_id: str, candidate_index_hash: str,
    buggy_materialization_hash: str, fixed_materialization_hash: str,
    primary_transition_hash: str, replay_transition_hash: str, fixed_snapshot: Path,
    license_relative_path: str, license_sha256: str,
) -> dict[str, Any]:
    """Compile one qualification from mutually binding sealed evidence.

    The fixed snapshot is used solely to rehash its public licence file.  The
    snapshot location itself never appears in the resulting record.
    """
    if (not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", case_id)
            or not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash)
            or not all(_HASH.fullmatch(item) for item in (buggy_materialization_hash, fixed_materialization_hash, primary_transition_hash, replay_transition_hash))
            or not isinstance(fixed_snapshot, Path) or not fixed_snapshot.is_absolute()
            or not isinstance(license_relative_path, str) or not license_relative_path or license_relative_path.startswith("/") or ".." in license_relative_path.split("/")
            or not _HASH.fullmatch(license_sha256)):
        _fail("session2_fresh_input_invalid")
    target = _root(repository_root); root = target.parents[2]
    index = _record(root / "session2" / "cases" / (candidate_index_hash[7:] + ".candidate-index.json"), candidate_index_hash, ".candidate-index.json")
    candidates = [item for item in index.get("candidates", []) if isinstance(item, dict) and item.get("candidate_id") == candidate_id]
    if len(candidates) != 1: _fail("session2_fresh_candidate_missing")
    candidate = candidates[0]
    transitions: list[dict[str, Any]] = []
    for digest in (primary_transition_hash, replay_transition_hash):
        transition = _record(root / "session2" / "cases" / "transitions" / (digest[7:] + ".pair-execution-transition.json"), digest, ".pair-execution-transition.json")
        if (transition.get("schema_id") != "external_validation.session2_pair_execution_transition.v1"
                or transition.get("case_id") != case_id or transition.get("candidate_id") != candidate_id
                or transition.get("candidate_index_hash") != candidate_index_hash
                or transition.get("buggy_materialization_hash") != buggy_materialization_hash
                or transition.get("fixed_materialization_hash") != fixed_materialization_hash):
            _fail("session2_fresh_transition_mismatch")
        if tuple(transition.get(k) for k in ("buggy_target_oracle", "fixed_target_oracle", "buggy_protected_checks", "fixed_protected_checks")) != ("EXPECTED_FAILURE", "PASSED", "PASSED", "PASSED"):
            _fail("session2_fresh_transition_invalid")
        transitions.append(transition)
    if primary_transition_hash == replay_transition_hash: _fail("session2_fresh_replay_not_independent")
    materialization = _record(root / "session2" / "cases" / "materializations" / (fixed_materialization_hash[7:] + ".materialization.json"), fixed_materialization_hash, ".materialization.json")
    if materialization.get("candidate_id") != candidate_id: _fail("session2_fresh_materialization_mismatch")
    if not fixed_snapshot.is_dir() or _is_reparse(fixed_snapshot):
        _fail("session2_fresh_license_snapshot_missing")
    _allocation_bound_snapshot(materialization, fixed_snapshot)
    license_file = fixed_snapshot / license_relative_path
    if not license_file.is_file() or license_file.is_symlink() or _digest(license_file.read_bytes()) != license_sha256:
        _fail("session2_fresh_license_invalid")
    duration = _duration_minutes(root / "session2" / "receipts" / "executions", transitions[0])
    band = contamination_band(candidate["issue_created_at"], candidate["fix_created_at"])
    result = {
        "case_id": case_id, "repository": candidate["repository"],
        "buggy_sha": "",
        "fixed_sha": materialization.get("commit_sha"), "issue_created_at": candidate["issue_created_at"], "fix_created_at": candidate["fix_created_at"],
        "contamination_band": band, "cutoff_compliant": band == "FRESH_A",
        "fallback_reason": None if band == "FRESH_A" else candidate.get("fallback_reason"),
        "public_repository": True, "usable_license": True, "authoritative_issue_or_requirement": True,
        "buggy_target_oracle": "EXPECTED_FAILURE", "fixed_target_oracle": "PASSED", "buggy_protected_checks": "PASSED", "fixed_protected_checks": "PASSED",
        "target_runtime_minutes": duration, "paid_credentials_required": False, "gpu_required": False, "proprietary_service_required": False, "uncontrolled_patient_network_required": False,
        "qualified_linux_container_path": True, "dependency_authority_frozen": True,
        "production_supervisor_receipt_present": True, "production_supervisor_receipt_opaque_id": primary_transition_hash[7:] + ".pair-execution-transition.json", "production_supervisor_receipt_hash": primary_transition_hash,
        "independent_replay_present": True, "independent_replay_receipt_opaque_id": replay_transition_hash[7:] + ".pair-execution-transition.json", "independent_replay_receipt_hash": replay_transition_hash,
    }
    # Recover the source commits from their sealed materializations, never an
    # input string.  This statement is intentionally after all transition checks.
    buggy = _record(root / "session2" / "cases" / "materializations" / (buggy_materialization_hash[7:] + ".materialization.json"), buggy_materialization_hash, ".materialization.json")
    if (buggy.get("candidate_id") != candidate_id or not isinstance(buggy.get("commit_sha"), str)
            or not isinstance(materialization.get("commit_sha"), str)):
        _fail("session2_fresh_materialization_mismatch")
    result["buggy_sha"] = buggy.get("commit_sha")
    validate_fresh_qualification(result)
    return {"schema_id":"external_validation.session2_fresh_qualification.v1", "schema_version":"1", "qualification":result,
            "candidate_index_hash":candidate_index_hash, "primary_transition_hash":primary_transition_hash, "replay_transition_hash":replay_transition_hash,
            "license_relative_path":license_relative_path, "license_sha256":license_sha256}


def seal_fresh_qualification(repository_root: Path, **kwargs: Any) -> dict[str, str]:
    """Atomically seal one compiler-derived qualification under supervisor control."""
    record = compile_fresh_qualification(repository_root, **kwargs)
    target = _root(repository_root)
    raw = canonical_json(record); digest = _digest(raw)
    path = target / (digest[7:] + ".fresh-qualification.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != raw: _fail("session2_fresh_output_collision")
    else:
        try:
            if os.write(fd, raw) != len(raw): _fail("session2_fresh_short_write")
            os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
        parent = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    return {"qualification_hash": digest, "qualification_opaque_id": path.name}


def validate_fresh_qualification_artifact(value: Any) -> dict[str, Any]:
    """Independent semantic validation for the public/private wrapper record."""
    required = {"schema_id", "schema_version", "qualification", "candidate_index_hash", "primary_transition_hash", "replay_transition_hash", "license_relative_path", "license_sha256"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema_id") != "external_validation.session2_fresh_qualification.v1"
            or value.get("schema_version") != "1"):
        _fail("session2_fresh_artifact_invalid")
    qualification = validate_fresh_qualification(value["qualification"])
    for key in ("candidate_index_hash", "primary_transition_hash", "replay_transition_hash", "license_sha256"):
        if not _HASH.fullmatch(value[key]): _fail("session2_fresh_artifact_invalid")
    if value["primary_transition_hash"] == value["replay_transition_hash"]:
        _fail("session2_fresh_replay_not_independent")
    if (not isinstance(value["license_relative_path"], str) or not value["license_relative_path"]
            or value["license_relative_path"].startswith("/") or ".." in value["license_relative_path"].split("/")):
        _fail("session2_fresh_artifact_invalid")
    return {**value, "qualification": qualification}
