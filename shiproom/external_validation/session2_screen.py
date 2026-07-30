"""Supervisor-owned, immutable prequalification screens for Session 2 cases.

An unsuccessful public candidate is still evidence: this module seals the
actual Git comparison and a narrow typed exclusion.  It is intentionally not a
qualification receipt and cannot claim a target oracle passed or failed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root


class CandidateScreenError(RuntimeError):
    pass


_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASONS = {
    "NO_AUTHORITATIVE_EXECUTABLE_TARGET_CONTRACT",
    "DEPENDENCY_AUTHORITY_NOT_FROZEN",
    "TARGET_RUNTIME_EXCEEDS_LIMIT",
    "REQUIRES_FORBIDDEN_SERVICE_OR_CREDENTIAL",
    "UNQUALIFIED_LINUX_CONTAINER_PATH",
    "FIXED_TWIN_NON_MINIMAL",
}
_PRIMARY_RETRIEVAL_UNAVAILABLE = "PRIMARY_RETRIEVAL_RECEIPT_UNAVAILABLE"
_MIRROR_ACQUISITION_TIMED_OUT = "MIRROR_ACQUISITION_TIMED_OUT"
_UNSAFE_PATIENT_TREE_ENTRY = "UNSAFE_PATIENT_TREE_ENTRY"
_RESOLUTION_REASON = "MATERIALIZATION_POLICY_NARROWING_CORRECTED"
_FIXED_TWIN_RESOLUTION_REASON = "FIXED_TWIN_COMMIT_AUTHORITY_CORRECTED"
_RUNNER_RESOLUTION_REASON = "QUALIFIED_RUNNER_COMPATIBILITY_SUPERSEDED"
_REQUIREMENTS_AUTHORITY_RESOLUTION_REASON = "HASH_PINNED_REQUIREMENTS_AUTHORITY_SUPERSEDED"


def _fail(code: str) -> None:
    raise CandidateScreenError(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_screen_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise CandidateScreenError("session2_screen_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_screen_external_root_invalid")
    target = root / "session2" / "cases" / "screens"
    target.mkdir(mode=0o700, exist_ok=True)
    if _is_reparse(target): _fail("session2_screen_store_invalid")
    return target


def _run_git(mirror: Path, *args: str) -> dict[str, Any]:
    started = _utc()
    completed = subprocess.run(["/usr/bin/git", "-C", str(mirror), "--no-pager", *args], capture_output=True, check=False, timeout=60, env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_LFS_SKIP_SMUDGE": "1"})
    ended = _utc()
    return {"argv": ["git", "-C", "<isolated-bare-mirror>", "--no-pager", *args], "started_at": started, "completed_at": ended, "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}


def _write_once(directory: Path, suffix: str, raw: bytes) -> str:
    digest = _sha(raw); path = directory / (digest[7:] + suffix)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw: _fail("session2_screen_artifact_collision")
    else:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        if hasattr(os, "chown"):
            os.chown(path, 0, 0)
        os.chmod(path, 0o400)
    return digest


def _canonical_record(path: Path, expected_hash: str, *, missing: str, invalid: str) -> dict[str, Any]:
    """Load one sealed private record without treating a filename as authority."""
    if not path.is_file() or _is_reparse(path):
        _fail(missing)
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateScreenError(invalid) from exc
    if _sha(raw) != expected_hash or not isinstance(value, dict) or canonical_json(value) != raw:
        _fail(invalid)
    return value


def _sealed_raw_json(path: Path, expected_hash: str, *, missing: str, invalid: str) -> None:
    """Validate an immutable raw API page without imposing canonical JSON bytes."""
    if not path.is_file() or _is_reparse(path): _fail(missing)
    try:
        raw = path.read_bytes(); json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateScreenError(invalid) from exc
    if _sha(raw) != expected_hash: _fail(invalid)


def _candidate_from_index(directory: Path, *, candidate_id: str, candidate_index_hash: str) -> dict[str, Any]:
    """Bind a screen to an actual candidate in the cited immutable index.

    A screen is exclusion evidence, not an opportunity to mint a convenient
    identifier.  In particular, a visually similar ``repo#issue-pr`` value
    must never be able to suppress the canonical ``repo#issue->repo#pr`` row.
    """
    root = directory.parents[2]
    index = _canonical_record(
        root / "session2" / "cases" / (candidate_index_hash[7:] + ".candidate-index.json"),
        candidate_index_hash,
        missing="session2_screen_candidate_index_missing",
        invalid="session2_screen_candidate_index_invalid",
    )
    candidates = index.get("candidates")
    matches = [item for item in candidates if isinstance(item, dict) and item.get("candidate_id") == candidate_id] if isinstance(candidates, list) else []
    if (index.get("schema_id") not in {"external_validation.session2_github_issue_fix_candidate_index.v1", "external_validation.session2_github_issue_fix_candidate_index.v2", "external_validation.session2_github_issue_fix_candidate_index.v3"}
            or index.get("schema_version") != "1" or len(matches) != 1):
        _fail("session2_screen_candidate_not_in_index")
    return matches[0]


def _assert_candidate_in_index(directory: Path, *, candidate_id: str, candidate_index_hash: str) -> dict[str, Any]:
    """Return the canonical candidate after proving index membership.

    The candidate frame records *paginated retrieval* receipts.  Later
    materialization records bind a different authority: exact issue/PR object
    receipts.  Callers must carry both layers rather than substituting one
    digest type for the other.
    """
    return _candidate_from_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)


def _validate_source_object_receipts(
    directory: Path, *, candidate_id: str, materialization: dict[str, Any],
    source_object_receipt_hashes: list[str],
) -> None:
    """Validate exact GitHub objects independently of the candidate frame.

    Candidate-frame retrieval receipts prove complete, paginated discovery;
    these exact-object receipts prove the issue and PR subsequently staged.
    They are intentionally different contracts and must never be compared as
    if they were interchangeable hashes.
    """
    try:
        issue_part, fix_part = candidate_id.split("->", 1)
        repository, issue_number = issue_part.rsplit("#", 1)
        fix_repository, fix_number = fix_part.rsplit("#", 1)
    except ValueError:
        _fail("session2_screen_candidate_identifier_invalid")
    if repository != fix_repository or not issue_number.isdigit() or not fix_number.isdigit():
        _fail("session2_screen_candidate_identifier_invalid")
    expected = materialization.get("source_object_receipt_hashes")
    if not isinstance(expected, list) or sorted(expected) != sorted(source_object_receipt_hashes):
        _fail("session2_screen_source_object_receipt_mismatch")
    root = directory.parents[2] / "session2" / "retrieval"
    expected_objects = (("issue", int(issue_number)), ("pull_request", int(fix_number)))
    observed: list[tuple[str, int]] = []
    for digest in source_object_receipt_hashes:
        receipt = _canonical_record(
            root / (digest[7:] + ".object-receipt.json"), digest,
            missing="session2_screen_source_object_receipt_missing",
            invalid="session2_screen_source_object_receipt_invalid",
        )
        kind, number = receipt.get("object_kind"), receipt.get("number")
        if receipt.get("schema_id") != "external_validation.session2_github_object_receipt.v1" or receipt.get("repository") != repository or not isinstance(kind, str) or not isinstance(number, int):
            _fail("session2_screen_source_object_receipt_invalid")
        raw_hash = receipt.get("raw_response_hash")
        if not isinstance(raw_hash, str) or not _HASH.fullmatch(raw_hash):
            _fail("session2_screen_source_object_receipt_invalid")
        _sealed_raw_json(root / "raw" / (raw_hash[7:] + ".json"), raw_hash,
                         missing="session2_screen_source_object_raw_missing",
                         invalid="session2_screen_source_object_raw_invalid")
        observed.append((kind, number))
    if sorted(observed) != sorted(expected_objects):
        _fail("session2_screen_source_object_identity_mismatch")


def seal_primary_retrieval_unavailable(repository_root: Path, *, candidate_id: str, candidate_index_hash: str) -> dict[str, str]:
    """Seal missing candidate-frame primary evidence without substituting re-fetches."""
    if not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash):
        _fail("session2_screen_input_invalid")
    directory = _root(repository_root)
    candidate = _candidate_from_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)
    expected = [candidate.get("issue_retrieval_receipt_hash"), candidate.get("fix_retrieval_receipt_hash")]
    if any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in expected):
        _fail("session2_screen_candidate_primary_receipt_fields_invalid")
    receipt_root = directory.parents[2] / "session2" / "retrieval"
    # Candidate-frame hashes bind the paginated primary retrieval receipts
    # (query, filters, pagination and raw pages), not later per-object detail
    # receipts.  Keep those authorities distinct.
    missing = [value for value in expected if not (receipt_root / (value[7:] + ".retrieval-receipt.json")).is_file()]
    if not missing:
        _fail("session2_screen_candidate_primary_receipts_present")
    record = {
        "schema_id": "external_validation.session2_candidate_provenance_screen.v1",
        "schema_version": "1", "candidate_id": candidate_id,
        "candidate_index_hash": candidate_index_hash,
        "stage": "PRIMARY_RETRIEVAL_AUTHORITY", "decision": "EXCLUDED_PREQUALIFICATION",
        "reason": _PRIMARY_RETRIEVAL_UNAVAILABLE,
        "expected_source_object_receipt_hashes": sorted(expected),
        "missing_source_object_receipt_hashes": sorted(missing), "created_at": _utc(),
    }
    return {"screen_hash": _write_once(directory, ".provenance-screen.json", canonical_json(record)), "decision": record["decision"]}


def seal_mirror_acquisition_timeout(
    repository_root: Path, *, candidate_id: str, candidate_index_hash: str,
    mirror_attempt_hash: str,
) -> dict[str, str]:
    """Seal a terminal source exclusion from a production fetch timeout.

    A retained, content-addressed mirror attempt is the authority here: the
    mirror producer has already bound it to the exact candidate, public object
    receipts and immutable commits before it begins the network fetch.  This
    function deliberately cannot manufacture a timeout from a caller boolean
    or a partial staging path.
    """
    if (not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash)
            or not _HASH.fullmatch(mirror_attempt_hash)):
        _fail("session2_mirror_timeout_screen_input_invalid")
    directory = _root(repository_root)
    candidate = _candidate_from_index(directory, candidate_id=candidate_id,
                                      candidate_index_hash=candidate_index_hash)
    root = directory.parents[2]
    attempt = _canonical_record(
        root / "session2" / "cases" / "mirrors" / (mirror_attempt_hash[7:] + ".mirror.json"),
        mirror_attempt_hash,
        missing="session2_mirror_timeout_screen_attempt_missing",
        invalid="session2_mirror_timeout_screen_attempt_invalid",
    )
    required = {"schema_id", "schema_version", "candidate_id", "repository", "base_sha", "head_sha",
                "attempt_id", "stage", "outcome", "fetch_timeout_seconds", "started_at", "completed_at",
                "partial_mirror_path", "stdout_hash", "stderr_hash"}
    if (set(attempt) != required or attempt.get("schema_id") != "external_validation.session2_source_mirror_attempt.v1"
            or attempt.get("schema_version") != "1" or attempt.get("candidate_id") != candidate_id
            or attempt.get("repository") != candidate.get("repository") or attempt.get("stage") != "EXACT_FETCH"
            or attempt.get("outcome") != "TIMED_OUT" or attempt.get("partial_mirror_path") != "supervisor_staging_only"
            or not isinstance(attempt.get("attempt_id"), str) or not attempt["attempt_id"]
            or not isinstance(attempt.get("fetch_timeout_seconds"), int) or not 30 <= attempt["fetch_timeout_seconds"] <= 600
            or not all(isinstance(attempt.get(key), str) and _SHA.fullmatch(attempt[key]) for key in ("base_sha", "head_sha"))
            or not all(isinstance(attempt.get(key), str) and _HASH.fullmatch(attempt[key]) for key in ("stdout_hash", "stderr_hash"))):
        _fail("session2_mirror_timeout_screen_attempt_invalid")
    mirror_store = root / "session2" / "cases" / "mirrors"
    for key, suffix in (("stdout_hash", ".mirror-attempt.stdout"), ("stderr_hash", ".mirror-attempt.stderr")):
        path = mirror_store / (attempt[key][7:] + suffix)
        if not path.is_file() or _is_reparse(path) or _sha(path.read_bytes()) != attempt[key]:
            _fail("session2_mirror_timeout_screen_stream_invalid")
    record = {
        "schema_id": "external_validation.session2_mirror_acquisition_screen.v1",
        "schema_version": "1", "candidate_id": candidate_id,
        "candidate_index_hash": candidate_index_hash,
        "mirror_attempt_hash": mirror_attempt_hash,
        "stage": "SOURCE_MIRROR_ACQUISITION",
        "decision": "EXCLUDED_PREQUALIFICATION",
        "reason": _MIRROR_ACQUISITION_TIMED_OUT,
        "created_at": _utc(),
    }
    return {"screen_hash": _write_once(directory, ".mirror-acquisition-screen.json", canonical_json(record)),
            "decision": record["decision"]}


def seal_unsafe_materialization_screen(
    repository_root: Path, *, candidate_id: str, candidate_index_hash: str,
    materialization_failure_hash: str,
) -> dict[str, str]:
    """Turn a sealed safe-export rejection into a deterministic exclusion."""
    if (not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash)
            or not _HASH.fullmatch(materialization_failure_hash)):
        _fail("session2_safe_export_screen_input_invalid")
    directory = _root(repository_root)
    _candidate_from_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)
    root = directory.parents[2]
    failure = _canonical_record(
        root / "session2" / "cases" / "materializations" / (materialization_failure_hash[7:] + ".materialization-failure.json"),
        materialization_failure_hash,
        missing="session2_safe_export_screen_failure_missing",
        invalid="session2_safe_export_screen_failure_invalid",
    )
    required = {"schema_id", "schema_version", "candidate_id", "commit_sha", "tree_sha",
                "source_object_receipt_hashes", "mirror_receipt_hash", "failure_code",
                "snapshot_location", "started_at", "completed_at"}
    if (set(failure) != required or failure.get("schema_id") != "external_validation.session2_source_materialization_failure.v1"
            or failure.get("schema_version") != "1" or failure.get("candidate_id") != candidate_id
            or failure.get("failure_code") != "session2_materialization_unsafe_patient_tree_entry"
            or failure.get("snapshot_location") != "supervisor_staging_only"
            or not all(isinstance(failure.get(key), str) and _SHA.fullmatch(failure[key]) for key in ("commit_sha", "tree_sha"))
            or not isinstance(failure.get("source_object_receipt_hashes"), list)
            or len(failure["source_object_receipt_hashes"]) < 2
            or any(not isinstance(item, str) or not _HASH.fullmatch(item) for item in failure["source_object_receipt_hashes"])
            or not isinstance(failure.get("mirror_receipt_hash"), str) or not _HASH.fullmatch(failure["mirror_receipt_hash"])):
        _fail("session2_safe_export_screen_failure_invalid")
    record = {"schema_id":"external_validation.session2_safe_export_screen.v1", "schema_version":"1",
              "candidate_id":candidate_id, "candidate_index_hash":candidate_index_hash,
              "materialization_failure_hash":materialization_failure_hash,
              "stage":"SAFE_SOURCE_EXPORT", "decision":"EXCLUDED_PREQUALIFICATION",
              "reason":_UNSAFE_PATIENT_TREE_ENTRY, "created_at":_utc()}
    return {"screen_hash":_write_once(directory, ".safe-export-screen.json", canonical_json(record)),
            "decision":record["decision"]}


def resolve_primary_retrieval_reference(repository_root: Path, *, candidate_id: str, supersedes_screen_hash: str) -> dict[str, str]:
    """Reopen only an historical screen created by the object/receipt type bug."""
    if not isinstance(candidate_id, str) or not _HASH.fullmatch(supersedes_screen_hash):
        _fail("session2_screen_resolution_input_invalid")
    directory = _root(repository_root); path = directory / (supersedes_screen_hash[7:] + ".provenance-screen.json")
    record = _canonical_record(path, supersedes_screen_hash, missing="session2_screen_resolution_predecessor_missing", invalid="session2_screen_resolution_predecessor_invalid")
    expected = record.get("expected_source_object_receipt_hashes")
    if (record.get("schema_id") != "external_validation.session2_candidate_provenance_screen.v1" or record.get("candidate_id") != candidate_id
            or record.get("reason") != _PRIMARY_RETRIEVAL_UNAVAILABLE or not isinstance(expected, list) or len(expected) != 2):
        _fail("session2_screen_resolution_predecessor_invalid")
    root = directory.parents[2] / "session2" / "retrieval"
    for digest in expected:
        receipt = _canonical_record(root / (digest[7:] + ".retrieval-receipt.json"), digest, missing="session2_screen_resolution_primary_receipt_missing", invalid="session2_screen_resolution_primary_receipt_invalid")
        pages = receipt.get("pages")
        if not isinstance(pages, list) or not pages:
            _fail("session2_screen_resolution_primary_receipt_invalid")
        for page in pages:
            raw_hash = page.get("raw_response_hash") if isinstance(page, dict) else None
            if not isinstance(raw_hash, str) or not _HASH.fullmatch(raw_hash): _fail("session2_screen_resolution_primary_receipt_invalid")
            _sealed_raw_json(root / "raw" / (raw_hash[7:] + ".json"), raw_hash, missing="session2_screen_resolution_primary_raw_missing", invalid="session2_screen_resolution_primary_raw_invalid")
    successor = {"schema_id":"external_validation.session2_candidate_provenance_resolution.v1", "schema_version":"1", "candidate_id":candidate_id,
                 "supersedes_screen_hash":supersedes_screen_hash, "reason":"PRIMARY_RETRIEVAL_REFERENCE_TYPE_CORRECTED",
                 "resolution":"REOPEN_FOR_REQUALIFICATION", "created_at":_utc()}
    return {"resolution_hash": _write_once(directory, ".provenance-resolution.json", canonical_json(successor)), "resolution": successor["resolution"]}


def _validate_runtime_evidence(
    directory: Path, *, candidate_id: str, fixed_sha: str,
    materialization_hash: str, execution_evidence_hash: str,
    source_object_receipt_hashes: list[str],
) -> None:
    """Bind a runtime exclusion to the exact staged snapshot and build result.

    A caller-supplied pair of hashes is deliberately insufficient: both sealed
    records must be canonical, addressable from the Session 2 root, and agree
    on the same candidate/snapshot.  This keeps an old build failure from
    excluding a later corrected materialization.
    """
    root = directory.parents[2]
    materialization = _canonical_record(
        root / "session2" / "cases" / "materializations" / (materialization_hash[7:] + ".materialization.json"),
        materialization_hash,
        missing="session2_screen_execution_materialization_missing",
        invalid="session2_screen_execution_materialization_invalid",
    )
    if (materialization.get("schema_id") != "external_validation.session2_source_materialization.v1"
            or materialization.get("candidate_id") != candidate_id
            or materialization.get("commit_sha") != fixed_sha):
        _fail("session2_screen_execution_materialization_mismatch")
    _validate_source_object_receipts(directory, candidate_id=candidate_id,
                                     materialization=materialization,
                                     source_object_receipt_hashes=source_object_receipt_hashes)
    environment_path = root / "session2" / "receipts" / "environments" / (execution_evidence_hash[7:] + ".environment-build-failure.json")
    if environment_path.is_file():
        execution = _canonical_record(environment_path, execution_evidence_hash,
            missing="session2_screen_execution_receipt_missing", invalid="session2_screen_execution_receipt_invalid")
        if (execution.get("schema_id") != "external_validation.session2_environment_build_failure.v1"
                or execution.get("materialization_hash") != materialization_hash
                or not isinstance(execution.get("failure_stage"), str)):
            _fail("session2_screen_execution_receipt_mismatch")
        return
    # A real supervisor receipt may prove a qualified runner cannot execute a
    # repository's declared contract even though dependency construction did
    # succeed.  This is distinct from a target oracle: it must be a failed
    # command contract on this exact fixed snapshot, with network disabled.
    execution = _canonical_record(
        root / "session2" / "receipts" / "executions" / (execution_evidence_hash[7:] + ".execution-receipt.json"),
        execution_evidence_hash,
        missing="session2_screen_execution_receipt_missing", invalid="session2_screen_execution_receipt_invalid")
    if (execution.get("schema_id") != "external_validation.session2_execution_receipt.v1"
            or execution.get("source_record_hash") != materialization_hash
            or execution.get("network_policy") != "none"
            or execution.get("contract_satisfied") is not False
            or not isinstance(execution.get("exit_code"), int)
            or execution.get("exit_code") == execution.get("expected_exit_code")):
        _fail("session2_screen_execution_receipt_mismatch")


def seal_prequalification_resolution(
    repository_root: Path, *, candidate_id: str, supersedes_screen_hash: str,
    prior_candidate_index_hash: str, implementation_commit: str,
) -> dict[str, str]:
    """Reopen only a screen caused by the corrected source-link policy.

    Screens are immutable historical evidence.  This successor does not claim
    qualification: it merely returns the candidate to the deterministic queue
    for the complete source, dependency, and execution gates.
    """
    if (not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(supersedes_screen_hash)
            or not _HASH.fullmatch(prior_candidate_index_hash) or not _SHA.fullmatch(implementation_commit)):
        _fail("session2_screen_resolution_input_invalid")
    directory = _root(repository_root)
    screen = directory / (supersedes_screen_hash[7:] + ".screen.json")
    if not screen.is_file() or _is_reparse(screen) or _sha(screen.read_bytes()) != supersedes_screen_hash:
        _fail("session2_screen_resolution_predecessor_missing")
    try:
        predecessor = json.loads(screen.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateScreenError("session2_screen_resolution_predecessor_invalid") from exc
    predecessor_reason = predecessor.get("reason")
    if predecessor.get("candidate_id") != candidate_id or predecessor_reason not in {"UNQUALIFIED_LINUX_CONTAINER_PATH", "FIXED_TWIN_NON_MINIMAL", "DEPENDENCY_AUTHORITY_NOT_FROZEN"}:
        _fail("session2_screen_resolution_predecessor_invalid")
    reason = (_RUNNER_RESOLUTION_REASON if predecessor_reason == "UNQUALIFIED_LINUX_CONTAINER_PATH"
              else _FIXED_TWIN_RESOLUTION_REASON if predecessor_reason == "FIXED_TWIN_NON_MINIMAL"
              else _REQUIREMENTS_AUTHORITY_RESOLUTION_REASON)
    record = {
        "schema_id": "external_validation.session2_prequalification_resolution.v1",
        "schema_version": "1",
        "candidate_id": candidate_id,
        "supersedes_screen_hash": supersedes_screen_hash,
        "prior_candidate_index_hash": prior_candidate_index_hash,
        "reason": reason,
        "resolution": "REOPEN_FOR_REQUALIFICATION",
        "implementation_commit": implementation_commit,
        "created_at": _utc(),
    }
    raw = canonical_json(record)
    return {"resolution_hash": _write_once(directory, ".resolution.json", raw), "resolution": record["resolution"]}


def seal_prequalification_exclusion(
    repository_root: Path, *, candidate_id: str, candidate_index_hash: str,
    mirror: Path, buggy_sha: str, fixed_sha: str, reason: str,
    source_object_receipt_hashes: list[str], materialization_hash: str | None = None,
    execution_evidence_hash: str | None = None,
) -> dict[str, str]:
    """Seal actual Git evidence before recording one typed failing source gate."""
    if (not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash)
            or not _SHA.fullmatch(buggy_sha) or not _SHA.fullmatch(fixed_sha) or buggy_sha == fixed_sha
            or reason not in _REASONS or not isinstance(source_object_receipt_hashes, list)
            or len(source_object_receipt_hashes) < 2 or any(not _HASH.fullmatch(item) for item in source_object_receipt_hashes)):
        _fail("session2_screen_input_invalid")
    # A runtime container-path or dependency-authority exclusion is a runtime
    # fact, never a reviewer assertion.  It must bind the exact sealed
    # materialization and production build failure for that snapshot.
    # It must bind the exact sealed materialization and the production build
    # receipt that failed for that snapshot. Other source gates omit them.
    runtime_reason = reason in {"UNQUALIFIED_LINUX_CONTAINER_PATH", "DEPENDENCY_AUTHORITY_NOT_FROZEN"}
    if runtime_reason:
        if not (_HASH.fullmatch(materialization_hash or "") and _HASH.fullmatch(execution_evidence_hash or "")):
            _fail("session2_screen_execution_evidence_required")
    elif materialization_hash is not None or execution_evidence_hash is not None:
        _fail("session2_screen_execution_evidence_unexpected")
    if not mirror.is_dir() or _is_reparse(mirror): _fail("session2_screen_mirror_invalid")
    directory = _root(repository_root)
    candidate = _assert_candidate_in_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)
    if runtime_reason:
        _validate_runtime_evidence(directory, candidate_id=candidate_id, fixed_sha=fixed_sha,
            materialization_hash=materialization_hash or "", execution_evidence_hash=execution_evidence_hash or "",
            source_object_receipt_hashes=source_object_receipt_hashes)
    for sha in (buggy_sha, fixed_sha):
        check = _run_git(mirror, "cat-file", "-e", sha + "^{commit}")
        if check["exit_code"] != 0: _fail("session2_screen_snapshot_missing")
    comparison = _run_git(mirror, "diff", "--no-ext-diff", "--name-status", buggy_sha, fixed_sha)
    if comparison["exit_code"] != 0: _fail("session2_screen_git_diff_failed")
    stdout_hash = _write_once(directory, ".stdout", comparison.pop("stdout"))
    stderr_hash = _write_once(directory, ".stderr", comparison.pop("stderr"))
    stdout_size = (directory / (stdout_hash[7:] + ".stdout")).stat().st_size
    stderr_size = (directory / (stderr_hash[7:] + ".stderr")).stat().st_size
    record = {
        # v2 is deliberately reserved for a runtime exclusion whose two
        # supervisor records are cross-bound below.  Source-only gates remain
        # the compact v1 contract; otherwise a fixed-twin exclusion could be
        # mistaken for an unbound runtime assertion by independent readers.
        "schema_id": ("external_validation.session2_prequalification_screen.v2"
                      if runtime_reason
                      else "external_validation.session2_prequalification_screen.v1"),
        "schema_version": "1",
        "candidate_id": candidate_id,
        "candidate_index_hash": candidate_index_hash,
        "buggy_sha": buggy_sha,
        "fixed_sha": fixed_sha,
        "stage": "SOURCE_CONTRACT_SCREEN",
        "decision": "EXCLUDED_PREQUALIFICATION",
        "reason": reason,
        "source_object_receipt_hashes": sorted(source_object_receipt_hashes),
        "supervisor_command": {**comparison, "stdout": {"bytes": stdout_size, "sha256": stdout_hash}, "stderr": {"bytes": stderr_size, "sha256": stderr_hash}},
        "created_at": _utc(),
    }
    if runtime_reason:
        record["materialization_hash"] = materialization_hash
        record["execution_evidence_hash"] = execution_evidence_hash
        # These are the paginated primary retrieval receipts from the frozen
        # candidate frame.  They deliberately remain distinct from the exact
        # object receipts above, which are validated against materialization.
        if not isinstance(candidate, dict):
            _fail("session2_screen_candidate_not_in_index")
        primary = [candidate.get("issue_retrieval_receipt_hash"), candidate.get("fix_retrieval_receipt_hash")]
        if any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in primary):
            _fail("session2_screen_candidate_primary_receipt_fields_invalid")
        record["candidate_primary_retrieval_receipt_hashes"] = sorted(primary)
    raw = canonical_json(record)
    return {"screen_hash": _write_once(directory, ".screen.json", raw), "decision": record["decision"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal one Session 2 prequalification exclusion.")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--candidate-index-hash")
    parser.add_argument("--mirror", type=Path)
    parser.add_argument("--buggy-sha"); parser.add_argument("--fixed-sha")
    parser.add_argument("--reason", choices=sorted(_REASONS | {_PRIMARY_RETRIEVAL_UNAVAILABLE}))
    parser.add_argument("--source-object-receipt-hash", action="append")
    parser.add_argument("--materialization-hash")
    parser.add_argument("--execution-evidence-hash")
    parser.add_argument("--resolve-screen-hash")
    parser.add_argument("--resolve-provenance-screen-hash")
    parser.add_argument("--prior-candidate-index-hash")
    parser.add_argument("--implementation-commit")
    args = parser.parse_args(argv)
    try:
        if args.resolve_provenance_screen_hash is not None:
            if any(item is not None for item in (args.candidate_index_hash, args.mirror, args.buggy_sha, args.fixed_sha, args.reason, args.source_object_receipt_hash, args.materialization_hash, args.execution_evidence_hash, args.resolve_screen_hash, args.prior_candidate_index_hash, args.implementation_commit)):
                _fail("session2_screen_resolution_input_invalid")
            result = resolve_primary_retrieval_reference(args.repository_root, candidate_id=args.candidate_id, supersedes_screen_hash=args.resolve_provenance_screen_hash)
        elif args.resolve_screen_hash is not None:
            if args.prior_candidate_index_hash is None or args.implementation_commit is None:
                _fail("session2_screen_resolution_input_invalid")
            result = seal_prequalification_resolution(args.repository_root, candidate_id=args.candidate_id,
                supersedes_screen_hash=args.resolve_screen_hash, prior_candidate_index_hash=args.prior_candidate_index_hash,
                implementation_commit=args.implementation_commit)
        else:
            if args.reason == _PRIMARY_RETRIEVAL_UNAVAILABLE:
                if any(item is not None for item in (args.mirror, args.buggy_sha, args.fixed_sha, args.source_object_receipt_hash, args.materialization_hash, args.execution_evidence_hash)) or args.candidate_index_hash is None:
                    _fail("session2_screen_input_invalid")
                result = seal_primary_retrieval_unavailable(args.repository_root, candidate_id=args.candidate_id, candidate_index_hash=args.candidate_index_hash)
                print(json.dumps(result, sort_keys=True)); return 0
            if any(item is None for item in (args.candidate_index_hash, args.mirror, args.buggy_sha, args.fixed_sha, args.reason, args.source_object_receipt_hash)):
                _fail("session2_screen_input_invalid")
            result = seal_prequalification_exclusion(args.repository_root, candidate_id=args.candidate_id, candidate_index_hash=args.candidate_index_hash, mirror=args.mirror, buggy_sha=args.buggy_sha, fixed_sha=args.fixed_sha, reason=args.reason, source_object_receipt_hashes=args.source_object_receipt_hash, materialization_hash=args.materialization_hash, execution_evidence_hash=args.execution_evidence_hash)
        print(json.dumps(result, sort_keys=True))
    except CandidateScreenError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
