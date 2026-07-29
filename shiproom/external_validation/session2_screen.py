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
    if (index.get("schema_id") != "external_validation.session2_github_issue_fix_candidate_index.v1"
            or index.get("schema_version") != "1" or len(matches) != 1):
        _fail("session2_screen_candidate_not_in_index")
    return matches[0]


def _assert_candidate_in_index(directory: Path, *, candidate_id: str, candidate_index_hash: str) -> None:
    _candidate_from_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)


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
            _canonical_record(root / "raw" / (raw_hash[7:] + ".json"), raw_hash, missing="session2_screen_resolution_primary_raw_missing", invalid="session2_screen_resolution_primary_raw_invalid")
    successor = {"schema_id":"external_validation.session2_candidate_provenance_resolution.v1", "schema_version":"1", "candidate_id":candidate_id,
                 "supersedes_screen_hash":supersedes_screen_hash, "reason":"PRIMARY_RETRIEVAL_REFERENCE_TYPE_CORRECTED",
                 "resolution":"REOPEN_FOR_REQUALIFICATION", "created_at":_utc()}
    return {"resolution_hash": _write_once(directory, ".provenance-resolution.json", canonical_json(successor)), "resolution": successor["resolution"]}


def _validate_runtime_evidence(
    directory: Path, *, candidate_id: str, fixed_sha: str,
    materialization_hash: str, execution_evidence_hash: str,
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
    execution = _canonical_record(
        root / "session2" / "receipts" / "environments" / (execution_evidence_hash[7:] + ".environment-build-failure.json"),
        execution_evidence_hash,
        missing="session2_screen_execution_receipt_missing",
        invalid="session2_screen_execution_receipt_invalid",
    )
    if (execution.get("schema_id") != "external_validation.session2_environment_build_failure.v1"
            or execution.get("materialization_hash") != materialization_hash
            or not isinstance(execution.get("failure_stage"), str)):
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
    _assert_candidate_in_index(directory, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash)
    if runtime_reason:
        _validate_runtime_evidence(directory, candidate_id=candidate_id, fixed_sha=fixed_sha,
            materialization_hash=materialization_hash or "", execution_evidence_hash=execution_evidence_hash or "")
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
