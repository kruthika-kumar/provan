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
}


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
        os.chown(path, 0, 0); os.chmod(path, 0o400)
    return digest


def seal_prequalification_exclusion(
    repository_root: Path, *, candidate_id: str, candidate_index_hash: str,
    mirror: Path, buggy_sha: str, fixed_sha: str, reason: str,
    source_object_receipt_hashes: list[str],
) -> dict[str, str]:
    """Seal actual Git evidence before recording one typed failing source gate."""
    if (not isinstance(candidate_id, str) or not candidate_id or not _HASH.fullmatch(candidate_index_hash)
            or not _SHA.fullmatch(buggy_sha) or not _SHA.fullmatch(fixed_sha) or buggy_sha == fixed_sha
            or reason not in _REASONS or not isinstance(source_object_receipt_hashes, list)
            or len(source_object_receipt_hashes) < 2 or any(not _HASH.fullmatch(item) for item in source_object_receipt_hashes)):
        _fail("session2_screen_input_invalid")
    if not mirror.is_dir() or _is_reparse(mirror): _fail("session2_screen_mirror_invalid")
    directory = _root(repository_root)
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
        "schema_id": "external_validation.session2_prequalification_screen.v1",
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
    raw = canonical_json(record)
    return {"screen_hash": _write_once(directory, ".screen.json", raw), "decision": record["decision"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal one Session 2 prequalification exclusion.")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--candidate-index-hash", required=True)
    parser.add_argument("--mirror", required=True, type=Path)
    parser.add_argument("--buggy-sha", required=True); parser.add_argument("--fixed-sha", required=True)
    parser.add_argument("--reason", required=True, choices=sorted(_REASONS))
    parser.add_argument("--source-object-receipt-hash", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(seal_prequalification_exclusion(args.repository_root, candidate_id=args.candidate_id, candidate_index_hash=args.candidate_index_hash, mirror=args.mirror, buggy_sha=args.buggy_sha, fixed_sha=args.fixed_sha, reason=args.reason, source_object_receipt_hashes=args.source_object_receipt_hash), sort_keys=True))
    except CandidateScreenError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
