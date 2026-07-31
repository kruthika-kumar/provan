"""Seal safe immutable source materialization for a Session 2 candidate.

This module is deliberately narrower than case qualification.  It creates a
supervisor-owned staging snapshot from an isolated bare mirror and records the
exact commit/tree authority before a patient worktree or container can exist.
It never evaluates repository code, talks to a model, or infers an oracle.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import subprocess
from typing import Any

from .identity import canonical_json
from .materialize import materialize_snapshot
from .security import _is_reparse, external_root
from .session2_staging_guard import MOUNT, StagingGuardError, reject_direct_materialization
from .remediation_backend.control import Control, ControlError


class MaterializationError(RuntimeError):
    """Stable rejection code for Session 2 source staging."""


_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CONTROL_DB = Path("/var/lib/shiproom-remediation/control.sqlite3")


def _fail(code: str) -> None:
    raise MaterializationError(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_materialization_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise MaterializationError("session2_materialization_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_materialization_external_root_invalid")
    result = root / "session2" / "cases" / "materializations"
    result.mkdir(mode=0o700, exist_ok=True)
    value = result.stat(follow_symlinks=False)
    if _is_reparse(result) or not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        _fail("session2_materialization_store_untrusted")
    return result


def _git(mirror: Path, *args: str) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(mirror), "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", *args],
        check=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
             "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "core.hooksPath",
             "GIT_CONFIG_VALUE_0": os.devnull, "GIT_CONFIG_KEY_1": "submodule.recurse",
             "GIT_CONFIG_VALUE_1": "false", "GIT_CONFIG_KEY_2": "filter.lfs.smudge", "GIT_CONFIG_VALUE_2": "cat"},
    ).stdout


def _write_once(directory: Path, raw: bytes, *, suffix: str = ".materialization.json") -> str:
    digest = _hash(raw)
    path = directory / (digest[7:] + suffix)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw:
            _fail("session2_materialization_receipt_collision")
    else:
        try:
            # The production entrypoint is Linux/root-only.  Conditional
            # calls keep its pure canonical-record tests portable on Windows
            # without relaxing the actual Linux authority boundary.
            if hasattr(os, "fchown"):
                os.fchown(fd, 0, 0)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o400)
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name == "posix":
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    return digest


def _validate_mirror_receipt(
    store: Path, *, mirror: Path, mirror_receipt_hash: str, candidate_id: str,
    source_object_receipt_hashes: list[str],
) -> None:
    """Bind an export to the production exact-fetch mirror authority."""
    if not _HASH.fullmatch(mirror_receipt_hash):
        _fail("session2_materialization_mirror_receipt_invalid")
    receipt_path = store.parent / "mirrors" / (mirror_receipt_hash[7:] + ".mirror.json")
    if not receipt_path.is_file() or _is_reparse(receipt_path):
        _fail("session2_materialization_mirror_receipt_missing")
    raw = receipt_path.read_bytes()
    if _hash(raw) != mirror_receipt_hash:
        _fail("session2_materialization_mirror_receipt_invalid")
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaterializationError("session2_materialization_mirror_receipt_invalid") from exc
    if (not isinstance(receipt, dict) or canonical_json(receipt) != raw
            or receipt.get("schema_id") != "external_validation.session2_source_mirror_receipt.v1"
            or receipt.get("schema_version") != "1"
            or receipt.get("candidate_id") != candidate_id
            or receipt.get("staging_mirror_name") != mirror.name
            or receipt.get("source_object_receipt_hashes") != sorted(source_object_receipt_hashes)):
        _fail("session2_materialization_mirror_receipt_mismatch")


def _allocation_bound_destination(destination: Path, allocation_attempt: str | None) -> dict[str, Any]:
    """Load and verify the sole production authority for an active tree."""
    if not isinstance(allocation_attempt, str) or not _ATTEMPT.fullmatch(allocation_attempt):
        _fail("session2_materialization_quota_worktree_authority_required")
    try:
        control = Control(_CONTROL_DB)
        try:
            control.assert_ready()
            allocation = control.allocation(allocation_attempt)
        finally:
            control.close()
    except (OSError, sqlite3.Error, ControlError) as exc:
        raise MaterializationError("session2_materialization_quota_worktree_authority_invalid") from exc
    authority = allocation.get("worktree_authority_json")
    if (allocation.get("status") != "ACTIVE" or allocation.get("phase") != "REGISTRY_COMMITTED"
            or not isinstance(authority, dict) or not isinstance(authority.get("canonical_path"), str)):
        _fail("session2_materialization_quota_worktree_authority_invalid")
    tree = Path(authority["canonical_path"])
    try:
        tree.relative_to(MOUNT / "worktrees")
        destination.relative_to(tree)
        value = tree.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise MaterializationError("session2_materialization_quota_worktree_authority_invalid") from exc
    expected = (authority.get("device"), authority.get("inode"), authority.get("uid"), authority.get("gid"))
    actual = (value.st_dev, value.st_ino, value.st_uid, value.st_gid)
    if (tree.is_symlink() or not stat.S_ISDIR(value.st_mode) or expected != actual
            or allocation.get("attempt_id") != allocation_attempt):
        _fail("session2_materialization_quota_worktree_authority_invalid")
    return authority


@contextmanager
def _prepared_allocation_destination(destination: Path, authority: dict[str, Any]):
    """Create destination parents descriptor-relatively without symlink escape.

    The allocated root is patient-owned, so an ordinary lexical prefix check
    is not an authority boundary.  This helper accepts only a newly created
    root-owned parent chain beneath the recorded worktree.  It keeps the final
    parent descriptor open while the caller exports the immutable snapshot.
    """
    tree = Path(str(authority["canonical_path"]))
    try:
        relative = destination.relative_to(tree)
    except ValueError as exc:
        raise MaterializationError("session2_materialization_quota_worktree_authority_invalid") from exc
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("session2_materialization_destination_invalid")
    try:
        root_fd = os.open(tree, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise MaterializationError("session2_materialization_quota_worktree_authority_invalid") from exc
    current_fd = root_fd
    try:
        root = os.fstat(root_fd)
        expected = (authority["device"], authority["inode"], authority["uid"], authority["gid"])
        if (root.st_dev, root.st_ino, root.st_uid, root.st_gid) != expected:
            _fail("session2_materialization_quota_worktree_authority_invalid")
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current_fd)
            except FileExistsError:
                # A sibling twin reuses ancestors created by the first export.
                # Accept only that root-owned, exact-mode, same-device chain;
                # a patient-created directory, symlink, special file, or a
                # stale permissive path is still an authority violation.
                pass
            except OSError as exc:
                raise MaterializationError("session2_materialization_destination_ancestor_unsafe") from exc
            try:
                child_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current_fd)
                child = os.fstat(child_fd)
            except OSError as exc:
                raise MaterializationError("session2_materialization_destination_ancestor_unsafe") from exc
            if (not stat.S_ISDIR(child.st_mode) or child.st_uid != 0 or child.st_gid != 0
                    or stat.S_IMODE(child.st_mode) != 0o700 or child.st_dev != root.st_dev):
                os.close(child_fd); _fail("session2_materialization_destination_ancestor_unsafe")
            if current_fd != root_fd: os.close(current_fd)
            current_fd = child_fd
        try:
            os.stat(parts[-1], dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise MaterializationError("session2_materialization_destination_invalid") from exc
        else:
            _fail("session2_materialization_destination_invalid")
        # The descriptor path keeps the selected parent bound even if the
        # pathname is concurrently renamed.  ``materialize_snapshot`` receives
        # this fixed descriptor address, never a caller-controlled prefix.
        yield Path(f"/proc/self/fd/{current_fd}") / parts[-1], relative.as_posix()
    finally:
        if current_fd != root_fd: os.close(current_fd)
        os.close(root_fd)


def seal_materialization(
    repository_root: Path, *, candidate_id: str, mirror: Path, commit_sha: str,
    destination: Path, source_object_receipt_hashes: list[str], mirror_receipt_hash: str,
    allocation_attempt: str | None = None,
) -> dict[str, str]:
    """Materialize one commit and seal the verified source authority.

    ``destination`` is intentionally outside the external evidence root.  It
    is a supervisor staging tree and must be absent before export; a patient
    is never granted write access to it.
    """
    try:
        reject_direct_materialization(destination)
    except StagingGuardError as exc:
        raise MaterializationError(str(exc)) from exc
    allocation_authority = _allocation_bound_destination(destination, allocation_attempt)
    if (not isinstance(candidate_id, str) or not candidate_id or not _SHA.fullmatch(commit_sha)
            or not isinstance(source_object_receipt_hashes, list) or len(source_object_receipt_hashes) < 2
            or any(not isinstance(item, str) or not _HASH.fullmatch(item) for item in source_object_receipt_hashes)):
        _fail("session2_materialization_input_invalid")
    if not mirror.is_dir() or _is_reparse(mirror) or not (mirror / "HEAD").is_file():
        _fail("session2_materialization_mirror_invalid")
    if destination.exists() or _is_reparse(destination) or not destination.is_absolute():
        _fail("session2_materialization_destination_invalid")
    store = _root(repository_root)
    _validate_mirror_receipt(store, mirror=mirror, mirror_receipt_hash=mirror_receipt_hash,
                             candidate_id=candidate_id, source_object_receipt_hashes=source_object_receipt_hashes)
    try:
        resolved = _git(mirror, "rev-parse", "--verify", commit_sha + "^{commit}").decode("ascii").strip()
        tree = _git(mirror, "rev-parse", "--verify", commit_sha + "^{tree}").decode("ascii").strip()
        tracked_count = len([line for line in _git(mirror, "ls-tree", "-r", "--name-only", commit_sha).splitlines() if line])
    except (subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise MaterializationError("session2_materialization_git_authority_invalid") from exc
    if resolved != commit_sha or not _SHA.fullmatch(tree) or tracked_count < 1:
        _fail("session2_materialization_git_authority_invalid")
    started = _utc()
    with _prepared_allocation_destination(destination, allocation_authority) as (safe_destination, safe_relative):
        try:
            materialize_snapshot(mirror, commit_sha, safe_destination)
            destination_info = safe_destination.stat(follow_symlinks=False)
        except Exception as exc:
        # Safe export rejects a forbidden patient-tree entry before any
        # container or worktree exists.  Preserve that fact as supervisor
        # evidence instead of leaving only an exception transcript.
            code = "session2_materialization_unsafe_patient_tree_entry" if str(exc) == "unsafe_patient_tree_entry" else "session2_materialization_export_failed"
            failure = {
                "schema_id": "external_validation.session2_source_materialization_failure.v1",
                "schema_version": "1", "candidate_id": candidate_id,
                "commit_sha": commit_sha, "tree_sha": tree,
                "source_object_receipt_hashes": sorted(source_object_receipt_hashes),
                "mirror_receipt_hash": mirror_receipt_hash,
                "failure_code": code, "snapshot_location": "allocation_bound_quota_worktree_only",
                "started_at": started, "completed_at": _utc(),
            }
            digest = _write_once(store, canonical_json(failure), suffix=".materialization-failure.json")
            raise MaterializationError(code + ":" + digest) from exc
    completed = _utc()
    if not destination.is_dir() or _is_reparse(destination):
        _fail("session2_materialization_export_invalid")
    entries: list[dict[str, str]] = []
    for path in sorted(destination.rglob("*"), key=lambda item: item.relative_to(destination).as_posix()):
        relative = path.relative_to(destination).as_posix()
        value = path.lstat()
        if stat.S_ISREG(value.st_mode):
            entries.append({"path": relative, "type": "regular"})
        elif stat.S_ISLNK(value.st_mode):
            target = os.readlink(path)
            if not target:
                _fail("session2_materialization_export_invalid")
            entries.append({"path": relative, "type": "relative_internal_symlink", "target": target})
        elif not stat.S_ISDIR(value.st_mode):
            _fail("session2_materialization_export_invalid")
    if len(entries) != tracked_count:
        _fail("session2_materialization_tree_count_mismatch")
    links = [item for item in entries if item["type"] == "relative_internal_symlink"]
    receipt = {
        "schema_id": "external_validation.session2_source_materialization.v1",
        "schema_version": "1",
        "candidate_id": candidate_id,
        "commit_sha": commit_sha,
        "tree_sha": tree,
        "source_object_receipt_hashes": sorted(source_object_receipt_hashes),
        "mirror_receipt_hash": mirror_receipt_hash,
        "supervisor_command": ["git", "archive", "--format=tar", commit_sha],
        "snapshot_location": "allocation_bound_quota_worktree_only",
        "allocation_attempt": allocation_attempt,
        "worktree_authority_hash": _hash(canonical_json(allocation_authority)),
        "snapshot_authority": {
            "device": destination_info.st_dev,
            "inode": destination_info.st_ino,
            "uid": destination_info.st_uid,
            "gid": destination_info.st_gid,
            "relative_path": safe_relative,
        },
        "tracked_file_count": tracked_count,
        "exported_file_count": len(entries),
        "symlink_policy": "relative_internal_tracked_target_only.v1",
        "symlink_manifest_hash": _hash(canonical_json(links)),
        "started_at": started,
        "completed_at": completed,
    }
    return {"materialization_hash": _write_once(store, canonical_json(receipt)), "tree_sha": tree}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize and seal one Session 2 immutable source snapshot.")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--mirror", required=True, type=Path)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--allocation-attempt", required=True)
    parser.add_argument("--source-object-receipt-hash", required=True, action="append")
    parser.add_argument("--mirror-receipt-hash", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(seal_materialization(args.repository_root, candidate_id=args.candidate_id, mirror=args.mirror,
              commit_sha=args.commit_sha, destination=args.destination,
              source_object_receipt_hashes=args.source_object_receipt_hash,
              mirror_receipt_hash=args.mirror_receipt_hash,
              allocation_attempt=args.allocation_attempt), sort_keys=True, separators=(",", ":")))
    except MaterializationError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
