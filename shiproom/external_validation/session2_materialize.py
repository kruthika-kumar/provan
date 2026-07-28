"""Seal safe immutable source materialization for a Session 2 candidate.

This module is deliberately narrower than case qualification.  It creates a
supervisor-owned staging snapshot from an isolated bare mirror and records the
exact commit/tree authority before a patient worktree or container can exist.
It never evaluates repository code, talks to a model, or infers an oracle.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
from typing import Any

from .identity import canonical_json
from .materialize import materialize_snapshot
from .security import _is_reparse, external_root


class MaterializationError(RuntimeError):
    """Stable rejection code for Session 2 source staging."""


_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def _write_once(directory: Path, raw: bytes) -> str:
    digest = _hash(raw)
    path = directory / (digest[7:] + ".materialization.json")
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


def seal_materialization(
    repository_root: Path, *, candidate_id: str, mirror: Path, commit_sha: str,
    destination: Path, source_object_receipt_hashes: list[str],
) -> dict[str, str]:
    """Materialize one commit and seal the verified source authority.

    ``destination`` is intentionally outside the external evidence root.  It
    is a supervisor staging tree and must be absent before export; a patient
    is never granted write access to it.
    """
    if (not isinstance(candidate_id, str) or not candidate_id or not _SHA.fullmatch(commit_sha)
            or not isinstance(source_object_receipt_hashes, list) or len(source_object_receipt_hashes) < 2
            or any(not isinstance(item, str) or not _HASH.fullmatch(item) for item in source_object_receipt_hashes)):
        _fail("session2_materialization_input_invalid")
    if not mirror.is_dir() or _is_reparse(mirror) or not (mirror / "HEAD").is_file():
        _fail("session2_materialization_mirror_invalid")
    if destination.exists() or _is_reparse(destination) or not destination.is_absolute():
        _fail("session2_materialization_destination_invalid")
    store = _root(repository_root)
    try:
        resolved = _git(mirror, "rev-parse", "--verify", commit_sha + "^{commit}").decode("ascii").strip()
        tree = _git(mirror, "rev-parse", "--verify", commit_sha + "^{tree}").decode("ascii").strip()
        tracked_count = len([line for line in _git(mirror, "ls-tree", "-r", "--name-only", commit_sha).splitlines() if line])
    except (subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise MaterializationError("session2_materialization_git_authority_invalid") from exc
    if resolved != commit_sha or not _SHA.fullmatch(tree) or tracked_count < 1:
        _fail("session2_materialization_git_authority_invalid")
    started = _utc()
    try:
        materialize_snapshot(mirror, commit_sha, destination)
    except Exception as exc:
        raise MaterializationError("session2_materialization_export_failed") from exc
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
        "supervisor_command": ["git", "archive", "--format=tar", commit_sha],
        "snapshot_location": "supervisor_staging_only",
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
    parser.add_argument("--source-object-receipt-hash", required=True, action="append")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(seal_materialization(args.repository_root, candidate_id=args.candidate_id, mirror=args.mirror,
              commit_sha=args.commit_sha, destination=args.destination,
              source_object_receipt_hashes=args.source_object_receipt_hash), sort_keys=True, separators=(",", ":")))
    except MaterializationError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
