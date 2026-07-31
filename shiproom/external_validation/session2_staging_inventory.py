"""Seal a conservative, read-only inventory of Session 2 supervisor staging.

The qualified staging filesystem is deliberately separate from the canonical
external evidence root.  This tool records enough immutable source-attempt
authority to distinguish disposable failed mirror attempts from staging that
must remain untouched.  It never performs deletion; a later, reviewed release
tool must consume its content-addressed allowlist.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2_staging_guard import StagingGuardError, require_supervisor_staging


EXPECTED_ROOT = Path("/var/lib/shiproom-external-validation")
STAGING_ROOT = Path("/mnt/shiproom-remediation/session2-supervisor")
_PRODUCTION_STAGING_ROOT = STAGING_ROOT
MIRRORS = STAGING_ROOT / "mirrors"
SNAPSHOTS = STAGING_ROOT / "snapshots"
_ATTEMPT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class StagingInventoryError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise StagingInventoryError(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _normal_name(candidate_id: str, attempt_id: str) -> str:
    name = re.sub(r"[^a-z0-9]+", "-", candidate_id.lower()).strip("-")
    return name if attempt_id == "initial" else name + "--attempt-" + attempt_id


def _authority_records(root: Path) -> dict[str, dict[str, Any]]:
    """Index mirror attempts by their derived immutable staging directory."""
    directory = root / "session2" / "cases" / "mirrors"
    if not directory.is_dir() or _is_reparse(directory):
        _fail("session2_staging_inventory_authority_missing")
    collected: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(directory.glob("*.mirror.json")):
        if _is_reparse(path) or not path.is_file() or path.stat(follow_symlinks=False).st_uid != 0:
            _fail("session2_staging_inventory_authority_invalid")
        raw = path.read_bytes()
        if _hash(raw)[7:] != path.name.split(".", 1)[0]:
            _fail("session2_staging_inventory_authority_hash_invalid")
        try:
            item = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StagingInventoryError("session2_staging_inventory_authority_invalid") from exc
        if (not isinstance(item, dict)
                or item.get("schema_id") not in {"external_validation.session2_source_mirror_receipt.v1", "external_validation.session2_source_mirror_attempt.v1"}
                or item.get("schema_version") != "1"
                or not isinstance(item.get("candidate_id"), str)
                or not isinstance(item.get("attempt_id", "initial"), str)
                or not _ATTEMPT.fullmatch(item.get("attempt_id", "initial"))):
            _fail("session2_staging_inventory_authority_invalid")
        name = _normal_name(item["candidate_id"], item.get("attempt_id", "initial"))
        collected.setdefault(name, []).append({"receipt_hash": _hash(raw), "candidate_id": item["candidate_id"], "attempt_id": item.get("attempt_id", "initial"), "outcome": item.get("outcome", "SUCCEEDED")})
    # Historical duplicate records are evidence of uncertain staging lineage,
    # not a reason to lose the inventory.  They are represented explicitly and
    # can never become deletion-eligible.
    result: dict[str, dict[str, Any]] = {}
    for name, records in collected.items():
        if len(records) == 1:
            result[name] = records[0]
        else:
            result[name] = {"ambiguous": True, "receipt_hashes": sorted(item["receipt_hash"] for item in records)}
    return result


def _entry(path: Path, *, kind: str, authority: dict[str, Any] | None) -> dict[str, Any]:
    value = path.stat(follow_symlinks=False)
    record = {"relative_path": path.relative_to(STAGING_ROOT).as_posix(), "kind": kind, "device": value.st_dev, "inode": value.st_ino, "allocated_bytes": 0, "inode_count": 1, "authority": authority, "entry_state": "VERIFIED_DIRECTORY"}
    if _is_reparse(path) or not stat.S_ISDIR(value.st_mode):
        record["entry_state"] = "UNSAFE_ENTRY_TYPE"; record["deletion_eligible"] = False
        return record
    if value.st_uid != 0 or value.st_gid != 0:
        record["entry_state"] = "UNTRUSTED_OWNERSHIP"; record["deletion_eligible"] = False
        return record
    total_bytes = 0
    inode_count = 1
    for parent, directories, files in os.walk(path, topdown=True, followlinks=False):
        for name in [*directories, *files]:
            child = Path(parent) / name
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode) or not (stat.S_ISDIR(child_stat.st_mode) or stat.S_ISREG(child_stat.st_mode)):
                record["entry_state"] = "UNSAFE_DESCENDANT"; record["deletion_eligible"] = False
                return record
            inode_count += 1
            if stat.S_ISREG(child_stat.st_mode):
                # POSIX records allocated blocks.  The Windows test harness
                # lacks ``st_blocks``, for which rounded byte size is the
                # conservative portable stand-in.
                total_bytes += getattr(child_stat, "st_blocks", (child_stat.st_size + 511) // 512) * 512
    record["allocated_bytes"] = total_bytes; record["inode_count"] = inode_count
    # Failed exact-attempt mirrors are the only objects ever eligible for a
    # later deletion allowlist.  Snapshots and any unlinked/ambiguous entry
    # remain retained by construction.
    record["deletion_eligible"] = bool(kind == "mirror" and authority and authority.get("ambiguous") is not True and authority.get("outcome") in {"FAILED", "TIMED_OUT", "BLOCKED"})
    return record


def _capacity() -> dict[str, int]:
    if not hasattr(os, "statvfs"):
        _fail("session2_staging_inventory_platform_unsupported")
    data = os.statvfs(STAGING_ROOT)
    return {"free_bytes": data.f_frsize * data.f_bavail, "free_inodes": data.f_favail, "total_bytes": data.f_frsize * data.f_blocks, "total_inodes": data.f_files}


def _write_once(directory: Path, raw: bytes) -> tuple[Path, str]:
    digest = _hash(raw)
    target = directory / (digest[7:] + ".staging-inventory.json")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        if _is_reparse(target) or target.read_bytes() != raw:
            _fail("session2_staging_inventory_collision")
        return target, digest
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        if not hasattr(os, "fchown") or not hasattr(os, "fchmod"):
            _fail("session2_staging_inventory_platform_unsupported")
        os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400); os.write(descriptor, raw); os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix":
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    return target, digest


def inventory(repository_root: Path, *, implementation_commit: str, implementation_tree: str) -> dict[str, str]:
    if os.geteuid() != 0 or not _GIT_SHA.fullmatch(implementation_commit) or not _GIT_SHA.fullmatch(implementation_tree):
        _fail("session2_staging_inventory_input_invalid")
    root = external_root(None, repository_root)
    if STAGING_ROOT == _PRODUCTION_STAGING_ROOT:
        try:
            require_supervisor_staging(STAGING_ROOT)
        except StagingGuardError as exc:
            raise StagingInventoryError(str(exc)) from exc
    if root != EXPECTED_ROOT or _is_reparse(STAGING_ROOT) or not MIRRORS.is_dir() or not SNAPSHOTS.is_dir():
        _fail("session2_staging_inventory_root_invalid")
    authority = _authority_records(root)
    entries = []
    for kind, parent in (("mirror", MIRRORS), ("snapshot", SNAPSHOTS)):
        for path in sorted(parent.iterdir(), key=lambda item: item.name):
            entries.append(_entry(path, kind=kind, authority=authority.get(path.name) if kind == "mirror" else None))
    document = {"schema_id": "external_validation.session2_supervisor_staging_inventory.v1", "schema_version": "1", "created_at": _utc(), "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "staging_root": str(STAGING_ROOT), "capacity": _capacity(), "entries": entries, "deletion_allowlist": [item["relative_path"] for item in entries if item["deletion_eligible"]]}
    target, digest = _write_once(root / "session2" / "reviews" / "staging-inventory", canonical_json(document))
    return {"inventory_hash": digest, "path": str(target), "eligible_count": str(len(document["deletion_allowlist"]))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal a read-only Session 2 supervisor-staging inventory.")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--implementation-tree", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inventory(args.repository_root, implementation_commit=args.implementation_commit, implementation_tree=args.implementation_tree), sort_keys=True))
    except StagingInventoryError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
