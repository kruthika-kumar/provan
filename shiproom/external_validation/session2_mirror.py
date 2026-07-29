"""Acquire one Session 2 source pair into a sealed isolated bare mirror."""
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

from .identity import canonical_json
from .security import _is_reparse, external_root

ROOT = Path("/var/lib/shiproom-external-validation")
MIRRORS = Path("/mnt/shiproom-remediation/session2-supervisor/mirrors")
MIN_STAGING_FREE_BYTES = 2 * 1024 * 1024 * 1024
MIN_STAGING_FREE_INODES = 4096
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ATTEMPT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class MirrorAcquisitionError(RuntimeError): pass


def _fail(code: str) -> None: raise MirrorAcquisitionError(code)
def _utc() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
def _hash(raw: bytes) -> str: return "sha256:" + sha256(raw).hexdigest()


def _run(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["/usr/bin/git", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout,
        env={"PATH":"/usr/bin:/bin", "HOME":"/root", "LANG":"C.UTF-8", "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null", "GIT_TERMINAL_PROMPT":"0", "GIT_LFS_SKIP_SMUDGE":"1"})


def _store(repo: Path) -> Path:
    if os.geteuid() != 0 or os.name != "posix" or platform.system() != "Linux": _fail("session2_mirror_linux_root_required")
    try: root = external_root(None, repo)
    except PermissionError as exc: raise MirrorAcquisitionError("session2_mirror_external_root_invalid") from exc
    target = root / "session2" / "cases" / "mirrors"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = target.stat(follow_symlinks=False)
    if root != ROOT or _is_reparse(target) or not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022: _fail("session2_mirror_store_invalid")
    return target


def _write_once(directory: Path, raw: bytes) -> str:
    digest = _hash(raw); path = directory / (digest[7:] + ".mirror.json")
    try: fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os,"O_NOFOLLOW",0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw: _fail("session2_mirror_receipt_collision")
    else:
        try: os.fchown(fd,0,0); os.fchmod(fd,0o400); os.write(fd,raw); os.fsync(fd)
        finally: os.close(fd)
    return digest


def _write_blob(directory: Path, suffix: str, raw: bytes) -> str:
    """Seal a raw acquisition stream before referencing its digest in a receipt."""
    digest = _hash(raw)
    path = directory / (digest[7:] + suffix)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw:
            _fail("session2_mirror_receipt_collision")
    else:
        try:
            os.fchown(fd, 0, 0); os.fchmod(fd, 0o400); os.write(fd, raw); os.fsync(fd)
        finally:
            os.close(fd)
    return digest


def _staging_capacity() -> dict[str, int | bool]:
    """Return the live supervisor-staging admission evidence before Git writes.

    The mirror is intentionally not created under a nearly full quota and then
    diagnosed from a partial packfile.  Both data blocks and inode headroom are
    required because bare Git fetches can exhaust either independently.
    """
    if not hasattr(os, "statvfs"):
        raise MirrorAcquisitionError("session2_mirror_staging_capacity_unavailable")
    try:
        values = os.statvfs(MIRRORS)
    except OSError as exc:
        raise MirrorAcquisitionError("session2_mirror_staging_capacity_unavailable") from exc
    free_bytes = values.f_frsize * values.f_bavail
    free_inodes = values.f_favail
    return {
        "free_bytes": free_bytes,
        "free_inodes": free_inodes,
        "minimum_free_bytes": MIN_STAGING_FREE_BYTES,
        "minimum_free_inodes": MIN_STAGING_FREE_INODES,
        "sufficient": free_bytes >= MIN_STAGING_FREE_BYTES and free_inodes >= MIN_STAGING_FREE_INODES,
    }


def acquire_pair(repo: Path, *, candidate_id: str, repository: str, base_sha: str, head_sha: str,
                 source_receipts: list[str], attempt_id: str = "initial", fetch_timeout_seconds: int = 180) -> dict[str,str]:
    if (not candidate_id or not _SLUG.fullmatch(repository) or not _SHA.fullmatch(base_sha) or not _SHA.fullmatch(head_sha)
            or base_sha == head_sha or len(source_receipts) != 2 or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in source_receipts)
            or not _ATTEMPT.fullmatch(attempt_id) or not isinstance(fetch_timeout_seconds, int)
            or not 30 <= fetch_timeout_seconds <= 600):
        _fail("session2_mirror_input_invalid")
    store = _store(repo); name = re.sub(r"[^a-z0-9]+", "-", candidate_id.lower()).strip("-")
    if attempt_id != "initial":
        name += "--attempt-" + attempt_id
    target = MIRRORS / name
    if target.exists() or _is_reparse(target): _fail("session2_mirror_destination_exists")
    MIRRORS.mkdir(parents=True, exist_ok=True, mode=0o700)
    capacity = _staging_capacity()
    if not capacity["sufficient"]:
        timestamp = _utc()
        failure = {
            "schema_id": "external_validation.session2_source_mirror_attempt.v1",
            "schema_version": "1", "candidate_id": candidate_id,
            "repository": repository, "base_sha": base_sha, "head_sha": head_sha,
            "attempt_id": attempt_id, "stage": "STAGING_CAPACITY_PREFLIGHT",
            "outcome": "BLOCKED", "started_at": timestamp, "completed_at": timestamp,
            "staging_capacity": capacity,
        }
        raise MirrorAcquisitionError("session2_mirror_staging_capacity_insufficient:" + _write_once(store, canonical_json(failure)))
    started = _utc(); init = _run("init", "--bare", str(target), timeout=30)
    if init.returncode:
        failure = {"schema_id":"external_validation.session2_source_mirror_attempt.v1", "schema_version":"1", "candidate_id":candidate_id,
                   "repository":repository, "base_sha":base_sha, "head_sha":head_sha, "attempt_id":attempt_id,
                   "stage":"BARE_INITIALIZATION", "outcome":"FAILED", "started_at":started, "completed_at":_utc(),
                   "stdout_hash":_write_blob(store, ".mirror-attempt.stdout", init.stdout), "stderr_hash":_write_blob(store, ".mirror-attempt.stderr", init.stderr)}
        raise MirrorAcquisitionError("session2_mirror_init_failed:" + _write_once(store, canonical_json(failure)))
    try:
        fetch = _run("-C", str(target), "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "fetch", "--no-tags", "--no-recurse-submodules", "https://github.com/" + repository + ".git", base_sha, head_sha, timeout=fetch_timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        completed = _utc()
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        failure = {"schema_id":"external_validation.session2_source_mirror_attempt.v1", "schema_version":"1", "candidate_id":candidate_id,
                   "repository":repository, "base_sha":base_sha, "head_sha":head_sha, "attempt_id":attempt_id,
                   "stage":"EXACT_FETCH", "outcome":"TIMED_OUT", "fetch_timeout_seconds":fetch_timeout_seconds, "started_at":started, "completed_at":completed,
                   "partial_mirror_path":"supervisor_staging_only", "stdout_hash":_write_blob(store, ".mirror-attempt.stdout", stdout),
                   "stderr_hash":_write_blob(store, ".mirror-attempt.stderr", stderr)}
        raise MirrorAcquisitionError("session2_mirror_fetch_timed_out:" + _write_once(store, canonical_json(failure))) from exc
    completed = _utc()
    if fetch.returncode:
        failure = {"schema_id":"external_validation.session2_source_mirror_attempt.v1", "schema_version":"1", "candidate_id":candidate_id,
                   "repository":repository, "base_sha":base_sha, "head_sha":head_sha, "attempt_id":attempt_id,
                   "stage":"EXACT_FETCH", "outcome":"FAILED", "fetch_timeout_seconds":fetch_timeout_seconds, "started_at":started, "completed_at":completed,
                   "partial_mirror_path":"supervisor_staging_only", "stdout_hash":_write_blob(store, ".mirror-attempt.stdout", fetch.stdout),
                   "stderr_hash":_write_blob(store, ".mirror-attempt.stderr", fetch.stderr)}
        raise MirrorAcquisitionError("session2_mirror_fetch_failed:" + _write_once(store, canonical_json(failure)))
    verified = []
    for commit in (base_sha, head_sha):
        result = _run("-C", str(target), "rev-parse", "--verify", commit + "^{commit}", timeout=30)
        if result.returncode or result.stdout.decode("ascii","ignore").strip() != commit: _fail("session2_mirror_commit_verification_failed")
        tree = _run("-C", str(target), "rev-parse", "--verify", commit + "^{tree}", timeout=30)
        if tree.returncode or not _SHA.fullmatch(tree.stdout.decode("ascii","ignore").strip()): _fail("session2_mirror_tree_verification_failed")
        verified.append({"commit":commit,"tree":tree.stdout.decode("ascii").strip()})
    record={"schema_id":"external_validation.session2_source_mirror_receipt.v1","schema_version":"1","candidate_id":candidate_id,"repository":repository,"base_sha":base_sha,"head_sha":head_sha,"source_object_receipt_hashes":sorted(source_receipts),"staging_mirror_name":target.name,"remote":"https://github.com/"+repository+".git","fetch_policy":"bare_exact_commit_no_tags_no_submodules.v1","fetch_timeout_seconds":fetch_timeout_seconds,"verified_commits":verified,"started_at":started,"completed_at":completed,"fetch_stdout_hash":_hash(fetch.stdout),"fetch_stderr_hash":_hash(fetch.stderr)}
    return {"mirror_path":str(target),"mirror_receipt_hash":_write_once(store,canonical_json(record))}


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--repository-root",type=Path,required=True); p.add_argument("--candidate-id",required=True); p.add_argument("--repository",required=True); p.add_argument("--base-sha",required=True); p.add_argument("--head-sha",required=True); p.add_argument("--source-object-receipt-hash",action="append",required=True); p.add_argument("--attempt-id", default="initial"); p.add_argument("--fetch-timeout-seconds", type=int, default=180); a=p.parse_args()
    try: print(json.dumps(acquire_pair(a.repository_root,candidate_id=a.candidate_id,repository=a.repository,base_sha=a.base_sha,head_sha=a.head_sha,source_receipts=a.source_object_receipt_hash,attempt_id=a.attempt_id,fetch_timeout_seconds=a.fetch_timeout_seconds),sort_keys=True))
    except MirrorAcquisitionError as exc: print(str(exc)); return 2
    return 0

if __name__ == "__main__": raise SystemExit(main())
