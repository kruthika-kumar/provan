"""Fail-closed authority checks for the Session 2 supervisor staging mount.

After a WSL restart ``/mnt/shiproom-remediation`` is an ordinary ext4
directory.  It must never silently become a substitute for the qualified XFS
backend merely because its path exists.  All supervisor-staging writers call
this verifier immediately before their first write.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable


ROOT = Path("/var/lib/shiproom-remediation")
IMAGE = ROOT / "shiproom-remediation.xfs"
STATE = ROOT / "backend.state"
MOUNT = Path("/mnt/shiproom-remediation")
SUPERVISOR_ROOT = MOUNT / "session2-supervisor"
_LOOP = re.compile(r"^/dev/loop[0-9]+$")


class StagingGuardError(RuntimeError):
    """Stable rejection code; callers must not create a staging path."""


def _fail(code: str) -> None:
    raise StagingGuardError(code)


def _command(*argv: str) -> str:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=True,
                                timeout=30, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StagingGuardError("session2_staging_guard_probe_unavailable") from exc
    if result.returncode:
        _fail("session2_staging_guard_probe_failed")
    return result.stdout


def _linux_root() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _state() -> dict[str, str]:
    try:
        info = STATE.stat(follow_symlinks=False)
        raw = STATE.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise StagingGuardError("session2_staging_guard_state_invalid") from exc
    if STATE.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        _fail("session2_staging_guard_state_invalid")
    values: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or parts[0] in values:
            _fail("session2_staging_guard_state_invalid")
        try:
            decoded = base64.b64decode(parts[1], validate=True).decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise StagingGuardError("session2_staging_guard_state_invalid") from exc
        if not decoded or "\n" in decoded or "\r" in decoded:
            _fail("session2_staging_guard_state_invalid")
        values[parts[0]] = decoded
    required = {"IMAGE": str(IMAGE), "MOUNT": str(MOUNT), "RUN": "/run/shiproom-remediation-docker",
                "LOOP": None, "DATA_PROJECT": "10000", "DATA_BYTES": "8589934592", "DATA_INODES": "200000"}
    for key, expected in required.items():
        if key not in values or (expected is not None and values[key] != expected):
            _fail("session2_staging_guard_state_invalid")
    if not _LOOP.fullmatch(values["LOOP"]):
        _fail("session2_staging_guard_state_invalid")
    return values


def _mount_record(run: Callable[..., str]) -> tuple[str, str, set[str]]:
    raw = run("/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "--target", str(MOUNT)).strip()
    fields = raw.split(maxsplit=2)
    if len(fields) != 3:
        _fail("session2_staging_guard_mount_invalid")
    return fields[0], fields[1], set(fields[2].split(","))


def verify_supervisor_staging(*, run: Callable[..., str] = _command) -> dict[str, str]:
    """Prove the exact qualified XFS source before any supervisor write.

    This function makes neither directories nor mounts.  An absent mount, an
    ext4 mount, stale loop binding, or missing quota evidence rejects before a
    caller can create ``session2-supervisor``.
    """
    if not _linux_root():
        _fail("session2_staging_guard_linux_root_required")
    state = _state()
    try:
        mount_stat = MOUNT.stat(follow_symlinks=False)
    except OSError as exc:
        raise StagingGuardError("session2_staging_guard_mount_invalid") from exc
    if MOUNT.is_symlink() or not stat.S_ISDIR(mount_stat.st_mode) or not os.path.ismount(MOUNT):
        _fail("session2_staging_guard_mount_invalid")
    source, fstype, options = _mount_record(run)
    if source != state["LOOP"] or fstype != "xfs" or not {"prjquota", "noatime"}.issubset(options):
        _fail("session2_staging_guard_mount_invalid")
    if run("/usr/sbin/losetup", "-n", "-O", "BACK-FILE", state["LOOP"]).strip() != str(IMAGE):
        _fail("session2_staging_guard_loop_identity_invalid")
    if "ftype=1" not in run("/usr/sbin/xfs_info", str(MOUNT)):
        _fail("session2_staging_guard_ftype_invalid")
    # Query both quota dimensions in the same frozen machine-readable form as
    # the qualified backend.  This is runtime evidence, not a post-run size.
    quota = run("/usr/sbin/xfs_quota", "-x", "-c", "quota -p -nNv -b -i 10000", str(MOUNT))
    # ``xfs_quota`` reports selected-project limits in one headerless numeric
    # row.  Its blocks are KiB, whereas the frozen authority is bytes.  Do
    # not accept a line that merely mentions the mount or a post-run statvfs.
    verified = False
    for line in quota.splitlines():
        fields = line.split()
        if (len(fields) == 12 and fields[0] == state["LOOP"] and fields[-1].replace("\\040", " ") == str(MOUNT)
                and fields[3].isdigit() and fields[8].isdigit()
                and int(fields[3]) * 1024 == int(state["DATA_BYTES"])
                and int(fields[8]) == int(state["DATA_INODES"])):
            verified = True
            break
    if not verified:
        _fail("session2_staging_guard_quota_invalid")
    return {"loop": state["LOOP"], "mount": str(MOUNT), "image": str(IMAGE),
            "data_project": state["DATA_PROJECT"], "data_bytes": state["DATA_BYTES"], "data_inodes": state["DATA_INODES"]}


def require_supervisor_staging(destination: Path | None = None, *, run: Callable[..., str] = _command) -> dict[str, str]:
    """Verify staging and reject a destination escaping its exact subtree."""
    result = verify_supervisor_staging(run=run)
    if destination is not None:
        if not destination.is_absolute() or destination == MOUNT:
            _fail("session2_staging_guard_destination_invalid")
        try:
            destination.relative_to(SUPERVISOR_ROOT)
        except ValueError as exc:
            raise StagingGuardError("session2_staging_guard_destination_invalid") from exc
    return result


def reject_direct_materialization(destination: Path) -> None:
    """Active source trees belong only to production quota worktrees."""
    try:
        destination.relative_to(SUPERVISOR_ROOT)
    except ValueError:
        return
    _fail("session2_materialization_direct_supervisor_staging_forbidden")
