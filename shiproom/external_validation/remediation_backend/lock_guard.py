#!/usr/bin/env python3
"""Prepare the fixed backend lock without following a sticky-dir pathname."""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

try:
    from .bootstrap import require_staged_script
except ImportError:
    from bootstrap import require_staged_script

LOCK = Path("/run/lock/shiproom-remediation.backend.lock")


class LockError(RuntimeError):
    pass


def prepare() -> None:
    parent = LOCK.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0:
        raise LockError("backend_lock_parent_untrusted")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOCK, flags, 0o600)
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise LockError("backend_lock_untrusted")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("--prepare", action="store_true"); a = p.parse_args()
    if os.geteuid() != 0:
        raise LockError("backend_lock_root_required")
    require_staged_script(Path(__file__))
    if not a.prepare:
        raise LockError("backend_lock_action_invalid")
    prepare(); print("backend_lock_prepared")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LockError, OSError) as exc:
        print("lock_error:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
