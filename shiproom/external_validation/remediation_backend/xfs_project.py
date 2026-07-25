#!/usr/bin/env python3
"""Small, direct Linux XFS project-attribute reader.

``xfs_quota project -c`` is a traversal diagnostic, not a boolean assertion:
it can return success when a path is intentionally no longer assigned.  This
helper reads the inode's fsxattr through the kernel ioctl instead.
"""
from __future__ import annotations

import argparse
import array
try:
    import fcntl
except ImportError:  # permits non-Linux semantic tests without a fallback
    fcntl = None  # type: ignore[assignment]
import os
import struct
import sys
from pathlib import Path

try:
    from .bootstrap import require_staged_script
except ImportError:
    from bootstrap import require_staged_script


# struct fsxattr from linux/fs.h: five u32s and eight pad bytes (28 bytes).
FSXATTR_FORMAT = "=IIIII8s"
FS_IOC_FSGETXATTR = 0x801C581F  # _IOR('X', 31, struct fsxattr)
FS_XFLAG_PROJINHERIT = 0x00000200


class ProjectAttributeError(RuntimeError):
    pass


def attributes(path: Path) -> tuple[int, int]:
    if fcntl is None:
        raise ProjectAttributeError("xfs_project_attribute_unavailable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        buffer = bytearray(struct.calcsize(FSXATTR_FORMAT))
        try:
            fcntl.ioctl(fd, FS_IOC_FSGETXATTR, buffer, True)
        except OSError as exc:
            raise ProjectAttributeError("xfs_project_attribute_unavailable") from exc
        xflags, _extsize, _nextents, project_id, _cowextsize, _pad = struct.unpack(FSXATTR_FORMAT, buffer)
        return project_id, xflags
    finally:
        os.close(fd)


def require_cleared(path: Path) -> None:
    project_id, xflags = attributes(path)
    if project_id != 0 or xflags & FS_XFLAG_PROJINHERIT:
        raise ProjectAttributeError("project_assignment_clear_unverified")


def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("path", type=Path); p.add_argument("--require-cleared", action="store_true"); a = p.parse_args()
    if os.geteuid() != 0:
        raise ProjectAttributeError("xfs_project_root_required")
    require_staged_script(Path(__file__))
    project_id, xflags = attributes(a.path)
    if a.require_cleared and (project_id != 0 or xflags & FS_XFLAG_PROJINHERIT):
        raise ProjectAttributeError("project_assignment_clear_unverified")
    print("%d\t%d" % (project_id, xflags))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProjectAttributeError, OSError) as exc:
        print("xfs_project_error:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
