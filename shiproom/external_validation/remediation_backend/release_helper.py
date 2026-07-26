#!/usr/bin/env python3
"""Versioned descriptor-relative remediation worktree deletion helper.

The caller holds the backend lock and has marked the allocation RELEASING.
This helper never follows a patient-controlled path below the registered root
and intentionally has no ``rm -rf`` fallback.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import os
import stat
import sys
from pathlib import Path
try:
    from .bootstrap import require_staged_script
except ImportError:
    from bootstrap import require_staged_script

HELPER_VERSION = "remediation-release-helper.v1"
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_BENEATH = 0x08
RESOLVE_NO_SYMLINKS = 0x04
SYS_OPENAT2 = {"x86_64": 437, "amd64": 437}.get(os.uname().machine if hasattr(os, "uname") else "")
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class ReleaseBlocked(RuntimeError):
    pass


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_ulonglong), ("mode", ctypes.c_ulonglong), ("resolve", ctypes.c_ulonglong)]


def openat2(dirfd: int, name: str, flags: int = os.O_RDONLY | O_DIRECTORY | O_CLOEXEC) -> int:
    if SYS_OPENAT2 is None:
        raise ReleaseBlocked("release_capability_blocked:unsupported_architecture")
    how = OpenHow(flags, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(SYS_OPENAT2, dirfd, name.encode("utf-8"), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            raise ReleaseBlocked("release_capability_blocked:openat2")
        raise OSError(error, os.strerror(error), name)
    return fd


def require_openat2() -> None:
    """Prove the kernel supports the exact resolver contract before release."""
    fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        probe = openat2(fd, ".")
        os.close(probe)
    finally:
        os.close(fd)


def mount_id(fd: int) -> int:
    for line in Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii").splitlines():
        if line.startswith("mnt_id:"):
            return int(line.split()[1])
    raise ReleaseBlocked("release_mount_id_unavailable")


def verify_root(fd: int, expected_device: int, expected_inode: int, expected_mount_id: int) -> os.stat_result:
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode):
        raise ReleaseBlocked("release_root_not_directory")
    if value.st_dev != expected_device or value.st_ino != expected_inode:
        raise ReleaseBlocked("release_root_authority_changed")
    if mount_id(fd) != expected_mount_id:
        raise ReleaseBlocked("release_mount_authority_changed")
    return value


def child_names(fd: int) -> list[str]:
    names = os.listdir(fd)
    if any(name in {".", ".."} or "/" in name or "\x00" in name for name in names):
        raise ReleaseBlocked("release_directory_entry_invalid")
    return sorted(names, key=lambda item: os.fsencode(item))


def delete_tree(fd: int, root_device: int, expected_mount: int, *, allow_runtime_sockets: bool = False) -> None:
    if mount_id(fd) != expected_mount or os.fstat(fd).st_dev != root_device:
        raise ReleaseBlocked("release_filesystem_boundary_changed")
    for name in child_names(fd):
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if item.st_dev != root_device:
            raise ReleaseBlocked("release_cross_device_entry")
        if stat.S_ISDIR(item.st_mode):
            child = openat2(fd, name)
            try:
                delete_tree(child, root_device, expected_mount, allow_runtime_sockets=allow_runtime_sockets)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=fd)
        elif stat.S_ISREG(item.st_mode):
            if item.st_nlink != 1:
                raise ReleaseBlocked("release_hard_link_rejected")
            os.unlink(name, dir_fd=fd)
        elif allow_runtime_sockets and stat.S_ISSOCK(item.st_mode):
            # A custom-daemon runtime root can retain dead Unix socket
            # directory entries after its verified process/residual sweep.
            # This mode is never available to patient worktree release: it is
            # selected only by the supervisor for the fixed $RUN root.
            os.unlink(name, dir_fd=fd)
        else:
            raise ReleaseBlocked("release_special_file_rejected")


def open_registered_root(root: Path) -> tuple[int, int]:
    if root.name in {"", ".", ".."} or not root.is_absolute():
        raise ReleaseBlocked("release_root_path_invalid")
    parent_fd = os.open(root.parent, os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        root_fd = openat2(parent_fd, root.name)
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd, root_fd


def action(args: argparse.Namespace) -> None:
    if os.geteuid() != 0:
        raise ReleaseBlocked("release_root_required")
    require_staged_script(Path(__file__))
    parent_fd, root_fd = open_registered_root(args.root)
    try:
        verify_root(root_fd, args.expected_device, args.expected_inode, args.expected_mount_id)
        if args.operation == "verify-empty":
            if child_names(root_fd):
                raise ReleaseBlocked("release_root_not_empty")
        elif args.operation == "delete-contents":
            delete_tree(root_fd, args.expected_device, args.expected_mount_id, allow_runtime_sockets=args.allow_runtime_sockets)
            verify_root(root_fd, args.expected_device, args.expected_inode, args.expected_mount_id)
            if child_names(root_fd):
                raise ReleaseBlocked("release_delete_incomplete")
        elif args.operation == "delete-root":
            if child_names(root_fd):
                raise ReleaseBlocked("release_root_not_empty")
            # Parent descriptor is retained from the initial authority check;
            # no second patient-controlled pathname traversal is performed.
            os.close(root_fd)
            root_fd = -1
            os.rmdir(args.root.name, dir_fd=parent_fd)
        else:
            raise ReleaseBlocked("release_operation_invalid")
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("verify-empty", "delete-contents", "delete-root"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-device", type=int, required=True)
    parser.add_argument("--expected-inode", type=int, required=True)
    parser.add_argument("--expected-mount-id", type=int, required=True)
    parser.add_argument("--allow-runtime-sockets", action="store_true")
    args = parser.parse_args()
    action(args)
    print(HELPER_VERSION + ":ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseBlocked, OSError) as exc:
        print(f"release_error:{exc}", file=sys.stderr)
        raise SystemExit(2)
