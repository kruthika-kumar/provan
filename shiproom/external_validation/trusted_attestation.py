"""Descriptor-safe authority loader for the private Session 1 attestation.

This module intentionally has no ``pathlib`` fallback.  The authorization
object is a root-owned Linux capability, so an unavailable ``openat2`` is a
blocked capability rather than a reason to weaken path authority.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TRUSTED_ROOT = Path("/var/lib/shiproom-remediation/status-attestations/session1")
MAX_ATTESTATION_BYTES = 64 * 1024
_ID = re.compile(r"^[0-9a-f]{64}$")
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2 = {"x86_64": 437, "amd64": 437}.get(os.uname().machine if hasattr(os, "uname") else "")
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class TrustedAttestationError(RuntimeError):
    """A stable fail-closed trusted-attestation rejection."""


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_ulonglong), ("mode", ctypes.c_ulonglong), ("resolve", ctypes.c_ulonglong)]


def validate_attestation_id(value: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise TrustedAttestationError("status_attestation_id_invalid")
    return value


def _openat2(dirfd: int, name: str, flags: int) -> int:
    if SYS_OPENAT2 is None:
        raise TrustedAttestationError("status_attestation_openat2_unavailable")
    how = _OpenHow(flags, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)
    result = ctypes.CDLL(None, use_errno=True).syscall(
        SYS_OPENAT2, dirfd, name.encode("utf-8"), ctypes.byref(how), ctypes.sizeof(how)
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            raise TrustedAttestationError("status_attestation_openat2_unavailable")
        if error in {errno.ELOOP, errno.EXDEV}:
            raise TrustedAttestationError("status_attestation_symlink_rejected")
        raise TrustedAttestationError("status_attestation_parent_untrusted")
    return result


def _directory(fd: int, *, expected_device: int | None) -> int:
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_gid != 0:
        raise TrustedAttestationError("status_attestation_parent_untrusted")
    if value.st_mode & 0o022:
        raise TrustedAttestationError("status_attestation_parent_untrusted")
    if expected_device is not None and value.st_dev != expected_device:
        raise TrustedAttestationError("status_attestation_parent_untrusted")
    return value.st_dev


def _open_trusted_root(root: Path) -> tuple[int, int]:
    """Open every fixed parent without resolving an attacker-provided path."""
    if not root.is_absolute():
        raise TrustedAttestationError("status_attestation_outside_trusted_root")
    fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC | os.O_NOFOLLOW)
    try:
        device = _directory(fd, expected_device=None)
        for component in root.parts[1:]:
            next_fd = _openat2(fd, component, os.O_RDONLY | O_DIRECTORY | O_CLOEXEC | os.O_NOFOLLOW)
            os.close(fd)
            fd = next_fd
            device = _directory(fd, expected_device=device)
        return fd, device
    except BaseException:
        os.close(fd)
        raise


def _validate_file(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise TrustedAttestationError("status_attestation_invalid")
    if value.st_uid != 0 or value.st_gid != 0:
        raise TrustedAttestationError("status_attestation_owner_invalid")
    if stat.S_IMODE(value.st_mode) != 0o400:
        raise TrustedAttestationError("status_attestation_mode_invalid")
    if value.st_nlink != 1:
        raise TrustedAttestationError("status_attestation_hardlink_rejected")
    if value.st_size < 1 or value.st_size > MAX_ATTESTATION_BYTES:
        raise TrustedAttestationError("status_attestation_too_large")


@dataclass(frozen=True)
class LoadedAttestation:
    identifier: str
    raw_bytes: bytes
    document: dict[str, Any]


def load_trusted_attestation(identifier: str, *, trusted_root: Path = TRUSTED_ROOT) -> LoadedAttestation:
    """Load the requested content-addressed record from the one trusted root."""
    identifier = validate_attestation_id(identifier)
    root_fd, device = _open_trusted_root(trusted_root)
    try:
        filename = identifier + ".json"
        fd = _openat2(root_fd, filename, os.O_RDONLY | O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            _validate_file(before)
            if before.st_dev != device:
                raise TrustedAttestationError("status_attestation_parent_untrusted")
            chunks: list[bytes] = []
            remaining = MAX_ATTESTATION_BYTES + 1
            while remaining:
                block = os.read(fd, min(8192, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size) != (
                after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size
            ):
                raise TrustedAttestationError("status_attestation_path_changed")
            _validate_file(after)
            if len(raw) != before.st_size or len(raw) > MAX_ATTESTATION_BYTES:
                raise TrustedAttestationError("status_attestation_too_large")
            if hashlib.sha256(raw).hexdigest() != identifier:
                raise TrustedAttestationError("status_attestation_id_mismatch")
            # Detect a replacement of the name after the descriptor was opened;
            # the descriptor bytes remain authoritative either way.
            now_fd = _openat2(root_fd, filename, os.O_RDONLY | O_CLOEXEC | os.O_NOFOLLOW)
            try:
                current = os.fstat(now_fd)
            finally:
                os.close(now_fd)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise TrustedAttestationError("status_attestation_path_changed")
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TrustedAttestationError("status_attestation_invalid") from exc
            if not isinstance(parsed, dict):
                raise TrustedAttestationError("status_attestation_invalid")
            return LoadedAttestation(identifier, raw, parsed)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
