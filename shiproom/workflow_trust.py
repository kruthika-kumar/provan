"""Trusted immutable storage primitives for Sessions 6--8 only."""
from __future__ import annotations

import os
import stat
from pathlib import Path


DOMAIN_NAMES = {"remediation", "review-organisation", "contestability", "management-artifacts"}


def _unsafe(path: Path, *, directory: bool) -> bool:
    info = path.lstat()
    reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return path.is_symlink() or reparse or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))


def safe_entry(path: Path, *, directory: bool, label: str) -> None:
    if _unsafe(path, directory=directory):
        raise ValueError(f"unsafe_storage_entry:{label}")


def ensure_directory(repository_root: Path, target: Path, *, label: str) -> Path:
    root = Path(os.path.abspath(repository_root)); destination = Path(os.path.abspath(target))
    try:
        parts = destination.relative_to(root).parts
    except ValueError as exc:
        raise ValueError("storage_outside_repository") from exc
    if len(parts) < 5 or parts[:3] != (".shiproom", "local", "releases") or parts[4] not in DOMAIN_NAMES:
        raise ValueError("storage_outside_approved_root")
    safe_entry(root, directory=True, label="repository_root")
    current = root
    for part in parts:
        current = current / part
        if current.exists() or current.is_symlink():
            safe_entry(current, directory=True, label=label)
        else:
            current.mkdir()
            safe_entry(current, directory=True, label=label)
    return destination


def write_bytes(repository_root: Path, target: Path, data: bytes, *, label: str) -> None:
    ensure_directory(repository_root, target.parent, label=label + "_parent")
    if target.exists() or target.is_symlink():
        safe_entry(target, directory=False, label=label)
    target.write_bytes(data)


def replace_bytes(repository_root: Path, target: Path, data: bytes, *, label: str) -> None:
    ensure_directory(repository_root, target.parent, label=label + "_parent")
    temporary = target.with_name(target.name + ".tmp")
    for item in (target, temporary):
        if item.exists() or item.is_symlink():
            safe_entry(item, directory=False, label=label)
    temporary.write_bytes(data)
    safe_entry(temporary, directory=False, label=label + "_temporary")
    temporary.replace(target)


def exact_children(path: Path, expected: set[str], *, label: str) -> None:
    safe_entry(path, directory=True, label=label)
    entries = list(path.iterdir())
    names = [entry.name for entry in entries]
    if set(names) != expected or len({name.casefold() for name in names}) != len(names):
        raise ValueError(f"storage_file_set_mismatch:{label}")
    for entry in entries:
        safe_entry(entry, directory=entry.is_dir(), label=label)
