"""Trusted immutable storage primitives for Sessions 6--8 only."""
from __future__ import annotations

import os
import json
import stat
from pathlib import Path


DOMAIN_NAMES = {"remediation", "review-organisation", "contestability", "management-artifacts"}
MAX_JSON_BYTES = 1024 * 1024
MAX_RENDERED_BYTES = 2 * 1024 * 1024
MAX_GENERATION_FILES = 256
MAX_GENERATION_DEPTH = 8


def _unsafe(path: Path, *, directory: bool) -> bool:
    info = path.lstat()
    reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return path.is_symlink() or reparse or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))


def safe_entry(path: Path, *, directory: bool, label: str) -> None:
    if _unsafe(path, directory=directory):
        raise ValueError(f"unsafe_storage_entry:{label}")


def _trusted_path(repository_root: Path, target: Path, *, label: str, directory: bool) -> Path:
    root = Path(os.path.abspath(repository_root)); candidate = Path(os.path.abspath(target))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("storage_outside_repository") from exc
    if len(relative.parts) > MAX_GENERATION_DEPTH + 5:
        raise ValueError("bounded_capacity_exceeded:directory_depth")
    current = root
    safe_entry(current, directory=True, label="repository_root")
    for index, part in enumerate(relative.parts):
        current = current / part
        if not (current.exists() or current.is_symlink()):
            raise ValueError(f"storage_entry_missing:{label}")
        safe_entry(current, directory=directory if index == len(relative.parts) - 1 else True, label=label)
    return candidate


def read_bytes(repository_root: Path, target: Path, *, label: str, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    path = _trusted_path(repository_root, target, label=label, directory=False)
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError("bounded_capacity_exceeded:input_bytes")
    return data


def read_json(repository_root: Path, target: Path, *, label: str, max_bytes: int = MAX_JSON_BYTES) -> object:
    try:
        return json.loads(read_bytes(repository_root, target, label=label, max_bytes=max_bytes).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"storage_utf8_invalid:{label}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"storage_json_invalid:{label}") from exc


def checked_children(repository_root: Path, target: Path, *, label: str) -> list[Path]:
    directory = _trusted_path(repository_root, target, label=label, directory=True)
    entries = list(directory.iterdir())
    if len(entries) > MAX_GENERATION_FILES:
        raise ValueError("bounded_capacity_exceeded:file_count")
    names = [entry.name for entry in entries]
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError(f"storage_casefold_collision:{label}")
    for entry in entries:
        # Do not ask ``Path.is_dir`` here: on a link it follows the link before
        # the storage boundary has rejected it.  Determine kind from lstat only.
        mode = entry.lstat().st_mode
        if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
            raise ValueError(f"unsafe_storage_entry:{label}")
        safe_entry(entry, directory=stat.S_ISDIR(mode), label=label)
    return entries


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
    if len(entries) > MAX_GENERATION_FILES:
        raise ValueError("bounded_capacity_exceeded:file_count")
    names = [entry.name for entry in entries]
    if set(names) != expected or len({name.casefold() for name in names}) != len(names):
        raise ValueError(f"storage_file_set_mismatch:{label}")
    for entry in entries:
        mode = entry.lstat().st_mode
        if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
            raise ValueError(f"unsafe_storage_entry:{label}")
        safe_entry(entry, directory=stat.S_ISDIR(mode), label=label)
