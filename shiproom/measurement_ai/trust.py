from __future__ import annotations

import os
import stat
from pathlib import Path


def is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def safe_entry(path: Path, *, directory: bool, label: str) -> None:
    info = path.lstat()
    invalid = path.is_symlink() or is_reparse(info)
    invalid = invalid or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
    if invalid:
        raise ValueError(f"{label} is unsafe")


def validate_ancestry(root: Path, path: Path, *, directory: bool, label: str) -> None:
    root_abs = Path(os.path.abspath(root))
    path_abs = Path(os.path.abspath(path))
    try:
        relative = path_abs.relative_to(root_abs)
    except ValueError as exc:
        raise ValueError(f"{label} escapes its trusted root") from exc
    safe_entry(root_abs, directory=True, label=f"{label} trusted root")
    current = root_abs
    for index, part in enumerate(relative.parts):
        current = current / part
        safe_entry(current, directory=directory if index == len(relative.parts) - 1 else True, label=label)


def exact_children(path: Path, expected: set[str], label: str) -> None:
    safe_entry(path, directory=True, label=label)
    entries = list(path.iterdir())
    folded = [entry.name.casefold() for entry in entries]
    if len(folded) != len(set(folded)) or {entry.name for entry in entries} != expected:
        raise ValueError(f"{label} file set mismatch")
    for entry in entries:
        info = entry.lstat()
        if entry.is_symlink() or is_reparse(info) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError(f"{label} contains an unsafe entry")


def ensure_directory(trusted_root:Path,target:Path,*,label:str)->Path:
    """Create a directory without ever traversing an unsafe existing node."""
    root=Path(os.path.abspath(trusted_root)); destination=Path(os.path.abspath(target))
    try: relative=destination.relative_to(root)
    except ValueError as exc: raise ValueError(f"{label} escapes its trusted root") from exc
    safe_entry(root,directory=True,label=f"{label} trusted root")
    current=root
    for part in relative.parts:
        current=current/part
        if current.exists() or current.is_symlink(): safe_entry(current,directory=True,label=label)
        else:
            current.mkdir()
            safe_entry(current,directory=True,label=label)
    return destination

def ensure_approved_write_target(repository_root:Path,target:Path,*,label:str)->Path:
    """Restrict Session 5 writes to its ignored release root or qualification store."""
    root=Path(os.path.abspath(repository_root));destination=Path(os.path.abspath(target))
    try:parts=destination.relative_to(root).parts
    except ValueError as exc:raise ValueError(f"{label} escapes its trusted root") from exc
    qualification=parts[:3]==(".shiproom","local","measurement-reviewer-qualifications")
    release=len(parts)>=5 and parts[:3]==(".shiproom","local","releases") and parts[4]=="measurement-ai-readiness"
    if not (qualification or release):raise ValueError(f"{label} is outside approved ignored roots")
    return ensure_directory(root,destination,label=label)


def safe_atomic_path(trusted_root:Path,path:Path,*,label:str)->Path:
    ensure_directory(trusted_root,path.parent,label=label+" parent")
    temporary=path.with_name(path.name+".tmp")
    for candidate in (path,temporary):
        if candidate.exists() or candidate.is_symlink(): safe_entry(candidate,directory=False,label=label)
    return temporary


def write_bytes_safe(trusted_root:Path,path:Path,data:bytes,*,label:str)->None:
    """Write a new/regular file only through validated trusted ancestry."""
    ensure_directory(trusted_root,path.parent,label=label+" parent")
    if path.exists() or path.is_symlink(): safe_entry(path,directory=False,label=label)
    path.write_bytes(data)


def replace_bytes_safe(trusted_root:Path,path:Path,data:bytes,*,label:str)->None:
    temporary=safe_atomic_path(trusted_root,path,label=label)
    temporary.write_bytes(data)
    safe_entry(temporary,directory=False,label=label+" temporary")
    if path.exists() or path.is_symlink(): safe_entry(path,directory=False,label=label)
    temporary.replace(path)


def repository_root_for(path:Path)->Path:
    """Return the lexical repository root without resolving filesystem links."""
    absolute=Path(os.path.abspath(path))
    for candidate in (absolute,*absolute.parents):
        marker=candidate/".git"
        if marker.exists() and marker.is_dir():
            safe_entry(candidate,directory=True,label="repository root")
            return candidate
    raise ValueError("trusted repository root was not found")
