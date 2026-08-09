from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path

from .errors import (
    CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
    OUTPUT_PATH_OUTSIDE_PROVAN_STATE,
    PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,
    ProvanError,
)


def trusted_state_root(value: Path) -> Path:
    """Return the exact dedicated Provan state root, never a repository location."""
    requested = Path(os.path.abspath(value.expanduser()))
    cursor = requested
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            info = None
        if info is not None and (stat.S_ISLNK(info.st_mode) or _is_reparse(info)):
            raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "symlinked state path is forbidden")
        if (cursor / ".git").exists() or cursor.name == ".git":
            raise ProvanError(CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, "state root may not be inside a customer repository")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return requested


def state_root() -> Path:
    override = os.environ.get("PROVAN_HOME")
    return trusted_state_root(Path(override) if override else Path.home() / ".provan")


def _is_reparse(info: os.stat_result) -> bool:
    return os.name == "nt" and bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_unsafe_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "linked or non-directory Provan state component is forbidden")


def _validate_relative_json(relative: Path, area: str) -> tuple[str, ...]:
    text = str(relative)
    parts = relative.parts
    if (not text or relative.is_absolute() or relative.suffix.lower() != ".json" or not parts or
            parts[0] != area or any(part in {"", ".", ".."} for part in parts)):
        raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE, f"JSON output must remain below {area}")
    if os.name == "nt" and (text.startswith(("\\\\", "\\?\\", "\\.\\")) or ":" in text):
        raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE, "Windows device paths and alternate streams are forbidden")
    return parts


def _ensure_state_root(root: Path) -> None:
    if root.exists() or root.is_symlink():
        _reject_unsafe_directory(root)
        return
    root.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir()
    _reject_unsafe_directory(root)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("state write made no progress")
        written += count


def secure_write(relative: Path, data: bytes) -> Path:
    """Create a new JSON state file without following state-child links.

    POSIX uses mkdirat/openat through Python's dir_fd support, O_NOFOLLOW, and
    fsync. Windows rejects reparse points component-by-component, uses
    create-new semantics, and verifies the opened path. Python cannot provide a
    POSIX-equivalent descriptor-relative traversal on Windows, so a privileged
    concurrent reparse swap remains a residual TOCTOU limitation.
    """
    area = relative.parts[0] if relative.parts else ""
    parts = _validate_relative_json(relative, area)
    root = state_root()
    _ensure_state_root(root)
    if os.name != "nt" and os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(root, directory_flags)
        try:
            for component in parts[:-1]:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, directory_flags, dir_fd=descriptor)
                if not stat.S_ISDIR(os.fstat(child).st_mode):
                    os.close(child)
                    raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "state child is not a directory")
                os.close(descriptor)
                descriptor = child
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            leaf = os.open(parts[-1], flags, 0o600, dir_fd=descriptor)
            try:
                _write_all(leaf, data)
                os.fsync(leaf)
            finally:
                os.close(leaf)
            try:
                os.fsync(descriptor)
            except OSError:
                pass
        except OSError as exc:
            if getattr(exc, "errno", None) in {40, 62}:
                raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "linked state component is forbidden") from exc
            raise
        finally:
            os.close(descriptor)
        return root.joinpath(*parts)

    cursor = root
    for component in parts[:-1]:
        child = cursor / component
        _reject_unsafe_directory(child)
        try:
            child.mkdir()
        except FileExistsError:
            pass
        _reject_unsafe_directory(child)
        cursor = child
    leaf = cursor / parts[-1]
    if leaf.exists() or leaf.is_symlink():
        raise FileExistsError(str(leaf))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(leaf, flags, 0o600)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        if leaf.resolve(strict=True).parent != cursor.resolve(strict=True):
            raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE, "output identity changed during publication")
    finally:
        os.close(descriptor)
    return leaf


def secure_read(relative: Path, *, limit: int = 32 * 1024 * 1024) -> bytes:
    """Read a bounded Provan-owned JSON leaf without following linked components."""
    area = relative.parts[0] if relative.parts else ""
    parts = _validate_relative_json(relative, area)
    root = state_root()
    _ensure_state_root(root)
    if os.name != "nt" and os.open in os.supports_dir_fd:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(root, directory_flags)
        try:
            for component in parts[:-1]:
                child = os.open(component, directory_flags, dir_fd=descriptor)
                os.close(descriptor); descriptor = child
            leaf = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
            try:
                info = os.fstat(leaf)
                if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                    raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE, "state leaf is not a bounded regular file")
                chunks=[]; total=0
                while True:
                    chunk=os.read(leaf,min(65536,limit+1-total))
                    if not chunk: break
                    chunks.append(chunk);total+=len(chunk)
                    if total>limit: raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE,"state leaf exceeds read bound")
                after=os.fstat(leaf)
                if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns):raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,"state leaf changed during read")
                return b"".join(chunks)
            finally: os.close(leaf)
        except OSError as exc:
            if getattr(exc,"errno",None) in {40,62}: raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,"linked state component is forbidden") from exc
            raise
        finally: os.close(descriptor)
    cursor=root
    for component in parts[:-1]:
        cursor/=component;_reject_unsafe_directory(cursor)
    leaf=cursor/parts[-1];before=leaf.lstat()
    if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_size>limit:
        raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,"linked or unbounded state leaf is forbidden")
    descriptor=os.open(leaf,os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,"state leaf identity changed")
        chunks=[];total=0
        while True:
            chunk=os.read(descriptor,min(65536,limit+1-total))
            if not chunk:break
            chunks.append(chunk);total+=len(chunk)
            if total>limit:raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE,"state leaf exceeds read bound")
        after=os.fstat(descriptor)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns):raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN,"state leaf changed during read")
        return b"".join(chunks)
    finally:os.close(descriptor)


def write_pending(path: Path, data: bytes) -> None:
    root = state_root()
    expected = root / "pending" / path.name
    if path.resolve(strict=False) != expected.resolve(strict=False) or path.suffix.lower() != ".json":
        raise ProvanError(CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, "pending write escaped Provan state")
    secure_write(Path("pending") / path.name, data)


def trusted_output_path(value: Path) -> Path:
    root = state_root()
    output_root = root / "outputs"
    _reject_unsafe_directory(output_root)
    candidate = Path(os.path.abspath(value.expanduser()))
    if output_root not in candidate.parents or candidate == output_root or candidate.suffix.lower() != ".json":
        raise ProvanError(OUTPUT_PATH_OUTSIDE_PROVAN_STATE, "inspection receipts are restricted to Provan outputs")
    relative = candidate.relative_to(root)
    _validate_relative_json(relative, "outputs")
    cursor = root
    for component in relative.parts[:-1]:
        cursor = cursor / component
        _reject_unsafe_directory(cursor)
    if candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
        raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "linked output leaf is forbidden")
    return candidate


def write_output(path: Path, data: bytes) -> Path:
    candidate = trusted_output_path(path)
    return secure_write(candidate.relative_to(state_root()), data)


def secure_replace(relative: Path, data: bytes) -> Path:
    """Replace a Provan-owned JSON leaf without following linked components."""
    area = relative.parts[0] if relative.parts else ""
    _validate_relative_json(relative, area)
    root = state_root()
    target = root / relative
    parent_relative = relative.parent
    probe = parent_relative / f".{relative.name}.{uuid.uuid4()}.json"
    temporary = secure_write(probe, data)
    try:
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ProvanError(PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN, "linked state leaf is forbidden")
        os.replace(temporary, target)
        return target
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def validate_state_children() -> dict[str, Path]:
    """Validate/create the canonical outputs and pending directories."""
    root = state_root()
    _ensure_state_root(root)
    result = {"root": root}
    for name in ("outputs", "pending"):
        child = root / name
        _reject_unsafe_directory(child)
        try:
            child.mkdir()
        except FileExistsError:
            pass
        _reject_unsafe_directory(child)
        result[name] = child
    return result
