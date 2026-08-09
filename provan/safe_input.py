from __future__ import annotations

import os
import json
import stat
from pathlib import Path
from typing import Any

from .errors import ProvanError

INPUT_FILE_TYPE_FORBIDDEN = "INPUT_FILE_TYPE_FORBIDDEN"
INPUT_FILE_TOO_LARGE = "INPUT_FILE_TOO_LARGE"
INPUT_FILE_ENCODING_INVALID = "INPUT_FILE_ENCODING_INVALID"
INPUT_FILE_PATH_UNSAFE = "INPUT_FILE_PATH_UNSAFE"


def _reparse(info: os.stat_result) -> bool:
    return os.name == "nt" and bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _path_snapshot(absolute: Path) -> list[tuple[str, int, int, int, int]]:
    """Revalidate every Windows path component without reading file content.

    Windows Python does not expose openat-style directory descriptors.  We
    therefore bind every component before opening and again after opening and
    reading, while the leaf handle provides create/open identity.  A swap that
    occurs entirely between two component observations remains a documented
    Windows TOCTOU limitation; reparse points and observed identity changes are
    rejected.
    """
    rows: list[tuple[str, int, int, int, int]] = []
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            raise ProvanError(INPUT_FILE_PATH_UNSAFE, "linked or reparse-point input is forbidden")
        rows.append((part, info.st_dev, info.st_ino, info.st_mode, getattr(info, "st_file_attributes", 0)))
    return rows


def _read_posix(absolute: Path, limit: int) -> bytes:
    """Read through descriptor-relative, no-follow directory traversal."""
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    leaf_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptors: list[int] = []
    try:
        parent = os.open(absolute.anchor, directory_flags); descriptors.append(parent)
        parent_ids: list[tuple[int, int]] = [(os.fstat(parent).st_dev, os.fstat(parent).st_ino)]
        for part in absolute.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input parent is not a directory")
            descriptors.append(child); parent = child; parent_ids.append((info.st_dev, info.st_ino))
        before = os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise ProvanError(INPUT_FILE_PATH_UNSAFE, "linked input is forbidden")
        if not stat.S_ISREG(before.st_mode):
            raise ProvanError(INPUT_FILE_TYPE_FORBIDDEN, "input must be a regular file")
        if before.st_size > limit:
            raise ProvanError(INPUT_FILE_TOO_LARGE, f"input exceeds {limit} bytes")
        descriptor = os.open(absolute.name, leaf_flags, dir_fd=parent); descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input identity changed before read")
        chunks: list[bytes] = []; total = 0
        while True:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
            if total > limit: raise ProvanError(INPUT_FILE_TOO_LARGE, f"input exceeds {limit} bytes")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input identity changed during read")
        verify = os.open(absolute.anchor, directory_flags)
        try:
            if (os.fstat(verify).st_dev, os.fstat(verify).st_ino) != parent_ids[0]:
                raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input parent identity changed")
            for index, part in enumerate(absolute.parts[1:-1], start=1):
                child = os.open(part, directory_flags, dir_fd=verify)
                if (os.fstat(child).st_dev, os.fstat(child).st_ino) != parent_ids[index]:
                    os.close(child); raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input parent identity changed")
                os.close(verify); verify = child
            leaf = os.stat(absolute.name, dir_fd=verify, follow_symlinks=False)
            if (leaf.st_dev, leaf.st_ino) != (opened.st_dev, opened.st_ino) or stat.S_ISLNK(leaf.st_mode):
                raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input path changed after opening")
        finally:
            os.close(verify)
        return b"".join(chunks)
    except FileNotFoundError as exc:
        raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input file does not exist") from exc
    except OSError as exc:
        raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input path could not be traversed safely") from exc
    finally:
        for descriptor in reversed(descriptors):
            try: os.close(descriptor)
            except OSError: pass


def read_bounded_file(path: Path, *, limit: int, structured: bool = False) -> tuple[str, Any | None]:
    """Read one explicit UTF-8 regular file without path inference or special-file access."""
    requested = Path(path)
    if not str(requested) or any(part in {"", ".", ".."} for part in requested.parts):
        raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input path is empty or traversing")
    absolute = Path(os.path.abspath(requested))
    if os.name != "nt":
        raw = _read_posix(absolute, limit)
    else:
        try: before_components = _path_snapshot(absolute)
        except FileNotFoundError as exc: raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input file does not exist") from exc
        before = absolute.stat()
        if not stat.S_ISREG(before.st_mode): raise ProvanError(INPUT_FILE_TYPE_FORBIDDEN, "input must be a regular file")
        if before.st_size > limit: raise ProvanError(INPUT_FILE_TOO_LARGE, f"input exceeds {limit} bytes")
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino): raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input identity changed before read")
            if _path_snapshot(absolute) != before_components: raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input component changed after opening")
            chunks=[]; total=0
            while True:
                chunk=os.read(descriptor,min(65536,limit+1-total))
                if not chunk: break
                chunks.append(chunk);total+=len(chunk)
                if total>limit: raise ProvanError(INPUT_FILE_TOO_LARGE,f"input exceeds {limit} bytes")
            after=os.fstat(descriptor)
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns): raise ProvanError(INPUT_FILE_PATH_UNSAFE,"input identity changed during read")
            if _path_snapshot(absolute) != before_components: raise ProvanError(INPUT_FILE_PATH_UNSAFE, "input component changed during read")
            raw=b"".join(chunks)
        finally: os.close(descriptor)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProvanError(INPUT_FILE_ENCODING_INVALID, "input is not valid UTF-8") from exc
    parsed = None
    if structured:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            try:
                import yaml
                parsed = yaml.safe_load(text)
            except Exception as exc:
                # PyYAML is a declared dependency. A deliberately --no-deps
                # smoke install can still use every non-YAML command safely.
                raise ProvanError(INPUT_FILE_ENCODING_INVALID, "structured input is invalid JSON/YAML or YAML support is unavailable") from exc
        if parsed is None:
            raise ProvanError(INPUT_FILE_ENCODING_INVALID, "structured input is invalid JSON/YAML")
    return text, parsed
