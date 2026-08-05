from __future__ import annotations

import os
from pathlib import Path

from .errors import CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, ProvanError


def trusted_state_root(value: Path) -> Path:
    """Return a dedicated Provan state root, never a repository location."""
    root = value.expanduser().resolve(strict=False)
    if root.name != ".provan":
        raise ProvanError(
            CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
            "state writes require a dedicated .provan directory",
        )
    cursor = root
    while True:
        if cursor.is_symlink():
            raise ProvanError(CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, "symlinked state path is forbidden")
        if (cursor / ".git").exists() or cursor.name == ".git":
            raise ProvanError(
                CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
                "state root may not be inside a customer repository",
            )
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return root


def state_root() -> Path:
    override = os.environ.get("PROVAN_HOME")
    return trusted_state_root(Path(override) if override else Path.home() / ".provan")


def write_pending(path: Path, data: bytes) -> None:
    root = state_root()
    pending = root / "pending"
    expected = pending / path.name
    if path.resolve(strict=False) != expected.resolve(strict=False) or path.suffix != ".json":
        raise ProvanError(CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, "pending write escaped Provan state")
    root.mkdir(parents=True, exist_ok=True)
    pending.mkdir(exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(expected, flags, 0o600)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("pending envelope write made no progress")
            written += count
    finally:
        os.close(descriptor)


def trusted_output_path(value: Path) -> Path:
    root = state_root()
    output_root = (root / "outputs").resolve(strict=False)
    candidate = value.expanduser().resolve(strict=False)
    if output_root not in candidate.parents or candidate == output_root or candidate.suffix != ".json":
        raise ProvanError(
            CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
            "inspection receipts are restricted to .provan/outputs",
        )
    return candidate
