from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .authority import require_operation
from .project import resolve_policy_path

BRANCH_PREFIX = "shiproom/private-remediation-"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=check)


def prepare_isolated_worktree(repo: Path, status: dict, task_id: str, *, executor=_git) -> dict:
    require_operation(status, "source.write.isolated")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", task_id): raise ValueError("invalid remediation task ID")
    root = Path(_git(repo, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    head = _git(root, "rev-parse", "HEAD").stdout.strip()
    target = (root / ".shiproom" / "local" / "worktrees" / task_id).resolve()
    local_root = (root / ".shiproom" / "local" / "worktrees").resolve()
    if local_root not in target.parents or target.exists(): raise PermissionError("isolated worktree target is unsafe or already exists")
    branch = BRANCH_PREFIX + task_id
    if _git(root, "branch", "--list", branch).stdout.strip(): raise PermissionError("remediation branch already exists")
    executor(root, "worktree", "add", "-b", branch, str(target), head)
    if not target.is_dir() or _git(target, "rev-parse", "HEAD").stdout.strip() != head:
        raise PermissionError("isolated worktree verification failed")
    return {"worktree": str(target), "branch": branch, "base_commit": head}


def authorize_isolated_write(repo: Path, worktree: Path, status: dict, relative: str) -> Path:
    require_operation(status, "source.write.isolated")
    if worktree.resolve() == repo.resolve() or repo.resolve() / ".shiproom" / "local" / "worktrees" not in worktree.resolve().parents:
        raise PermissionError("writes require an isolated Shiproom worktree")
    return resolve_policy_path(worktree, relative, status["contract"]["protected_paths"], status["contract"]["excluded_paths"], operation="write")
