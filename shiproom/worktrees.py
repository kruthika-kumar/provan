from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .authority import require_operation

LOCAL_ROOT = Path(".shiproom/local/worktrees")


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=check)


def _safe_target(repo: Path, task_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", task_id): raise ValueError("invalid worktree task ID")
    root=(repo/LOCAL_ROOT).resolve(); target=(root/task_id).resolve()
    if root not in target.parents: raise PermissionError("worktree target escaped local storage")
    return target


def _registered(repo: Path) -> dict[str, dict]:
    entries={}; current=None
    for line in git(repo,"worktree","list","--porcelain").stdout.splitlines():
        if line.startswith("worktree "): current=str(Path(line[9:]).resolve()); entries[current]={"path":current}
        elif current and " " in line:
            key,value=line.split(" ",1); entries[current][key]=value
    return entries


def prepare_isolated_worktree(repo: Path, status: dict, task_id: str, *, base_commit: str | None = None, branch: str | None = None, executor=git) -> dict:
    require_operation(status,"source.write.isolated"); repo=Path(git(repo,"rev-parse","--show-toplevel").stdout.strip()).resolve(); base_commit=base_commit or git(repo,"rev-parse","HEAD").stdout.strip(); target=_safe_target(repo,task_id)
    if branch and not branch.startswith("shiproom/"): raise PermissionError("worktree branch is outside the Shiproom namespace")
    if target.exists():
        record=_registered(repo).get(str(target))
        if not record or record.get("HEAD")!=base_commit or (branch and record.get("branch")!=f"refs/heads/{branch}"): raise PermissionError("existing worktree does not match recorded authority")
    else:
        args=("worktree","add","-b",branch,str(target),base_commit) if branch else ("worktree","add","--detach",str(target),base_commit)
        executor(repo,*args)
    if git(target,"rev-parse","HEAD").stdout.strip()!=base_commit: raise PermissionError("isolated worktree base commit mismatch")
    return {"worktree":str(target),"branch":branch,"base_commit":base_commit}


def validate_worktree(repo: Path, path: str, *, base_commit: str, branch: str | None, allow_descendant: bool = False) -> Path:
    repo=Path(git(repo,"rev-parse","--show-toplevel").stdout.strip()).resolve(); candidate=Path(path).resolve(); root=(repo/LOCAL_ROOT).resolve()
    if root not in candidate.parents: raise PermissionError("recorded worktree path is outside local storage")
    record=_registered(repo).get(str(candidate))
    head_ok=bool(record and record.get("HEAD")==base_commit)
    if allow_descendant and record: head_ok=git(candidate,"merge-base","--is-ancestor",base_commit,record.get("HEAD",""),check=False).returncode==0
    if not record or not head_ok or (branch and record.get("branch")!=f"refs/heads/{branch}"): raise PermissionError("recorded worktree metadata mismatch")
    return candidate


def cleanup_isolated_worktree(repo: Path, *, path: str | None, base_commit: str, branch: str | None) -> None:
    repo=Path(git(repo,"rev-parse","--show-toplevel").stdout.strip()).resolve()
    if path:
        candidate=Path(path).resolve(); root=(repo/LOCAL_ROOT).resolve()
        if root not in candidate.parents: raise PermissionError("recorded worktree path is outside local storage")
        if candidate.exists(): candidate=validate_worktree(repo,path,base_commit=base_commit,branch=branch,allow_descendant=True); git(repo,"worktree","remove","--force",str(candidate))
        elif str(candidate) in _registered(repo): raise PermissionError("missing worktree path remains registered")
    git(repo,"worktree","prune",check=False)
    if branch:
        if not branch.startswith("shiproom/"): raise PermissionError("refusing to delete non-Shiproom branch")
        if git(repo,"branch","--list",branch).stdout.strip(): git(repo,"branch","-D",branch)
