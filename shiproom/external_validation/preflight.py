from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from .security import protected_hashes, validate_public_tree


PLAN_HASHES = {
    "external_validation/plan/shiproom_external_validation_testing_plan_v2.md": "sha256:d821c15e67ed06200e23d7bf77de39842310b318d821e56a23993c8d980d9886",
    "external_validation/plan/shiproom_external_validation_codex_action_plan.md": "sha256:c9e8a1944f1b023f753092827eb35a3901f77d6b0b1432b107421c2cbb6aad0b",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def verify_preflight(repository_root: Path, protected: list[str] | None = None) -> dict:
    repo = repository_root.resolve()
    violations = validate_public_tree(repo)
    plan_hashes = {relative: "sha256:" + hashlib.sha256((repo / relative).read_bytes()).hexdigest() for relative in PLAN_HASHES}
    mismatched = [path for path, digest in plan_hashes.items() if PLAN_HASHES[path] != digest]
    branch = _git(repo, "branch", "--show-current")
    try:
        upstream = _git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
        ahead_behind = _git(repo, "rev-list", "--left-right", "--count", "@{upstream}...HEAD").split()
    except subprocess.CalledProcessError:
        upstream, ahead_behind = None, ["missing"]
    status = _git(repo, "status", "--porcelain")
    if violations or mismatched or status or ahead_behind != ["0", "0"]:
        raise RuntimeError("preflight_failed:" + ",".join(violations + mismatched + (["worktree_dirty"] if status else []) + (["upstream_out_of_sync"] if ahead_behind != ["0", "0"] else [])))
    return {"head": _git(repo, "rev-parse", "HEAD"), "branch": branch, "upstream": upstream, "plan_hashes": plan_hashes, "protected_hashes": protected_hashes(repo, protected or [])}
