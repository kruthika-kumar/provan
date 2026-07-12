from __future__ import annotations

import argparse
import json
import shutil
import threading
from pathlib import Path

from shiproom.evidence import http_check
from shiproom.remediation import BRANCH_PREFIX, ROUTE_TARGETS, _assert_route_state, git, repository_root, validate_branch
from shiproom.worktrees import cleanup_isolated_worktree, validate_worktree


ALLOWED_RUNTIME_ROOTS = {"release-state", "evidence", "dist", "reports", "session-exports", "audio", "private-reports"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--release", default="release-state/release.json")
    args = parser.parse_args()
    repo = repository_root(Path(args.repo))
    release_path = Path(args.release).resolve()
    try: release_relative=release_path.relative_to(repo.resolve())
    except ValueError: raise PermissionError("release state path is outside repository")
    if not release_relative.parts or release_relative.parts[0] not in ALLOWED_RUNTIME_ROOTS: raise PermissionError("release state path is outside approved runtime roots")
    release = json.loads(release_path.read_text(encoding="utf-8"))
    base = release.get("repository", {}).get("base_branch")
    tasks = release.get("remediation_tasks", [])
    task=tasks[-1] if tasks else {}; branch = task.get("branch")
    if not base or not branch:
        raise ValueError("reset requires recorded base and remediation branches")
    validate_branch(branch, release["release_id"])
    if not branch.startswith(BRANCH_PREFIX):
        raise ValueError("refusing to delete a non-Shiproom branch")
    expected_base=release.get("project_authority",{}).get("repository_commit")
    if not expected_base: raise ValueError("reset requires release-bound base commit")
    if task.get("status")!="PATCHED" or not task.get("commit_sha"): raise ValueError("reset requires a PATCHED remediation task")
    worktree=validate_worktree(repo,task.get("worktree",""),base_commit=expected_base,branch=branch,allow_descendant=True); head=git(worktree,"rev-parse","HEAD").stdout.strip(); parent=git(worktree,"rev-parse",f"{head}^").stdout.strip()
    if head!=task["commit_sha"] or parent!=expected_base: raise PermissionError("remediation commit does not exactly match recorded task")
    if git(worktree,"status","--porcelain","--untracked-files=all").stdout.strip(): raise PermissionError("remediation worktree is dirty")
    branch_head=git(repo,"rev-parse",f"refs/heads/{branch}").stdout.strip()
    if branch_head!=task["commit_sha"]: raise PermissionError("remediation branch contains an unexpected commit")
    active_status=git(repo,"status","--porcelain","--untracked-files=all").stdout.strip()
    if active_status: raise PermissionError("active checkout must be clean before controlled reset")
    for relative, (broken, fixed) in ROUTE_TARGETS.items():
        _assert_route_state(repo / relative, broken, fixed, expect_broken=True)
    artifacts=[]
    for item in release.get("runtime_artifacts",[]):
        relative=Path(item.get("path",""))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] not in ALLOWED_RUNTIME_ROOTS or item.get("release_id")!=release["release_id"]: raise PermissionError("recorded runtime artifact is not safely owned by this release")
        artifact=(repo/relative).resolve()
        if repo.resolve() not in artifact.parents: raise PermissionError("runtime artifact escaped repository")
        artifacts.append(artifact)
    from demo_patient.server import Handler, ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        check = http_check(f"http://127.0.0.1:{server.server_port}/result/demo")
        if check.get("status") != 404:
            raise ValueError(f"reset verification failed: {check}")
    finally:
        server.shutdown(); thread.join(timeout=5); server.server_close()
    # Destructive phase begins only after every validation and the local 404 probe pass.
    cleanup_isolated_worktree(repo,path=str(worktree),base_commit=expected_base,branch=branch,expected_head=task["commit_sha"],require_clean=True)
    for artifact in artifacts:
        if artifact.is_dir(): shutil.rmtree(artifact)
        elif artifact.exists(): artifact.unlink()
        parent=artifact.parent
        if parent!=repo and parent.name in ALLOWED_RUNTIME_ROOTS and parent.exists() and not any(parent.iterdir()): parent.rmdir()
    release_path.unlink()
    if release_path.parent!=repo and release_path.parent.exists() and not any(release_path.parent.iterdir()): release_path.parent.rmdir()
    print(json.dumps({"status": "RESET", "base_branch": base, "deleted_branch": branch, "public_result_status": 404, "single_use":True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
