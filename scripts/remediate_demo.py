from __future__ import annotations

import argparse, json, os, tempfile
from pathlib import Path

from shiproom.remediation import ROUTE_TARGETS, patch_demo_route_isolated, remediation_branch, repository_root, git
from shiproom.authority import LocalExecutionContext
from shiproom.worktrees import cleanup_isolated_worktree, prepare_isolated_worktree, validate_worktree


def atomic_save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as stream: json.dump(data,stream,indent=2); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
        try:
            directory_fd=os.open(path.parent,os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
        except OSError: pass
    finally:
        if os.path.exists(name): os.unlink(name)


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--repo",default="."); parser.add_argument("--release",default="release-state/release.json"); args=parser.parse_args()
    repo=repository_root(Path(args.repo)); release_path=Path(args.release).resolve(); release=json.loads(release_path.read_text(encoding="utf-8")); context=LocalExecutionContext.from_release(release); release_id=release["release_id"]; branch=remediation_branch(release_id); task_id=f"rem_route_fix_{release_id}"; base=context.authority_binding["repository_commit"]
    task=next((t for t in release.setdefault("remediation_tasks",[]) if t.get("id")==task_id),None)
    if task and task.get("status")=="PATCHED": raise ValueError("release already records patched remediation")
    if not task:
        task={"id":task_id,"class":"route_fix","branch":branch,"base_branch":release["repository"]["base_branch"],"base_commit":base,"status":"PREPARING","auto_merge":False}; release["remediation_tasks"].append(task); atomic_save(release_path,release)
    record=None
    try:
        if task.get("worktree"):
            worktree=validate_worktree(repo,task["worktree"],base_commit=base,branch=branch,allow_descendant=True); head=git(worktree,"rev-parse","HEAD").stdout.strip()
            if head!=base:
                parent=git(worktree,"rev-parse",f"{head}^",check=False).stdout.strip(); status=git(worktree,"status","--porcelain","--untracked-files=all").stdout.strip(); actual=set(git(worktree,"diff-tree","--no-commit-id","--name-only","-r",head).stdout.splitlines())
                if parent==base and not status and actual and actual.issubset({p.as_posix() for p in ROUTE_TARGETS}): task.update({"commit_sha":head,"status":"PATCHED","targets":sorted(actual)}); release["state"]="VERIFYING"; atomic_save(release_path,release); print(json.dumps(task,indent=2)); return 0
                raise PermissionError("existing remediation commit cannot be recovered")
            record={"worktree":str(worktree),"branch":branch,"base_commit":base}
        else:
            record=prepare_isolated_worktree(repo,context.activation,f"remediate-{release_id}",base_commit=base,branch=branch); task.update(record); atomic_save(release_path,release)
        task["status"]="PATCHING"; atomic_save(release_path,release)
        targets,commit_sha,record=patch_demo_route_isolated(context,release); task.update({"commit_sha":commit_sha,"targets":[str(p.relative_to(Path(record["worktree"]))) for p in targets],"status":"PATCHED"}); release["state"]="VERIFYING"; atomic_save(release_path,release); print(json.dumps(task,indent=2)); return 0
    except Exception:
        if record:
            head=git(Path(record["worktree"]),"rev-parse","HEAD",check=False).stdout.strip() if Path(record["worktree"]).exists() else base
            if head!=base: task.update({"status":"FAILED_RECOVERY_REQUIRED","candidate_commit_sha":head})
            else:
                try: cleanup_isolated_worktree(repo,path=record["worktree"],base_commit=base,branch=branch); task["status"]="FAILED_CLEANED"; task.pop("worktree",None)
                except Exception: task["status"]="FAILED_RECOVERY_REQUIRED"
        else:
            candidate=(repo/".shiproom/local/worktrees"/f"remediate-{release_id}").resolve()
            if candidate.exists(): task.update({"status":"FAILED_RECOVERY_REQUIRED","worktree":str(candidate),"branch":branch,"base_commit":base})
            else: task["status"]="FAILED_CLEANED"
        atomic_save(release_path,release); raise


if __name__=="__main__": raise SystemExit(main())
