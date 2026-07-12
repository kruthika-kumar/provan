from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .verdict import calculate, close_finding
from .authority import LocalExecutionContext
from .worktrees import prepare_isolated_worktree

ALLOWED_CLASSES = {"route_fix", "regression_test", "broken_link", "basic_error_handling"}
PROTECTED_PARTS = {".env", ".git", "credentials", "secrets"}
BRANCH_PREFIX = "shiproom/fix-public-result-route-"
ROUTE_TARGETS = {
    Path("demo_patient/server.py"): (
        'elif path.startswith("/results/"):',
        'elif path.startswith("/result/") or path.startswith("/results/"):',
    ),
    Path("cloudflare/worker.js"): (
        'if (url.pathname.startsWith("/results/")) {',
        'if (url.pathname.startsWith("/result/") || url.pathname.startsWith("/results/")) {',
    ),
}


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=check)


def repository_root(path: Path) -> Path:
    result = git(path.resolve(), "rev-parse", "--show-toplevel")
    root = Path(result.stdout.strip()).resolve()
    if not root.is_dir():
        raise ValueError("resolved Git repository root is missing")
    return root


def current_branch(repo: Path) -> str:
    branch = git(repo, "branch", "--show-current").stdout.strip()
    if not branch:
        raise ValueError("a named base branch is required")
    return branch


def assert_clean_worktree(repo: Path) -> None:
    status = git(repo, "status", "--porcelain", "--untracked-files=all").stdout.strip()
    if status:
        raise ValueError(f"tracked or unexpected source changes present:\n{status}")


def remediation_branch(release_id: str) -> str:
    if not re.fullmatch(r"rel_[A-Za-z0-9_-]+", release_id):
        raise ValueError("invalid release_id for remediation branch")
    return f"{BRANCH_PREFIX}{release_id}"


def validate_branch(branch: str, release_id: str) -> None:
    expected = remediation_branch(release_id)
    if branch != expected or not branch.startswith(BRANCH_PREFIX):
        raise ValueError("remediation branch does not match the release")


def validate_target(repo: Path, target: Path, remediation_class: str) -> Path:
    if remediation_class not in ALLOWED_CLASSES:
        raise ValueError("remediation class is not allowlisted")
    repo = repo.resolve(); target = target.resolve()
    if repo not in target.parents or any(part.lower() in PROTECTED_PARTS for part in target.parts):
        raise ValueError("remediation target is outside repository or protected")
    return target


def _assert_route_state(target: Path, broken: str, fixed: str, *, expect_broken: bool) -> str:
    source = target.read_text(encoding="utf-8")
    broken_count, fixed_count = source.count(broken), source.count(fixed)
    expected = (1, 0) if expect_broken else (0, 1)
    if (broken_count, fixed_count) != expected:
        raise ValueError(
            f"unexpected route state in {target}: broken={broken_count}, fixed={fixed_count}, expected={expected}"
        )
    return source


def patch_demo_route_isolated(context: LocalExecutionContext, release: dict) -> tuple[list[Path], str, dict]:
    repo=context.repository_root; release_id=release["release_id"]; branch=remediation_branch(release_id); base=context.authority_binding["repository_commit"]
    worktree_record=prepare_isolated_worktree(repo,context.activation,f"remediate-{release_id}",base_commit=base,branch=branch); worktree=Path(worktree_record["worktree"]); authorized={p.as_posix() for p in ROUTE_TARGETS}
    changed=[]
    for relative,(broken,fixed) in ROUTE_TARGETS.items():
        target=context.write_isolated_file(worktree,relative.as_posix()); source=_assert_route_state(target,broken,fixed,expect_broken=True); updated=source.replace(broken,fixed,1)
        if updated==source: raise ValueError(f"route remediation was a no-op for {relative}")
        target.write_text(updated,encoding="utf-8"); _assert_route_state(target,broken,fixed,expect_broken=False); changed.append(target)
    actual={line.strip() for line in git(worktree,"diff","--name-only",base).stdout.splitlines() if line.strip()}
    untracked={line[3:] for line in git(worktree,"status","--porcelain","--untracked-files=all").stdout.splitlines() if line.startswith("?? ")}
    actual|=untracked
    if not actual or not actual.issubset(authorized): raise PermissionError(f"remediation diff contains unauthorized paths: {sorted(actual-authorized)}")
    git(worktree,"add","--",*sorted(actual)); staged={line.strip() for line in git(worktree,"diff","--cached","--name-only",base).stdout.splitlines() if line.strip()}
    if staged!=actual: raise PermissionError("staged remediation paths differ from authorized diff")
    git(worktree,"commit","-m",f"fix: close public result route for {release_id}"); commit_sha=git(worktree,"rev-parse","HEAD").stdout.strip()
    return changed,commit_sha,worktree_record


def verify_and_close(release: dict, context: LocalExecutionContext) -> dict:
    from .authority import PRODUCT_CRITERION, product_check_id
    path=release["deployment"]["generated_path"]; expected_id=product_check_id(release["release_id"],context.authority_binding["deployment_grant_hash"],path)
    failed = next((c for c in release.get("checks", []) if c.get("check_id")==expected_id and c.get("criterion_id") == PRODUCT_CRITERION and c.get("granted_path")==path and not c.get("passed")), None)
    finding = next((f for f in release.get("findings", []) if f.get("criterion_id") == "PRODUCT_PUBLIC_RESULT_OPENS" and f.get("state") != "CLOSED"), None)
    if not failed:
        raise ValueError("original failed check is required")
    if not finding:
        closed = next((f for f in release.get("findings", []) if f.get("criterion_id") == "PRODUCT_PUBLIC_RESULT_OPENS" and f.get("state") == "CLOSED"), None)
        passed_rerun = next((c for c in release.get("checks", []) if c.get("criterion_id") == "PRODUCT_PUBLIC_RESULT_OPENS" and c.get("passed") and c.get("rerun_of_check_id")==expected_id), None)
        if not closed or not passed_rerun:
            raise ValueError("closed finding requires a successful independent rerun")
        release["verdict"] = calculate(release); release["state"] = release["verdict"]["status"]
        return release
    runtime=context.read_configured_deployment(path); rerun=runtime.to_check(context.deployment_grant["origin"]+path)
    rerun.update({"check_id":expected_id+"-rerun","granted_path":path,"deployment_grant_hash":context.authority_binding["deployment_grant_hash"]})
    rerun["criterion_id"] = failed["criterion_id"]
    rerun["rerun_of_check_id"] = expected_id
    release["checks"].append(rerun)
    if runtime.outcome=="observed_success":
        evidence = {"status": rerun["evidence_status"], "kind": "http_status", "value": rerun["status"], "reference": rerun["target"]}
        closed = close_finding(finding, evidence)
        release["findings"][release["findings"].index(finding)] = closed
    release["verdict"] = calculate(release); release["state"] = release["verdict"]["status"]
    return release
