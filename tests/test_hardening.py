from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from shiproom.remediation import BRANCH_PREFIX, ROUTE_TARGETS, _assert_route_state, remediation_branch
from shiproom.authority import LocalExecutionContext
from shiproom.worktrees import cleanup_isolated_worktree, prepare_isolated_worktree


ROOT = Path(__file__).resolve().parents[1]


def run(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy(); env["PYTHONPATH"] = str(repo)
    return subprocess.run([sys.executable, *args], cwd=repo, env=env, text=True, capture_output=True, check=check)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "shiproom"
    repo.mkdir()
    for name in ("demo_patient", "shiproom", "scripts", "cloudflare"):
        shutil.copytree(ROOT / name, repo / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("pyproject.toml", ".gitignore"):
        shutil.copy2(ROOT / name, repo / name)
    (repo/".shiproom").mkdir(); contract=json.loads((ROOT/".shiproom/project-contract.json").read_text(encoding="utf-8")); contract["default_capability_profile"]="remediate"; (repo/".shiproom/project-contract.json").write_text(json.dumps(contract,indent=2)+"\n",encoding="utf-8")
    for relative in ROUTE_TARGETS:
        broken, fixed = ROUTE_TARGETS[relative]
        current = (repo / relative).read_text(encoding="utf-8")
        if current.count(broken) == 1 and current.count(fixed) == 0:
            baseline = current
        elif current.count(fixed) == 1 and current.count(broken) == 0:
            baseline = current.replace(fixed, broken, 1)
        else:
            raise AssertionError(f"controlled-patient source has an ambiguous route state for {relative}")
        (repo / relative).write_text(baseline, encoding="utf-8")
    git(repo, "init", "-b", "event-base")
    git(repo, "config", "user.email", "shiproom-test@example.invalid")
    git(repo, "config", "user.name", "Shiproom Test")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test fixture")
    run(repo,"-m","shiproom.cli","project","activate","--repo",str(repo))
    return repo


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]


def wait_http(url: str, expected: int, timeout: float = 8) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response: status = response.status
        except urllib.error.HTTPError as exc: status = exc.code
        except OSError:
            time.sleep(.1); continue
        if status == expected: return
        time.sleep(.1)
    raise AssertionError(f"{url} did not reach HTTP {expected}")


def start_patient(repo: Path, port: int) -> subprocess.Popen:
    env = os.environ.copy(); env.update({"PYTHONPATH": str(repo), "PORT": str(port)})
    process = subprocess.Popen([sys.executable, "-m", "demo_patient.server"], cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return process


def stop(process: subprocess.Popen) -> None:
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


def test_branch_identity_and_route_state(tmp_path):
    assert remediation_branch("rel_abc") == f"{BRANCH_PREFIX}rel_abc"
    with pytest.raises(ValueError): remediation_branch("bad/id")
    target = tmp_path / "route.py"
    broken, fixed = ROUTE_TARGETS[Path("demo_patient/server.py")]
    target.write_text(f"{broken}\n{broken}\n", encoding="utf-8")
    with pytest.raises(ValueError): _assert_route_state(target, broken, fixed, expect_broken=True)
    target.write_text(f"{fixed}\n", encoding="utf-8")
    with pytest.raises(ValueError): _assert_route_state(target, broken, fixed, expect_broken=True)


def test_complete_release_loop_and_reset(tmp_path):
    repo = make_repo(tmp_path); port = free_port(); url = f"http://127.0.0.1:{port}"
    patient = start_patient(repo, port)
    try:
        wait_http(f"{url}/result/demo", 404)
        run(repo, "-m", "shiproom.cli", "release", "init", "--repo", str(repo), "--live-url", url, "--promise", "Users can generate and open a public launch card.")
        release_path = repo / "release-state" / "release.json"
        release = json.loads(release_path.read_text()); release_id = release["release_id"]
        assert release["repository"]["base_branch"] == "event-base"
        run(repo, "-m", "shiproom.cli", "review", "--module", "product", "--release", str(release_path))
        run(repo, "-m", "shiproom.cli", "decision", "add", "--release", str(release_path))
        release = json.loads(release_path.read_text())
        assert release["verdict"]["status"] == "HOLD"
        assert release["checks"][0]["status"] == 404
    finally:
        stop(patient)

    run(repo, "scripts/remediate_demo.py", "--repo", str(repo), "--release", str(release_path))
    release = json.loads(release_path.read_text())
    branch = release["remediation_tasks"][-1]["branch"]
    assert branch == remediation_branch(release_id)
    assert release["remediation_tasks"][-1]["auto_merge"] is False
    remediation_worktree=Path(release["remediation_tasks"][-1]["worktree"])
    release["checks"][0]["target"]="https://mutated.example/not-authoritative"; release_path.write_text(json.dumps(release,indent=2))
    patient = start_patient(remediation_worktree, port)
    try:
        wait_http(f"{url}/result/demo", 200)
        first_verify = run(repo, "scripts/verify_demo.py", "--release", str(release_path), check=False)
        assert first_verify.returncode != 0
        assert json.loads(release_path.read_text())["verdict"]["status"] == "AWAITING_OWNER"
        run(repo, "-m", "shiproom.cli", "decision", "record", "--release", str(release_path), "--choice", "Revise the beta promise", "--resolution", "accepted_condition")
        second_verify = run(repo, "scripts/verify_demo.py", "--release", str(release_path), check=False)
        assert second_verify.returncode == 0
        release = json.loads(release_path.read_text())
        assert release["verdict"]["status"] == "SHIP_WITH_CONDITIONS"
        assert [c.get("status") for c in release["checks"]] == [404, 200]
        assert release["checks"][1]["rerun_of_check_id"]==release["checks"][0]["check_id"]
        public_url = "https://shiproom-demo.example.workers.dev"
        release["deployment"].update({"url": public_url, "report_url": f"{public_url}/reports/{release_id}"})
        release["integrations"] = {"github": {"repository": "kruthika-kumar/shiproom", "pr_number": 1, "comment_url": "https://github.com/kruthika-kumar/shiproom/pull/1"}, "cloudflare": {"report_url": release["deployment"]["report_url"]}}
        for check in release["checks"]: check["target"] = f"{public_url}/result/demo"
        for item in release["findings"][0]["evidence"]: item["reference"] = f"{public_url}/result/demo"
        release_path.write_text(json.dumps(release, indent=2), encoding="utf-8")
        run(repo, "-m", "shiproom.cli", "report", "render", "--release", str(release_path), "--output", "dist/release-report.html")
        report = (repo / "dist" / "release-report.html").read_text(encoding="utf-8")
        assert release_id in report and "404" in report and "200" in report and "Revise the beta promise" in report
    finally:
        stop(patient)

    run(repo, "scripts/reset_demo.py", "--repo", str(repo), "--release", str(release_path))
    assert git(repo, "branch", "--show-current") == "event-base"
    assert not git(repo, "branch", "--list", branch)
    assert not (repo / "release-state").exists()
    assert not (repo / "dist").exists()
    assert git(repo, "status", "--porcelain", "--untracked-files=all") == ""


def test_real_remediation_preserves_dirty_active_checkout(tmp_path):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"
    (repo/"README.local").write_text("untracked dirty\n"); (repo/"pyproject.toml").write_text((repo/"pyproject.toml").read_text()+"\n# staged\n"); git(repo,"add","pyproject.toml")
    branch=git(repo,"branch","--show-current"); head=git(repo,"rev-parse","HEAD"); status=git(repo,"status","--porcelain","--untracked-files=all"); cached=git(repo,"diff","--cached"); dirty=(repo/"README.local").read_bytes()
    run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); release=json.loads(release_path.read_text()); task=release["remediation_tasks"][-1]
    assert git(repo,"branch","--show-current")==branch and git(repo,"rev-parse","HEAD")==head and git(repo,"status","--porcelain","--untracked-files=all")==status and git(repo,"diff","--cached")==cached and (repo/"README.local").read_bytes()==dirty
    cleanup_isolated_worktree(repo,path=task["worktree"],base_commit=task["base_commit"],branch=task["branch"])


def test_unexpected_remediation_diff_fails_without_commit_and_cleanup_is_idempotent(tmp_path):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"; release=json.loads(release_path.read_text()); context=LocalExecutionContext.from_release(release); branch=remediation_branch(release["release_id"]); record=prepare_isolated_worktree(repo,context.activation,f"remediate-{release['release_id']}",base_commit=context.authority_binding["repository_commit"],branch=branch); worktree=Path(record["worktree"]); (worktree/"unexpected.txt").write_text("not authorized")
    result=run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path),check=False)
    failed=json.loads(release_path.read_text())["remediation_tasks"][-1]
    assert result.returncode!=0 and not worktree.exists() and failed["status"]=="FAILED_CLEANED"
    cleanup_isolated_worktree(repo,path=record["worktree"],base_commit=record["base_commit"],branch=branch); cleanup_isolated_worktree(repo,path=record["worktree"],base_commit=record["base_commit"],branch=branch)
    with pytest.raises(PermissionError): cleanup_isolated_worktree(repo,path=str(tmp_path/"outside"),base_commit=record["base_commit"],branch=branch)


def test_remediation_recovers_after_worktree_creation(tmp_path):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"; release=json.loads(release_path.read_text()); context=LocalExecutionContext.from_release(release); branch=remediation_branch(release["release_id"]); record=prepare_isolated_worktree(repo,context.activation,f"remediate-{release['release_id']}",base_commit=context.authority_binding["repository_commit"],branch=branch); release["remediation_tasks"]=[{"id":f"rem_route_fix_{release['release_id']}","class":"route_fix","branch":branch,"base_branch":"event-base","base_commit":record["base_commit"],"worktree":record["worktree"],"status":"PREPARING","auto_merge":False}]; release_path.write_text(json.dumps(release,indent=2))
    run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); recovered=json.loads(release_path.read_text())["remediation_tasks"][-1]; assert recovered["status"]=="PATCHED" and recovered["commit_sha"]
    cleanup_isolated_worktree(repo,path=recovered["worktree"],base_commit=recovered["base_commit"],branch=branch,expected_head=recovered["commit_sha"],require_clean=True)


def test_remediation_recovers_commit_and_reset_rejects_dirty_or_extra_head(tmp_path):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"; run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); release=json.loads(release_path.read_text()); task=release["remediation_tasks"][-1]; commit=task.pop("commit_sha"); task["status"]="PATCHING"; release_path.write_text(json.dumps(release,indent=2)); run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); release=json.loads(release_path.read_text()); task=release["remediation_tasks"][-1]; assert task["status"]=="PATCHED" and task["commit_sha"]==commit
    worktree=Path(task["worktree"]); (worktree/"dirty.txt").write_text("dirty"); assert run(repo,"scripts/reset_demo.py","--repo",str(repo),"--release",str(release_path),check=False).returncode!=0; (worktree/"dirty.txt").unlink(); git(worktree,"commit","--allow-empty","-m","unexpected")
    assert run(repo,"scripts/reset_demo.py","--repo",str(repo),"--release",str(release_path),check=False).returncode!=0
    git(repo,"worktree","remove","--force",str(worktree)); git(repo,"branch","-D",task["branch"])


@pytest.mark.parametrize("failure",["invalid_artifact","dirty_active"])
def test_reset_preflight_failure_preserves_remediation_branch_and_worktree(tmp_path,failure):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"; run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); release=json.loads(release_path.read_text()); task=release["remediation_tasks"][-1]; worktree=Path(task["worktree"])
    if failure=="invalid_artifact": release["runtime_artifacts"]=[{"release_id":release["release_id"],"path":"../outside","kind":"report"}]; release_path.write_text(json.dumps(release,indent=2))
    else: (repo/"pyproject.toml").write_text((repo/"pyproject.toml").read_text()+"\n# dirty\n")
    result=run(repo,"scripts/reset_demo.py","--repo",str(repo),"--release",str(release_path),check=False)
    assert result.returncode!=0 and worktree.exists() and git(repo,"branch","--list",task["branch"])
    if failure=="dirty_active": git(repo,"restore","pyproject.toml")
    cleanup_isolated_worktree(repo,path=task["worktree"],base_commit=task["base_commit"],branch=task["branch"],expected_head=task["commit_sha"],require_clean=True)


@pytest.mark.parametrize("artifact_case",["dist_root","reports_root","release_state","duplicate","overlap"])
def test_reset_artifact_preflight_preserves_remediation_on_unsafe_records(tmp_path,artifact_case):
    repo=make_repo(tmp_path); run(repo,"-m","shiproom.cli","release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open result"); release_path=repo/"release-state/release.json"; run(repo,"scripts/remediate_demo.py","--repo",str(repo),"--release",str(release_path)); release=json.loads(release_path.read_text()); task=release["remediation_tasks"][-1]; rid=release["release_id"]
    cases={"dist_root":[{"release_id":rid,"path":"dist","kind":"report"}],"reports_root":[{"release_id":rid,"path":"reports","kind":"release_directory"}],"release_state":[{"release_id":rid,"path":"release-state/release.json","kind":"file"}],"duplicate":[{"release_id":rid,"path":"reports/a.html","kind":"file"},{"release_id":rid,"path":"reports/a.html","kind":"file"}],"overlap":[{"release_id":rid,"path":f"reports/{rid}","kind":"release_directory"},{"release_id":rid,"path":f"reports/{rid}/a.html","kind":"file"}]}; release["runtime_artifacts"]=cases[artifact_case]; release_path.write_text(json.dumps(release,indent=2))
    result=run(repo,"scripts/reset_demo.py","--repo",str(repo),"--release",str(release_path),check=False)
    assert result.returncode!=0 and Path(task["worktree"]).exists() and git(repo,"branch","--list",task["branch"])
    cleanup_isolated_worktree(repo,path=task["worktree"],base_commit=task["base_commit"],branch=task["branch"],expected_head=task["commit_sha"],require_clean=True)
