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
    for relative in ROUTE_TARGETS:
        baseline = subprocess.run(["git", "show", f"main:{relative.as_posix()}"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
        (repo / relative).write_text(baseline, encoding="utf-8")
    git(repo, "init", "-b", "event-base")
    git(repo, "config", "user.email", "shiproom-test@example.invalid")
    git(repo, "config", "user.name", "Shiproom Test")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test fixture")
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
    patient = start_patient(repo, port)
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
