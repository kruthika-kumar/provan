from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from shiproom.authority import LocalExecutionContext, run_bounded_command
from shiproom.cli import main
from shiproom.onboarding import human_project_view, paths, project_authority_view
from shiproom.project import activate, default_contract, deployment_target, file_hash, resolve_policy_path


def git(repo: Path, *args: str, check=True) -> str:
    return subprocess.run(["git",*args],cwd=repo,text=True,capture_output=True,check=check).stdout.strip()


def project_repo(tmp_path: Path, profile="inspect", commands=None) -> Path:
    repo=tmp_path/"project"; repo.mkdir(); git(repo,"init","-b","main"); git(repo,"config","user.email","test@example.invalid"); git(repo,"config","user.name","Test")
    (repo/".gitignore").write_text(".shiproom/local/\nrelease-state/\n",encoding="utf-8"); (repo/"pyproject.toml").write_text("[project]\nname='fixture'\n",encoding="utf-8"); (repo/"app.py").write_text("print('ok')\n",encoding="utf-8"); (repo/"verify_fixture.py").write_text("print('verified')\n",encoding="utf-8")
    contract=default_contract("Fixture","Exercise local authority",["testers"],profile); contract["execution_policy"]["approved_commands"]=commands or []
    (repo/".shiproom").mkdir(); (repo/".shiproom/project-contract.json").write_text(json.dumps(contract,indent=2)+"\n",encoding="utf-8"); git(repo,"add","."); git(repo,"commit","-m","base"); activate(repo,*paths(repo)); return repo


def command(repo: Path, *, command_id="unit", criterion="ENGINEERING_UNIT", required=True, argv=None, timeout=10, limit=4096) -> dict:
    return {"command_id":command_id,"criterion_id":criterion,"required_for_release":required,"argv":argv or [sys.executable,"verify_fixture.py"],"cwd":".","purpose":"Fixture verification","source":{"ref":"pyproject.toml","hash":file_hash(repo/"pyproject.toml")},"timeout_seconds":timeout,"output_limit_bytes":limit,"allowed_environment":{"PYTHONUTF8":"1"}}


def set_commands(repo: Path, profile: str, commands: list[dict]) -> None:
    path,receipt=paths(repo); data=json.loads(path.read_text()); data["default_capability_profile"]=profile; data["execution_policy"]["approved_commands"]=commands; path.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8"); git(repo,"add",str(path.relative_to(repo))); git(repo,"commit","-m","authority"); activate(repo,path,receipt)


def init_release(repo: Path, output: Path) -> dict:
    assert main(["release","init","--repo",str(repo),"--live-url","http://127.0.0.1:8787","--promise","Open the result","--output",str(output)])==0
    return json.loads(output.read_text())


def test_external_init_uses_real_external_contract_cli(tmp_path: Path):
    contract={"schema_version":"external_release_contract.v1","project_name":"Public","repository_url":"https://github.com/example/public","live_url":"https://example.com","target_user":"users","product_promise":"Open","critical_journey":["Open"],"non_goals":[],"owner_constraints":[],"capabilities":{key:key=="inspect_public_surfaces" for key in ("inspect_public_surfaces","run_safe_commands","publish_report","comment_upstream","create_local_diff","push_branch","open_pr","modify_deployment")}}
    source=tmp_path/"external.json"; output=tmp_path/"release.json"; source.write_text(json.dumps(contract))
    root=Path(__file__).resolve().parents[1]; env=os.environ.copy(); env["PYTHONPATH"]=str(root); result=subprocess.run([sys.executable,"-m","shiproom.cli","external","init","--contract",str(source),"--output",str(output),"--run-root",str(tmp_path/"runs")],cwd=tmp_path,env=env,text=True,capture_output=True)
    assert result.returncode==0, result.stderr
    assert json.loads(output.read_text())["mode"]=="external"


def test_release_binding_and_changed_authority_fail_closed(tmp_path: Path):
    repo=project_repo(tmp_path); release_path=tmp_path/"release.json"; release=init_release(repo,release_path); binding=release["project_authority"]
    assert binding["project_id"]=="fixture" and binding["repository_commit"]==git(repo,"rev-parse","HEAD") and release["deployment"]["read_grant"]["origin"]=="http://127.0.0.1:8787"
    contract,_=paths(repo); data=json.loads(contract.read_text()); data["product_purpose"]="Changed authority"; contract.write_text(json.dumps(data,indent=2)+"\n")
    with pytest.raises(ValueError,match="stale"): LocalExecutionContext.from_release(release)


def test_inspect_engineering_has_required_and_optional_missing_evidence_without_process(tmp_path: Path):
    repo=project_repo(tmp_path); grants=[command(repo,command_id="required",criterion="REQ",required=True),command(repo,command_id="optional",criterion="OPT",required=False)]; set_commands(repo,"inspect",grants); path=tmp_path/"release.json"; init_release(repo,path)
    with patch("shiproom.authority.run_bounded_command") as bounded:
        assert main(["review","--module","engineering","--release",str(path)])==0
    bounded.assert_not_called(); release=json.loads(path.read_text()); checks={c["criterion_id"]:c for c in release["checks"]}; assert checks["REQ"]["required"] and not checks["OPT"]["required"] and release["verdict"]["status"]=="HOLD"


def test_verify_runs_in_disposable_recorded_commit_worktree_and_stale_source_fails(tmp_path: Path):
    repo=project_repo(tmp_path); grant=command(repo); set_commands(repo,"verify",[grant]); path=tmp_path/"release.json"; release=init_release(repo,path); branch=git(repo,"branch","--show-current"); head=git(repo,"rev-parse","HEAD"); (repo/"app.py").write_text("dirty\n")
    assert main(["review","--module","engineering","--release",str(path)])==0
    after=json.loads(path.read_text()); assert after["checks"][0]["passed"] and git(repo,"branch","--show-current")==branch and git(repo,"rev-parse","HEAD")==head and (repo/"app.py").read_text()=="dirty\n" and not list((repo/".shiproom/local/worktrees").glob("verify-*"))
    (repo/"pyproject.toml").write_text("changed\n")
    with pytest.raises(ValueError,match="stale"): LocalExecutionContext.from_release(release)


def _alive(pid: int) -> bool:
    if os.name=="nt": return str(pid) in subprocess.run(["tasklist","/FI",f"PID eq {pid}"],text=True,capture_output=True).stdout
    try: os.kill(pid,0); return True
    except OSError: return False


def test_bounded_timeout_stops_spawned_child(tmp_path: Path):
    pidfile=tmp_path/"child.pid"; code="import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); pathlib.Path('child.pid').write_text(str(p.pid)); time.sleep(60)"; grant={"command_id":"timeout","criterion_id":"TIMEOUT","required_for_release":True,"argv":[sys.executable,"-c",code],"cwd":".","purpose":"Timeout fixture","source":{"ref":"source.txt","hash":"sha256:x"},"timeout_seconds":1,"output_limit_bytes":1024,"allowed_environment":{}}
    result=run_bounded_command(grant,tmp_path); pid=int(pidfile.read_text()); time.sleep(.2)
    assert result.status in {"timeout","termination_failed"} and result.duration_ms>=900 and not _alive(pid)


def test_bounded_output_overflow_stops_spawned_child(tmp_path: Path):
    pidfile=tmp_path/"child.pid"; code="import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); pathlib.Path('child.pid').write_text(str(p.pid)); print('x'*200000,flush=True); time.sleep(60)"; grant={"command_id":"overflow","criterion_id":"OVERFLOW","required_for_release":True,"argv":[sys.executable,"-c",code],"cwd":".","purpose":"Overflow fixture","source":{"ref":"source.txt","hash":"sha256:x"},"timeout_seconds":10,"output_limit_bytes":1024,"allowed_environment":{}}
    result=run_bounded_command(grant,tmp_path); pid=int(pidfile.read_text()); time.sleep(.2)
    assert result.status in {"output_limit_exceeded","termination_failed"} and result.bytes_captured==1024 and not _alive(pid)


@pytest.mark.parametrize("relative",[".env","nested/.env",".env.local","nested/.env.test","credentials/key.txt","nested/credentials/key.txt","secrets/a","nested/secrets/a","root.pem","nested/root.pem","root.key","nested/root.key"])
def test_sensitive_root_and_nested_paths_fail_closed(tmp_path: Path,relative: str):
    repo=tmp_path/"repo"; repo.mkdir()
    with pytest.raises(PermissionError): resolve_policy_path(repo,relative,[],[],operation="read")


def test_configured_directory_descendants_and_protected_reads(tmp_path: Path):
    repo=tmp_path/"repo"; (repo/"migrations").mkdir(parents=True); target=repo/"migrations/001.sql"; target.write_text("select 1")
    with pytest.raises(PermissionError): resolve_policy_path(repo,"migrations/001.sql",[],["migrations"],operation="read")
    assert resolve_policy_path(repo,"migrations/001.sql",["migrations"],[],operation="read")==target.resolve()
    with pytest.raises(PermissionError): resolve_policy_path(repo,"migrations/001.sql",["migrations"],[],operation="write")


@pytest.mark.skipif(os.name!="nt",reason="Windows junction behavior")
def test_junction_escape_is_rejected(tmp_path: Path):
    repo=tmp_path/"repo"; outside=tmp_path/"outside"; repo.mkdir(); outside.mkdir(); link=repo/"junction"; result=subprocess.run(["cmd","/c","mklink","/J",str(link),str(outside)],capture_output=True)
    if result.returncode: pytest.skip("junction creation unavailable")
    with pytest.raises(PermissionError): resolve_policy_path(repo,"junction/secret.txt",[],[],operation="read")


def test_project_show_contract_binding_and_snapshot_compatibility(tmp_path: Path):
    repo=project_repo(tmp_path); default,receipt=paths(repo); alternative=tmp_path/"alternative.json"; data=json.loads(default.read_text()); data["project_name"]="Alternative"; alternative.write_text(json.dumps(data))
    view=project_authority_view(repo,alternative,receipt); assert view["project"]["name"]=="Alternative" and view["authority"]["binding"]=="unbound/stale" and "Alternative" in human_project_view(view)
    old=deployment_target(); old.pop("observed_at"); target_path=repo/".shiproom/local/deployment-target.json"; target_path.write_text(json.dumps(old)); from shiproom.onboarding import discover; assert discover(repo)["deployment"]["observed_at"]=="not_recorded"


def test_project_show_cli_honors_selected_contract_and_doctor_recomputes(tmp_path: Path,capsys):
    repo=project_repo(tmp_path); default,receipt=paths(repo); alternative=tmp_path/"alternative.json"; data=json.loads(default.read_text()); data["project_name"]="Selected Contract"; alternative.write_text(json.dumps(data)); stored=repo/".shiproom/local/project-locator.json"; stored.write_text(json.dumps({"schema_version":"local_project_locator.v1","head":"stale","observed_at":"not_recorded"}))
    assert main(["project","show","--repo",str(repo),"--contract",str(alternative),"--json"])==0; payload=json.loads(capsys.readouterr().out); assert payload["project"]["name"]=="Selected Contract" and payload["authority"]["binding"]=="unbound/stale"
    assert main(["doctor","--repo",str(repo),"--json"])==0; doctor=json.loads(capsys.readouterr().out); assert doctor["repository"]["head"]==git(repo,"rev-parse","HEAD") and doctor["network_probes"]==[]
