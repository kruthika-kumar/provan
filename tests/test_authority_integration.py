from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from shiproom.authority import LocalExecutionContext, run_bounded_command
from shiproom.cli import main
from shiproom.onboarding import human_project_view, paths, project_authority_view
from shiproom.project import activate, default_contract, deployment_target, file_hash, resolve_policy_path, validate_command


def git(repo: Path, *args: str, check=True) -> str:
    return subprocess.run(["git",*args],cwd=repo,text=True,capture_output=True,check=check).stdout.strip()


def project_repo(tmp_path: Path, profile="inspect", commands=None) -> Path:
    repo=tmp_path/"project"; repo.mkdir(); git(repo,"init","-b","main"); git(repo,"config","user.email","test@example.invalid"); git(repo,"config","user.name","Test")
    (repo/".gitignore").write_text(".shiproom/local/\nrelease-state/\n",encoding="utf-8"); (repo/"pyproject.toml").write_text("[project]\nname='fixture'\n",encoding="utf-8"); (repo/"app.py").write_text("print('ok')\n",encoding="utf-8"); (repo/"verify_fixture.py").write_text("print('verified')\n",encoding="utf-8")
    contract=default_contract("Fixture","Exercise local authority",["testers"],profile); contract["execution_policy"]["approved_commands"]=commands or []
    (repo/".shiproom").mkdir(); (repo/".shiproom/project-contract.json").write_text(json.dumps(contract,indent=2)+"\n",encoding="utf-8"); git(repo,"add","."); git(repo,"commit","-m","base"); activate(repo,*paths(repo)); return repo


def command(repo: Path, *, command_id="unit", criterion="ENGINEERING_UNIT", required=True, argv=None, timeout=10, limit=4096) -> dict:
    return {"command_id":command_id,"criterion_id":criterion,"required_for_release":required,"argv":argv or ["python","verify_fixture.py"],"cwd":".","purpose":"Fixture verification","source":{"ref":"pyproject.toml","hash":file_hash(repo/"pyproject.toml")},"timeout_seconds":timeout,"output_limit_bytes":limit,"allowed_environment":{"PYTHONUTF8":"1"}}


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


@pytest.mark.parametrize("url",["http://localhost:8000/path","http://localhost:8000/?x=1","http://user:pass@localhost:8000","http://[::1]:8000"])
def test_local_release_origin_rejects_path_query_credentials_and_ipv6(tmp_path: Path,url: str):
    repo=project_repo(tmp_path); output=tmp_path/"release.json"
    with pytest.raises(ValueError): main(["release","init","--repo",str(repo),"--live-url",url,"--promise","Open","--output",str(output)])


def test_deployment_grant_mutation_fails_before_module(tmp_path: Path):
    repo=project_repo(tmp_path); output=tmp_path/"release.json"; release=init_release(repo,output); release["deployment"]["read_grant"]["allowed_paths"].append("/other")
    with pytest.raises(ValueError,match="deployment_grant_hash"): LocalExecutionContext.from_release(release)


@pytest.mark.parametrize("runtime,expected",[("gap","evidence_gap"),("redirect","authority_policy_violation")])
def test_product_runtime_policy_is_typed_through_review_cli(tmp_path: Path,runtime: str,expected: str):
    repo=project_repo(tmp_path); output=tmp_path/"release.json"; init_release(repo,output)
    class Opener:
        def open(self,request,timeout=10):
            if runtime=="gap": raise urllib.error.URLError("dns")
            raise urllib.error.HTTPError(request.full_url,302,"redirect",{"Location":"https://other.example/x"},None)
    with patch("shiproom.authority.urllib.request.build_opener",return_value=Opener()): assert main(["review","--module","product","--release",str(output)])==0
    release=json.loads(output.read_text()); assert release["checks"][0]["runtime_outcome"]==expected and release["checks"][0]["evidence_status"]=="missing_evidence" and release["findings"][0]["blocking"] is False


def test_inspect_engineering_has_required_and_optional_missing_evidence_without_process(tmp_path: Path):
    repo=project_repo(tmp_path); grants=[command(repo,command_id="required",criterion="REQ",required=True),command(repo,command_id="optional",criterion="OPT",required=False)]; set_commands(repo,"inspect",grants); path=tmp_path/"release.json"; init_release(repo,path)
    with patch("shiproom.authority.run_bounded_command") as bounded:
        assert main(["review","--module","engineering","--release",str(path)])==0
    bounded.assert_not_called(); release=json.loads(path.read_text()); checks={c["criterion_id"]:c for c in release["checks"]}; assert checks["REQ"]["required"] and not checks["OPT"]["required"] and release["verdict"]["status"]=="HOLD"


def test_verify_runs_in_disposable_recorded_commit_worktree_and_ignores_active_source_change(tmp_path: Path):
    repo=project_repo(tmp_path); grant=command(repo); set_commands(repo,"verify",[grant]); path=tmp_path/"release.json"; release=init_release(repo,path); branch=git(repo,"branch","--show-current"); head=git(repo,"rev-parse","HEAD"); (repo/"app.py").write_text("dirty\n")
    assert main(["review","--module","engineering","--release",str(path)])==0
    after=json.loads(path.read_text()); assert after["checks"][0]["passed"] and git(repo,"branch","--show-current")==branch and git(repo,"rev-parse","HEAD")==head and (repo/"app.py").read_text()=="dirty\n" and not list((repo/".shiproom/local/worktrees").glob("verify-*"))
    (repo/"pyproject.toml").write_text("changed active checkout only\n")
    rerun=LocalExecutionContext.from_release(release).execute_approved_commands(); assert rerun.command_results[0][1].status=="passed"


def test_two_commands_get_independent_worktrees_and_same_path_side_effect(tmp_path: Path):
    repo=project_repo(tmp_path); (repo/"write1.py").write_text("from pathlib import Path\nPath('same.txt').write_text('one')\n"); (repo/"write2.py").write_text("from pathlib import Path\nPath('same.txt').write_text('two')\n"); git(repo,"add","write1.py","write2.py"); git(repo,"commit","-m","writers")
    grants=[command(repo,command_id="one",criterion="ONE",argv=["python","write1.py"]),command(repo,command_id="two",criterion="TWO",argv=["python","write2.py"])]; set_commands(repo,"verify",grants); output=tmp_path/"release.json"; release=init_release(repo,output); batch=LocalExecutionContext.from_release(release).execute_approved_commands()
    assert batch.status=="completed" and [r.side_effect_paths for _,r in batch.command_results]==[["same.txt"],["same.txt"]] and not (repo/"same.txt").exists()


def test_verification_cleanup_failure_is_explicit(tmp_path: Path):
    repo=project_repo(tmp_path); set_commands(repo,"verify",[command(repo)]); output=tmp_path/"release.json"; context=LocalExecutionContext.from_release(init_release(repo,output)); import shiproom.authority as authority; original=authority._git
    def failing_git(root,*args,**kwargs):
        if args[:3]==("worktree","remove","--force"): return subprocess.CompletedProcess([],1,"","denied")
        return original(root,*args,**kwargs)
    with patch("shiproom.authority._git",side_effect=failing_git): batch=context.execute_approved_commands()
    assert batch.status=="recovery_required" and batch.command_results[0][1].cleanup_status=="recovery_required" and batch.command_results[0][1].recovery_worktree
    subprocess.run(["git","worktree","remove","--force",batch.command_results[0][1].recovery_worktree],cwd=repo,check=True,capture_output=True)


def test_commit_pinned_blob_reader_ignores_new_head_and_rejects_sensitive_entries(tmp_path: Path):
    repo=project_repo(tmp_path); (repo/"document.txt").write_text("bound\n"); (repo/"binary.bin").write_bytes(b"\x00\xff"); (repo/"large.txt").write_text("x"*2048); (repo/".ENV").write_text("secret"); git(repo,"add","."); blob=subprocess.run(["git","hash-object","-w","--stdin"],cwd=repo,input="document.txt",text=True,capture_output=True,check=True).stdout.strip(); git(repo,"update-index","--add","--cacheinfo",f"120000,{blob},link"); git(repo,"commit","-m","blob fixtures"); git(repo,"reset","--hard","HEAD"); output=tmp_path/"release.json"; release=init_release(repo,output); context=LocalExecutionContext.from_release(release)
    (repo/"document.txt").write_text("dirty active\n"); git(repo,"add","document.txt"); git(repo,"commit","-m","advance head")
    assert context.read_release_blob("document.txt")["text"]=="bound\n" and context.read_release_blob("binary.bin")["classification"]=="binary"
    with pytest.raises(ValueError): context.read_release_blob("large.txt",byte_limit=100)
    with pytest.raises(PermissionError): context.read_release_blob(".ENV")
    with pytest.raises(PermissionError): context.read_release_blob("link")


def test_commit_pinned_blob_reader_rejects_submodule_entry(tmp_path: Path):
    repo=project_repo(tmp_path); head=git(repo,"rev-parse","HEAD"); git(repo,"update-index","--add","--cacheinfo",f"160000,{head},submodule"); git(repo,"commit","-m","gitlink"); git(repo,"update-index","--skip-worktree","submodule"); output=tmp_path/"release.json"; release=init_release(repo,output)
    with pytest.raises(PermissionError): LocalExecutionContext.from_release(release).read_release_blob("submodule")


def test_shared_and_local_only_argv_scope(tmp_path: Path):
    repo=project_repo(tmp_path); grant=command(repo); grant["argv"]=[str(Path("C:/Python/python.exe")),"verify_fixture.py"]
    with pytest.raises(ValueError,match="machine-specific"): validate_command(grant,storage_scope="shared")
    validate_command(grant,storage_scope="local_only")


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


def test_bounded_spawn_error_is_typed(tmp_path: Path):
    grant={"command_id":"missing","criterion_id":"MISSING","required_for_release":True,"argv":["definitely-not-a-real-executable"],"cwd":".","purpose":"Spawn failure","source":{"ref":"source.txt","hash":"sha256:x"},"timeout_seconds":10,"output_limit_bytes":1024,"allowed_environment":{}}
    result=run_bounded_command(grant,tmp_path); assert result.status=="spawn_error" and result.exit_code is None and result.termination=="not_started"


@pytest.mark.parametrize("relative",[".env",".ENV","nested/.env",".Env.local","nested/.env.test","credentials/key.txt","Credentials/key.txt","nested/credentials/key.txt","SECRETS/a","nested/secrets/a","root.pem","root.PEM","nested/root.pem","root.KEY","nested/root.key"])
def test_sensitive_root_and_nested_paths_fail_closed(tmp_path: Path,relative: str):
    repo=tmp_path/"repo"; repo.mkdir()
    with pytest.raises(PermissionError): resolve_policy_path(repo,relative,[],[],operation="read")


def test_configured_directory_descendants_and_protected_reads(tmp_path: Path):
    repo=tmp_path/"repo"; (repo/"migrations").mkdir(parents=True); target=repo/"migrations/001.sql"; target.write_text("select 1")
    with pytest.raises(PermissionError): resolve_policy_path(repo,"migrations/001.sql",[],["migrations"],operation="read")
    assert resolve_policy_path(repo,"migrations/001.sql",["migrations"],[],operation="read")==target.resolve()
    with pytest.raises(PermissionError): resolve_policy_path(repo,"migrations/001.sql",["migrations"],[],operation="write")
    if os.name=="nt":
        with pytest.raises(PermissionError): resolve_policy_path(repo,"migrations/001.sql",["MIGRATIONS"],[],operation="write")


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
