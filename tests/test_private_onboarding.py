from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from shiproom.authority import execute_approved_command, execute_operation
from shiproom.external import CAPABILITIES, validate_contract as validate_external
from shiproom.onboarding import discover, initialize, paths
from shiproom.project import (
    DEFAULT_EXCLUDED, activation_status, content_hash, default_contract,
    deployment_target, file_hash, local_locator, resolve_policy_path,
    validate_command, validate_contract,
)
from shiproom.worktrees import authorize_isolated_write, prepare_isolated_worktree


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root=tmp_path/"private"; root.mkdir(); git(root,"init","-b","main"); git(root,"config","user.email","test@example.com"); git(root,"config","user.name","Test")
    (root/".gitignore").write_text(".shiproom/local/\n",encoding="utf-8"); (root/"pyproject.toml").write_text("[tool.pytest.ini_options]\n",encoding="utf-8"); (root/"app.py").write_text("print('ok')\n",encoding="utf-8")
    git(root,"add","."); git(root,"commit","-m","base"); return root


def init_project(repo: Path, profile="inspect") -> dict:
    return initialize(repo,project_name="Private App",product_purpose="Serve private teams",primary_users=["operators"],profile=profile,local_only=False,confirmed=True)


def test_external_contract_semantics_are_unchanged():
    contract={"schema_version":"external_release_contract.v1","project_name":"Public","repository_url":"https://github.com/example/public","live_url":"https://example.com","target_user":"users","product_promise":"Open","critical_journey":["Open"],"non_goals":[],"owner_constraints":[],"capabilities":{k:k=="inspect_public_surfaces" for k in CAPABILITIES}}
    assert validate_external(contract) is contract
    with pytest.raises(ValueError): validate_external({**contract,"repository_url":"C:/private"})


def test_minimal_contract_defaults_and_schema():
    contract=validate_contract(default_contract("Private App","Serve teams",["operators"]))
    assert contract["report_visibility"]=="private" and contract["memory_policy"]=="disabled"
    assert contract["accepted_risks"]==[] and contract["default_capability_profile"]=="inspect"
    assert contract["excluded_paths"]==DEFAULT_EXCLUDED


def test_init_writes_only_shiproom_and_gitignore(repo: Path):
    before=git(repo,"rev-parse","HEAD"); result=init_project(repo)
    assert result["status"]=="ACTIVE" and git(repo,"rev-parse","HEAD")==before and git(repo,"branch","--show-current")=="main"
    changed=git(repo,"status","--porcelain").splitlines()
    assert all(".shiproom" in line or ".gitignore" in line for line in changed)
    assert (repo/".shiproom/local/activation-receipt.json").is_file()


def test_preview_makes_no_writes(repo: Path):
    result=initialize(repo,project_name="P",product_purpose="Purpose",primary_users=["users"],profile="inspect",local_only=False,confirmed=False)
    assert result["status"]=="PREVIEW" and not (repo/".shiproom").exists() and not git(repo,"status","--porcelain")


def test_activation_stale_falls_back_to_inspect(repo: Path):
    init_project(repo,"verify"); contract,receipt=paths(repo)
    fresh=activation_status(repo,contract,receipt); assert fresh["effective_profile"]=="verify"
    data=json.loads(contract.read_text()); data["product_purpose"]="Changed"; contract.write_text(json.dumps(data),encoding="utf-8")
    stale=activation_status(repo,contract,receipt); assert not stale["activation_fresh"] and stale["effective_profile"]=="inspect"


def test_clean_tracked_contract_is_reusable_in_fresh_clone(repo: Path, tmp_path: Path):
    init_project(repo,"verify"); git(repo,"add",".gitignore",".shiproom/project-contract.json"); git(repo,"commit","-m","contract")
    clone=tmp_path/"clone"; subprocess.run(["git","clone",str(repo),str(clone)],check=True,capture_output=True)
    contract,receipt=paths(clone); status=activation_status(clone,contract,receipt)
    assert status["reusable"] and status["activation_fresh"] and status["effective_profile"]=="verify"


def approved(repo: Path) -> dict:
    command={"command_id":"unit","argv":["python","-m","pytest","-q"],"cwd":".","purpose":"Unit tests","source":{"ref":"pyproject.toml","hash":file_hash(repo/"pyproject.toml")},"timeout_seconds":120,"output_limit_bytes":4096,"allowed_environment":{"NO_COLOR":"1"}}
    validate_command(command,repo); return command


def test_detected_command_is_not_authority_and_denied_executor_is_not_called(repo: Path):
    init_project(repo); status=activation_status(repo,*paths(repo)); executor=Mock()
    with pytest.raises(PermissionError): execute_operation(status,"command.execute",executor)
    executor.assert_not_called()


def test_approved_command_uses_argv_no_shell_and_minimal_environment(repo: Path):
    init_project(repo,"verify"); contract,receipt=paths(repo); data=json.loads(contract.read_text()); data["execution_policy"]["approved_commands"]=[approved(repo)]; contract.write_text(json.dumps(data),encoding="utf-8")
    from shiproom.project import activate
    activate(repo,contract,receipt); status=activation_status(repo,contract,receipt); executor=Mock(return_value=subprocess.CompletedProcess([],0,"ok",""))
    execute_approved_command(repo,status,"unit",executor)
    _,kwargs=executor.call_args; assert kwargs["shell"] is False and kwargs["cwd"]==repo.resolve() and "NO_COLOR" in kwargs["env"] and "HOME" not in kwargs["env"]


def test_changed_command_source_hash_invalidates_grant(repo: Path):
    command=approved(repo); (repo/"pyproject.toml").write_text("changed",encoding="utf-8")
    with pytest.raises(ValueError,match="stale"): validate_command(command,repo)


def test_changed_command_source_marks_activation_stale(repo: Path):
    init_project(repo,"verify"); contract,receipt=paths(repo); data=json.loads(contract.read_text()); data["execution_policy"]["approved_commands"]=[approved(repo)]; contract.write_text(json.dumps(data),encoding="utf-8")
    from shiproom.project import activate
    activate(repo,contract,receipt); (repo/"pyproject.toml").write_text("changed",encoding="utf-8")
    status=activation_status(repo,contract,receipt)
    assert not status["activation_fresh"] and status["effective_profile"]=="inspect" and status["invalid_command_grants"]==["unit"]


@pytest.mark.parametrize("argv",[["pytest && whoami"],["$HOME"],["@args.txt"],["echo\nwhoami"]])
def test_shell_syntax_and_expansion_are_rejected(repo: Path, argv):
    command=approved(repo); command["argv"]=argv
    with pytest.raises(ValueError): validate_command(command,repo)


def test_unapproved_environment_is_rejected(repo: Path):
    command=approved(repo); command["allowed_environment"]={"AWS_SECRET_ACCESS_KEY":"x"}
    with pytest.raises(ValueError): validate_command(command,repo)


def test_excluded_and_protected_paths_are_distinct(repo: Path):
    (repo/"README.md").write_text("public",encoding="utf-8"); (repo/".env").write_text("secret",encoding="utf-8")
    assert resolve_policy_path(repo,"README.md",["README.md"],[],operation="read").name=="README.md"
    with pytest.raises(PermissionError,match="protected"): resolve_policy_path(repo,"README.md",["README.md"],[],operation="write")
    with pytest.raises(PermissionError,match="excluded"): resolve_policy_path(repo,".env",[],[],operation="read")


@pytest.mark.parametrize("value",["../outside","C:\\Windows\\secret","//server/share","..\\outside"])
def test_path_traversal_and_windows_escapes_are_rejected(repo: Path,value: str):
    with pytest.raises((ValueError,PermissionError)): resolve_policy_path(repo,value,[],[],operation="read")


def test_symlink_escape_is_rejected(repo: Path,tmp_path: Path):
    link=repo/"escape"
    try: link.symlink_to(tmp_path,target_is_directory=True)
    except OSError: pytest.skip("symlinks unavailable")
    with pytest.raises(PermissionError): resolve_policy_path(repo,"escape/file.txt",[],[],operation="read")


def test_remote_credentials_rejected_and_absent_remote_allowed(repo: Path):
    assert local_locator(repo)["remote_url"] is None
    git(repo,"remote","add","origin","https://user:pass@example.com/private.git")
    with pytest.raises(ValueError,match="credential-free"): local_locator(repo)


def test_deployment_locator_types():
    assert deployment_target()["kind"]=="none"
    assert deployment_target("localhost","http://localhost:8000")["kind"]=="localhost"
    assert deployment_target("preview","https://preview.example.com")["kind"]=="preview"
    with pytest.raises(ValueError): deployment_target("public","http://localhost:8000")


def test_doctor_default_has_zero_network_calls(repo: Path):
    init_project(repo)
    with patch("urllib.request.urlopen") as urlopen:
        result=discover(repo,probe=False)
    urlopen.assert_not_called(); assert result["network_probes"]==[] and result["contract"]["effective_profile"]=="inspect"


def test_remediation_uses_isolated_worktree_even_when_active_tree_dirty(repo: Path):
    init_project(repo,"remediate"); contract,receipt=paths(repo); from shiproom.project import activate; activate(repo,contract,receipt); status=activation_status(repo,contract,receipt)
    (repo/"app.py").write_text("dirty\n",encoding="utf-8"); result=prepare_isolated_worktree(repo,status,"task1"); worktree=Path(result["worktree"])
    assert worktree!=repo and result["base_commit"]==git(repo,"rev-parse","HEAD") and (repo/"app.py").read_text()=="dirty\n"
    target=authorize_isolated_write(repo,worktree,status,"app.py"); assert target.parent==worktree


def test_remediation_denial_never_calls_worktree_executor(repo: Path):
    init_project(repo,"inspect"); status=activation_status(repo,*paths(repo)); executor=Mock()
    with pytest.raises(PermissionError): prepare_isolated_worktree(repo,status,"task2",executor=executor)
    executor.assert_not_called()


def test_risk_requires_named_decision_and_does_not_touch_findings():
    contract=default_contract("P","Purpose",["users"]); contract["accepted_risks"]=[{"risk_id":"r1"}]
    with pytest.raises(ValueError,match="named decision"): validate_contract(contract)


def test_shared_contract_rejects_credentials_and_absolute_policy_paths():
    contract=default_contract("P","Purpose",["users"]); contract["project_principles"]=["token sk-abcdefghijklmnopqrstuvwxyz123456"]
    with pytest.raises(ValueError,match="credential-like"): validate_contract(contract)
    contract=default_contract("P","Purpose",["users"]); contract["protected_paths"]=["C:\\private\\config"]
    with pytest.raises(ValueError,match="repository-relative"): validate_contract(contract)
