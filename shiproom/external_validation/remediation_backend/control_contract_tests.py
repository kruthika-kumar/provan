#!/usr/bin/env python3
"""Non-privileged behavioral tests for SQLite authority and contracts."""
from __future__ import annotations

import tempfile
import subprocess
import sys
from pathlib import Path
import json
from types import SimpleNamespace
from unittest import mock

from control import Control, ControlError, canonical, digest
from contracts import ContractError, validate_release_authorization
import package_contract
import bootstrap
import gate
from package_contract import PackageContractError, validate as validate_package_contract
from bootstrap import FILES as BOOTSTRAP_FILES, source_manifest, validate_attestation
import release_helper
import xfs_project

H = "sha256:" + "a" * 64

# Root provenance checks must never inherit a caller's Git redirection state.
reviewed_repository=Path("/reviewed/repository")
with mock.patch.dict(__import__("os").environ, {"GIT_DIR":"/attacker/git", "GIT_WORK_TREE":"/attacker/tree", "GIT_INDEX_FILE":"/attacker/index", "GIT_CONFIG_GLOBAL":"/attacker/config"}, clear=False):
    closed_git_environment=bootstrap.git_environment(reviewed_repository)
assert closed_git_environment["GIT_CONFIG_VALUE_1"]==str(reviewed_repository)
assert not any(key in closed_git_environment for key in ("GIT_DIR","GIT_WORK_TREE","GIT_INDEX_FILE"))
assert closed_git_environment["GIT_CONFIG_GLOBAL"]=="/dev/null"
assert closed_git_environment["GIT_CONFIG_NOSYSTEM"]=="1"
with mock.patch.dict(__import__("os").environ, {"GIT_DIR":"/attacker/git", "GIT_WORK_TREE":"/attacker/tree", "GIT_INDEX_FILE":"/attacker/index"}, clear=False):
    gate_git_environment=gate.git_environment(reviewed_repository)
assert not any(key in gate_git_environment for key in ("GIT_DIR","GIT_WORK_TREE","GIT_INDEX_FILE"))
assert gate_git_environment["GIT_CONFIG_VALUE_1"]==str(reviewed_repository)
try: gate.canonical_bundle(Path("/attacker/remediation_backend"))
except SystemExit as exc: assert str(exc)=="gate_bundle_not_approved"
else: raise AssertionError("unapproved Stage-0 bundle accepted")

PACKAGE = {"schema_id": "remediation_package_contract.v1", "schema_version": "1", "distribution_id": "ubuntu", "release": "noble", "apt_sources_hash": H, "apt_sources_artifact": "/stage/sources.bin", "simulation_hash": H, "simulation_artifact": "/stage/simulation.txt", "packages": [{"name": "docker.io", "version": "1.0", "source": "fixture"}, {"name": "xfsprogs", "version": "1.0", "source": "fixture"}, {"name": "quota", "version": "1.0", "source": "fixture"}], "created_at": "2026-07-25T00:00:00Z"}


def authority(instance: str, attempt: str, project: int) -> dict[str, object]:
    return {
        "backend_instance_id": instance, "attempt_id": attempt, "project_id": project,
        "allocation_record_id": attempt, "capacity_reservation_id": str(project),
        "canonical_path": f"/mnt/shiproom-remediation/worktrees/{attempt}", "path_hash": H,
        "device": 1, "inode": 2, "mount_id": 3, "uid": 65533, "gid": 65533,
        "source_snapshot_hash": H,
    }


def authorization(instance: str, attempt: str, project: int) -> dict[str, object]:
    return {
        "schema_id": "remediation_release_authorization.v1", "schema_version": "1",
        "authorization_id": "authorization_" + ("b" if attempt == "attempt-a" else "c") * 32,
        "backend_instance_id": instance, "attempt_id": attempt, "project_id": project,
        "allocation_record_id": attempt, "capacity_reservation_id": str(project),
        "worktree_authority": authority(instance, attempt, project), "source_snapshot_hash": H,
        "sealed_artifact_manifest_hash": H, "receipt_id": "receipt_1", "patch_hash": H,
        "changed_file_manifest_hash": H, "untracked_file_manifest_hash": H,
        "test_result_hashes": [H], "log_hashes": [H],
        "artifact_records": [{"kind": "sealed_manifest", "canonical_path": "/supervisor/sealed/a.json", "sha256": H}],
        "supervisor_package_hash": H,
        "created_at": "2026-07-25T00:00:00Z",
    }


def expect(code: str, fn) -> None:
    try:
        fn()
    except (ControlError, ContractError, xfs_project.ProjectAttributeError, RuntimeError) as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError(code + " not rejected")


def expect_package(code: str, fn) -> None:
    try: fn()
    except PackageContractError as exc: assert str(exc) == code, (str(exc), code)
    else: raise AssertionError(code + " not rejected")


untrusted_directory=SimpleNamespace(st_mode=__import__("stat").S_IFLNK,st_uid=0,st_gid=0,st_dev=1,st_ino=2)
with mock.patch.object(bootstrap.os,"mkdir",side_effect=FileExistsError), mock.patch.object(Path,"lstat",return_value=untrusted_directory):
    expect("bootstrap_directory_untrusted",lambda: bootstrap.secure_root_directory(Path("/run/shiproom-remediation-bootstrap")))
trusted_directory=SimpleNamespace(st_mode=__import__("stat").S_IFDIR|0o700,st_uid=0,st_gid=0,st_dev=1,st_ino=2)
different_directory=SimpleNamespace(st_dev=1,st_ino=3)
with mock.patch.object(bootstrap.os,"O_DIRECTORY",0,create=True), mock.patch.object(bootstrap.os,"O_NOFOLLOW",0,create=True), mock.patch.object(bootstrap.os,"mkdir",side_effect=FileExistsError), mock.patch.object(Path,"lstat",return_value=trusted_directory), mock.patch.object(bootstrap.os,"open",return_value=9), mock.patch.object(bootstrap.os,"fstat",return_value=different_directory), mock.patch.object(bootstrap.os,"close"):
    expect("bootstrap_directory_raced",lambda: bootstrap.secure_root_directory(Path("/run/shiproom-remediation-bootstrap")))
approval_hash="sha256:"+"b"*64
class ApprovalHandle:
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def fileno(self): return 11
    def write(self,_): return 1
    def flush(self): pass
fsynced=[]
with mock.patch.object(bootstrap.os,"O_DIRECTORY",0,create=True), mock.patch.object(bootstrap.os,"O_NOFOLLOW",0,create=True), mock.patch.object(bootstrap,"source_root"), mock.patch.object(bootstrap,"validate_attestation",return_value={"attestation_hash":approval_hash}), mock.patch.object(bootstrap,"secure_root_directory"), mock.patch.object(bootstrap,"approval_path",return_value=Path("/run/shiproom-remediation-bootstrap/approvals/"+"b"*64)), mock.patch.object(bootstrap.os,"open",side_effect=[10,11]), mock.patch.object(bootstrap.os,"fdopen",return_value=ApprovalHandle()), mock.patch.object(bootstrap.os,"fchown",create=True), mock.patch.object(bootstrap.os,"fchmod",create=True), mock.patch.object(bootstrap.os,"fsync",side_effect=fsynced.append), mock.patch.object(bootstrap.os,"close"):
    bootstrap.approve(Path("/source"),Path("/attestation"),"0"*40,"1"*40)
assert fsynced==[11,10]
gate_runs=[]
def gate_run(command, **kwargs):
    gate_runs.append((command,kwargs)); return SimpleNamespace(returncode=0,stdout="",stderr="")
with mock.patch.object(bootstrap,"trusted_host_executable"), mock.patch.object(bootstrap.subprocess,"run",side_effect=gate_run):
    bootstrap.rerun_privileged_gate(Path("/sealed/bundle"),Path("/approved/repository"))
git_run=next(item for item in gate_runs if item[0][1:]==["diff","--check"])
assert git_run[1]["cwd"]==Path("/approved/repository") and git_run[1]["env"]==bootstrap.git_environment(Path("/approved/repository"))
assert all(item[1]["cwd"]==Path("/sealed/bundle") for item in gate_runs if item is not git_run)


validate_package_contract(PACKAGE)
bad_package = dict(PACKAGE); bad_package["packages"] = list(PACKAGE["packages"][:-1])
expect_package("package_contract_packages_invalid", lambda: validate_package_contract(bad_package))
policy_fixture="""docker.io:
  Installed: (none)
  Candidate: 29.1.3-0ubuntu3~24.04.2
  Version table:
     29.1.3-0ubuntu3~24.04.2 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages
"""
with mock.patch.object(package_contract.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=policy_fixture,stderr="")):
    assert package_contract.policy_candidate("docker.io")==("29.1.3-0ubuntu3~24.04.2","http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages")
candidate_without_origin="""docker.io:
  Installed: 2.0
  Candidate: 2.0
  Version table:
 *** 2.0 100
        100 /var/lib/dpkg/status
     1.0 500
        500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
"""
with mock.patch.object(package_contract.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=candidate_without_origin,stderr="")):
    expect_package("package_contract_candidate_source_missing",lambda: package_contract.policy_candidate("docker.io"))
with mock.patch.object(package_contract.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="Candidate: (none)\n",stderr="")):
    expect_package("package_contract_candidate_missing",lambda: package_contract.policy_candidate("docker.io"))
symlink_stat=SimpleNamespace(st_mode=__import__("stat").S_IFLNK,st_uid=0,st_gid=0)
with mock.patch.object(Path,"lstat",return_value=symlink_stat):
    try: package_contract.staged_regular(Path("/run/shiproom-remediation-bootstrap/" + "a" * 64 + "/bootstrap.py"))
    except RuntimeError as exc: assert str(exc)=="staged_file_untrusted"
    else: raise AssertionError("staged bootstrap symlink accepted")
with mock.patch.object(Path,"lstat",return_value=symlink_stat):
    try: package_contract.staged_directory(Path("/run/shiproom-remediation-bootstrap")/("a"*64)/"schemas",0o755)
    except RuntimeError as exc: assert str(exc)=="staged_directory_untrusted"
    else: raise AssertionError("staged schemas directory symlink accepted")
isolated_capture=subprocess.run([sys.executable,"-I","-S",str(Path(package_contract.__file__).resolve()),"--capture",str(Path(tempfile.gettempdir())/"package-contract-isolated.json")],text=True,capture_output=True,check=False)
assert isolated_capture.returncode==2 and "package_contract_error:staged_path_invalid" in isolated_capture.stderr
with mock.patch.object(package_contract,"require_staged_script",side_effect=RuntimeError("staged_path_invalid")):
    expect_package("staged_path_invalid",lambda: package_contract.capture(Path("/run/shiproom-remediation-bootstrap/" + "a" * 64 + "/package-contract.json")))
partial_writes=[]
def partial_write(_fd, data):
    raw=bytes(data); partial_writes.append(raw)
    return 1 if len(partial_writes)==1 else len(raw)
with mock.patch.object(package_contract.os,"O_NOFOLLOW",0,create=True), mock.patch.object(package_contract.os,"O_DIRECTORY",0,create=True), mock.patch.object(package_contract.os,"open",side_effect=[31,32]), mock.patch.object(package_contract.os,"close"), mock.patch.object(package_contract.os,"fchown",create=True), mock.patch.object(package_contract.os,"fchmod",create=True), mock.patch.object(package_contract.os,"fsync"), mock.patch.object(package_contract.os,"write",side_effect=partial_write):
    package_contract.write_immutable(Path("/stage/partial-write"),b"abc")
assert partial_writes==[b"abc",b"bc"]
with tempfile.TemporaryDirectory() as package_raw:
    source_artifact=Path(package_raw)/"sources.bin"; simulation_artifact=Path(package_raw)/"simulation.txt"
    source_artifact.write_bytes(b"sources"); simulation_artifact.write_bytes(b"simulation")
    package_live=dict(PACKAGE); package_live["apt_sources_artifact"]=str(source_artifact); package_live["simulation_artifact"]=str(simulation_artifact)
    package_live["apt_sources_hash"]="sha256:"+__import__("hashlib").sha256(b"sources").hexdigest(); package_live["simulation_hash"]="sha256:"+__import__("hashlib").sha256(b"simulation").hexdigest()
    contract_path=Path(package_raw)/"contract.json"; contract_path.write_text(json.dumps(package_live),encoding="utf-8")
    def fake_run(argv, **_):
        text="simulation" if "apt-get" in argv[0] else f"Candidate: 1.0\nfixture"
        return type("Result",(),{"returncode":0,"stdout":text,"stderr":""})()
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract,"policy_candidate",return_value=("1.0","fixture")), mock.patch.object(package_contract.subprocess,"run",side_effect=fake_run): package_contract.verify_live(contract_path)
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=H): expect_package("package_contract_sources_drift",lambda: package_contract.verify_live(contract_path))
    def changed_simulation(argv, **_):
        text="changed" if "apt-get" in argv[0] else "Candidate: 1.0\nfixture"
        return type("Result",(),{"returncode":0,"stdout":text,"stderr":""})()
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract,"policy_candidate",return_value=("1.0","fixture")), mock.patch.object(package_contract.subprocess,"run",side_effect=changed_simulation): expect_package("package_contract_simulation_drift",lambda: package_contract.verify_live(contract_path))
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract,"policy_candidate",return_value=("1.0","wrong-source")), mock.patch.object(package_contract.subprocess,"run",side_effect=fake_run): expect_package("package_contract_candidate_drift",lambda: package_contract.verify_live(contract_path))
    with mock.patch.object(package_contract,"immutable_root_file",side_effect=PackageContractError("package_contract_artifact_untrusted")): expect_package("package_contract_artifact_untrusted",lambda: package_contract.verify_live(contract_path))
with mock.patch.object(release_helper.os,"geteuid",return_value=0,create=True), mock.patch.object(release_helper,"require_staged_script",side_effect=RuntimeError("staged_path_invalid")):
    args=type("Args",(),{"root":Path("/tmp/fixture"),"expected_device":1,"expected_inode":1,"expected_mount_id":1,"operation":"verify-empty"})()
    expect("staged_path_invalid",lambda: release_helper.action(args))
with tempfile.TemporaryDirectory() as xfs_raw:
    def cleared_ioctl(_fd, _request, buffer, _mutate=True):
        buffer[:] = __import__("struct").pack(xfs_project.FSXATTR_FORMAT, 0, 0, 0, 0, 0, b"\0" * 8)
        return 0
    with mock.patch.object(xfs_project,"fcntl",SimpleNamespace(ioctl=cleared_ioctl)), mock.patch.object(xfs_project.os,"open",return_value=3), mock.patch.object(xfs_project.os,"close"):
        xfs_project.require_cleared(Path(xfs_raw))
    def assigned_ioctl(_fd, _request, buffer, _mutate=True):
        buffer[:] = __import__("struct").pack(xfs_project.FSXATTR_FORMAT, xfs_project.FS_XFLAG_PROJINHERIT, 0, 0, 20000, 0, b"\0" * 8)
        return 0
    with mock.patch.object(xfs_project,"fcntl",SimpleNamespace(ioctl=assigned_ioctl)), mock.patch.object(xfs_project.os,"open",return_value=3), mock.patch.object(xfs_project.os,"close"):
        expect("project_assignment_clear_unverified",lambda: xfs_project.require_cleared(Path(xfs_raw)))
try:
    import jsonschema
except ImportError:
    jsonschema = None
if jsonschema is not None:
    # The reviewed source keeps schemas beside remediation_backend; a sealed
    # staging bundle keeps them inside its immutable root.  Both are explicit
    # package layouts, and no caller-supplied schema path is accepted.
    staged_schema_root = Path(__file__).parent / "schemas"
    schema_root = staged_schema_root if staged_schema_root.is_dir() else Path(__file__).parent.parent / "schemas"
    release_schema = json.loads((schema_root / "remediation-release-authorization.v1.json").read_text(encoding="utf-8"))
    package_schema = json.loads((schema_root / "remediation-package-contract.v1.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(release_schema); jsonschema.Draft202012Validator.check_schema(package_schema)
    jsonschema.Draft202012Validator(package_schema).validate(PACKAGE)


with tempfile.TemporaryDirectory() as raw:
    backend_source = Path(__file__).parent
    shell_scripts=[name for name in BOOTSTRAP_FILES if name.endswith(".sh")]
    stage_commands=[
        {"command":["/usr/bin/bash","-n",*shell_scripts],"exit_code":0},
        {"command":["/usr/bin/bash","tests.sh"],"exit_code":0},
        {"command":["/usr/bin/git","diff","--check"],"exit_code":0},
        {"command":["/usr/bin/shellcheck","--version"],"exit_code":0},
        {"command":["/usr/bin/shellcheck","-S","warning",*shell_scripts],"exit_code":0},
    ]
    stage0 = {"schema_id":"remediation_stage0_attestation.v1","schema_version":"1","commit":"0"*40,"tree":"1"*40,"bundle_files":source_manifest(backend_source)["files"],"schemas":source_manifest(backend_source)["schemas"],"shellcheck":{"path":"/usr/bin/shellcheck","hash":H,"version":"fixture"},"commands":stage_commands,"created_at":"2026-07-25T00:00:00Z"}
    stage0["attestation_hash"] = digest(stage0)
    stage0_path=Path(raw)/"stage0.json"; stage0_path.write_text(json.dumps(stage0),encoding="utf-8")
    real_bootstrap_sha=bootstrap.sha
    def fixture_sha(path:Path)->str: return H if path==Path("/usr/bin/shellcheck") else real_bootstrap_sha(path)
    with mock.patch.object(bootstrap,"trusted_host_executable"), mock.patch.object(bootstrap,"sha",side_effect=fixture_sha):
        assert validate_attestation(stage0_path,backend_source,"0"*40,"1"*40)["attestation_hash"] == stage0["attestation_hash"]
    tampered=dict(stage0); tampered["tree"]="2"*40; (Path(raw)/"bad-stage0.json").write_text(json.dumps(tampered),encoding="utf-8")
    with mock.patch.object(bootstrap,"trusted_host_executable"), mock.patch.object(bootstrap,"sha",side_effect=fixture_sha):
        expect("attestation_hash_invalid", lambda: validate_attestation(Path(raw)/"bad-stage0.json",backend_source,"0"*40,"2"*40))
    malformed=dict(stage0); malformed["commands"]=[dict(row) for row in stage_commands]; malformed["commands"][2]["command"]=["git","status","--porcelain"]; malformed["attestation_hash"]=digest({key:value for key,value in malformed.items() if key!="attestation_hash"}); (Path(raw)/"malformed-stage0.json").write_text(json.dumps(malformed),encoding="utf-8")
    with mock.patch.object(bootstrap,"trusted_host_executable"), mock.patch.object(bootstrap,"sha",side_effect=fixture_sha):
        expect("attestation_commands_invalid", lambda: validate_attestation(Path(raw)/"malformed-stage0.json",backend_source,"0"*40,"1"*40))
    shadowed=dict(stage0); shadowed["shellcheck"]={"path":"/tmp/shellcheck","hash":H,"version":"fixture"}; shadowed["attestation_hash"]=digest({key:value for key,value in shadowed.items() if key!="attestation_hash"}); (Path(raw)/"shadowed-stage0.json").write_text(json.dumps(shadowed),encoding="utf-8")
    with mock.patch.object(bootstrap,"trusted_host_executable"), mock.patch.object(bootstrap,"sha",side_effect=fixture_sha):
        expect("attestation_shellcheck_invalid", lambda: validate_attestation(Path(raw)/"shadowed-stage0.json",backend_source,"0"*40,"1"*40))
    control = Control(Path(raw) / "control.sqlite3")
    instance = control.initialize()
    assert control.initialize() == instance
    capacity = {
        "capacity_id": "capacity-1", "backend_instance_id": instance, "evidence_hash": H,
        "nominal_image_bytes": 17_179_869_184, "filesystem_total_data_bytes": 16_000_000_000,
        "filesystem_available_bytes": 16_000_000_000, "metadata_reserve_bytes": 1_000_000_000,
        "supervisor_reserve_bytes": 1_000_000_000, "docker_bytes": 8_000_000_000,
        "aggregate_worktree_bytes": 6_000_000_000, "inode_policy_cap": 10_000,
        "max_active_projects": 2,
    }
    control.install_capacity(capacity)
    expect("setup_phase_transition_invalid", lambda: control.phase("DAEMON_STARTED"))
    control.phase("ROOTS_CREATED"); control.phase("STATE_INITIALIZED"); control.phase("POLICY_GUARD_CREATED")
    first = control.reserve("attempt-a", 4_000_000_000, 4_000, H, "capacity-1", 9_000_000_000)
    second = control.reserve("attempt-b", 2_000_000_000, 4_000, H, "capacity-1", 9_000_000_000)
    assert (first, second) == (20000, 20001)
    expect("capacity_project_count_exceeded", lambda: control.reserve("attempt-c", 1, 1, H, "capacity-1", 9_000_000_000))
    document = authorization(instance, "attempt-a", first)
    recorded_authority = authority(instance, "attempt-a", first)
    expect("allocation_phase_transition_invalid", lambda: control.allocation_phase("attempt-a", "PROJECT_ASSIGNED", recorded_authority))
    control.allocation_phase("attempt-a", "TREE_CREATED", recorded_authority)
    control.allocation_phase("attempt-a", "PROJECT_ASSIGNED", recorded_authority)
    control.allocation_phase("attempt-a", "LIMIT_ASSIGNED", recorded_authority, {"project_id": first, "byte_limit": 4_000_000_000, "inode_limit": 4_000})
    control.allocation_phase("attempt-a", "REGISTRY_COMMITTED", recorded_authority, {"project_id": first, "byte_limit": 4_000_000_000, "inode_limit": 4_000})
    validate_release_authorization(document)
    if jsonschema is not None: jsonschema.Draft202012Validator(release_schema).validate(document)
    control.authorize_release(document, "/supervisor/authorizations/a.json")
    expect("backend_execution_blocked:RELEASING", lambda: control.reserve("attempt-c", 1, 1, H, "capacity-1", 9_000_000_000))
    stored_second = authority(instance, "attempt-b", second); stored_second["inode"] = 99
    control.allocation_phase("attempt-b", "TREE_CREATED", stored_second)
    control.allocation_phase("attempt-b", "PROJECT_ASSIGNED", stored_second)
    control.allocation_phase("attempt-b", "LIMIT_ASSIGNED", stored_second, {"project_id": second, "byte_limit": 2_000_000_000, "inode_limit": 4_000})
    control.allocation_phase("attempt-b", "REGISTRY_COMMITTED", stored_second, {"project_id": second, "byte_limit": 2_000_000_000, "inode_limit": 4_000})
    expect("authorization_worktree_authority_mismatch", lambda: control.authorize_release(authorization(instance, "attempt-b", second), "/supervisor/authorizations/b.json"))
    expect("release_phase_transition_invalid", lambda: control.release_phase("attempt-a", "PROJECT_CLEARED_VERIFIED"))
    for phase in ("RESIDUAL_ABSENCE_VERIFIED", "WORKTREE_CONTENT_DELETE_STARTED", "WORKTREE_EMPTY_VERIFIED", "PROJECT_CLEAR_STARTED", "PROJECT_CLEARED_VERIFIED", "WORKTREE_ROOT_DELETE_STARTED", "WORKTREE_ABSENT_VERIFIED", "REGISTRY_REMOVAL_PREPARED"):
        control.release_phase("attempt-a", phase)
    control.commit_release("attempt-a")
    # Capacity returns atomically only after the retirement transaction.
    third = control.reserve("attempt-c", 4_000_000_000, 4_000, H, "capacity-1", 9_000_000_000)
    assert third == 20002
    incident = control.incident("test", "QUOTA_STATE_UNCERTAIN", {"reason": "fixture"})
    expect("backend_execution_blocked:QUOTA_STATE_UNCERTAIN", control.assert_ready)
    control.resolve_incident(incident, {"proof": H})
    control.assert_ready()
    bad = authorization(instance, "attempt-b", second)
    bad["worktree_authority"]["attempt_id"] = "other"  # type: ignore[index]
    expect("worktree_binding_mismatch", lambda: validate_release_authorization(bad))
    control.close()

print("control and contract behavioral tests passed")
