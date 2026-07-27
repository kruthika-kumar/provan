#!/usr/bin/env python3
"""Non-privileged behavioral tests for SQLite authority and contracts."""
from __future__ import annotations

import sqlite3
import os
import socket
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
import doctor
from package_contract import PackageContractError, validate as validate_package_contract
from bootstrap import FILES as BOOTSTRAP_FILES, source_manifest, validate_attestation
import release_helper
try:
    import release
except ModuleNotFoundError as exc:
    if exc.name != "fcntl":
        raise
    # The command-shim suite runs this module on Linux.  Retain its static and
    # SQLite checks on Windows, where Python deliberately lacks fcntl.
    release = None
import xfs_project

setup_source=(Path(__file__).parent/"setup.sh").read_text(encoding="utf-8")
assert "state_put PHASE POLICY_GUARD_REMOVED; control_phase POLICY_GUARD_REMOVED; journal POLICY_GUARD removed" in setup_source
lib_source=(Path(__file__).parent/"lib.sh").read_text(encoding="utf-8")
root_residual_source=lib_source.split("root_residual_absence_proven(){",1)[1].split("safe_remove_owned_root(){",1)[0]
assert "findmnt -rn -o TARGET" in root_residual_source
assert "findmnt -R -n -o TARGET --target" not in root_residual_source
assert 'xfs_quota -x -c "quota -p -nNv -b -i $p" "$MOUNT"' in lib_source
assert "quota -p -nN $p" not in lib_source
assert "xfs_quota -x -d \"$p\"" not in lib_source
assert '$1==source && $NF==mount && NF==12' in lib_source
assert 'quota_limit_kib(){' in lib_source
assert 'printf \'%sk\'' in lib_source
setup_quota_source=(Path(__file__).parent/"setup.sh").read_text(encoding="utf-8")
worktree_quota_source=(Path(__file__).parent/"quota-worktree.sh").read_text(encoding="utf-8")
start_source=(Path(__file__).parent/"start.sh").read_text(encoding="utf-8")
teardown_source=(Path(__file__).parent/"teardown.sh").read_text(encoding="utf-8")
assert 'data_limit=$(quota_limit_kib 8589934592)' in setup_quota_source
assert 'bhard=${data_limit}' in setup_quota_source
assert 'limit=$(quota_limit_kib "$bytes")' in worktree_quota_source
assert 'bhard=${limit}' in worktree_quota_source
assert 'bhard=${bytes}b' not in worktree_quota_source
# Allocation stdout is parsed as exactly one canonical worktree path by the
# privileged doctor; noisy xfs_quota diagnostics must not share that channel.
assert 'project -s -p $tree $project" "$MOUNT" >&2' in worktree_quota_source
assert 'bhard=${limit} ihard=$inodes $project" "$MOUNT" >&2' in worktree_quota_source
assert 'bounded-log.py" --input "$LOG_FIFO" --output "$LOG" --maximum 1048576 9>&-' in start_source
assert '"$SETSID" "$DOCKERD" --config-file "$DAEMON_JSON" --pidfile "$PID" 9>&-' in start_source
assert '"$SETSID" "$TAIL" -f /dev/null 9>&- >"$LOG_FIFO"' in start_source
assert '"$SETSID" "$PYTHON" "$DIR/bounded-log.py"' in start_source
assert 'log_pipeline_verified || die logger_identity' in start_source
assert 'stop_log_pipeline || die' in teardown_source
assert "unverified logger pipeline" in teardown_source
assert 'stop_or_absent_logger(){' in lib_source
assert 'log_pipeline_verified(){ logger_probe && log_keeper_probe; }' in lib_source
assert 'stop_log_pipeline(){ stop_or_absent_log_keeper && stop_or_absent_logger; }' in lib_source
assert '! -e "/proc/$lp/stat"' in lib_source
assert 'if [[ "$target" == "$RUN" ]]; then' in lib_source
assert 'allow_runtime_sockets' in Path(__file__).with_name("release_helper.py").read_text(encoding="utf-8")
release_source=(Path(__file__).parent/"release.py").read_text(encoding="utf-8")
assert 'f"quota -p -nNv -b -i {project}"' in release_source
assert '"-d", str(project)' not in release_source
assert '"-n", "-o", "SOURCE", "--target", str(mount)' in release_source
assert 'line.split()[0] == sources[0]' in release_source
assert 'matching[0][3] != "0" or matching[0][8] != "0"' in release_source
doctor_source=(Path(__file__).parent/"doctor.py").read_text(encoding="utf-8")
assert 'parser.add_argument("--run-remediation-fixture", action="store_true")' in doctor_source
assert 'real_git_remediation_fixture' in doctor_source
assert 'prepare_fixture_source' in doctor_source and 'materialize_fixture' in doctor_source
assert 'seal_and_finalize' in doctor_source and 'validate_release_authorization' in doctor_source
assert '"0" * 64' not in doctor_source and '"a" * 64' not in doctor_source
assert 'tree != Path(str(authority["canonical_path"])) or not tree.is_dir()' in doctor_source
assert '_STAGED_MODULE_DIRECTORY' in doctor_source
# The privileged doctor is deliberately launched with ``-I -S``.  Its help
# path must still import every co-staged module without a site package or a
# caller-controlled PYTHONPATH; otherwise the real doctor fails before any
# safety check runs.
isolated_doctor = subprocess.run(
    [sys.executable, "-I", "-S", str(Path(__file__).parent / "doctor.py"), "--help"],
    text=True, capture_output=True, check=False,
)
assert isolated_doctor.returncode == 0 and "--run-remediation-fixture" in isolated_doctor.stdout

H = "sha256:" + "a" * 64

def capacity_record(instance: str, *, total: int = 16_000_000_000, available: int = 16_000_000_000, aggregate: int = 6_000_000_000, predecessor: str | None = None, qualified_at: str = "2026-07-27T00:00:00Z") -> dict[str, object]:
    evidence = {
        "backend_instance_id": instance, "nominal_image_bytes": 17_179_869_184,
        "filesystem_total_data_bytes": total, "filesystem_available_bytes": available,
        "metadata_reserve_bytes": 1_000_000_000, "supervisor_reserve_bytes": 1_000_000_000,
        "docker_bytes": 8_000_000_000, "qualified_worktree_aggregate_limit": aggregate,
        "inode_policy_cap": 10_000, "max_active_projects": 2, "predecessor_capacity_id": predecessor, "qualified_at": qualified_at,
    }
    evidence_hash = digest(evidence)
    return {
        "capacity_id": "capacity_" + evidence_hash.split(":", 1)[1][:32], "backend_instance_id": instance,
        "evidence_hash": evidence_hash, "nominal_image_bytes": evidence["nominal_image_bytes"],
        "filesystem_total_data_bytes": total, "filesystem_available_bytes": available,
        "metadata_reserve_bytes": evidence["metadata_reserve_bytes"], "supervisor_reserve_bytes": evidence["supervisor_reserve_bytes"],
        "docker_bytes": evidence["docker_bytes"], "aggregate_worktree_bytes": aggregate,
        "inode_policy_cap": evidence["inode_policy_cap"], "max_active_projects": evidence["max_active_projects"], "predecessor_capacity_id": predecessor, "qualified_at": qualified_at,
    }

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
isolated_output=Path(package_contract.__file__).resolve().with_name("package-contract-isolated.json")
isolated_capture=subprocess.run([sys.executable,"-I","-S",str(Path(package_contract.__file__).resolve()),"--capture",str(isolated_output)],text=True,capture_output=True,check=False)
assert isolated_capture.returncode==2 and "package_contract_error:package_contract_capture_authority_invalid" in isolated_capture.stderr and not isolated_output.exists()
with mock.patch.object(package_contract.os,"geteuid",return_value=0,create=True), mock.patch.object(package_contract,"require_staged_script",side_effect=RuntimeError("staged_path_invalid")):
    expect_package("staged_path_invalid",lambda: package_contract.capture(Path(package_contract.__file__).resolve().with_name("package-contract-capture.json")))
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
if os.name == "posix":
    with tempfile.TemporaryDirectory() as runtime_raw:
        runtime_root=Path(runtime_raw); runtime_fd=os.open(runtime_root,os.O_RDONLY|release_helper.O_DIRECTORY|release_helper.O_CLOEXEC)
        runtime_socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            runtime_socket.bind(str(runtime_root/"dead.sock")); runtime_stat=os.fstat(runtime_fd); runtime_mount=release_helper.mount_id(runtime_fd)
            expect("release_special_file_rejected",lambda: release_helper.delete_tree(runtime_fd,runtime_stat.st_dev,runtime_mount))
            release_helper.delete_tree(runtime_fd,runtime_stat.st_dev,runtime_mount,allow_runtime_sockets=True)
            assert not (runtime_root/"dead.sock").exists()
        finally:
            runtime_socket.close(); os.close(runtime_fd)
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

if release is not None:
    # Release clearance reuses the verbose quota format and fails closed if
    # either hard limit or the only mounted-filesystem row is unexpected.
    quota_row="/dev/loop7 0 0 0 0 - 0 0 0 0 - /mnt/fixture\n"
    def project_clear_command(argv, **_):
        output="/dev/loop7\n" if Path(argv[0]).name=="findmnt" else quota_row
        return SimpleNamespace(returncode=0,stdout=output,stderr="")
    with mock.patch.object(release,"trusted_binary",side_effect=lambda name: "/usr/bin/findmnt" if name=="findmnt" else "/usr/sbin/xfs_quota"), mock.patch.object(release,"run"), mock.patch.object(release,"require_cleared"), mock.patch.object(release.subprocess,"run",side_effect=project_clear_command):
        release.project_clear(Path("/mnt/fixture"),Path("/mnt/fixture/worktree"),20000)
    # XFS 6.6 omits a cleared, zero-usage project from an otherwise-successful
    # numeric report.  The root remains kernel-verified as unassigned, so an
    # empty report is the documented zero-limit representation.
    def empty_project_clear_command(argv, **_):
        output="/dev/loop7\n" if Path(argv[0]).name=="findmnt" else ""
        return SimpleNamespace(returncode=0,stdout=output,stderr="")
    with mock.patch.object(release,"trusted_binary",side_effect=lambda name: "/usr/bin/findmnt" if name=="findmnt" else "/usr/sbin/xfs_quota"), mock.patch.object(release,"run"), mock.patch.object(release,"require_cleared"), mock.patch.object(release.subprocess,"run",side_effect=empty_project_clear_command):
        release.project_clear(Path("/mnt/fixture"),Path("/mnt/fixture/worktree"),20000)
    for invalid_quota_row in ("/dev/wrong 0 0 0 0 - 0 0 0 0 - /mnt/fixture\n", "/dev/wrong 0 0 0 0 - 0 0 0 0 - /mnt/other\n", "/dev/loop7 0 0 1 0 - 0 0 0 0 - /mnt/fixture\n", "/dev/loop7 0 0 0 0 - 0 0 1 0 - /mnt/fixture\n"):
        def invalid_project_clear_command(argv, **_):
            output="/dev/loop7\n" if Path(argv[0]).name=="findmnt" else invalid_quota_row
            return SimpleNamespace(returncode=0,stdout=output,stderr="")
        with mock.patch.object(release,"trusted_binary",side_effect=lambda name: "/usr/bin/findmnt" if name=="findmnt" else "/usr/sbin/xfs_quota"), mock.patch.object(release,"run"), mock.patch.object(release,"require_cleared"), mock.patch.object(release.subprocess,"run",side_effect=invalid_project_clear_command):
            try:
                release.project_clear(Path("/mnt/fixture"),Path("/mnt/fixture/worktree"),20000)
            except release.ReleaseError as exc:
                assert str(exc)=="project_limit_clear_unverified"
            else:
                raise AssertionError("project_limit_clear_unverified not rejected")
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
    manifest=source_manifest(backend_source)
    stage0 = {"schema_id":"remediation_stage0_attestation.v1","schema_version":"1","commit":"0"*40,"tree":"1"*40,"bundle_files":manifest["files"],"schemas":manifest["schemas"],"production_files":manifest["production_files"],"runner_files":manifest["runner_files"],"shellcheck":{"path":"/usr/bin/shellcheck","hash":H,"version":"fixture"},"commands":stage_commands,"created_at":"2026-07-25T00:00:00Z"}
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
    capacity = capacity_record(instance)
    control.install_capacity(capacity)
    capacity_id = str(capacity["capacity_id"])
    forged = dict(capacity); forged["filesystem_available_bytes"] = 99_000_000_000
    expect("capacity_evidence_invalid", lambda: control.install_capacity(forged))
    wrong_id = dict(capacity); wrong_id["capacity_id"] = "capacity_" + "0" * 32
    expect("capacity_evidence_invalid", lambda: control.install_capacity(wrong_id))
    expect("setup_phase_transition_invalid", lambda: control.phase("DAEMON_STARTED"))
    control.phase("ROOTS_CREATED"); control.phase("STATE_INITIALIZED"); control.phase("POLICY_GUARD_CREATED")
    first = control.reserve("attempt-a", 4_000_000_000, 4_000, H, capacity_id, 9_000_000_000)
    second = control.reserve("attempt-b", 2_000_000_000, 4_000, H, capacity_id, 9_000_000_000)
    assert (first, second) == (20000, 20001)
    expect("capacity_project_count_exceeded", lambda: control.reserve("attempt-c", 1, 1, H, capacity_id, 9_000_000_000))
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
    expect("backend_execution_blocked:RELEASING", lambda: control.reserve("attempt-c", 1, 1, H, capacity_id, 9_000_000_000))
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
    third = control.reserve("attempt-c", 4_000_000_000, 4_000, H, capacity_id, 9_000_000_000)
    assert third == 20002
    incident = control.incident("test", "QUOTA_STATE_UNCERTAIN", {"reason": "fixture"})
    expect("backend_execution_blocked:QUOTA_STATE_UNCERTAIN", control.assert_ready)
    control.resolve_incident(incident, {"proof": H})
    control.assert_ready()
    bad = authorization(instance, "attempt-b", second)
    bad["worktree_authority"]["attempt_id"] = "other"  # type: ignore[index]
    expect("worktree_binding_mismatch", lambda: validate_release_authorization(bad))
    control.close()

# The opt-in privileged doctor must never use an allocation helper's stdout as
# path authority.  These fixtures run without root or a mounted XFS backend.
with tempfile.TemporaryDirectory() as raw:
    root=Path(raw); tree=root/"worktree"; tree.mkdir()
    document={"canonical_path":str(tree)}
    class FixtureControl:
        def __init__(self, _db: Path): pass
        def allocation(self, _attempt: str) -> dict[str, object]: return {"worktree_authority_json":document}
        def close(self) -> None: pass
    result={"stdout":str(tree)+"\n","exit_code":0}
    with mock.patch.object(doctor,"Control",FixtureControl):
        assert doctor.allocated_tree(root/"control.sqlite3","doctor-fixture",result) == tree
        expect("doctor_allocation_output_invalid",lambda: doctor.allocated_tree(root/"control.sqlite3","doctor-fixture",{"stdout":str(tree)+"\nextra\n"}))
        document["canonical_path"]=str(root/"other")
        expect("doctor_allocation_authority_mismatch",lambda: doctor.allocated_tree(root/"control.sqlite3","doctor-fixture",result))
    with mock.patch.object(doctor,"invocation",side_effect=AssertionError("unqualified doctor invoked allocation")):
        blocked=doctor.real_git_remediation_fixture(root/"not-authoritative.sqlite3","example/runner@sha256:"+"a"*64,"b"*40,"sha256:"+"c"*64)
    assert blocked == {"name":"real_git_remediation_fixture","ok":False,"reason":"doctor_paths_not_qualified"}

print("control and contract behavioral tests passed")
