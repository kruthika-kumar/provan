#!/usr/bin/env python3
"""Non-privileged behavioral tests for SQLite authority and contracts."""
from __future__ import annotations

import tempfile
from pathlib import Path
import json
from unittest import mock

from control import Control, ControlError, canonical, digest
from contracts import ContractError, validate_release_authorization
import package_contract
import bootstrap
from package_contract import PackageContractError, validate as validate_package_contract
from bootstrap import FILES as BOOTSTRAP_FILES, source_manifest, validate_attestation
import release_helper

H = "sha256:" + "a" * 64

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
    except (ControlError, ContractError, RuntimeError) as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError(code + " not rejected")


def expect_package(code: str, fn) -> None:
    try: fn()
    except PackageContractError as exc: assert str(exc) == code, (str(exc), code)
    else: raise AssertionError(code + " not rejected")


validate_package_contract(PACKAGE)
bad_package = dict(PACKAGE); bad_package["packages"] = list(PACKAGE["packages"][:-1])
expect_package("package_contract_packages_invalid", lambda: validate_package_contract(bad_package))
with tempfile.TemporaryDirectory() as package_raw:
    source_artifact=Path(package_raw)/"sources.bin"; simulation_artifact=Path(package_raw)/"simulation.txt"
    source_artifact.write_bytes(b"sources"); simulation_artifact.write_bytes(b"simulation")
    package_live=dict(PACKAGE); package_live["apt_sources_artifact"]=str(source_artifact); package_live["simulation_artifact"]=str(simulation_artifact)
    package_live["apt_sources_hash"]="sha256:"+__import__("hashlib").sha256(b"sources").hexdigest(); package_live["simulation_hash"]="sha256:"+__import__("hashlib").sha256(b"simulation").hexdigest()
    contract_path=Path(package_raw)/"contract.json"; contract_path.write_text(json.dumps(package_live),encoding="utf-8")
    def fake_run(argv, **_):
        text="simulation" if "apt-get" in argv[0] else f"Candidate: 1.0\nfixture"
        return type("Result",(),{"returncode":0,"stdout":text,"stderr":""})()
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract.subprocess,"run",side_effect=fake_run): package_contract.verify_live(contract_path)
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=H): expect_package("package_contract_sources_drift",lambda: package_contract.verify_live(contract_path))
    def changed_simulation(argv, **_):
        text="changed" if "apt-get" in argv[0] else "Candidate: 1.0\nfixture"
        return type("Result",(),{"returncode":0,"stdout":text,"stderr":""})()
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract.subprocess,"run",side_effect=changed_simulation): expect_package("package_contract_simulation_drift",lambda: package_contract.verify_live(contract_path))
    def bad_candidate(argv, **_):
        text="simulation" if "apt-get" in argv[0] else "Candidate: wrong\nfixture"
        return type("Result",(),{"returncode":0,"stdout":text,"stderr":""})()
    with mock.patch.object(package_contract,"immutable_root_file"), mock.patch.object(package_contract,"current_sources_hash",return_value=package_live["apt_sources_hash"]), mock.patch.object(package_contract.subprocess,"run",side_effect=bad_candidate): expect_package("package_contract_candidate_drift",lambda: package_contract.verify_live(contract_path))
    with mock.patch.object(package_contract,"immutable_root_file",side_effect=PackageContractError("package_contract_artifact_untrusted")): expect_package("package_contract_artifact_untrusted",lambda: package_contract.verify_live(contract_path))
with mock.patch.object(release_helper.os,"geteuid",return_value=0,create=True), mock.patch.object(release_helper,"require_staged_script",side_effect=RuntimeError("staged_path_invalid")):
    args=type("Args",(),{"root":Path("/tmp/fixture"),"expected_device":1,"expected_inode":1,"expected_mount_id":1,"operation":"verify-empty"})()
    expect("staged_path_invalid",lambda: release_helper.action(args))
try:
    import jsonschema
except ImportError:
    jsonschema = None
if jsonschema is not None:
    schema_root = Path(__file__).parent.parent / "schemas"
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
