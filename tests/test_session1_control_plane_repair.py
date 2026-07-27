"""Regression, migration, and status-authority proof for the final repair."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from shiproom.external_validation.remediation_backend.control import Control, ControlError, canonical, digest
from shiproom.external_validation.remediation_backend.migration import MigrationError, migrate_v2_to_v3
from shiproom.external_validation.status import resolve_status_authority
from shiproom.external_validation.v2 import V2ValidationError


PREDECESSOR = "72e0884a69cbf57c17bc7b620c2c4a1314d3fe01"
H = "sha256:" + "a" * 64


def _predecessor_control(tmp_path: Path):
    source = subprocess.check_output(["git", "show", f"{PREDECESSOR}:shiproom/external_validation/remediation_backend/control.py"], text=True)
    path = tmp_path / "predecessor_control.py"; path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("session1_predecessor_control", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _v2_capacity(module, instance: str, *, aggregate: int, available: int, suffix: str, total: int = 16_000_000_000) -> dict[str, object]:
    evidence = {"backend_instance_id": instance, "nominal_image_bytes": 17_179_869_184, "filesystem_total_data_bytes": total, "filesystem_available_bytes": available, "metadata_reserve_bytes": 1_000_000_000, "supervisor_reserve_bytes": 1_000_000_000, "docker_bytes": 8_000_000_000, "qualified_worktree_aggregate_limit": aggregate, "inode_policy_cap": 100_000, "max_active_projects": 4}
    evidence_hash = module.digest(evidence)
    return {"capacity_id": "capacity_" + evidence_hash.split(":", 1)[1][:32], "backend_instance_id": instance, "evidence_hash": evidence_hash, "nominal_image_bytes": evidence["nominal_image_bytes"], "filesystem_total_data_bytes": total, "filesystem_available_bytes": available, "metadata_reserve_bytes": evidence["metadata_reserve_bytes"], "supervisor_reserve_bytes": evidence["supervisor_reserve_bytes"], "docker_bytes": evidence["docker_bytes"], "aggregate_worktree_bytes": aggregate, "inode_policy_cap": evidence["inode_policy_cap"], "max_active_projects": 4}


def _v3_capacity(instance: str, *, predecessor: str | None, aggregate: int = 6_000_000_000, stamp: str = "2026-07-27T00:00:00Z") -> dict[str, object]:
    evidence = {"backend_instance_id": instance, "nominal_image_bytes": 17_179_869_184, "filesystem_total_data_bytes": 16_000_000_000, "filesystem_available_bytes": 16_000_000_000, "metadata_reserve_bytes": 1_000_000_000, "supervisor_reserve_bytes": 1_000_000_000, "docker_bytes": 8_000_000_000, "qualified_worktree_aggregate_limit": aggregate, "inode_policy_cap": 100_000, "max_active_projects": 4, "predecessor_capacity_id": predecessor, "qualified_at": stamp}
    evidence_hash = digest(evidence)
    return {"capacity_id": "capacity_" + evidence_hash.split(":", 1)[1][:32], "backend_instance_id": instance, "evidence_hash": evidence_hash, "nominal_image_bytes": evidence["nominal_image_bytes"], "filesystem_total_data_bytes": evidence["filesystem_total_data_bytes"], "filesystem_available_bytes": evidence["filesystem_available_bytes"], "metadata_reserve_bytes": evidence["metadata_reserve_bytes"], "supervisor_reserve_bytes": evidence["supervisor_reserve_bytes"], "docker_bytes": evidence["docker_bytes"], "aggregate_worktree_bytes": aggregate, "inode_policy_cap": evidence["inode_policy_cap"], "max_active_projects": evidence["max_active_projects"], "predecessor_capacity_id": predecessor, "qualified_at": stamp}


def test_exact_predecessor_reproduces_multi_incident_ready_defect(tmp_path: Path):
    old = _predecessor_control(tmp_path); control = old.Control(tmp_path / "old.sqlite")
    try:
        control.initialize(); first = control.incident("doctor_attempt_failure", "QUOTA_STATE_UNCERTAIN", {"proof": H}); second = control.incident("containment_failure", "CONTAINMENT_UNPROVEN", {"proof": H})
        control.resolve_incident(first, {"proof": H})
        assert control.db.execute("SELECT execution_state FROM backend").fetchone()[0] == "READY"
        assert control.db.execute("SELECT resolved_by FROM incidents WHERE incident_id=?", (second,)).fetchone()[0] is None
    finally:
        control.close()


def test_exact_predecessor_reproduces_cross_capacity_accounting_defect(tmp_path: Path):
    old = _predecessor_control(tmp_path); control = old.Control(tmp_path / "old.sqlite")
    try:
        instance = control.initialize(); first = _v2_capacity(old, instance, aggregate=6_000_000_000, available=16_000_000_000, suffix="a"); control.install_capacity(first)
        control.reserve("attempt-a", 4_000_000_000, 1_000, H, str(first["capacity_id"]), 16_000_000_000)
        second = _v2_capacity(old, instance, aggregate=6_000_000_000, available=16_000_000_000, total=17_000_000_000, suffix="b"); control.install_capacity(second)
        control.reserve("attempt-b", 4_000_000_000, 1_000, H, str(second["capacity_id"]), 15_000_000_000)
        # The predecessor admits another 2GB on B while A's 4GB stays active.
        control.reserve("attempt-c", 2_000_000_000, 1_000, H, str(second["capacity_id"]), 15_000_000_000)
        assert control.db.execute("SELECT COUNT(*) FROM projects WHERE status='ACTIVE'").fetchone()[0] == 3
        assert control.db.execute("SELECT COUNT(*) FROM capacity WHERE active=0").fetchone()[0] == 1
    finally:
        control.close()


def test_multi_incident_state_is_derived_and_persists(tmp_path: Path):
    control = Control(tmp_path / "control.sqlite"); control.initialize()
    try:
        first = control.incident("allocation_failure", "QUOTA_STATE_UNCERTAIN", {"proof": H}); second = control.incident("containment_failure", "CONTAINMENT_UNPROVEN", {"proof": H})
        assert control.effective_status()["effective_state"] == "BLOCKED_MULTIPLE_INCIDENTS"
        control.resolve_incident(first, {"proof": H})
        assert control.effective_status()["effective_state"] == "CONTAINMENT_UNPROVEN"
        with pytest.raises(ControlError, match="backend_execution_blocked:CONTAINMENT_UNPROVEN"): control.assert_ready()
        control.close(); control = Control(tmp_path / "control.sqlite")
        assert control.effective_status()["unresolved_incident_ids"] == [second]
        control.resolve_incident(second, {"proof": H}); control.assert_ready()
        with pytest.raises(ControlError, match="incident_resolution_invalid"): control.resolve_incident(first, {"proof": H})
    finally:
        control.close()


def test_incident_type_is_immutable_authority_and_unknown_types_fail_closed(tmp_path: Path):
    control = Control(tmp_path / "control.sqlite"); control.initialize()
    try:
        with pytest.raises(ControlError, match="incident_type_unknown"):
            control.incident("caller_controlled_payload_type", "QUOTA_STATE_UNCERTAIN", {"proof": H})
        control.db.execute("INSERT INTO incidents(incident_id,predecessor_incident_id,incident_type,blocking,blocking_state,payload_hash,payload_json,resolved_by,created_at,qualification_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)", ("incident_unknown", None, "UNKNOWN_FUTURE_TYPE", 1, "QUOTA_STATE_UNCERTAIN", H, "{}", None, 1, None))
        with pytest.raises(ControlError, match="incident_type_unknown:incident_unknown"):
            control.effective_status()
    finally:
        control.close()


def test_capacity_replacement_rejects_any_nonterminal_lineage_reservation(tmp_path: Path):
    control = Control(tmp_path / "control.sqlite"); instance = control.initialize()
    try:
        first = _v3_capacity(instance, predecessor=None); control.install_capacity(first)
        control.reserve("attempt-a", 1_000_000, 1_024, H, str(first["capacity_id"]), 15_000_000_000)
        successor = _v3_capacity(instance, predecessor=str(first["capacity_id"]), stamp="2026-07-27T00:00:01Z")
        with pytest.raises(ControlError, match="capacity_replacement_nonterminal_projects"): control.install_capacity(successor)
        assert control.active_capacity_id() == first["capacity_id"]
    finally:
        control.close()


def test_qualification_run_uses_production_capacity_and_rejects_concurrency(tmp_path: Path):
    control = Control(tmp_path / "control.sqlite"); instance = control.initialize()
    try:
        cap = _v3_capacity(instance, predecessor=None); control.install_capacity(cap)
        run = "qualification_" + "1" * 32
        control.start_qualification(run, "a" * 40, "b" * 40)
        with pytest.raises(ControlError, match="qualification_run_concurrent"):
            control.start_qualification("qualification_" + "2" * 32, "a" * 40, "b" * 40)
        control.finish_qualification(run, True)
        row = control.db.execute("SELECT capacity_id,state FROM qualification_runs WHERE qualification_run_id=?", (run,)).fetchone()
        assert tuple(row) == (cap["capacity_id"], "PASSED")
    finally:
        control.close()


def test_doctor_calls_production_lifecycle_interface_not_inline_docker() -> None:
    source = Path("shiproom/external_validation/remediation_backend/doctor.py").read_text(encoding="utf-8")
    assert "execute_patient_command(" in source
    assert '"create", "--name"' not in source
    assert "start_qualification(" in source and "finish_qualification(" in source


def test_v2_migration_preserves_history_and_blocks_unknown_version(tmp_path: Path):
    old = _predecessor_control(tmp_path); database = tmp_path / "v2.sqlite"; control = old.Control(database)
    try:
        instance = control.initialize(); cap = _v2_capacity(old, instance, aggregate=6_000_000_000, available=16_000_000_000, suffix="a"); control.install_capacity(cap)
        control.reserve("attempt-a", 1_000_000, 1_024, H, str(cap["capacity_id"]), 15_000_000_000)
        first = control.incident("allocation_failure", "QUOTA_STATE_UNCERTAIN", {"proof": H}); control.incident("containment_failure", "CONTAINMENT_UNPROVEN", {"proof": H}); control.resolve_incident(first, {"proof": H})
    finally:
        control.close()
    evidence = migrate_v2_to_v3(database, tmp_path / "backup.sqlite", commit="b" * 40, implementation=Path(__file__), allow_live_nonterminal=True)
    assert Path(tmp_path / "backup.sqlite").is_file() and evidence["effective_state"] == "CONTAINMENT_UNPROVEN"
    migrated = Control(database)
    try:
        assert migrated.effective_status()["effective_state"] == "CONTAINMENT_UNPROVEN"
        assert migrated.db.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 1
    finally:
        migrated.close()
    with pytest.raises(MigrationError, match="migration_predecessor_version_unknown"):
        migrate_v2_to_v3(database, tmp_path / "backup2.sqlite", commit="b" * 40, implementation=Path(__file__))


def test_status_authority_has_one_profile_current_chain():
    result = resolve_status_authority(Path("external_validation/status/session1-status-authority.v1.json"))
    # Final records are intentionally ineffective until the external
    # attestation binds the pushed proof/status commit.
    assert result["profiles"] == {"detection": "QUALIFIED", "remediation": "BLOCKED", "overall": "PARTIALLY_QUALIFIED"}


def test_status_attestation_rejects_a_non_proof_only_commit(tmp_path: Path) -> None:
    """Commit B cannot be forged by pointing an attestation at code changes."""
    root = Path.cwd()
    authority = root / "external_validation/status/session1-status-authority.v1.json"
    authority_document = json.loads(authority.read_text(encoding="utf-8"))
    chain = root / authority_document["current_chain"]["path"]
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    attestation = tmp_path / "attestation.json"
    attestation.write_text(json.dumps({
        "schema_id": "external_validation.status_attestation.v1",
        "schema_version": "1",
        "commit_b": head,
        "commit_b_tree": tree,
        # The attestation binds the profile chain's canonical proof hash.  A
        # Windows checkout may represent this public JSON with CRLF, while
        # the staged/root authority sees the committed LF blob.
        "proof_bundle_hash": json.loads(chain.read_text(encoding="utf-8"))["profiles"]["detection"][-1]["proof_bundle_hash"],
        "status_authority_hash": "sha256:" + hashlib.sha256(authority.read_bytes()).hexdigest(),
        "status_chain_hash": "sha256:" + hashlib.sha256(chain.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    attestation.chmod(0o400)
    with pytest.raises(V2ValidationError, match="status_attestation_commit_scope_invalid"):
        resolve_status_authority(authority, repository_root=root, attestation=attestation)
