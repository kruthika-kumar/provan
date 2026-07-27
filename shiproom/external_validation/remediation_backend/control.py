#!/usr/bin/env python3
"""Root-owned SQLite authority for the remediation backend.

This is deliberately small and dependency-free.  It is the only mutable
authority for provisioning, allocation, capacity, incidents, and release.
Shell files are adapters; evidence files are immutable projections.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 3
# ``READY`` is the only executable state.  Blocking incident state is immutable
# at creation and the effective state is derived from every unresolved blocker,
# never from an arbitrary latest row.
STATES = {"READY", "BLOCKED_MULTIPLE_INCIDENTS", "RECOVERY_REQUIRED", "CONTAINMENT_UNPROVEN", "PACKAGE_STATE_UNCERTAIN", "UNIT_RESTORATION_UNPROVEN", "QUOTA_STATE_UNCERTAIN", "MAINTENANCE_SCHEMA_MIGRATION", "SCHEMA_MIGRATION_FAILED", "QUALIFICATION_FAILED"}
PHASES = {"PREFLIGHT_COMPLETE", "ROOTS_CREATED", "STATE_INITIALIZED", "POLICY_GUARD_CREATED", "PACKAGE_INSTALL_ATTEMPTED", "PACKAGES_CONFIGURED", "UNITS_CONTAINED", "POLICY_GUARD_REMOVED", "IMAGE_CREATED", "LOOP_ATTACHED", "FILESYSTEM_FORMATTED", "FILESYSTEM_MOUNTED", "DATA_PROJECT_ASSIGNED", "DATA_LIMITS_VERIFIED", "DAEMON_CONFIG_WRITTEN", "DAEMON_STARTED", "STATUS_VERIFIED", "SETUP_COMPLETE"}
RETIREMENTS = {"ACTIVE", "RELEASED_RETIRED", "FAILED_RETIRED", "QUARANTINED_RETIRED", "INCIDENT_RETIRED"}
TERMINAL_PROJECT_STATES = {"RELEASED_RETIRED", "FAILED_RETIRED", "QUARANTINED_RETIRED", "INCIDENT_RETIRED"}
NONTERMINAL_PROJECT_STATES = {"RESERVED", "ALLOCATING", "ACTIVE", "RELEASING", "QUARANTINED_PENDING", "INCIDENT_BOUND", "RECOVERY_REQUIRED"}
ALLOCATION_PHASES = {"RESERVED", "TREE_CREATED", "PROJECT_ASSIGNED", "LIMIT_ASSIGNED", "REGISTRY_COMMITTED", "QUARANTINED", "INCIDENT"}
RELEASE_PHASES = {"EVIDENCE_SEALED", "RESIDUAL_ABSENCE_VERIFIED", "WORKTREE_CONTENT_DELETE_STARTED", "WORKTREE_EMPTY_VERIFIED", "PROJECT_CLEAR_STARTED", "PROJECT_CLEARED_VERIFIED", "WORKTREE_ROOT_DELETE_STARTED", "WORKTREE_ABSENT_VERIFIED", "REGISTRY_REMOVAL_PREPARED", "RELEASE_COMMITTED"}
PHASE_PREDECESSOR = {"ROOTS_CREATED":"PREFLIGHT_COMPLETE","STATE_INITIALIZED":"ROOTS_CREATED","POLICY_GUARD_CREATED":"STATE_INITIALIZED","PACKAGE_INSTALL_ATTEMPTED":"POLICY_GUARD_CREATED","PACKAGES_CONFIGURED":"PACKAGE_INSTALL_ATTEMPTED","UNITS_CONTAINED":"PACKAGES_CONFIGURED","POLICY_GUARD_REMOVED":"UNITS_CONTAINED","IMAGE_CREATED":"POLICY_GUARD_REMOVED","LOOP_ATTACHED":"IMAGE_CREATED","FILESYSTEM_FORMATTED":"LOOP_ATTACHED","FILESYSTEM_MOUNTED":"FILESYSTEM_FORMATTED","DATA_PROJECT_ASSIGNED":"FILESYSTEM_MOUNTED","DATA_LIMITS_VERIFIED":"DATA_PROJECT_ASSIGNED","DAEMON_CONFIG_WRITTEN":"DATA_LIMITS_VERIFIED","DAEMON_STARTED":"DAEMON_CONFIG_WRITTEN","STATUS_VERIFIED":"DAEMON_STARTED","SETUP_COMPLETE":"STATUS_VERIFIED"}
ALLOCATION_PREDECESSOR = {"TREE_CREATED":"RESERVED","PROJECT_ASSIGNED":"TREE_CREATED","LIMIT_ASSIGNED":"PROJECT_ASSIGNED","REGISTRY_COMMITTED":"LIMIT_ASSIGNED"}
RELEASE_PREDECESSOR = {"RESIDUAL_ABSENCE_VERIFIED":"EVIDENCE_SEALED","WORKTREE_CONTENT_DELETE_STARTED":"RESIDUAL_ABSENCE_VERIFIED","WORKTREE_EMPTY_VERIFIED":"WORKTREE_CONTENT_DELETE_STARTED","PROJECT_CLEAR_STARTED":"WORKTREE_EMPTY_VERIFIED","PROJECT_CLEARED_VERIFIED":"PROJECT_CLEAR_STARTED","WORKTREE_ROOT_DELETE_STARTED":"PROJECT_CLEARED_VERIFIED","WORKTREE_ABSENT_VERIFIED":"WORKTREE_ROOT_DELETE_STARTED","REGISTRY_REMOVAL_PREPARED":"WORKTREE_ABSENT_VERIFIED"}


class ControlError(RuntimeError):
    """Stable control-plane rejection code."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class Control:
    def __init__(self, path: Path):
        self.path = path
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")

    def close(self) -> None:
        self.db.close()

    @contextlib.contextmanager
    def tx(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def initialize(self) -> str:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER PRIMARY KEY CHECK(version=3));
            CREATE TABLE IF NOT EXISTS backend (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), backend_instance_id TEXT UNIQUE NOT NULL,
              execution_state TEXT NOT NULL, setup_phase TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (
              incident_id TEXT PRIMARY KEY, predecessor_incident_id TEXT REFERENCES incidents(incident_id),
              incident_type TEXT NOT NULL, blocking INTEGER NOT NULL CHECK(blocking IN (0,1)),
              blocking_state TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL,
              resolved_by TEXT UNIQUE REFERENCES incidents(incident_id), created_at INTEGER NOT NULL,
              qualification_run_id TEXT);
            CREATE TABLE IF NOT EXISTS package_units (
              unit TEXT PRIMARY KEY, existed INTEGER NOT NULL, unit_file_state TEXT, runtime_state TEXT, containment_json TEXT, restoration_json TEXT);
            CREATE TABLE IF NOT EXISTS project_counter (singleton INTEGER PRIMARY KEY CHECK(singleton=1), next_project_id INTEGER NOT NULL CHECK(next_project_id>=20000));
            CREATE TABLE IF NOT EXISTS capacity (
              capacity_id TEXT PRIMARY KEY, backend_instance_id TEXT NOT NULL, evidence_hash TEXT NOT NULL,
              nominal_image_bytes INTEGER NOT NULL, filesystem_total_data_bytes INTEGER NOT NULL, filesystem_available_bytes INTEGER NOT NULL,
              metadata_reserve_bytes INTEGER NOT NULL, supervisor_reserve_bytes INTEGER NOT NULL, docker_bytes INTEGER NOT NULL,
              aggregate_worktree_bytes INTEGER NOT NULL, inode_policy_cap INTEGER NOT NULL, max_active_projects INTEGER NOT NULL,
              predecessor_capacity_id TEXT REFERENCES capacity(capacity_id), qualification_run_id TEXT,
              active INTEGER NOT NULL CHECK(active IN (0,1)));
            CREATE TABLE IF NOT EXISTS projects (
              project_id INTEGER PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, status TEXT NOT NULL,
              reservation_bytes INTEGER NOT NULL, reservation_inodes INTEGER NOT NULL, worktree_hash TEXT NOT NULL,
              capacity_id TEXT NOT NULL REFERENCES capacity(capacity_id), incident_id TEXT REFERENCES incidents(incident_id),
              qualification_run_id TEXT, created_at INTEGER NOT NULL, retired_at INTEGER);
            CREATE TABLE IF NOT EXISTS allocations (
              attempt_id TEXT PRIMARY KEY REFERENCES projects(attempt_id), phase TEXT NOT NULL,
              worktree_authority_json TEXT NOT NULL, quota_evidence_json TEXT, pending_hash TEXT, terminal_status TEXT);
            CREATE TABLE IF NOT EXISTS authorizations (
              authorization_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL REFERENCES allocations(attempt_id),
              content_hash TEXT UNIQUE NOT NULL, artifact_path TEXT NOT NULL UNIQUE, receipt_id TEXT NOT NULL, manifest_hash TEXT NOT NULL,
              supervisor_hash TEXT NOT NULL, indexed_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS releases (
              attempt_id TEXT PRIMARY KEY REFERENCES allocations(attempt_id), authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
              phase TEXT NOT NULL, pending_hash TEXT, terminal_status TEXT);
            CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS migration_history (
              migration_id TEXT PRIMARY KEY, predecessor_version INTEGER NOT NULL, successor_version INTEGER NOT NULL,
              predecessor_hash TEXT NOT NULL, backup_hash TEXT NOT NULL, implementation_hash TEXT NOT NULL,
              commit_sha TEXT NOT NULL, row_counts_json TEXT NOT NULL, completed_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS qualification_runs (
              qualification_run_id TEXT PRIMARY KEY, staged_commit TEXT NOT NULL, staged_tree TEXT NOT NULL,
              capacity_id TEXT NOT NULL REFERENCES capacity(capacity_id), state TEXT NOT NULL, created_at INTEGER NOT NULL,
              completed_at INTEGER);
            CREATE UNIQUE INDEX IF NOT EXISTS capacity_one_active ON capacity(active) WHERE active=1;
            CREATE INDEX IF NOT EXISTS incidents_unresolved_blocking ON incidents(blocking,resolved_by,incident_id);
            CREATE INDEX IF NOT EXISTS projects_capacity_status ON projects(capacity_id,status);
        """)
        with self.tx():
            versions = list(self.db.execute("SELECT version FROM schema_meta"))
            if not versions:
                self.db.execute("INSERT INTO schema_meta VALUES(?)", (SCHEMA_VERSION,))
            elif len(versions) != 1:
                raise ControlError("unknown_schema_version")
            elif int(versions[0][0]) != SCHEMA_VERSION:
                if int(versions[0][0]) == 2:
                    raise ControlError("migration_required_v2_to_v3")
                raise ControlError("unknown_schema_version")
            self.db.execute("INSERT OR IGNORE INTO project_counter VALUES(1,20000)")
            row = self.db.execute("SELECT backend_instance_id FROM backend WHERE singleton=1").fetchone()
            if row:
                return str(row[0])
            instance = "backend_" + secrets.token_hex(16)
            now = time.time_ns()
            self.db.execute("INSERT INTO backend VALUES(1,?,?,?,?,?)", (instance, "READY", "PREFLIGHT_COMPLETE", now, now))
            self.event("backend_initialized", {"backend_instance_id": instance})
            return instance

    def event(self, kind: str, payload: dict[str, Any]) -> None:
        self.db.execute("INSERT INTO events(kind,payload_hash,payload_json,created_at) VALUES(?,?,?,?)", (kind, digest(payload), canonical(payload).decode("utf-8"), time.time_ns()))

    def _backend(self) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM backend WHERE singleton=1").fetchone()
        if row is None:
            raise ControlError("backend_uninitialized")
        return row

    def effective_status(self) -> dict[str, Any]:
        """Return the sole effective backend authority in deterministic order."""
        rows = self.db.execute(
            "SELECT incident_id,incident_type,blocking_state,resolved_by,predecessor_incident_id "
            "FROM incidents WHERE blocking=1 AND resolved_by IS NULL ORDER BY incident_id"
        ).fetchall()
        if not rows:
            state = "READY"
        elif len(rows) == 1:
            state = str(rows[0]["blocking_state"])
        else:
            state = "BLOCKED_MULTIPLE_INCIDENTS"
        return {
            "effective_state": state,
            "unresolved_incident_count": len(rows),
            "unresolved_incident_ids": [str(row["incident_id"]) for row in rows],
            "unresolved_incident_types": [str(row["incident_type"]) for row in rows],
            "resolution_lineage": [
                {"incident_id": str(row["incident_id"]), "predecessor_incident_id": row["predecessor_incident_id"], "resolved_by": row["resolved_by"]}
                for row in self.db.execute("SELECT incident_id,predecessor_incident_id,resolved_by FROM incidents ORDER BY created_at,incident_id")
            ],
        }

    def _persist_effective_state(self) -> dict[str, Any]:
        result = self.effective_status()
        self.db.execute("UPDATE backend SET execution_state=?,updated_at=? WHERE singleton=1", (result["effective_state"], time.time_ns()))
        return result

    def assert_ready(self) -> None:
        backend = self._backend()
        persisted = str(backend["execution_state"])
        if persisted in {"MAINTENANCE_SCHEMA_MIGRATION", "SCHEMA_MIGRATION_FAILED"}:
            raise ControlError("backend_execution_blocked:" + persisted)
        result = self.effective_status()
        if persisted != result["effective_state"]:
            raise ControlError("backend_state_integrity_invalid")
        if result["effective_state"] != "READY":
            raise ControlError("backend_execution_blocked:" + str(result["effective_state"]))

    def assert_no_releasing_worktree(self) -> None:
        """A sealed attempt is exclusive until its retirement transaction commits."""
        row = self.db.execute("SELECT attempt_id FROM releases WHERE phase != 'RELEASE_COMMITTED' LIMIT 1").fetchone()
        if row is not None:
            raise ControlError("backend_execution_blocked:RELEASING")

    def instance_id(self) -> str:
        return str(self._backend()["backend_instance_id"])

    def active_capacity_id(self) -> str | None:
        row = self.db.execute("SELECT capacity_id FROM capacity WHERE active=1").fetchone()
        return None if row is None else str(row["capacity_id"])

    def start_qualification(self, qualification_run_id: str, staged_commit: str, staged_tree: str) -> None:
        """Durably reserve the production namespace for one doctor run."""
        if (not qualification_run_id.startswith("qualification_") or len(staged_commit) != 40
                or len(staged_tree) != 40):
            raise ControlError("qualification_run_invalid")
        with self.tx():
            self.assert_ready()
            self.assert_no_releasing_worktree()
            capacity_id = self.active_capacity_id()
            if capacity_id is None:
                raise ControlError("qualification_capacity_missing")
            if self.db.execute("SELECT 1 FROM qualification_runs WHERE state='RUNNING'").fetchone():
                raise ControlError("qualification_run_concurrent")
            self.db.execute(
                "INSERT INTO qualification_runs(qualification_run_id,staged_commit,staged_tree,capacity_id,state,created_at,completed_at) VALUES(?,?,?,?,?,?,NULL)",
                (qualification_run_id, staged_commit, staged_tree, capacity_id, "RUNNING", time.time_ns()),
            )
            self.event("qualification_started", {"qualification_run_id": qualification_run_id, "capacity_id": capacity_id})

    def finish_qualification(self, qualification_run_id: str, succeeded: bool) -> None:
        """Terminally record the doctor outcome; do not silently clear failures."""
        with self.tx():
            row = self.db.execute("SELECT state FROM qualification_runs WHERE qualification_run_id=?", (qualification_run_id,)).fetchone()
            if row is None or str(row["state"]) != "RUNNING":
                raise ControlError("qualification_run_state_invalid")
            state = "PASSED" if succeeded else "FAILED"
            self.db.execute("UPDATE qualification_runs SET state=?,completed_at=? WHERE qualification_run_id=?", (state, time.time_ns(), qualification_run_id))
            self.event("qualification_finished", {"qualification_run_id": qualification_run_id, "state": state})

    def phase(self, value: str) -> None:
        if value not in PHASES:
            raise ControlError("phase_invalid")
        with self.tx():
            self.assert_ready()
            if value == "PREFLIGHT_COMPLETE" or self._backend()["setup_phase"] != PHASE_PREDECESSOR[value]:
                raise ControlError("setup_phase_transition_invalid")
            self.db.execute("UPDATE backend SET setup_phase=?,updated_at=? WHERE singleton=1", (value, time.time_ns()))
            self.event("setup_phase", {"phase": value})

    def incident(self, incident_type: str, state: str, payload: dict[str, Any], predecessor: str | None = None, *, blocking: bool = True, qualification_run_id: str | None = None) -> str:
        if not isinstance(incident_type, str) or not incident_type or state not in STATES or state in {"READY", "BLOCKED_MULTIPLE_INCIDENTS", "MAINTENANCE_SCHEMA_MIGRATION"}:
            raise ControlError("incident_state_invalid")
        incident_id = "incident_" + secrets.token_hex(16)
        with self.tx():
            if predecessor and self.db.execute("SELECT 1 FROM incidents WHERE incident_id=?", (predecessor,)).fetchone() is None:
                raise ControlError("incident_predecessor_missing")
            self.db.execute(
                "INSERT INTO incidents(incident_id,predecessor_incident_id,incident_type,blocking,blocking_state,payload_hash,payload_json,resolved_by,created_at,qualification_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, predecessor, incident_type, int(blocking), state, digest(payload), canonical(payload).decode("utf-8"), None, time.time_ns(), qualification_run_id),
            )
            effective = self._persist_effective_state()
            self.event("incident", {"incident_id": incident_id, "incident_type": incident_type, "blocking_state": state, "effective_state": effective["effective_state"]})
        return incident_id

    def resolve_incident(self, predecessor: str, payload: dict[str, Any], *, qualification_run_id: str | None = None) -> str:
        with self.tx():
            prior = self.db.execute("SELECT * FROM incidents WHERE incident_id=?", (predecessor,)).fetchone()
            if prior is None or not bool(prior["blocking"]) or prior["resolved_by"] is not None:
                raise ControlError("incident_resolution_invalid")
            successor = "incident_" + secrets.token_hex(16)
            self.db.execute(
                "INSERT INTO incidents(incident_id,predecessor_incident_id,incident_type,blocking,blocking_state,payload_hash,payload_json,resolved_by,created_at,qualification_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (successor, predecessor, "RESOLUTION", 0, "READY", digest(payload), canonical(payload).decode("utf-8"), None, time.time_ns(), qualification_run_id),
            )
            self.db.execute("UPDATE incidents SET resolved_by=? WHERE incident_id=?", (successor, predecessor))
            effective = self._persist_effective_state()
            self.event("incident_resolved", {"predecessor": predecessor, "successor": successor, "effective_state": effective["effective_state"]})
            return successor

    def _capacity_invariant(self) -> None:
        row = self.db.execute(
            "SELECT p.project_id,p.attempt_id,p.status,p.capacity_id FROM projects p JOIN capacity c ON c.capacity_id=p.capacity_id "
            "WHERE c.active=0 AND p.status NOT IN ({}) LIMIT 1".format(",".join("?" for _ in TERMINAL_PROJECT_STATES)),
            tuple(sorted(TERMINAL_PROJECT_STATES)),
        ).fetchone()
        if row is not None:
            raise ControlError("capacity_inactive_nonterminal_reservation")

    def install_capacity(self, record: dict[str, Any], *, qualification_run_id: str | None = None) -> str:
        required = {"capacity_id", "backend_instance_id", "evidence_hash", "nominal_image_bytes", "filesystem_total_data_bytes", "filesystem_available_bytes", "metadata_reserve_bytes", "supervisor_reserve_bytes", "docker_bytes", "aggregate_worktree_bytes", "inode_policy_cap", "max_active_projects", "predecessor_capacity_id", "qualified_at"}
        if set(record) != required:
            raise ControlError("capacity_shape_invalid")
        numeric = required - {"capacity_id", "backend_instance_id", "evidence_hash", "predecessor_capacity_id", "qualified_at"}
        if any(not isinstance(record[k], int) or isinstance(record[k], bool) or record[k] < 0 for k in numeric):
            raise ControlError("capacity_value_invalid")
        if record["max_active_projects"] < 1 or not str(record["evidence_hash"]).startswith("sha256:"):
            raise ControlError("capacity_value_invalid")
        evidence = {
            "backend_instance_id": record["backend_instance_id"],
            "nominal_image_bytes": record["nominal_image_bytes"],
            "filesystem_total_data_bytes": record["filesystem_total_data_bytes"],
            "filesystem_available_bytes": record["filesystem_available_bytes"],
            "metadata_reserve_bytes": record["metadata_reserve_bytes"],
            "supervisor_reserve_bytes": record["supervisor_reserve_bytes"],
            "docker_bytes": record["docker_bytes"],
            "qualified_worktree_aggregate_limit": record["aggregate_worktree_bytes"],
            "inode_policy_cap": record["inode_policy_cap"],
            "max_active_projects": record["max_active_projects"],
            "predecessor_capacity_id": record["predecessor_capacity_id"],
            "qualified_at": record["qualified_at"],
        }
        expected_hash = digest(evidence)
        if record["evidence_hash"] != expected_hash or record["capacity_id"] != "capacity_" + expected_hash.split(":", 1)[1][:32]:
            raise ControlError("capacity_evidence_invalid")
        usable = min(record["filesystem_total_data_bytes"], record["filesystem_available_bytes"])
        if record["docker_bytes"] + record["metadata_reserve_bytes"] + record["supervisor_reserve_bytes"] + record["aggregate_worktree_bytes"] > usable:
            raise ControlError("capacity_overcommitted")
        with self.tx():
            self.assert_ready()
            if record["backend_instance_id"] != self.instance_id():
                raise ControlError("capacity_backend_mismatch")
            active = self.db.execute("SELECT capacity_id FROM capacity WHERE active=1").fetchone()
            nonterminal = self.db.execute(
                "SELECT project_id,attempt_id,status,capacity_id FROM projects WHERE status NOT IN ({}) ORDER BY project_id".format(",".join("?" for _ in TERMINAL_PROJECT_STATES)),
                tuple(sorted(TERMINAL_PROJECT_STATES)),
            ).fetchall()
            if nonterminal:
                raise ControlError("capacity_replacement_nonterminal_projects")
            self._capacity_invariant()
            expected_predecessor = None if active is None else str(active["capacity_id"])
            if record["predecessor_capacity_id"] != expected_predecessor:
                raise ControlError("capacity_replacement_evidence_mismatch")
            if active is not None:
                self.db.execute("UPDATE capacity SET active=0 WHERE capacity_id=?", (expected_predecessor,))
            self.db.execute(
                "INSERT INTO capacity(capacity_id,backend_instance_id,evidence_hash,nominal_image_bytes,filesystem_total_data_bytes,filesystem_available_bytes,metadata_reserve_bytes,supervisor_reserve_bytes,docker_bytes,aggregate_worktree_bytes,inode_policy_cap,max_active_projects,predecessor_capacity_id,qualification_run_id,active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                tuple(record[k] for k in ("capacity_id", "backend_instance_id", "evidence_hash", "nominal_image_bytes", "filesystem_total_data_bytes", "filesystem_available_bytes", "metadata_reserve_bytes", "supervisor_reserve_bytes", "docker_bytes", "aggregate_worktree_bytes", "inode_policy_cap", "max_active_projects", "predecessor_capacity_id")) + (qualification_run_id,),
            )
            self.event("capacity_qualified", {**record, "qualification_run_id": qualification_run_id})
        return str(record["capacity_id"])

    def reserve(self, attempt: str, bytes_: int, inodes: int, worktree_hash: str, capacity_id: str, runtime_available: int | None = None, *, qualification_run_id: str | None = None) -> int:
        if bytes_ <= 0 or inodes <= 0 or not attempt:
            raise ControlError("reservation_invalid")
        with self.tx():
            self.assert_ready()
            self.assert_no_releasing_worktree()
            self._capacity_invariant()
            cap = self.db.execute("SELECT * FROM capacity WHERE capacity_id=? AND active=1", (capacity_id,)).fetchone()
            if cap is None:
                raise ControlError("capacity_unqualified")
            if runtime_available is not None and runtime_available < bytes_ + int(cap["supervisor_reserve_bytes"]):
                raise ControlError("capacity_runtime_free_space_exceeded")
            used = self.db.execute(
                "SELECT COALESCE(SUM(reservation_bytes),0) AS bytes,COALESCE(SUM(reservation_inodes),0) AS inodes,COUNT(*) AS projects FROM projects WHERE status NOT IN ({}) AND capacity_id=?".format(",".join("?" for _ in TERMINAL_PROJECT_STATES)),
                tuple(sorted(TERMINAL_PROJECT_STATES)) + (capacity_id,),
            ).fetchone()
            if int(used["projects"]) >= int(cap["max_active_projects"]):
                raise ControlError("capacity_project_count_exceeded")
            if int(used["bytes"]) + bytes_ > int(cap["aggregate_worktree_bytes"]):
                raise ControlError("capacity_bytes_exceeded")
            if int(used["inodes"]) + inodes > int(cap["inode_policy_cap"]):
                raise ControlError("capacity_inodes_exceeded")
            next_id = int(self.db.execute("SELECT next_project_id FROM project_counter WHERE singleton=1").fetchone()[0])
            self.db.execute("UPDATE project_counter SET next_project_id=? WHERE singleton=1", (next_id + 1,))
            self.db.execute("INSERT INTO projects(project_id,attempt_id,status,reservation_bytes,reservation_inodes,worktree_hash,capacity_id,incident_id,qualification_run_id,created_at,retired_at) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (next_id, attempt, "RESERVED", bytes_, inodes, worktree_hash, capacity_id, None, qualification_run_id, time.time_ns()))
            self.db.execute("INSERT INTO allocations VALUES(?,?,?,?,?,NULL)", (attempt, "RESERVED", "{}", None, None))
            self.event("project_reserved", {"project_id": next_id, "attempt_id": attempt, "bytes": bytes_, "inodes": inodes, "runtime_available": runtime_available, "qualification_run_id": qualification_run_id})
            return next_id

    def allocation_phase(self, attempt: str, phase: str, authority: dict[str, Any], quota: dict[str, Any] | None = None, pending: dict[str, Any] | None = None) -> None:
        if phase not in ALLOCATION_PHASES:
            raise ControlError("allocation_phase_invalid")
        with self.tx():
            self.assert_ready()
            current = self.db.execute("SELECT phase FROM allocations WHERE attempt_id=?", (attempt,)).fetchone()
            if current is None:
                raise ControlError("allocation_missing")
            if phase in ALLOCATION_PREDECESSOR and current["phase"] != ALLOCATION_PREDECESSOR[phase]:
                raise ControlError("allocation_phase_transition_invalid")
            if phase in {"QUARANTINED", "INCIDENT"} and current["phase"] == "REGISTRY_COMMITTED":
                raise ControlError("allocation_terminal_transition_invalid")
            self.db.execute("UPDATE allocations SET phase=?,worktree_authority_json=?,quota_evidence_json=?,pending_hash=? WHERE attempt_id=?", (phase, canonical(authority).decode("utf-8"), None if quota is None else canonical(quota).decode("utf-8"), None if pending is None else digest(pending), attempt))
            project_state = {"RESERVED": "RESERVED", "TREE_CREATED": "ALLOCATING", "PROJECT_ASSIGNED": "ALLOCATING", "LIMIT_ASSIGNED": "ALLOCATING", "REGISTRY_COMMITTED": "ACTIVE", "QUARANTINED": "QUARANTINED_PENDING", "INCIDENT": "INCIDENT_BOUND"}[phase]
            self.db.execute("UPDATE projects SET status=? WHERE attempt_id=?", (project_state, attempt))
            self.event("allocation_phase", {"attempt_id": attempt, "phase": phase})

    def allocation(self, attempt: str) -> dict[str, Any]:
        row = self.db.execute("SELECT p.*,a.phase,a.worktree_authority_json,a.quota_evidence_json,a.pending_hash,a.terminal_status FROM projects p JOIN allocations a USING(attempt_id) WHERE p.attempt_id=?", (attempt,)).fetchone()
        if row is None:
            raise ControlError("allocation_missing")
        return {key: (json.loads(row[key]) if key in {"worktree_authority_json", "quota_evidence_json"} and row[key] is not None else row[key]) for key in row.keys()}

    def registered_worktree_paths(self) -> list[str]:
        """Return all durable worktree authorities for residual-alias checking."""
        rows = self.db.execute("SELECT worktree_authority_json FROM allocations WHERE worktree_authority_json != '{}' ").fetchall()
        paths: list[str] = []
        for row in rows:
            value = json.loads(str(row[0]))
            path = value.get("canonical_path")
            if isinstance(path, str):
                paths.append(path)
        return paths

    def authorize_release(self, document: dict[str, Any], artifact_path: str) -> str:
        try:
            from .contracts import validate_release_authorization
        except ImportError:
            from contracts import validate_release_authorization
        validate_release_authorization(document)
        auth_id = str(document["authorization_id"])
        with self.tx():
            self.assert_ready()
            if document["backend_instance_id"] != self.instance_id():
                raise ControlError("authorization_backend_mismatch")
            project = self.db.execute("SELECT * FROM projects WHERE attempt_id=? AND project_id=? AND status='ACTIVE'", (document["attempt_id"], document["project_id"])).fetchone()
            if project is None or document["capacity_reservation_id"] != str(project["project_id"]):
                raise ControlError("authorization_project_mismatch")
            allocation = self.db.execute("SELECT * FROM allocations WHERE attempt_id=?", (document["attempt_id"],)).fetchone()
            if allocation is None or allocation["phase"] != "REGISTRY_COMMITTED" or allocation["quota_evidence_json"] is None:
                raise ControlError("authorization_allocation_uncommitted")
            stored_authority = json.loads(allocation["worktree_authority_json"])
            if canonical(stored_authority) != canonical(document["worktree_authority"]) or stored_authority.get("source_snapshot_hash") != document["source_snapshot_hash"]:
                raise ControlError("authorization_worktree_authority_mismatch")
            content_hash = digest(document)
            self.db.execute("INSERT INTO authorizations VALUES(?,?,?,?,?,?,?,?)", (auth_id, document["attempt_id"], content_hash, artifact_path, document["receipt_id"], document["sealed_artifact_manifest_hash"], document["supervisor_package_hash"], time.time_ns()))
            self.db.execute("INSERT INTO releases VALUES(?,?,?,NULL,NULL)", (document["attempt_id"], auth_id, "EVIDENCE_SEALED"))
            self.db.execute("UPDATE projects SET status='RELEASING' WHERE attempt_id=?", (document["attempt_id"],))
            self.event("release_authorized", {"authorization_id": auth_id, "attempt_id": document["attempt_id"], "content_hash": content_hash})
        return auth_id

    def authorization(self, authorization_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM authorizations WHERE authorization_id=?", (authorization_id,)).fetchone()
        if row is None:
            raise ControlError("authorization_unindexed")
        return dict(row)

    def release_phase(self, attempt: str, phase: str, pending: dict[str, Any] | None = None) -> None:
        if phase not in RELEASE_PHASES:
            raise ControlError("release_phase_invalid")
        with self.tx():
            self.assert_ready()
            row = self.db.execute("SELECT phase FROM releases WHERE attempt_id=?", (attempt,)).fetchone()
            if row is None:
                raise ControlError("release_missing")
            if phase in RELEASE_PREDECESSOR and row["phase"] != RELEASE_PREDECESSOR[phase]:
                raise ControlError("release_phase_transition_invalid")
            self.db.execute("UPDATE releases SET phase=?,pending_hash=? WHERE attempt_id=?", (phase, None if pending is None else digest(pending), attempt))
            self.event("release_phase", {"attempt_id": attempt, "phase": phase})

    def commit_release(self, attempt: str) -> None:
        """One terminal transaction: registry retirement plus capacity release."""
        with self.tx():
            self.assert_ready()
            project = self.db.execute("SELECT * FROM projects WHERE attempt_id=? AND status='RELEASING'", (attempt,)).fetchone()
            release = self.db.execute("SELECT * FROM releases WHERE attempt_id=?", (attempt,)).fetchone()
            if project is None or release is None or release["phase"] != "REGISTRY_REMOVAL_PREPARED":
                raise ControlError("release_not_prepared")
            now = time.time_ns()
            self.db.execute("UPDATE projects SET status='RELEASED_RETIRED',retired_at=? WHERE attempt_id=?", (now, attempt))
            self.db.execute("UPDATE allocations SET terminal_status='RELEASED_RETIRED' WHERE attempt_id=?", (attempt,))
            self.db.execute("UPDATE releases SET phase='RELEASE_COMMITTED',terminal_status='RELEASED_RETIRED' WHERE attempt_id=?", (attempt,))
            self.event("release_committed", {"attempt_id": attempt, "project_id": project["project_id"], "capacity_released": project["reservation_bytes"], "project_status": "RELEASED_RETIRED"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    p_phase = sub.add_parser("phase"); p_phase.add_argument("value", choices=sorted(PHASES))
    sub.add_parser("assert-ready"); sub.add_parser("instance"); sub.add_parser("active-capacity")
    sub.add_parser("effective-status")
    p_incident = sub.add_parser("incident"); p_incident.add_argument("kind"); p_incident.add_argument("state", choices=sorted(STATES - {"READY"})); p_incident.add_argument("payload_json")
    p_resolve = sub.add_parser("resolve-incident"); p_resolve.add_argument("predecessor"); p_resolve.add_argument("payload_json")
    p_capacity = sub.add_parser("install-capacity"); p_capacity.add_argument("record_json"); p_capacity.add_argument("--qualification-run-id")
    p_reserve = sub.add_parser("reserve"); p_reserve.add_argument("attempt"); p_reserve.add_argument("bytes", type=int); p_reserve.add_argument("inodes", type=int); p_reserve.add_argument("worktree_hash"); p_reserve.add_argument("capacity_id"); p_reserve.add_argument("--runtime-available", type=int); p_reserve.add_argument("--qualification-run-id")
    p_alloc = sub.add_parser("allocation-phase"); p_alloc.add_argument("attempt"); p_alloc.add_argument("phase", choices=sorted(ALLOCATION_PHASES)); p_alloc.add_argument("authority_json"); p_alloc.add_argument("--quota-json"); p_alloc.add_argument("--pending-json")
    p_show_alloc = sub.add_parser("allocation"); p_show_alloc.add_argument("attempt")
    p_authorize = sub.add_parser("authorize-release"); p_authorize.add_argument("document_json"); p_authorize.add_argument("artifact_path")
    p_show_auth = sub.add_parser("authorization"); p_show_auth.add_argument("authorization_id")
    p_release = sub.add_parser("release-phase"); p_release.add_argument("attempt"); p_release.add_argument("phase", choices=sorted(RELEASE_PHASES - {"RELEASE_COMMITTED"})); p_release.add_argument("--pending-json")
    p_commit = sub.add_parser("commit-release"); p_commit.add_argument("attempt")
    p_qstart = sub.add_parser("start-qualification"); p_qstart.add_argument("qualification_run_id"); p_qstart.add_argument("staged_commit"); p_qstart.add_argument("staged_tree")
    p_qfinish = sub.add_parser("finish-qualification"); p_qfinish.add_argument("qualification_run_id"); p_qfinish.add_argument("--succeeded", action="store_true")
    args = parser.parse_args(); control = Control(args.db)
    try:
        if args.command == "init": print(control.initialize())
        elif args.command == "phase": control.phase(args.value)
        elif args.command == "assert-ready": control.assert_ready()
        elif args.command == "instance": print(control.instance_id())
        elif args.command == "active-capacity": print(control.active_capacity_id() or "")
        elif args.command == "effective-status": print(canonical(control.effective_status()).decode("utf-8"))
        elif args.command == "incident": print(control.incident(args.kind, args.state, json.loads(args.payload_json)))
        elif args.command == "resolve-incident": print(control.resolve_incident(args.predecessor, json.loads(args.payload_json)))
        elif args.command == "install-capacity": print(control.install_capacity(json.loads(args.record_json), qualification_run_id=args.qualification_run_id))
        elif args.command == "reserve": print(control.reserve(args.attempt, args.bytes, args.inodes, args.worktree_hash, args.capacity_id, args.runtime_available, qualification_run_id=args.qualification_run_id))
        elif args.command == "allocation-phase": control.allocation_phase(args.attempt, args.phase, json.loads(args.authority_json), None if args.quota_json is None else json.loads(args.quota_json), None if args.pending_json is None else json.loads(args.pending_json))
        elif args.command == "allocation": print(canonical(control.allocation(args.attempt)).decode("utf-8"))
        elif args.command == "authorize-release": print(control.authorize_release(json.loads(args.document_json), args.artifact_path))
        elif args.command == "authorization": print(canonical(control.authorization(args.authorization_id)).decode("utf-8"))
        elif args.command == "release-phase": control.release_phase(args.attempt, args.phase, None if args.pending_json is None else json.loads(args.pending_json))
        elif args.command == "commit-release": control.commit_release(args.attempt)
        elif args.command == "start-qualification": control.start_qualification(args.qualification_run_id, args.staged_commit, args.staged_tree)
        elif args.command == "finish-qualification": control.finish_qualification(args.qualification_run_id, args.succeeded)
    finally:
        control.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControlError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(f"control_error:{exc}", file=sys.stderr)
        raise SystemExit(2)
