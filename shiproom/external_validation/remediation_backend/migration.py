#!/usr/bin/env python3
"""Fail-closed v2-to-v3 remediation control-database migration.

This helper is root-staged with the backend.  It never copies a SQLite main
file behind a live WAL; it uses SQLite's online backup API after an exclusive
maintenance transition and retains both the backup and immutable evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Root execution intentionally uses ``python -I -S``.  Make only this sealed
# bundle importable; never rely on a mutable working directory or site path.
_STAGED_MODULE_DIRECTORY = str(Path(__file__).resolve().parent)
if _STAGED_MODULE_DIRECTORY not in sys.path:
    sys.path.insert(0, _STAGED_MODULE_DIRECTORY)

try:
    from .control import SCHEMA_VERSION, TERMINAL_PROJECT_STATES, canonical, digest
    from .bootstrap import require_staged_script
except ImportError:
    from control import SCHEMA_VERSION, TERMINAL_PROJECT_STATES, canonical, digest
    from bootstrap import require_staged_script


LOCK = Path("/run/lock/shiproom-remediation.backend.lock")


class MigrationError(RuntimeError):
    pass


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def rows(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def schema_version(connection: sqlite3.Connection) -> int:
    try:
        values = list(connection.execute("SELECT version FROM schema_meta"))
    except sqlite3.DatabaseError as exc:
        raise MigrationError("migration_schema_meta_missing") from exc
    if len(values) != 1:
        raise MigrationError("migration_schema_version_invalid")
    return int(values[0][0])


def _lock() -> Any:
    try:
        import fcntl
    except ModuleNotFoundError as exc:
        raise MigrationError("migration_lock_platform_unsupported") from exc
    LOCK.parent.mkdir(mode=0o755, exist_ok=True)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    value = os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        os.close(fd); raise MigrationError("migration_lock_untrusted")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return os.fdopen(fd, "r+", encoding="ascii")


def _state(connection: sqlite3.Connection, value: str) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("UPDATE backend SET execution_state=?,updated_at=? WHERE singleton=1", (value, time.time_ns()))
        connection.execute("INSERT INTO events(kind,payload_hash,payload_json,created_at) VALUES(?,?,?,?)", ("schema_migration_state", digest({"state": value}), canonical({"state": value}).decode("utf-8"), time.time_ns()))
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK"); raise


def _backup(connection: sqlite3.Connection, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists(): raise MigrationError("migration_backup_exists")
    target = sqlite3.connect(destination)
    try:
        connection.backup(target)
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target.commit()
    finally:
        target.close()
    os.chmod(destination, 0o400)


def _create_v3_tables(connection: sqlite3.Connection) -> None:
    script = """
      CREATE TABLE schema_meta (version INTEGER PRIMARY KEY CHECK(version=3));
      CREATE TABLE incidents (
        incident_id TEXT PRIMARY KEY, predecessor_incident_id TEXT REFERENCES incidents(incident_id),
        incident_type TEXT NOT NULL, blocking INTEGER NOT NULL CHECK(blocking IN (0,1)),
        blocking_state TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL,
        resolved_by TEXT UNIQUE REFERENCES incidents(incident_id), created_at INTEGER NOT NULL,
        qualification_run_id TEXT);
      CREATE TABLE capacity (
        capacity_id TEXT PRIMARY KEY, backend_instance_id TEXT NOT NULL, evidence_hash TEXT NOT NULL,
        nominal_image_bytes INTEGER NOT NULL, filesystem_total_data_bytes INTEGER NOT NULL, filesystem_available_bytes INTEGER NOT NULL,
        metadata_reserve_bytes INTEGER NOT NULL, supervisor_reserve_bytes INTEGER NOT NULL, docker_bytes INTEGER NOT NULL,
        aggregate_worktree_bytes INTEGER NOT NULL, inode_policy_cap INTEGER NOT NULL, max_active_projects INTEGER NOT NULL,
        predecessor_capacity_id TEXT REFERENCES capacity(capacity_id), qualification_run_id TEXT,
        active INTEGER NOT NULL CHECK(active IN (0,1)));
      CREATE TABLE projects (
        project_id INTEGER PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, status TEXT NOT NULL,
        reservation_bytes INTEGER NOT NULL, reservation_inodes INTEGER NOT NULL, worktree_hash TEXT NOT NULL,
        capacity_id TEXT NOT NULL REFERENCES capacity(capacity_id), incident_id TEXT REFERENCES incidents(incident_id),
        qualification_run_id TEXT, created_at INTEGER NOT NULL, retired_at INTEGER);
      CREATE TABLE migration_history (
        migration_id TEXT PRIMARY KEY, predecessor_version INTEGER NOT NULL, successor_version INTEGER NOT NULL,
        predecessor_hash TEXT NOT NULL, backup_hash TEXT NOT NULL, implementation_hash TEXT NOT NULL,
        commit_sha TEXT NOT NULL, row_counts_json TEXT NOT NULL, completed_at INTEGER NOT NULL);
      CREATE TABLE qualification_runs (
        qualification_run_id TEXT PRIMARY KEY, staged_commit TEXT NOT NULL, staged_tree TEXT NOT NULL,
        capacity_id TEXT NOT NULL REFERENCES capacity(capacity_id), state TEXT NOT NULL, created_at INTEGER NOT NULL, completed_at INTEGER);
      CREATE UNIQUE INDEX capacity_one_active ON capacity(active) WHERE active=1;
      CREATE INDEX incidents_unresolved_blocking ON incidents(blocking,resolved_by,incident_id);
      CREATE INDEX projects_capacity_status ON projects(capacity_id,status);
    """
    for statement in script.split(";"):
        if statement.strip(): connection.execute(statement)


def _effective_state(connection: sqlite3.Connection) -> str:
    rows_ = list(connection.execute("SELECT blocking_state FROM incidents WHERE blocking=1 AND resolved_by IS NULL ORDER BY incident_id"))
    return "READY" if not rows_ else (str(rows_[0][0]) if len(rows_) == 1 else "BLOCKED_MULTIPLE_INCIDENTS")


def _production_preflight(database: Path) -> None:
    """Reject a live backend rather than migrating a database under it.

    The offline migration function intentionally supports historic fixtures;
    this preflight is used only by the staged production CLI.  It is read-only
    and refusal leaves both the database and host runtime untouched.
    """
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        if schema_version(connection) != 2:
            raise MigrationError("migration_predecessor_version_unknown")
        terminal = tuple(sorted(TERMINAL_PROJECT_STATES))
        projects = connection.execute(
            "SELECT COUNT(*) FROM projects WHERE status NOT IN ({})".format(",".join("?" for _ in terminal)), terminal
        ).fetchone()[0]
        pending = connection.execute("SELECT COUNT(*) FROM allocations WHERE phase != 'REGISTRY_COMMITTED' OR terminal_status IS NULL").fetchone()[0]
        releases = connection.execute("SELECT COUNT(*) FROM releases WHERE phase != 'RELEASE_COMMITTED' OR terminal_status IS NULL").fetchone()[0]
        incidents = connection.execute("SELECT COUNT(*) FROM incidents WHERE kind != 'RESOLUTION' AND resolved_by IS NULL").fetchone()[0]
        if projects or pending or releases:
            raise MigrationError("migration_live_lifecycle_present")
        if incidents:
            raise MigrationError("migration_unresolved_incident_present")
    finally:
        connection.close()
    # A custom daemon must be cleanly stopped by the dedicated lifecycle
    # command before schema maintenance.  Do not guess which daemon to kill.
    result = subprocess.run(["/usr/bin/pgrep", "-af", "dockerd"], text=True, capture_output=True, check=False, timeout=10)
    if result.returncode == 0 and "/var/lib/shiproom-remediation" in result.stdout:
        raise MigrationError("migration_custom_daemon_running")


def migrate_v2_to_v3(database: Path, backup: Path, *, commit: str, implementation: Path, allow_live_nonterminal: bool = False) -> dict[str, Any]:
    """Migrate an exact v2 database; used by production and predecessor fixtures."""
    if not database.is_file(): raise MigrationError("migration_database_missing")
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        if schema_version(connection) != 2: raise MigrationError("migration_predecessor_version_unknown")
        pre_counts = {table: rows(connection, table) for table in ("backend", "incidents", "capacity", "projects", "allocations", "authorizations", "releases", "events")}
        nonterminal = connection.execute("SELECT COUNT(*) FROM projects WHERE status NOT IN ({})".format(",".join("?" for _ in TERMINAL_PROJECT_STATES)), tuple(sorted(TERMINAL_PROJECT_STATES))).fetchone()[0]
        if nonterminal and not allow_live_nonterminal: raise MigrationError("migration_nonterminal_projects_present")
        predecessor_hash = file_hash(database)
        _state(connection, "MAINTENANCE_SCHEMA_MIGRATION")
        connection.execute("PRAGMA wal_checkpoint(FULL)")
        _backup(connection, backup)
        backup_hash = file_hash(backup)
        # SQLite rewrites foreign-key references when a table is renamed.  The
        # related project/allocation/authorization/release tables therefore
        # move as one graph while FK enforcement is disabled, then receive a
        # full foreign-key check before commit.
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN EXCLUSIVE")
        try:
            for statement in (
              "ALTER TABLE schema_meta RENAME TO schema_meta_v2",
              "ALTER TABLE incidents RENAME TO incidents_v2",
              "ALTER TABLE capacity RENAME TO capacity_v2",
              "ALTER TABLE projects RENAME TO projects_v2",
              "ALTER TABLE allocations RENAME TO allocations_v2",
              "ALTER TABLE authorizations RENAME TO authorizations_v2",
              "ALTER TABLE releases RENAME TO releases_v2",
            ):
                connection.execute(statement)
            _create_v3_tables(connection)
            for statement in (
              """CREATE TABLE allocations (
                attempt_id TEXT PRIMARY KEY REFERENCES projects(attempt_id), phase TEXT NOT NULL,
                worktree_authority_json TEXT NOT NULL, quota_evidence_json TEXT, pending_hash TEXT, terminal_status TEXT)""",
              """CREATE TABLE authorizations (
                authorization_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL REFERENCES allocations(attempt_id),
                content_hash TEXT UNIQUE NOT NULL, artifact_path TEXT NOT NULL UNIQUE, receipt_id TEXT NOT NULL, manifest_hash TEXT NOT NULL,
                supervisor_hash TEXT NOT NULL, indexed_at INTEGER NOT NULL)""",
              """CREATE TABLE releases (
                attempt_id TEXT PRIMARY KEY REFERENCES allocations(attempt_id), authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
                phase TEXT NOT NULL, pending_hash TEXT, terminal_status TEXT)""",
            ):
                connection.execute(statement)
            connection.execute("INSERT INTO schema_meta VALUES(3)")
            connection.execute("INSERT INTO incidents SELECT incident_id,predecessor_incident_id,kind,CASE WHEN kind='RESOLUTION' THEN 0 ELSE 1 END,execution_state,payload_hash,payload_json,resolved_by,created_at,NULL FROM incidents_v2")
            connection.execute("INSERT INTO capacity SELECT capacity_id,backend_instance_id,evidence_hash,nominal_image_bytes,filesystem_total_data_bytes,filesystem_available_bytes,metadata_reserve_bytes,supervisor_reserve_bytes,docker_bytes,aggregate_worktree_bytes,inode_policy_cap,max_active_projects,NULL,NULL,active FROM capacity_v2")
            connection.execute("INSERT INTO projects SELECT project_id,attempt_id,status,reservation_bytes,reservation_inodes,worktree_hash,capacity_id,incident_id,NULL,created_at,retired_at FROM projects_v2")
            connection.execute("INSERT INTO allocations SELECT * FROM allocations_v2")
            connection.execute("INSERT INTO authorizations SELECT * FROM authorizations_v2")
            connection.execute("INSERT INTO releases SELECT * FROM releases_v2")
            for table in ("schema_meta_v2", "incidents_v2", "capacity_v2", "projects_v2", "allocations_v2", "authorizations_v2", "releases_v2"):
                connection.execute("DROP TABLE " + table)
            connection.execute("PRAGMA foreign_keys=ON")
            if list(connection.execute("PRAGMA foreign_key_check")): raise MigrationError("migration_foreign_key_check_failed")
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise MigrationError("migration_integrity_check_failed")
            post_counts = {table: rows(connection, table) for table in ("backend", "incidents", "capacity", "projects", "allocations", "authorizations", "releases", "events")}
            expected_post_counts = dict(pre_counts); expected_post_counts["events"] += 1  # durable maintenance transition
            if expected_post_counts != post_counts: raise MigrationError("migration_row_count_mismatch")
            effective = _effective_state(connection)
            connection.execute("UPDATE backend SET execution_state=?,updated_at=? WHERE singleton=1", (effective, time.time_ns()))
            migration_id = "migration_" + hashlib.sha256((predecessor_hash + backup_hash + commit).encode()).hexdigest()[:32]
            connection.execute("INSERT INTO migration_history VALUES(?,?,?,?,?,?,?,?,?)", (migration_id, 2, SCHEMA_VERSION, predecessor_hash, backup_hash, file_hash(implementation), commit, canonical(pre_counts).decode("utf-8"), time.time_ns()))
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction: connection.execute("ROLLBACK")
            raise
        return {"migration_id": migration_id, "predecessor_hash": predecessor_hash, "backup_hash": backup_hash, "row_counts": pre_counts, "effective_state": effective}
    except BaseException:
        try: _state(connection, "SCHEMA_MIGRATION_FAILED")
        except Exception: pass
        raise
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--db", type=Path, required=True); parser.add_argument("--backup", type=Path, required=True); parser.add_argument("--commit", required=True); parser.add_argument("--allow-offline-nonterminal", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0: raise MigrationError("migration_root_required")
    require_staged_script(Path(__file__))
    with _lock():
        if not args.allow_offline_nonterminal:
            _production_preflight(args.db)
        print(json.dumps(migrate_v2_to_v3(args.db, args.backup, commit=args.commit, implementation=Path(__file__), allow_live_nonterminal=args.allow_offline_nonterminal), sort_keys=True))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (MigrationError, sqlite3.Error, OSError) as exc: print("migration_error:" + str(exc), file=__import__("sys").stderr); raise SystemExit(2)
