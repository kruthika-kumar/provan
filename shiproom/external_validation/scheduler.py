from __future__ import annotations

"""Durable, crash-conscious scheduling authority.

SQLite records the observation separately from every infrastructure attempt.  A
provider call which might have been accepted is deliberately terminally
ambiguous: it is visible, billable/uncertain, and never silently reissued.
"""
import hashlib
import json
import random
import sqlite3
from pathlib import Path


RETRYABLE_INFRASTRUCTURE = {
    "container_startup", "provider_transport_before_completion",
    "dependency_download_corrupt", "runner_crash_before_delivery",
    "infrastructure_interruption",
}


class RunScheduler:
    """Transactional schedule, attempt, operation, and receipt index."""

    def __init__(self, database: Path):
        self.db = sqlite3.connect(database)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
              observation_key TEXT PRIMARY KEY, state TEXT NOT NULL,
              active_attempt_id TEXT, receipt_id TEXT, detail TEXT NOT NULL DEFAULT '',
              schedule_position INTEGER
            );
            CREATE TABLE IF NOT EXISTS attempts (
              attempt_id TEXT PRIMARY KEY, observation_key TEXT NOT NULL,
              lineage INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
              receipt_id TEXT, created_sequence INTEGER NOT NULL,
              FOREIGN KEY(observation_key) REFERENCES runs(observation_key)
            );
            CREATE TABLE IF NOT EXISTS operations (
              operation_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL,
              observation_key TEXT NOT NULL, state TEXT NOT NULL, provider_operation_id TEXT,
              FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
              checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT, observation_key TEXT NOT NULL,
              state TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS amendments (
              amendment_id INTEGER PRIMARY KEY AUTOINCREMENT, observation_key TEXT NOT NULL,
              prior_receipt_id TEXT, replacement_receipt_id TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schedule_metadata (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), schedule_id TEXT NOT NULL,
              run_set_hash TEXT NOT NULL, algorithm_version TEXT NOT NULL, public_seed TEXT NOT NULL
            );
        """)
        self.db.commit()

    def _transaction(self):
        return self.db

    def enqueue(self, observation_key: str, attempt_id: str, *, schedule_position: int | None = None) -> str:
        with self.db:
            row = self.db.execute("SELECT state FROM runs WHERE observation_key=?", (observation_key,)).fetchone()
            if row:
                return row[0]
            if self.db.execute("SELECT 1 FROM schedule_metadata WHERE singleton=1").fetchone():
                raise ValueError("schedule_closed_to_new_observations")
            self.db.execute("INSERT INTO runs (observation_key,state,active_attempt_id,receipt_id,detail,schedule_position) VALUES (?,?,?,?,?,?)",
                            (observation_key, "QUEUED", attempt_id, None, "", schedule_position))
            self.db.execute("INSERT INTO attempts (attempt_id,observation_key,lineage,state,created_sequence) VALUES (?,?,?,?,?)",
                            (attempt_id, observation_key, 1, "QUEUED", schedule_position if schedule_position is not None else 0))
        return "QUEUED"

    def freeze_schedule(self, observation_keys: list[str], public_seed: str, algorithm_version: str = "shuffle-v1") -> list[str]:
        """Persist one reproducible randomized order; order is never identity."""
        if len(set(observation_keys)) != len(observation_keys):
            raise ValueError("schedule_duplicate_observation")
        run_set_hash = "sha256:" + hashlib.sha256(json.dumps(sorted(observation_keys), separators=(",", ":")).encode()).hexdigest()
        schedule_id = "schedule_" + hashlib.sha256(json.dumps([run_set_hash, algorithm_version, public_seed], separators=(",", ":")).encode()).hexdigest()
        existing = self.db.execute("SELECT schedule_id,run_set_hash,algorithm_version,public_seed FROM schedule_metadata WHERE singleton=1").fetchone()
        if existing and tuple(existing) != (schedule_id, run_set_hash, algorithm_version, public_seed):
            raise ValueError("schedule_reseed_forbidden")
        order = list(observation_keys)
        random.Random(public_seed).shuffle(order)
        with self.db:
            if not existing:
                self.db.execute("INSERT INTO schedule_metadata VALUES (1,?,?,?,?)", (schedule_id, run_set_hash, algorithm_version, public_seed))
            for position, key in enumerate(order):
                if not self.db.execute("SELECT 1 FROM runs WHERE observation_key=?", (key,)).fetchone():
                    raise ValueError("schedule_observation_not_enqueued")
                self.db.execute("UPDATE runs SET schedule_position=? WHERE observation_key=?", (position, key))
        self.active_schedule_id = schedule_id
        return order

    def begin_operation(self, observation_key: str, operation_id: str, provider_operation_id: str | None = None) -> None:
        with self.db:
            run = self.db.execute("SELECT active_attempt_id,state,schedule_position FROM runs WHERE observation_key=?", (observation_key,)).fetchone()
            if not run or run[1] != "QUEUED" or run[2] is None:
                raise ValueError("operation_state_forbidden")
            self.db.execute("INSERT INTO operations VALUES (?,?,?,?,?)", (operation_id, run[0], observation_key, "IN_FLIGHT", provider_operation_id))
            self.db.execute("UPDATE runs SET state='RUNNING' WHERE observation_key=?", (observation_key,))
            self.db.execute("UPDATE attempts SET state='RUNNING' WHERE attempt_id=?", (run[0],))

    def checkpoint(self, observation_key: str, state: str, payload: dict) -> None:
        with self.db:
            self.db.execute("INSERT INTO checkpoints (observation_key,state,payload) VALUES (?,?,?)", (observation_key, state, json.dumps(payload, sort_keys=True)))

    def mark_ambiguous(self, operation_id: str) -> None:
        with self.db:
            row = self.db.execute("SELECT observation_key,attempt_id FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            if not row:
                raise ValueError("operation_unknown")
            self.db.execute("UPDATE operations SET state='INDETERMINATE_IN_FLIGHT' WHERE operation_id=?", (operation_id,))
            self.db.execute("UPDATE attempts SET state='INDETERMINATE_IN_FLIGHT' WHERE attempt_id=?", (row[1],))
            self.db.execute("UPDATE runs SET state='INDETERMINATE_IN_FLIGHT',detail='external call accepted but response not durably recorded' WHERE observation_key=?", (row[0],))
            self.db.execute("INSERT INTO checkpoints (observation_key,state,payload) VALUES (?,?,?)", (row[0], "INDETERMINATE_IN_FLIGHT", "{}"))

    def recover_interrupted(self) -> list[str]:
        """Convert only unknown in-flight work to ambiguity; return safe queued work."""
        with self.db:
            rows = self.db.execute("SELECT operation_id FROM operations WHERE state='IN_FLIGHT'").fetchall()
            for row in rows:
                self.mark_ambiguous(row[0])
        return [row[0] for row in self.db.execute("SELECT observation_key FROM runs WHERE state='QUEUED' ORDER BY schedule_position,observation_key")]

    def finalize(self, observation_key: str, receipt_id: str) -> None:
        with self.db:
            run = self.db.execute("SELECT active_attempt_id,state FROM runs WHERE observation_key=?", (observation_key,)).fetchone()
            if not run or run[1] in {"TERMINAL", "INDETERMINATE_IN_FLIGHT"}:
                return
            self.db.execute("UPDATE runs SET state='TERMINAL',receipt_id=? WHERE observation_key=?", (receipt_id, observation_key))
            self.db.execute("UPDATE attempts SET state='TERMINAL',receipt_id=? WHERE attempt_id=?", (receipt_id, run[0]))
            self.checkpoint(observation_key, "TERMINAL", {"receipt_id": receipt_id})

    def mark_infrastructure_failure(self, observation_key: str, reason: str) -> None:
        if reason not in RETRYABLE_INFRASTRUCTURE:
            raise ValueError("retry_not_infrastructure")
        with self.db:
            row = self.db.execute("SELECT active_attempt_id,state FROM runs WHERE observation_key=?", (observation_key,)).fetchone()
            if not row or row[1] not in {"QUEUED", "RUNNING"}:
                raise ValueError("failure_state_forbidden")
            operation = self.db.execute("SELECT 1 FROM operations WHERE attempt_id=? AND state='IN_FLIGHT'", (row[0],)).fetchone()
            if operation:
                raise ValueError("failure_requires_operation_resolution")
            self.db.execute("UPDATE runs SET state='INFRASTRUCTURE_FAILED',detail=? WHERE observation_key=?", (reason, observation_key))
            self.db.execute("UPDATE attempts SET state='INFRASTRUCTURE_FAILED',reason=? WHERE attempt_id=?", (reason, row[0]))

    def infrastructure_retry(self, observation_key: str, next_attempt: str, reason: str) -> None:
        if reason not in RETRYABLE_INFRASTRUCTURE:
            raise ValueError("retry_not_infrastructure")
        with self.db:
            row = self.db.execute("SELECT active_attempt_id,state FROM runs WHERE observation_key=?", (observation_key,)).fetchone()
            if not row or row[1] != "INFRASTRUCTURE_FAILED":
                raise ValueError("retry_state_forbidden")
            lineage = self.db.execute("SELECT COALESCE(MAX(lineage),0)+1 FROM attempts WHERE observation_key=?", (observation_key,)).fetchone()[0]
            self.db.execute("UPDATE attempts SET state='SUPERSEDED',reason=? WHERE attempt_id=?", (reason, row[0]))
            self.db.execute("INSERT INTO attempts (attempt_id,observation_key,lineage,state,reason,created_sequence) VALUES (?,?,?,?,?,?)", (next_attempt, observation_key, lineage, "QUEUED", reason, lineage))
            self.db.execute("UPDATE runs SET state='QUEUED',active_attempt_id=?,detail=? WHERE observation_key=?", (next_attempt, reason, observation_key))

    def index(self, schedule_id: str | None = None) -> dict:
        if schedule_id is None:
            row = self.db.execute("SELECT schedule_id FROM schedule_metadata WHERE singleton=1").fetchone()
            if not row: raise ValueError("schedule_not_frozen")
            schedule_id = row[0]
        records = []
        for run in self.db.execute("SELECT * FROM runs ORDER BY schedule_position,observation_key"):
            attempts = [{"attempt_id": row[0], "lineage": row[1], "state": row[2], "reason": row[3], "receipt_id": row[4]} for row in self.db.execute("SELECT attempt_id,lineage,state,reason,receipt_id FROM attempts WHERE observation_key=? ORDER BY lineage", (run[0],))]
            records.append({"observation_key": run[0], "state": run[1], "attempt_id": run[2], "receipt_id": run[3], "detail": run[4], "attempts": attempts})
        return {"schema_id": "external_validation.run_index", "schema_version": "1", "schedule_id": schedule_id, "records": records}
