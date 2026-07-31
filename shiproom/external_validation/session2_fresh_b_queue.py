"""Transactional, root-owned sequential authority for Fresh B qualification.

The source population is immutable.  This queue records only the supervisor's
progress through that population: it never decides a pass, constructs a case,
or accepts worker-authored evidence.  A claimed candidate is the sole next
candidate in the frozen B1/B2/B3 order; a terminal qualification/exclusion
must cite an independently sealed supervisor artifact.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import time
from typing import Any, Iterator

from .identity import canonical_json
from .security import _is_reparse, external_root


_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_STATES = {"PENDING", "IN_PROGRESS", "QUALIFIED", "EXCLUDED", "REPOSITORY_CAP_BLOCKED"}
_TERMINAL = {"QUALIFIED", "EXCLUDED"}


class FreshBQueueError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise FreshBQueueError(code)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_fresh_b_queue_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise FreshBQueueError("session2_fresh_b_queue_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_fresh_b_queue_external_root_invalid")
    directory = root / "session2" / "cases" / "fresh-b-queue"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = directory.lstat()
    if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or value.st_uid != 0
            or value.st_gid != 0 or stat.S_IMODE(value.st_mode) != 0o700):
        _fail("session2_fresh_b_queue_store_invalid")
    return directory


def _index(root: Path, index_hash: str) -> list[dict[str, Any]]:
    if not isinstance(index_hash, str) or not _HASH.fullmatch(index_hash):
        _fail("session2_fresh_b_queue_index_hash_invalid")
    path = root / "session2" / "cases" / (index_hash[7:] + ".candidate-index.json")
    if not path.is_file() or _is_reparse(path): _fail("session2_fresh_b_queue_index_missing")
    raw = path.read_bytes()
    if _digest(raw) != index_hash: _fail("session2_fresh_b_queue_index_hash_mismatch")
    try: value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise FreshBQueueError("session2_fresh_b_queue_index_invalid") from exc
    if (canonical_json(value) != raw or not isinstance(value, dict)
            or value.get("schema_id") != "external_validation.session2_fresh_b_candidate_index.v1"
            or value.get("schema_version") != "1" or value.get("selection_effect") != "source_population_only"
            or not isinstance(value.get("candidates"), list) or not value["candidates"]):
        _fail("session2_fresh_b_queue_index_invalid")
    required = {"candidate_id", "repository", "fresh_b_band", "contamination_band", "selection_status"}
    previous: tuple[int, str] | None = None; ids: set[str] = set(); rows: list[dict[str, Any]] = []
    bands = {"B1": 0, "B2": 1, "B3": 2}
    for ordinal, candidate in enumerate(value["candidates"]):
        if (not isinstance(candidate, dict) or not required.issubset(candidate) or not isinstance(candidate["candidate_id"], str)
                or candidate["candidate_id"] in ids or not isinstance(candidate["repository"], str)
                or candidate.get("fresh_b_band") not in bands or candidate.get("contamination_band") != "FRESH_B"
                or candidate.get("selection_status") != "SOURCE_OBJECTS_SEALED_NOT_QUALIFIED"):
            _fail("session2_fresh_b_queue_index_invalid")
        # The compiler has already sealed the exact timestamp sort.  The queue
        # preserves its literal list order and independently rejects a band
        # regression, which would otherwise permit a B3 candidate before B1.
        key = (bands[candidate["fresh_b_band"]], candidate["candidate_id"])
        if previous is not None and key[0] < previous[0]: _fail("session2_fresh_b_queue_index_order_invalid")
        previous = key; ids.add(candidate["candidate_id"])
        rows.append({"ordinal": ordinal, "candidate_id": candidate["candidate_id"], "repository": candidate["repository"], "band": candidate["fresh_b_band"]})
    return rows


class FreshBQueue:
    """SQLite authority; every mutation uses ``BEGIN IMMEDIATE``."""

    def __init__(self, database: Path):
        self.database = database
        self.db = sqlite3.connect(database, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS queue (
                ordinal INTEGER PRIMARY KEY, candidate_id TEXT UNIQUE NOT NULL, repository TEXT NOT NULL,
                band TEXT NOT NULL, state TEXT NOT NULL, claim_id TEXT UNIQUE, evidence_hash TEXT,
                terminal_reason TEXT, changed_at_ns INTEGER NOT NULL,
                CHECK(state IN ('PENDING','IN_PROGRESS','QUALIFIED','EXCLUDED','REPOSITORY_CAP_BLOCKED'))
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY, candidate_id TEXT NOT NULL, prior_state TEXT,
                state TEXT NOT NULL, evidence_hash TEXT, terminal_reason TEXT, created_at_ns INTEGER NOT NULL
            );
        """)

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK"); raise
        else:
            self.db.execute("COMMIT")

    def initialize(self, index_hash: str, rows: list[dict[str, Any]]) -> None:
        with self._transaction():
            current = self.db.execute("SELECT value FROM metadata WHERE key='candidate_index_hash'").fetchone()
            if current is not None:
                if current[0] != index_hash: _fail("session2_fresh_b_queue_index_conflict")
                count = self.db.execute("SELECT count(*) FROM queue").fetchone()[0]
                if count != len(rows): _fail("session2_fresh_b_queue_corrupt")
                return
            self.db.execute("INSERT INTO metadata(key,value) VALUES('schema_version','1'),('candidate_index_hash',?)", (index_hash,))
            now = time.time_ns()
            for row in rows:
                self.db.execute("INSERT INTO queue(ordinal,candidate_id,repository,band,state,claim_id,evidence_hash,terminal_reason,changed_at_ns) VALUES(?,?,?,?, 'PENDING',NULL,NULL,NULL,?)", (row["ordinal"], row["candidate_id"], row["repository"], row["band"], now))
                self.db.execute("INSERT INTO events(candidate_id,prior_state,state,evidence_hash,terminal_reason,created_at_ns) VALUES(?,NULL,'PENDING',NULL,NULL,?)", (row["candidate_id"], now))

    def claim_next(self) -> dict[str, Any] | None:
        """Claim exactly one next candidate; unresolved work cannot be skipped."""
        with self._transaction():
            active = self.db.execute("SELECT candidate_id FROM queue WHERE state='IN_PROGRESS'").fetchall()
            if active: _fail("session2_fresh_b_queue_in_progress")
            while True:
                row = self.db.execute("SELECT ordinal,candidate_id,repository,band,state FROM queue WHERE state='PENDING' ORDER BY ordinal LIMIT 1").fetchone()
                if row is None: return None
                qualified = self.db.execute("SELECT count(*) FROM queue WHERE repository=? AND state='QUALIFIED'", (row[2],)).fetchone()[0]
                now = time.time_ns()
                if qualified >= 2:
                    self.db.execute("UPDATE queue SET state='REPOSITORY_CAP_BLOCKED',terminal_reason='maximum_two_selected_pairs_per_repository',changed_at_ns=? WHERE ordinal=?", (now, row[0]))
                    self.db.execute("INSERT INTO events(candidate_id,prior_state,state,evidence_hash,terminal_reason,created_at_ns) VALUES(?, 'PENDING','REPOSITORY_CAP_BLOCKED',NULL,'maximum_two_selected_pairs_per_repository',?)", (row[1], now))
                    continue
                claim = "fresh_b_claim_" + sha256((row[1] + ":" + str(now)).encode("utf-8")).hexdigest()[:24]
                self.db.execute("UPDATE queue SET state='IN_PROGRESS',claim_id=?,changed_at_ns=? WHERE ordinal=?", (claim, now, row[0]))
                self.db.execute("INSERT INTO events(candidate_id,prior_state,state,evidence_hash,terminal_reason,created_at_ns) VALUES(?, 'PENDING','IN_PROGRESS',NULL,NULL,?)", (row[1], now))
                return {"ordinal": row[0], "candidate_id": row[1], "repository": row[2], "fresh_b_band": row[3], "claim_id": claim}

    def terminal(self, *, claim_id: str, state: str, evidence_hash: str, reason: str) -> None:
        if state not in _TERMINAL or not isinstance(claim_id, str) or not _HASH.fullmatch(evidence_hash) or not isinstance(reason, str) or not reason:
            _fail("session2_fresh_b_queue_terminal_input_invalid")
        with self._transaction():
            row = self.db.execute("SELECT candidate_id,state FROM queue WHERE claim_id=?", (claim_id,)).fetchone()
            if row is None or row[1] != "IN_PROGRESS": _fail("session2_fresh_b_queue_claim_invalid")
            now = time.time_ns()
            self.db.execute("UPDATE queue SET state=?,evidence_hash=?,terminal_reason=?,changed_at_ns=? WHERE claim_id=?", (state, evidence_hash, reason, now, claim_id))
            self.db.execute("INSERT INTO events(candidate_id,prior_state,state,evidence_hash,terminal_reason,created_at_ns) VALUES(?, 'IN_PROGRESS',?,?,?,?)", (row[0], state, evidence_hash, reason, now))


def open_queue(repository_root: Path, *, candidate_index_hash: str) -> FreshBQueue:
    directory = _root(repository_root); root = directory.parents[2]; rows = _index(root, candidate_index_hash)
    database = directory / "control.sqlite3"; existed = database.exists()
    if existed:
        value = database.lstat()
        if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_gid != 0 or stat.S_IMODE(value.st_mode) != 0o600:
            _fail("session2_fresh_b_queue_database_invalid")
    queue = FreshBQueue(database)
    if not existed:
        os.chown(database, 0, 0); os.chmod(database, 0o600)
    queue.initialize(candidate_index_hash, rows)
    return queue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the root-owned sequential Fresh B qualification queue.")
    parser.add_argument("--repository-root", required=True, type=Path); parser.add_argument("--candidate-index-hash", required=True)
    parser.add_argument("command", choices=("claim-next", "terminal")); parser.add_argument("--claim-id"); parser.add_argument("--state", choices=sorted(_TERMINAL)); parser.add_argument("--evidence-hash"); parser.add_argument("--reason")
    parsed = parser.parse_args(argv)
    try:
        queue = open_queue(parsed.repository_root, candidate_index_hash=parsed.candidate_index_hash)
        try:
            if parsed.command == "claim-next": result = queue.claim_next()
            else:
                if None in (parsed.claim_id, parsed.state, parsed.evidence_hash, parsed.reason): _fail("session2_fresh_b_queue_terminal_input_invalid")
                queue.terminal(claim_id=parsed.claim_id, state=parsed.state, evidence_hash=parsed.evidence_hash, reason=parsed.reason); result = {"state": "recorded"}
        finally:
            queue.close()
    except FreshBQueueError as exc:
        print(str(exc)); return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
