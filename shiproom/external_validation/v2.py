"""Session 1 repair contracts.

This module intentionally does not depend on JSON Schema.  Schemas in
``schemas/`` are a second, complementary boundary; these checks carry the
semantic authority used by the supervisor.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
from typing import Any, BinaryIO
import unicodedata

try:
    from .identity import canonical_json, attempt_id
except ImportError:  # root-staged remediation bundle copies hash-bound helpers
    from identity import canonical_json, attempt_id

SHA = "sha256:"
MAGIC = b"SRXFER02"
VERSION = 2
FRAME = struct.Struct(">HHIQ")  # type, flags, sequence, payload length
MANIFEST, ARCHIVE_CHUNK, SUCCESS, FAILURE = 1, 2, 3, 4
TERMINAL = {SUCCESS, FAILURE}
ARTIFACT_CLASSES = {
    "supervisor_command_log", "supervisor_docker_event_log", "patient_stdout",
    "patient_stderr", "patient_output_tree", "file_change_log", "containment_log",
}
TERMINATIONS = {
    "completed", "command_failed", "MODEL_BUDGET_EXCEEDED", "WALL_TIME_EXCEEDED",
    "STDOUT_LIMIT_EXCEEDED", "STDERR_LIMIT_EXCEEDED", "OUTPUT_TREE_LIMIT_EXCEEDED",
    "FILE_SIZE_LIMIT_EXCEEDED", "RESOURCE_LIMIT_EXCEEDED", "unsafe_execution",
    "malformed_output", "indeterminate_in_flight", "CONTAINMENT_FAILURE",
    "artifact_transfer_failed",
}


class V2ValidationError(ValueError):
    def __init__(self, code: str, path: str = ""):
        self.code, self.path = code, path
        super().__init__(f"{code}:{path}")


def _fail(code: str, path: str = "") -> None:
    raise V2ValidationError(code, path)


def _sha(value: Any, path: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(SHA) or any(c not in "0123456789abcdef" for c in value[7:]):
        _fail("sha256_invalid", path)


def _image_digest(value: Any, path: str) -> None:
    if not isinstance(value, str) or "@sha256:" not in value or len(value.rsplit("@sha256:", 1)[1]) != 64:
        _fail("image_digest_invalid", path)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict): _fail("object_required", path)
    return value


def _exact(value: dict[str, Any], keys: set[str], path: str = "") -> None:
    if set(value) != keys: _fail("field_set_invalid", path)


def artifact_manifest_id(value: dict[str, Any]) -> str:
    return SHA + sha256(canonical_json(value)).hexdigest()


def validate_artifact_manifest(value: Any) -> dict[str, Any]:
    item = _object(value, "")
    _exact(item, {"schema_id", "schema_version", "artifacts", "tree_hash", "aggregate_bytes"})
    if item["schema_id"] != "external_validation.artifact_manifest.v1" or item["schema_version"] != "1": _fail("artifact_manifest_header_invalid")
    if not isinstance(item["artifacts"], list) or not isinstance(item["aggregate_bytes"], int) or item["aggregate_bytes"] < 0: _fail("artifact_manifest_shape_invalid")
    prior: bytes | None = None; seen_casefold = set(); total = 0
    for index, raw in enumerate(item["artifacts"]):
        entry = _object(raw, f"/artifacts/{index}")
        _exact(entry, {"path", "type", "mode", "size", "sha256", "producer", "sealer", "trust", "truncated"}, f"/artifacts/{index}")
        path = entry["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            _fail("artifact_path_invalid", f"/artifacts/{index}/path")
        normalized = unicodedata.normalize("NFC", path)
        if normalized != path or normalized.casefold() in seen_casefold: _fail("artifact_path_collision", f"/artifacts/{index}/path")
        encoded = normalized.encode("utf-8")
        if prior is not None and encoded <= prior: _fail("artifact_order_invalid", f"/artifacts/{index}/path")
        prior = encoded; seen_casefold.add(normalized.casefold())
        if entry["type"] not in {"regular", "directory"} or not isinstance(entry["mode"], int) or not isinstance(entry["size"], int) or entry["size"] < 0:
            _fail("artifact_entry_invalid", f"/artifacts/{index}")
        if entry["type"] == "directory" and entry["size"]: _fail("directory_size_invalid", f"/artifacts/{index}/size")
        _sha(entry["sha256"], f"/artifacts/{index}/sha256")
        if entry["producer"] not in {"supervisor", "patient"} or entry["sealer"] != "host_supervisor" or entry["trust"] not in {"control_plane", "untrusted_patient"} or not isinstance(entry["truncated"], bool):
            _fail("artifact_authority_invalid", f"/artifacts/{index}")
        total += entry["size"]
    if total != item["aggregate_bytes"]: _fail("artifact_aggregate_mismatch", "/aggregate_bytes")
    _sha(item["tree_hash"], "/tree_hash")
    expected = SHA + sha256(canonical_json({"artifacts": item["artifacts"], "aggregate_bytes": total})).hexdigest()
    if item["tree_hash"] != expected: _fail("artifact_tree_hash_mismatch", "/tree_hash")
    return item


def receipt_id_v2(receipt: dict[str, Any]) -> str:
    return "receipt_" + sha256(canonical_json(receipt)).hexdigest()


def observation_key_v2(inputs: dict[str, Any]) -> str:
    """Scientific identity for executions whose runner/policy can affect behavior."""
    required = {"case_id", "snapshot_hash", "arm", "system_version", "prompt_version", "policy_version", "model", "model_settings", "model_sampling_seed", "tool_policy_version", "execution_policy_version", "cache_mode", "runner_image_digest", "execution_policy_hash"}
    if set(inputs) != required: _fail("v2_observation_inputs_invalid", "/observation_inputs")
    return "obs_" + sha256(canonical_json(inputs)).hexdigest()


def validate_receipt_v2(value: Any) -> dict[str, Any]:
    item = _object(value, "")
    required = {"schema_id", "schema_version", "observation_key", "observation_inputs", "attempt_id", "attempt_lineage", "case_id", "arm", "repository", "commit_sha", "release_surfaces", "source_hash", "release_packet_hash", "artifact_manifest_hash", "container", "execution", "model_usage", "cost", "applicability", "termination", "evidence_eligible", "finalization_journal_id", "supervisor"}
    _exact(item, required)
    if item["schema_id"] != "external_validation.run_receipt.v2" or item["schema_version"] != "2": _fail("receipt_v2_header_invalid")
    inputs = _object(item["observation_inputs"], "/observation_inputs")
    identity_required = {"case_id", "snapshot_hash", "arm", "system_version", "prompt_version", "policy_version", "model", "model_settings", "model_sampling_seed", "tool_policy_version", "execution_policy_version", "cache_mode", "runner_image_digest", "execution_policy_hash"}
    if set(inputs) != identity_required: _fail("v2_observation_inputs_invalid", "/observation_inputs")
    if inputs["case_id"] != item["case_id"] or inputs["arm"] != item["arm"]: _fail("v2_observation_binding_invalid")
    if item["observation_key"] != observation_key_v2(inputs): _fail("observation_identity_mismatch")
    if not isinstance(item["repository"], str) or not item["repository"] or not isinstance(item["commit_sha"], str) or len(item["commit_sha"]) != 40 or not isinstance(item["release_surfaces"], list) or not all(isinstance(surface, str) and surface for surface in item["release_surfaces"]):
        _fail("case_authority_invalid")
    if not isinstance(item["attempt_lineage"], int) or item["attempt_lineage"] < 1 or item["attempt_id"] != attempt_id(item["observation_key"], item["attempt_lineage"]): _fail("attempt_identity_mismatch")
    for key in ("source_hash", "release_packet_hash", "artifact_manifest_hash"): _sha(item[key], "/" + key)
    container = _object(item["container"], "/container")
    _exact(container, {"id", "name", "requested_policy_hash", "effective_inspect_hash", "runner_image_digest", "teardown", "residual_absence"}, "/container")
    if not all(isinstance(container[key], str) and container[key] for key in ("id", "name")) or container["teardown"] not in {"proven", "containment_failure"} or not isinstance(container["residual_absence"], bool): _fail("container_provenance_invalid", "/container")
    for key in ("requested_policy_hash", "effective_inspect_hash"): _sha(container[key], "/container/" + key)
    _image_digest(container["runner_image_digest"], "/container/runner_image_digest")
    execution = _object(item["execution"], "/execution")
    _exact(execution, {"started_at", "completed_at", "monotonic_seconds", "shiproom_commit", "package_tree_hash", "artifact_protocol_version", "wrapper_version", "cache_policy_version", "security_policy_version", "resource_policy_hash"}, "/execution")
    if not isinstance(execution["monotonic_seconds"], (int, float)) or execution["monotonic_seconds"] < 0 or not isinstance(execution["shiproom_commit"], str) or len(execution["shiproom_commit"]) not in {40, 64}:
        _fail("execution_provenance_invalid", "/execution")
    for key in ("package_tree_hash", "resource_policy_hash"): _sha(execution[key], "/execution/" + key)
    if item["termination"] not in TERMINATIONS or not isinstance(item["evidence_eligible"], bool): _fail("termination_invalid", "/termination")
    if item["termination"] == "CONTAINMENT_FAILURE" and item["evidence_eligible"]: _fail("containment_evidence_forbidden")
    usage = _object(item["model_usage"], "/model_usage")
    if usage.get("state") not in {"not_applicable", "available", "unavailable"}: _fail("model_usage_state_invalid")
    cost = _object(item["cost"], "/cost")
    if cost.get("state") not in {"not_applicable", "available", "cost_unavailable"}: _fail("cost_state_invalid")
    if usage["state"] == "available" and cost["state"] == "not_applicable": _fail("model_cost_state_invalid")
    if item["supervisor"] != "host_supervisor" or not isinstance(item["finalization_journal_id"], str) or not item["finalization_journal_id"]: _fail("finalizer_authority_invalid")
    return item


def validate_incident(value: Any) -> dict[str, Any]:
    item = _object(value, "")
    _exact(item, {"schema_id", "schema_version", "incident_id", "backend_fingerprint", "container_id", "labels", "failed_actions", "termination", "evidence_eligible", "outputs_eligible", "subsequent_execution_blocked", "predecessor_incident_id"})
    if item["schema_id"] != "external_validation.containment_incident.v1" or item["schema_version"] != "1": _fail("incident_header_invalid")
    if item["termination"] != "CONTAINMENT_FAILURE" or item["evidence_eligible"] or item["outputs_eligible"] or not item["subsequent_execution_blocked"]: _fail("incident_state_invalid")
    return item


def validate_status_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_id: dict[str, dict[str, Any]] = {}
    for value in records:
        item = validate_status_record(value)
        if item["status_id"] in by_id: _fail("status_duplicate")
        by_id[item["status_id"]] = item
    successors: dict[str, list[str]] = {}
    for item in by_id.values():
        parent = item["predecessor_status_id"]
        if parent is not None:
            if parent not in by_id: _fail("status_predecessor_missing")
            successors.setdefault(parent, []).append(item["status_id"])
    if any(len(values) > 1 for values in successors.values()): _fail("status_competing_successors")
    current = [item for key, item in by_id.items() if key not in successors]
    if len(current) != 1: _fail("status_current_ambiguous")
    seen = set(); cursor = current[0]
    while cursor:
        if cursor["status_id"] in seen: _fail("status_cycle")
        seen.add(cursor["status_id"]); parent = cursor["predecessor_status_id"]
        cursor = by_id.get(parent) if parent else None
    return current[0]


def validate_status_record(value: Any) -> dict[str, Any]:
    item = _object(value, "")
    _exact(item, {"schema_id", "schema_version", "status_id", "predecessor_status_id", "commit_sha", "branch", "scope", "timestamp", "status"})
    if item["schema_id"] != "external_validation.status_supersession.v1" or item["schema_version"] != "1" or not all(isinstance(item[key], str) and item[key] for key in ("status_id", "commit_sha", "branch", "scope", "timestamp", "status")):
        _fail("status_header_invalid")
    if len(item["commit_sha"]) != 40 or any(char not in "0123456789abcdef" for char in item["commit_sha"]): _fail("status_commit_invalid")
    if item["predecessor_status_id"] is not None and not isinstance(item["predecessor_status_id"], str): _fail("status_predecessor_invalid")
    return item


def validate_finalization_journal_record(value: Any) -> dict[str, Any]:
    item = _object(value, "")
    _exact(item, {"schema_id", "schema_version", "journal_id", "attempt_id", "run_id", "manifest_hash", "receipt_path", "nonce", "authority", "phase"})
    if item["schema_id"] != "external_validation.finalization_journal.v1" or item["schema_version"] != "1" or item["authority"] != "host_supervisor" or item["phase"] not in {"PREPARED", "RECEIPT_DURABLE", "TERMINAL_COMMITTED"}:
        _fail("finalization_journal_invalid")
    _sha(item["manifest_hash"], "/manifest_hash")
    if not all(isinstance(item[key], str) and item[key] for key in ("journal_id", "attempt_id", "run_id", "receipt_path", "nonce")): _fail("finalization_journal_binding_invalid")
    return item


@dataclass(frozen=True)
class TransferLimits:
    max_frame_bytes: int
    max_frames: int
    max_stream_bytes: int


def parse_transfer(stream: BinaryIO, limits: TransferLimits) -> tuple[dict[str, Any], bytes]:
    header = stream.read(12)
    if len(header) != 12 or header[:8] != MAGIC or int.from_bytes(header[8:10], "big") != VERSION or header[10:] != b"\0\0": _fail("transfer_header_invalid")
    manifest: dict[str, Any] | None = None; chunks: list[bytes] = []; sequence = 0; frames = 0; total = 0; terminal = None
    while terminal is None:
        raw = stream.read(FRAME.size)
        if len(raw) != FRAME.size: _fail("transfer_frame_truncated")
        frame_type, flags, received_sequence, length = FRAME.unpack(raw)
        if flags or received_sequence != sequence or length > limits.max_frame_bytes: _fail("transfer_frame_invalid")
        payload = stream.read(length)
        if len(payload) != length: _fail("transfer_payload_truncated")
        frames += 1; total += length; sequence += 1
        if frames > limits.max_frames or total > limits.max_stream_bytes: _fail("transfer_limit_exceeded")
        if frame_type == MANIFEST:
            if manifest is not None or chunks: _fail("transfer_manifest_order_invalid")
            try: manifest = validate_artifact_manifest(json.loads(payload.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise V2ValidationError("transfer_manifest_invalid") from exc
        elif frame_type == ARCHIVE_CHUNK:
            if manifest is None: _fail("transfer_chunk_before_manifest")
            chunks.append(payload)
        elif frame_type in TERMINAL:
            terminal = frame_type
            if frame_type == FAILURE: _fail("transfer_failure_terminal")
            if manifest is None: _fail("transfer_success_without_manifest")
            try: success = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise V2ValidationError("transfer_success_invalid") from exc
            if success.get("archive_sha256") != SHA + sha256(b"".join(chunks)).hexdigest(): _fail("transfer_digest_mismatch")
        else: _fail("transfer_frame_unknown")
    if stream.read(1): _fail("transfer_trailing_bytes")
    return manifest, b"".join(chunks)


class BackendLock:
    """Global per-Docker-backend execution lock, shared by scheduler and doctor."""
    def __init__(self, database: Path):
        self.db = sqlite3.connect(database, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS backend_locks (backend TEXT PRIMARY KEY, incident_id TEXT, owner TEXT NOT NULL)")

    def acquire(self, backend: str, owner: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT incident_id,owner FROM backend_locks WHERE backend=?", (backend,)).fetchone()
            if row and row[0]: raise RuntimeError("containment_incident_blocks_backend")
            if row and row[1] != owner: raise RuntimeError("backend_busy")
            self.db.execute("INSERT INTO backend_locks(backend,incident_id,owner) VALUES(?,?,?) ON CONFLICT(backend) DO UPDATE SET owner=excluded.owner", (backend, None, owner))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK"); raise

    def record_incident(self, backend: str, incident_id: str) -> None:
        with self.db: self.db.execute("INSERT INTO backend_locks(backend,incident_id,owner) VALUES(?,?,?) ON CONFLICT(backend) DO UPDATE SET incident_id=excluded.incident_id", (backend, incident_id, "incident"))

    def resolve(self, backend: str, incident_id: str) -> None:
        with self.db:
            row = self.db.execute("SELECT incident_id FROM backend_locks WHERE backend=?", (backend,)).fetchone()
            if not row or row[0] != incident_id: raise RuntimeError("incident_resolution_mismatch")
            self.db.execute("UPDATE backend_locks SET incident_id=NULL,owner='resolved' WHERE backend=?", (backend,))

    def release(self, backend: str, owner: str) -> None:
        with self.db:
            row = self.db.execute("SELECT incident_id,owner FROM backend_locks WHERE backend=?", (backend,)).fetchone()
            if row and row[0] is None and row[1] == owner:
                self.db.execute("DELETE FROM backend_locks WHERE backend=?", (backend,))


class FinalizationJournal:
    def __init__(self, database: Path):
        self.db = sqlite3.connect(database)
        self.db.execute("CREATE TABLE IF NOT EXISTS finalization_journal (journal_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, run_id TEXT NOT NULL, manifest_hash TEXT NOT NULL, receipt_path TEXT NOT NULL, nonce TEXT NOT NULL, authority TEXT NOT NULL, phase TEXT NOT NULL)")
        self.db.commit()

    def prepare(self, journal_id: str, attempt: str, run: str, manifest_hash: str, receipt_path: str, nonce: str) -> None:
        _sha(manifest_hash, "manifest_hash")
        with self.db: self.db.execute("INSERT INTO finalization_journal VALUES(?,?,?,?,?,?,?,?)", (journal_id, attempt, run, manifest_hash, receipt_path, nonce, "host_supervisor", "PREPARED"))

    def phase(self, journal_id: str, expected: str, next_phase: str) -> None:
        """Advance only the frozen finalization state machine.

        The journal is the adoption authority after a crash; a receipt on disk
        without the matching durable phase is never elevated to evidence.
        """
        if (expected, next_phase) not in {("PREPARED", "RECEIPT_DURABLE"), ("RECEIPT_DURABLE", "TERMINAL_COMMITTED")}:
            raise ValueError("journal_phase_transition_invalid")
        with self.db:
            changed = self.db.execute("UPDATE finalization_journal SET phase=? WHERE journal_id=? AND phase=?", (next_phase, journal_id, expected)).rowcount
            if changed != 1: raise RuntimeError("journal_phase_conflict")

    def can_adopt(self, journal_id: str, attempt: str, manifest_hash: str, receipt_path: str) -> bool:
        row = self.db.execute("SELECT attempt_id,manifest_hash,receipt_path,authority,phase FROM finalization_journal WHERE journal_id=?", (journal_id,)).fetchone()
        return bool(row and row[:4] == (attempt, manifest_hash, receipt_path, "host_supervisor") and row[4] in {"PREPARED", "RECEIPT_DURABLE"})

    def record(self, journal_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT journal_id,attempt_id,run_id,manifest_hash,receipt_path,nonce,authority,phase FROM finalization_journal WHERE journal_id=?", (journal_id,)).fetchone()
        if not row: return None
        return dict(zip(("journal_id", "attempt_id", "run_id", "manifest_hash", "receipt_path", "nonce", "authority", "phase"), row))
