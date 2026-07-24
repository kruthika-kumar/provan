from __future__ import annotations

import io
import json
from pathlib import Path
import struct

import pytest

from shiproom.external_validation.identity import canonical_json, attempt_id
from shiproom.external_validation.v2 import (
    ARCHIVE_CHUNK, FRAME, MAGIC, MANIFEST, SUCCESS, BackendLock,
    FinalizationJournal, TransferLimits, V2ValidationError, artifact_manifest_id,
    observation_key_v2, parse_transfer, receipt_id_v2, validate_artifact_manifest,
    validate_receipt_v2, validate_status_chain,
)
from shiproom.external_validation.scheduler import RunScheduler
from shiproom.external_validation.proof_views import public_doctor_view, sanitize_proof
from shiproom.external_validation.status import resolve_status

H = "sha256:" + "a" * 64


def _manifest() -> dict:
    artifacts = [{"path":"result.txt","type":"regular","mode":420,"size":2,"sha256":"sha256:" + "8f" * 32,"producer":"patient","sealer":"host_supervisor","trust":"untrusted_patient","truncated":False}]
    return {"schema_id":"external_validation.artifact_manifest.v1","schema_version":"1","artifacts":artifacts,"aggregate_bytes":2,"tree_hash":"sha256:" + __import__("hashlib").sha256(canonical_json({"artifacts":artifacts,"aggregate_bytes":2})).hexdigest()}


def _frame(frame_type: int, sequence: int, payload: bytes) -> bytes:
    return FRAME.pack(frame_type, 0, sequence, len(payload)) + payload


def _receipt() -> dict:
    image = "example.invalid/runner@" + H
    inputs = {"case_id":"case_a","snapshot_hash":H,"arm":"NATIVE_CHECKS_ONLY","system_version":"a" * 40,"prompt_version":"p","policy_version":"p","model":"none","model_settings":{},"model_sampling_seed":None,"tool_policy_version":"t","execution_policy_version":"policy-v2","cache_mode":"cold","runner_image_digest":image,"execution_policy_hash":H}
    observation = observation_key_v2(inputs)
    return {"schema_id":"external_validation.run_receipt.v2","schema_version":"2","observation_key":observation,"observation_inputs":inputs,"attempt_id":attempt_id(observation,1),"attempt_lineage":1,"case_id":"case_a","arm":"NATIVE_CHECKS_ONLY","repository":"synthetic/repository","commit_sha":"a" * 40,"release_surfaces":["service"],"source_hash":H,"release_packet_hash":H,"artifact_manifest_hash":H,"container":{"id":"cid","name":"name","requested_policy_hash":H,"effective_inspect_hash":H,"runner_image_digest":image,"teardown":"proven","residual_absence":True},"execution":{"started_at":"2026-07-24T00:00:00Z","completed_at":"2026-07-24T00:00:01Z","monotonic_seconds":1,"shiproom_commit":"a" * 40,"package_tree_hash":H,"artifact_protocol_version":"SRXFER02","wrapper_version":"1","cache_policy_version":"1","security_policy_version":"1","resource_policy_hash":H},"model_usage":{"state":"not_applicable"},"cost":{"state":"not_applicable"},"applicability":{},"termination":"completed","evidence_eligible":True,"finalization_journal_id":"journal_a","supervisor":"host_supervisor"}


def test_manifest_is_canonical_and_rejects_casefold_collision():
    manifest = _manifest(); assert validate_artifact_manifest(manifest) == manifest
    collision = json.loads(json.dumps(manifest)); collision["artifacts"].append({**collision["artifacts"][0], "path":"RESULT.txt"})
    collision["aggregate_bytes"] = 4
    with pytest.raises(V2ValidationError, match="artifact_path_collision"):
        validate_artifact_manifest(collision)


def test_transfer_protocol_rejects_untrusted_shape_and_trailing_data():
    manifest = _manifest(); archive = b"archive"
    success = json.dumps({"archive_sha256":"sha256:" + __import__("hashlib").sha256(archive).hexdigest()}, separators=(",", ":")).encode()
    stream = io.BytesIO(MAGIC + (2).to_bytes(2,"big") + b"\0\0" + _frame(MANIFEST,0,canonical_json(manifest)) + _frame(ARCHIVE_CHUNK,1,archive) + _frame(SUCCESS,2,success))
    assert parse_transfer(stream, TransferLimits(4096, 4, 4096))[0]["tree_hash"] == manifest["tree_hash"]
    malformed = io.BytesIO(MAGIC + (2).to_bytes(2,"big") + b"\0\0" + _frame(MANIFEST,0,canonical_json(manifest)) + _frame(ARCHIVE_CHUNK,1,archive) + _frame(SUCCESS,2,success) + b"x")
    with pytest.raises(V2ValidationError, match="transfer_trailing_bytes"):
        parse_transfer(malformed, TransferLimits(4096, 4, 4096))


def test_receipt_v2_binds_runner_identity_and_never_self_hashes():
    receipt = _receipt(); assert validate_receipt_v2(receipt) == receipt
    changed = json.loads(json.dumps(receipt)); changed["observation_inputs"]["runner_image_digest"] = "sha256:" + "b" * 64
    with pytest.raises(V2ValidationError, match="observation_identity_mismatch"):
        validate_receipt_v2(changed)
    assert receipt_id_v2(receipt).startswith("receipt_") and "receipt_id" not in receipt


def test_status_resolver_fails_closed_and_journal_requires_exact_binding(tmp_path: Path):
    initial = {"schema_id":"external_validation.status_supersession.v1","schema_version":"1","status_id":"original","predecessor_status_id":None,"commit_sha":"a" * 40,"branch":"old","scope":"session1","timestamp":"2026-07-24T00:00:00Z","status":"QUALIFIED"}
    reopening = {**initial,"status_id":"reopened","predecessor_status_id":"original","branch":"repair","status":"REOPENED"}
    assert validate_status_chain([initial,reopening])["status"] == "REOPENED"
    with pytest.raises(V2ValidationError, match="status_competing_successors"):
        validate_status_chain([initial,reopening,{**reopening,"status_id":"other"}])
    journal = FinalizationJournal(tmp_path / "journal.sqlite"); journal.prepare("j","attempt","run",H,"receipts/a.json","nonce")
    assert journal.can_adopt("j","attempt",H,"receipts/a.json")
    journal.phase("j", "PREPARED", "RECEIPT_DURABLE")
    assert journal.record("j")["phase"] == "RECEIPT_DURABLE"
    assert not journal.can_adopt("j","other",H,"receipts/a.json")


def test_backend_lock_blocks_other_worker_after_incident(tmp_path: Path):
    first = BackendLock(tmp_path / "locks.sqlite"); second = BackendLock(tmp_path / "locks.sqlite")
    first.acquire("daemon", "owner-one"); first.record_incident("daemon", "incident")
    with pytest.raises(RuntimeError, match="containment_incident_blocks_backend"):
        second.acquire("daemon", "owner-two")


def test_terminal_scheduler_recovery_cannot_reopen_finalized_operation(tmp_path: Path):
    path = tmp_path / "runs.sqlite"; scheduler = RunScheduler(path)
    scheduler.enqueue("obs", "attempt"); scheduler.freeze_schedule(["obs"], "seed")
    scheduler.begin_operation("obs", "operation"); scheduler.finalize("obs", "receipt")
    scheduler.db.close()
    reopened = RunScheduler(path); assert reopened.recover_interrupted() == []
    assert reopened.db.execute("SELECT state,receipt_id FROM runs WHERE observation_key='obs'").fetchone() == ("TERMINAL", "receipt")
    assert reopened.db.execute("SELECT state FROM operations WHERE operation_id='operation'").fetchone()[0] == "TERMINAL"


def test_schedule_freeze_rejects_omitted_enqueued_observation(tmp_path: Path):
    scheduler = RunScheduler(tmp_path / "runs.sqlite")
    scheduler.enqueue("one", "attempt-one"); scheduler.enqueue("two", "attempt-two")
    with pytest.raises(ValueError, match="schedule_run_set_incomplete"):
        scheduler.freeze_schedule(["one"], "seed")


def test_public_proof_view_is_deterministic_and_non_qualifying():
    canonical = {"result":"passed","container_id":"private","external_root":"C:/private"}
    one = sanitize_proof(canonical, canonical_hash=H, policy_version="1", tool_hash=H)
    two = sanitize_proof(canonical, canonical_hash=H, policy_version="1", tool_hash=H)
    assert one == two and one["authority"] == "non_qualifying_public_view"
    assert "container_id" not in one["proof"] and "external_root" not in one["proof"]
    doctor = {"implementation_commit":"a"*40,"source_tree":"b"*40,"runner_image":"example/runner@"+H,"adversarial_canaries":{"timeout":"proven"},"proof":{"corpus":{"receipt_count":5}}}
    assert public_doctor_view(doctor, canonical_hash=H, policy_version="1", tool_hash=H) == public_doctor_view(doctor, canonical_hash=H, policy_version="1", tool_hash=H)


def test_status_document_resolves_reopening_and_rejects_bad_document(tmp_path: Path):
    records = [
        {"schema_id":"external_validation.status_supersession.v1","schema_version":"1","status_id":"old","predecessor_status_id":None,"commit_sha":"a"*40,"branch":"old","scope":"session1","timestamp":"now","status":"QUALIFIED"},
        {"schema_id":"external_validation.status_supersession.v1","schema_version":"1","status_id":"new","predecessor_status_id":"old","commit_sha":"b"*40,"branch":"new","scope":"session1","timestamp":"later","status":"REOPENED"},
    ]
    path = tmp_path / "status.json"; path.write_text(json.dumps({"schema_id":"external_validation.status_chain.v1","schema_version":"1","records":records}), encoding="utf-8")
    assert resolve_status(path)["effective_status"] == "REOPENED"
