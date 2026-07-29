"""Derive a Session 2 pair transition solely from sealed supervisor receipts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .identity import canonical_json

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_FIELDS = {"schema_id", "schema_version", "case_id", "candidate_id", "candidate_index_hash", "buggy_materialization_hash", "fixed_materialization_hash", "target_buggy_receipt_hash", "target_fixed_receipt_hash", "protected_buggy_receipt_hash", "protected_fixed_receipt_hash"}


class Session2TransitionError(ValueError):
    pass


def _fail(code: str) -> None:
    raise Session2TransitionError(code)


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def validate_pair_transition_spec(value: Any) -> dict[str, Any]:
    """Validate a pre-execution contract naming four immutable receipts."""
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or value.get("schema_id") != "external_validation.session2_pair_transition_spec.v1"
            or value.get("schema_version") != "1"):
        _fail("session2_transition_spec_invalid")
    if not isinstance(value["case_id"], str) or not _OPAQUE.fullmatch(value["case_id"]) or not isinstance(value["candidate_id"], str) or not value["candidate_id"]:
        _fail("session2_transition_spec_invalid")
    for key in _FIELDS - {"schema_id", "schema_version", "case_id", "candidate_id"}:
        _sha(value[key], "session2_transition_spec_invalid")
    if len({value[key] for key in ("target_buggy_receipt_hash", "target_fixed_receipt_hash", "protected_buggy_receipt_hash", "protected_fixed_receipt_hash")}) != 4:
        _fail("session2_transition_spec_duplicate_receipt")
    return value


def _receipt(directory: Path, digest: str) -> dict[str, Any]:
    path = directory / (digest[7:] + ".execution-receipt.json")
    if not path.is_file() or path.is_symlink():
        _fail("session2_transition_receipt_missing")
    raw = path.read_bytes()
    if _hash(raw) != digest:
        _fail("session2_transition_receipt_hash_mismatch")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Session2TransitionError("session2_transition_receipt_invalid") from exc
    minimum = {"schema_id", "schema_version", "source_record_hash", "exit_code", "expected_exit_code", "contract_satisfied", "container_digest", "network_policy", "stdout", "stderr", "result_contract_id"}
    if (canonical_json(value) != raw or not isinstance(value, dict)
            or value.get("schema_id") != "external_validation.session2_execution_receipt.v1"
            or value.get("schema_version") != "1" or not minimum.issubset(value)
            or value.get("contract_satisfied") is not True
            or value.get("network_policy") != "none"
            or not isinstance(value.get("exit_code"), int)
            or value["exit_code"] != value.get("expected_exit_code")
            or not isinstance(value.get("result_contract_id"), str) or not value["result_contract_id"]):
        _fail("session2_transition_receipt_invalid")
    _sha(value["source_record_hash"], "session2_transition_receipt_invalid")
    _sha(value["container_digest"], "session2_transition_receipt_invalid")
    for name in ("stdout", "stderr"):
        stream = value[name]
        if not isinstance(stream, dict) or set(stream) != {"opaque_id", "bytes", "sha256"} or not isinstance(stream["opaque_id"], str) or not _OPAQUE.fullmatch(stream["opaque_id"]) or not isinstance(stream["bytes"], int) or stream["bytes"] < 0:
            _fail("session2_transition_stream_invalid")
        content = directory / stream["opaque_id"]
        if not content.is_file() or content.is_symlink() or len(content.read_bytes()) != stream["bytes"] or _hash(content.read_bytes()) != _sha(stream["sha256"], "session2_transition_stream_invalid"):
            _fail("session2_transition_stream_hash_mismatch")
    return value


def compile_pair_transition(specification: dict[str, Any], receipts_directory: Path) -> dict[str, Any]:
    """Derive execution feasibility; no caller supplied pass boolean exists."""
    spec = validate_pair_transition_spec(specification)
    roles = {
        "target_buggy": ("target_buggy_receipt_hash", spec["buggy_materialization_hash"], 1),
        "target_fixed": ("target_fixed_receipt_hash", spec["fixed_materialization_hash"], 0),
        "protected_buggy": ("protected_buggy_receipt_hash", spec["buggy_materialization_hash"], 0),
        "protected_fixed": ("protected_fixed_receipt_hash", spec["fixed_materialization_hash"], 0),
    }
    image = None
    for role, (field, materialization, expected) in roles.items():
        receipt = _receipt(receipts_directory, spec[field])
        if receipt["source_record_hash"] != materialization or receipt["exit_code"] != expected:
            _fail("session2_transition_receipt_contract_mismatch")
        if image is None: image = receipt["container_digest"]
        elif image != receipt["container_digest"]: _fail("session2_transition_environment_mismatch")
        needle = "target" if role.startswith("target") else "protected"
        if needle not in receipt["result_contract_id"]:
            _fail("session2_transition_role_contract_invalid")
    return {
        "schema_id": "external_validation.session2_pair_execution_transition.v1", "schema_version": "1",
        "case_id": spec["case_id"], "candidate_id": spec["candidate_id"],
        "candidate_index_hash": spec["candidate_index_hash"],
        "buggy_materialization_hash": spec["buggy_materialization_hash"],
        "fixed_materialization_hash": spec["fixed_materialization_hash"],
        "runner_image_digest": image,
        "target_buggy_receipt_hash": spec["target_buggy_receipt_hash"],
        "target_fixed_receipt_hash": spec["target_fixed_receipt_hash"],
        "protected_buggy_receipt_hash": spec["protected_buggy_receipt_hash"],
        "protected_fixed_receipt_hash": spec["protected_fixed_receipt_hash"],
        "buggy_target_oracle": "EXPECTED_FAILURE", "fixed_target_oracle": "PASSED",
        "buggy_protected_checks": "PASSED", "fixed_protected_checks": "PASSED",
    }
