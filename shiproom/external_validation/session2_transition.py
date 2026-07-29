"""Derive a Session 2 pair transition solely from sealed supervisor receipts."""
from __future__ import annotations

from hashlib import sha256
import argparse
import json
import os
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


def seal_pair_transition(specification_path: Path, receipts_directory: Path, output_directory: Path) -> dict[str, Any]:
    """Supervisor-owned, content-addressed transition finalization."""
    if not specification_path.is_file() or specification_path.is_symlink():
        _fail("session2_transition_spec_missing")
    raw = specification_path.read_bytes()
    if (not specification_path.name.endswith(".pair-transition-spec.json")
            or "sha256:" + specification_path.name.removesuffix(".pair-transition-spec.json") != _hash(raw)):
        _fail("session2_transition_spec_hash_mismatch")
    try:
        specification = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Session2TransitionError("session2_transition_spec_invalid") from exc
    if canonical_json(specification) != raw:
        _fail("session2_transition_spec_noncanonical")
    record = compile_pair_transition(specification, receipts_directory)
    payload = canonical_json(record)
    digest = _hash(payload)
    output_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = output_directory / (digest[7:] + ".pair-execution-transition.json")
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if target.is_symlink() or target.read_bytes() != payload:
            _fail("session2_transition_output_collision")
    else:
        try:
            if os.write(descriptor, payload) != len(payload):
                _fail("session2_transition_short_write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name == "posix":
            parent = os.open(output_directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
            try: os.fsync(parent)
            finally: os.close(parent)
    return {"transition_hash": digest, "transition_path": str(target), "record": record}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive a Session 2 pair transition from sealed receipts.")
    parser.add_argument("--specification", required=True, type=Path)
    parser.add_argument("--receipts-directory", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(seal_pair_transition(args.specification, args.receipts_directory, args.output_directory), sort_keys=True, separators=(",", ":")))
    except Session2TransitionError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
