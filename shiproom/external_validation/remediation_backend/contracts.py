"""Independent semantic validators for remediation backend contracts."""
from __future__ import annotations
import re
from typing import Any

SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
AUTH = re.compile(r"^authorization_[a-f0-9]{32}$")
REQUIRED_AUTH = {"schema_id", "schema_version", "authorization_id", "backend_instance_id", "attempt_id", "project_id", "allocation_record_id", "capacity_reservation_id", "worktree_authority", "source_snapshot_hash", "sealed_artifact_manifest_hash", "receipt_id", "patch_hash", "changed_file_manifest_hash", "untracked_file_manifest_hash", "test_result_hashes", "log_hashes", "artifact_records", "supervisor_package_hash", "created_at"}

class ContractError(ValueError):
    def __init__(self, code: str): self.code = code; super().__init__(code)

def _hash(value: object) -> None:
    if not isinstance(value, str) or not SHA.fullmatch(value): raise ContractError("hash_invalid")

def validate_release_authorization(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict): raise ContractError("authorization_type_invalid")
    if set(value) != REQUIRED_AUTH: raise ContractError("authorization_shape_invalid")
    if value["schema_id"] != "remediation_release_authorization.v1" or value["schema_version"] != "1": raise ContractError("authorization_version_invalid")
    if not isinstance(value["authorization_id"], str) or not AUTH.fullmatch(value["authorization_id"]): raise ContractError("authorization_id_invalid")
    if not isinstance(value["project_id"], int) or isinstance(value["project_id"], bool) or value["project_id"] < 1: raise ContractError("authorization_project_invalid")
    authority = value["worktree_authority"]
    required_authority = {"backend_instance_id", "attempt_id", "project_id", "allocation_record_id", "capacity_reservation_id", "canonical_path", "path_hash", "device", "inode", "mount_id", "uid", "gid", "source_snapshot_hash"}
    if not isinstance(authority, dict) or set(authority) != required_authority: raise ContractError("worktree_authority_invalid")
    if not isinstance(authority["canonical_path"], str) or not authority["canonical_path"].startswith("/"): raise ContractError("worktree_path_invalid")
    _hash(authority["path_hash"])
    _hash(authority["source_snapshot_hash"])
    if any(not isinstance(authority[key], int) or isinstance(authority[key], bool) or authority[key] < 0 for key in {"project_id", "device", "inode", "mount_id", "uid", "gid"}): raise ContractError("worktree_stat_invalid")
    for field in {"backend_instance_id", "attempt_id", "allocation_record_id", "capacity_reservation_id"}:
        if not isinstance(authority[field], str) or not authority[field]: raise ContractError("worktree_binding_invalid")
    for field in {"backend_instance_id", "attempt_id", "project_id", "allocation_record_id", "capacity_reservation_id", "source_snapshot_hash"}:
        if authority[field] != value[field]: raise ContractError("worktree_binding_mismatch")
    for field in {"source_snapshot_hash", "sealed_artifact_manifest_hash", "patch_hash", "changed_file_manifest_hash", "untracked_file_manifest_hash", "supervisor_package_hash"}: _hash(value[field])
    for field in {"test_result_hashes", "log_hashes"}:
        if not isinstance(value[field], list) or any(not isinstance(item, str) or not SHA.fullmatch(item) for item in value[field]): raise ContractError("authorization_artifacts_invalid")
    records = value["artifact_records"]
    if not isinstance(records, list) or not records: raise ContractError("authorization_artifact_records_invalid")
    seen_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"kind", "canonical_path", "sha256"}: raise ContractError("authorization_artifact_record_shape_invalid")
        if not isinstance(record["kind"], str) or not record["kind"] or not isinstance(record["canonical_path"], str) or not record["canonical_path"].startswith("/"): raise ContractError("authorization_artifact_record_path_invalid")
        _hash(record["sha256"])
        if record["canonical_path"] in seen_paths: raise ContractError("authorization_artifact_record_duplicate")
        seen_paths.add(record["canonical_path"])
    if any(not isinstance(value[field], str) or not value[field] for field in {"backend_instance_id", "attempt_id", "allocation_record_id", "capacity_reservation_id", "receipt_id", "created_at"}): raise ContractError("authorization_binding_invalid")
    return value
