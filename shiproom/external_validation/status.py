"""Canonical effective-status resolver; markdown status summaries are views."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .v2 import V2ValidationError, validate_status_chain


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _profile_chain(value: Any, historical: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_id", "schema_version", "historical_anchor", "profiles"}:
        raise V2ValidationError("profile_status_chain_document_invalid")
    if value["schema_id"] != "external_validation.profile_status_chain.v2" or value["schema_version"] != "2":
        raise V2ValidationError("profile_status_chain_header_invalid")
    anchor, profiles = value["historical_anchor"], value["profiles"]
    if not isinstance(anchor, dict) or not isinstance(profiles, dict) or set(profiles) != {"detection", "remediation", "overall"}:
        raise V2ValidationError("profile_status_chain_shape_invalid")
    if anchor.get("effective_status_id") != historical["status_id"]:
        raise V2ValidationError("profile_status_historical_anchor_invalid")
    result: dict[str, Any] = {}
    for profile, records in profiles.items():
        if not isinstance(records, list) or not records:
            raise V2ValidationError("profile_status_records_invalid")
        seen: dict[str, dict[str, Any]] = {}
        children: dict[str, list[str]] = {}
        for record in records:
            if not isinstance(record, dict) or set(record) != {"status_id", "predecessor_status_id", "profile", "status", "implementation_commit", "timestamp"}:
                raise V2ValidationError("profile_status_record_invalid")
            if record["profile"] != profile or not all(isinstance(record[key], str) and record[key] for key in ("status_id", "profile", "status", "implementation_commit", "timestamp")):
                raise V2ValidationError("profile_status_record_invalid")
            if len(record["implementation_commit"]) != 40 or any(c not in "0123456789abcdef" for c in record["implementation_commit"]):
                raise V2ValidationError("profile_status_commit_invalid")
            if record["status_id"] in seen: raise V2ValidationError("profile_status_duplicate")
            seen[record["status_id"]] = record
            parent = record["predecessor_status_id"]
            if parent is not None:
                if not isinstance(parent, str): raise V2ValidationError("profile_status_predecessor_invalid")
                if parent != historical["status_id"]: children.setdefault(parent, []).append(record["status_id"])
        local_children = {key: value for key, value in children.items() if key in seen}
        if any(len(values) > 1 for values in local_children.values()): raise V2ValidationError("profile_status_competing_successors")
        current = [record for record in seen.values() if record["status_id"] not in local_children]
        if len(current) != 1: raise V2ValidationError("profile_status_current_ambiguous")
        cursor = current[0]; visited: set[str] = set()
        while cursor["predecessor_status_id"] in seen:
            if cursor["status_id"] in visited: raise V2ValidationError("profile_status_cycle")
            visited.add(cursor["status_id"]); cursor = seen[cursor["predecessor_status_id"]]
        if cursor["predecessor_status_id"] != historical["status_id"]: raise V2ValidationError("profile_status_anchor_missing")
        result[profile] = current[0]
    return result


def resolve_status(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"schema_id", "schema_version", "records"} or value["schema_id"] != "external_validation.status_chain.v1" or value["schema_version"] != "1" or not isinstance(value["records"], list):
        raise V2ValidationError("status_chain_document_invalid")
    current = validate_status_chain(value["records"])
    return {"effective_status": current["status"], "effective_status_id": current["status_id"], "commit_sha": current["commit_sha"], "branch": current["branch"], "scope": current["scope"]}


def resolve_status_authority(authority_path: Path, *, repository_root: Path | None = None, attestation: Path | None = None) -> dict[str, Any]:
    """Resolve the single current authority, never whichever chain is nearby."""
    root = repository_root or authority_path.parents[2]
    try: authority = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise V2ValidationError("status_authority_unreadable") from exc
    required = {"schema_id", "schema_version", "historical_chains", "current_chain", "current_status_activation", "predecessor_branch", "predecessor_commit"}
    if set(authority) != required or authority["schema_id"] != "external_validation.status_authority.v1" or authority["schema_version"] != "1":
        raise V2ValidationError("status_authority_invalid")
    histories = authority["historical_chains"]
    if not isinstance(histories, list) or len(histories) != 1 or not isinstance(histories[0], dict): raise V2ValidationError("status_authority_historical_invalid")
    historical_ref = histories[0]; historical_path = root / str(historical_ref.get("path", ""))
    if not historical_path.is_file() or historical_ref.get("hash") != _hash(historical_path): raise V2ValidationError("status_authority_historical_hash_invalid")
    historical = resolve_status(historical_path)
    current_ref = authority["current_chain"]
    if not isinstance(current_ref, dict) or current_ref.get("schema_id") != "external_validation.profile_status_chain.v2": raise V2ValidationError("status_authority_current_invalid")
    current_path = root / str(current_ref.get("path", ""))
    if not current_path.is_file() or current_ref.get("hash") != _hash(current_path): raise V2ValidationError("status_authority_current_hash_invalid")
    try: chain = json.loads(current_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc: raise V2ValidationError("status_authority_current_invalid") from exc
    profiles = _profile_chain(chain, {"status_id": historical["effective_status_id"]})
    resolved = {name: row["status"] for name, row in profiles.items()}
    # A final profile record is only effective when a root/external attestation
    # binds this committed authority.  Reopening needs no external attestation.
    if any(row["status"] == "QUALIFIED" for row in profiles.values()) and authority["current_status_activation"] == "external_attestation_required":
        if attestation is None or not attestation.is_file():
            resolved["remediation"] = "BLOCKED" if resolved["remediation"] == "QUALIFIED" else resolved["remediation"]
            resolved["overall"] = "PARTIALLY_QUALIFIED"
        else:
            data = json.loads(attestation.read_text(encoding="utf-8"))
            if data.get("status_authority_hash") != _hash(authority_path): raise V2ValidationError("status_attestation_binding_invalid")
    return {"profiles": resolved, "profile_status_ids": {name: row["status_id"] for name, row in profiles.items()}, "historical": historical}


def main() -> int:
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--chain", type=Path); group.add_argument("--authority", type=Path); parser.add_argument("--attestation", type=Path)
    args = parser.parse_args(); print(json.dumps(resolve_status(args.chain) if args.chain else resolve_status_authority(args.authority, attestation=args.attestation), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
