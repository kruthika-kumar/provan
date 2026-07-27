"""Canonical effective-status resolver; markdown status summaries are views."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .v2 import V2ValidationError, validate_status_chain


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _committed_file(root: Path, path: Path) -> None:
    """A current authority may not point at an uncommitted working-tree blob."""
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise V2ValidationError("status_authority_path_outside_repository") from exc
    try:
        git = ["git", "-c", "safe.directory=" + str(root.resolve())]
        expected = subprocess.run([*git, "rev-parse", "HEAD:" + relative], cwd=root, text=True, capture_output=True, check=False, timeout=10)
        actual = subprocess.run([*git, "hash-object", "--path=" + relative, str(path)], cwd=root, text=True, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_authority_commit_check_unavailable") from exc
    # Compare Git blob identities rather than raw working-tree bytes: Windows
    # checkouts may legitimately apply CRLF filters while still representing
    # the exact committed authority blob.  An uncommitted semantic change
    # produces a different filtered blob hash and remains fail-closed.
    if expected.returncode != 0 or actual.returncode != 0 or expected.stdout.strip() != actual.stdout.strip():
        raise V2ValidationError("status_authority_uncommitted_blob")


def _git_blob(root: Path, revision: str, relative: str) -> str:
    """Return one committed blob ID, failing closed on an unavailable Git view."""
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=" + str(root.resolve()), "rev-parse", f"{revision}:{relative}"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if result.returncode != 0 or len(result.stdout.strip()) != 40:
        raise V2ValidationError("status_attestation_commit_binding_invalid")
    return result.stdout.strip()


def _committed_content_hash(root: Path, path: Path) -> str:
    """SHA-256 the canonical committed bytes, never checkout line endings."""
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise V2ValidationError("status_authority_path_outside_repository") from exc
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=" + str(root.resolve()), "show", "HEAD:" + relative],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if result.returncode != 0:
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    return "sha256:" + hashlib.sha256(result.stdout).hexdigest()


def _validate_external_attestation(
    *, root: Path, authority_path: Path, current_path: Path, profiles: dict[str, dict[str, Any]], attestation: Path
) -> None:
    """Validate the external Commit-B attestation against actual Git objects.

    The attestation is deliberately outside Git.  It must therefore bind the
    committed authority/chain/proof bytes and the implementation identity, not
    merely repeat hashes supplied by a caller.
    """
    if attestation.is_symlink() or not attestation.is_file() or attestation.stat().st_mode & 0o022:
        raise V2ValidationError("status_attestation_insecure_file")
    try:
        data = json.loads(attestation.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V2ValidationError("status_attestation_invalid") from exc
    required = {"schema_id", "schema_version", "commit_b", "commit_b_tree", "proof_bundle_hash", "status_authority_hash", "status_chain_hash"}
    if not isinstance(data, dict) or set(data) != required or data.get("schema_id") != "external_validation.status_attestation.v1" or data.get("schema_version") != "1":
        raise V2ValidationError("status_attestation_invalid")
    if data.get("status_authority_hash") != _hash(authority_path) or data.get("status_chain_hash") != _hash(current_path):
        raise V2ValidationError("status_attestation_binding_invalid")
    final_rows = list(profiles.values())
    if (
        not all(isinstance(data[key], str) for key in ("commit_b", "commit_b_tree", "proof_bundle_hash"))
        or any(row.get("proof_bundle_hash") != data["proof_bundle_hash"] for row in final_rows)
        or any(row.get("implementation_commit") != final_rows[0].get("implementation_commit") or row.get("implementation_tree") != final_rows[0].get("implementation_tree") for row in final_rows)
    ):
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    proof_path = root / "external_validation/proofs/session1/control_plane_repair_proof_manifest.json"
    if not proof_path.is_file() or _committed_content_hash(root, proof_path) != data["proof_bundle_hash"]:
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V2ValidationError("status_attestation_proof_binding_invalid") from exc
    implementation_commit = final_rows[0]["implementation_commit"]
    implementation_tree = final_rows[0]["implementation_tree"]
    expected_profiles = final_rows[0]["expected_profiles"]
    if (
        not isinstance(proof, dict)
        or proof.get("schema_id") != "external_validation.session1_control_plane_proof_manifest.v1"
        or proof.get("implementation_commit") != implementation_commit
        or proof.get("implementation_tree") != implementation_tree
        or proof.get("profiles") != expected_profiles
    ):
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    try:
        git = ["git", "-c", "safe.directory=" + str(root.resolve())]
        commit_tree = subprocess.run([*git, "rev-parse", str(data["commit_b"]) + "^{tree}"], cwd=root, text=True, capture_output=True, check=False, timeout=10)
        ancestor = subprocess.run([*git, "merge-base", "--is-ancestor", str(data["commit_b"]), "HEAD"], cwd=root, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if commit_tree.returncode != 0 or ancestor.returncode != 0 or commit_tree.stdout.strip() != data["commit_b_tree"]:
        raise V2ValidationError("status_attestation_commit_binding_invalid")
    try:
        commit_paths = subprocess.run(
            [*git, "diff-tree", "--no-commit-id", "--name-only", "-r", str(data["commit_b"])],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    proof_only_prefixes = (
        "external_validation/proofs/",
        "external_validation/reviews/",
        "external_validation/status/",
        "external_validation/README.md",
    )
    if commit_paths.returncode != 0 or any(
        path and not path.startswith(proof_only_prefixes) for path in commit_paths.stdout.splitlines()
    ):
        raise V2ValidationError("status_attestation_commit_scope_invalid")
    try:
        implementation_tree_result = subprocess.run(
            [*git, "rev-parse", implementation_commit + "^{tree}"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        implementation_ancestor = subprocess.run(
            [*git, "merge-base", "--is-ancestor", implementation_commit, str(data["commit_b"])],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if (
        implementation_tree_result.returncode != 0
        or implementation_ancestor.returncode != 0
        or implementation_tree_result.stdout.strip() != implementation_tree
    ):
        raise V2ValidationError("status_attestation_implementation_binding_invalid")
    for path in (authority_path, current_path, proof_path):
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        if _git_blob(root, str(data["commit_b"]), relative) != _git_blob(root, "HEAD", relative):
            raise V2ValidationError("status_attestation_commit_binding_invalid")


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
            base = {"status_id", "predecessor_status_id", "profile", "status", "implementation_commit", "timestamp"}
            final = base | {"implementation_tree", "proof_bundle_hash", "predecessor_status_ids", "expected_profiles"}
            if not isinstance(record, dict) or (set(record) != base and set(record) != final):
                raise V2ValidationError("profile_status_record_invalid")
            if record["profile"] != profile or not all(isinstance(record[key], str) and record[key] for key in ("status_id", "profile", "status", "implementation_commit", "timestamp")):
                raise V2ValidationError("profile_status_record_invalid")
            if len(record["implementation_commit"]) != 40 or any(c not in "0123456789abcdef" for c in record["implementation_commit"]):
                raise V2ValidationError("profile_status_commit_invalid")
            if record["status_id"] in seen: raise V2ValidationError("profile_status_duplicate")
            if set(record) == final:
                if (not isinstance(record["implementation_tree"], str) or len(record["implementation_tree"]) != 40
                        or not isinstance(record["proof_bundle_hash"], str) or not record["proof_bundle_hash"].startswith("sha256:")
                        or not isinstance(record["predecessor_status_ids"], dict) or set(record["predecessor_status_ids"]) != {"detection", "remediation", "overall"}
                        or not isinstance(record["expected_profiles"], dict) or set(record["expected_profiles"]) != {"detection", "remediation", "overall"}):
                    raise V2ValidationError("profile_status_qualification_binding_invalid")
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


def validate_profile_status_chain(value: Any) -> dict[str, Any]:
    """Independent structural/semantic validator for the v2 profile chain.

    File hashes and committed-blob authority are intentionally checked only by
    :func:`resolve_status_authority`; this validator handles the contract that
    can be assessed from the chain bytes alone.
    """
    if not isinstance(value, dict) or not isinstance(value.get("historical_anchor"), dict):
        raise V2ValidationError("profile_status_chain_document_invalid")
    anchor = value["historical_anchor"]
    required = {"chain_path", "chain_hash", "effective_status_id", "predecessor_branch", "predecessor_commit"}
    if set(anchor) != required or not isinstance(anchor["chain_hash"], str) or not anchor["chain_hash"].startswith("sha256:"):
        raise V2ValidationError("profile_status_historical_anchor_invalid")
    # The isolated status ID is a placeholder for the historical resolver; it
    # permits the same full chain validation without reading another authority.
    return _profile_chain(value, {"status_id": anchor["effective_status_id"]})


def validate_status_authority_document(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "historical_chains", "current_chain", "current_status_activation", "predecessor_branch", "predecessor_commit"}
    if not isinstance(value, dict) or set(value) != required or value["schema_id"] != "external_validation.status_authority.v1" or value["schema_version"] != "1":
        raise V2ValidationError("status_authority_invalid")
    if not isinstance(value["historical_chains"], list) or len(value["historical_chains"]) != 1:
        raise V2ValidationError("status_authority_historical_invalid")
    if not isinstance(value["current_chain"], dict) or value["current_chain"].get("schema_id") != "external_validation.profile_status_chain.v2":
        raise V2ValidationError("status_authority_current_invalid")
    if not isinstance(value["predecessor_commit"], str) or len(value["predecessor_commit"]) != 40:
        raise V2ValidationError("status_authority_predecessor_invalid")
    return value


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
    validate_status_authority_document(authority)
    _committed_file(root, authority_path)
    histories = authority["historical_chains"]
    if not isinstance(histories, list) or len(histories) != 1 or not isinstance(histories[0], dict): raise V2ValidationError("status_authority_historical_invalid")
    historical_ref = histories[0]; historical_path = root / str(historical_ref.get("path", ""))
    if not historical_path.is_file() or historical_ref.get("hash") != _hash(historical_path): raise V2ValidationError("status_authority_historical_hash_invalid")
    _committed_file(root, historical_path)
    historical = resolve_status(historical_path)
    current_ref = authority["current_chain"]
    if not isinstance(current_ref, dict) or current_ref.get("schema_id") != "external_validation.profile_status_chain.v2": raise V2ValidationError("status_authority_current_invalid")
    current_path = root / str(current_ref.get("path", ""))
    if not current_path.is_file() or current_ref.get("hash") != _hash(current_path): raise V2ValidationError("status_authority_current_hash_invalid")
    _committed_file(root, current_path)
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
            _validate_external_attestation(
                root=root,
                authority_path=authority_path,
                current_path=current_path,
                profiles=profiles,
                attestation=attestation,
            )
    return {"profiles": resolved, "profile_status_ids": {name: row["status_id"] for name, row in profiles.items()}, "historical": historical}


def main() -> int:
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--chain", type=Path); group.add_argument("--authority", type=Path); parser.add_argument("--attestation", type=Path)
    args = parser.parse_args(); print(json.dumps(resolve_status(args.chain) if args.chain else resolve_status_authority(args.authority, attestation=args.attestation), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
