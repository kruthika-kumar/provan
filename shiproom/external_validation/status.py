"""Canonical effective-status resolver; markdown status summaries are views."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .trusted_attestation import TrustedAttestationError, load_trusted_attestation
from .v2 import V2ValidationError, validate_status_chain


_CLOSEOUT_CLAIMS = (
    "detection.docker_isolation", "detection.nonroot_patient", "detection.network_isolation", "detection.mount_isolation", "detection.capability_isolation", "detection.bounded_output_transfer", "detection.timeout_cleanup", "detection.background_quiescence", "detection.five_arm_separation", "detection.cache_isolation",
    "evidence.immutable_materialization", "evidence.source_sha_authority", "evidence.sealed_artifact_rehash", "evidence.receipt_v2_authority", "evidence.corpus_journal_authority", "evidence.scheduler_terminal_integrity",
    "remediation.xfs_byte_quota", "remediation.xfs_inode_quota", "remediation.aggregate_admission", "remediation.concurrent_quota_domains", "remediation.cross_attempt_isolation", "remediation.real_git_repair_lifecycle", "remediation.target_fail_to_pass", "remediation.protected_pass_to_pass", "remediation.real_patch_manifests", "remediation.authorization_tamper", "remediation.artifact_tamper", "remediation.residual_cwd", "remediation.residual_fd", "remediation.descriptor_relative_deletion", "remediation.project_clear", "remediation.project_retirement", "remediation.capacity_return", "remediation.source_immutability",
    "control.multi_incident_blocking", "control.partial_resolution_blocked", "control.final_resolution_ready", "control.capacity_replacement_blocked", "control.successor_capacity", "control.inactive_capacity_invariant", "control.migration_integrity",
    "attestation.root_owner_enforced", "attestation.trusted_parent_enforced", "attestation.symlink_rejected", "attestation.hardlink_rejected", "attestation.arbitrary_path_rejected", "attestation.descriptor_safe_read", "attestation.complete_closeout_binding", "attestation.baseline_binding", "attestation.reviewer_go_binding", "attestation.claim_audit_binding", "attestation.leakage_binding", "attestation.proof_only_scope", "attestation.public_fail_closed", "attestation.authorized_qualified", "attestation.historical_chain_preservation", "attestation.public_status_consistency", "attestation.no_session2_or_benchmark",
)


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _committed_file(root: Path, path: Path) -> None:
    """A current authority may not point at an uncommitted working-tree blob."""
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise V2ValidationError("status_authority_path_outside_repository") from exc
    try:
        git = ["git", "-c", "core.autocrlf=true", "-c", "safe.directory=" + str(root.resolve())]
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
            ["git", "-c", "core.autocrlf=true", "-c", "safe.directory=" + str(root.resolve()), "rev-parse", f"{revision}:{relative}"],
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
            ["git", "-c", "core.autocrlf=true", "-c", "safe.directory=" + str(root.resolve()), "show", "HEAD:" + relative],
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


def _committed_bytes(root: Path, revision: str, path: Path) -> bytes:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise V2ValidationError("status_authority_path_outside_repository") from exc
    try:
        result = subprocess.run(
            ["git", "-c", "core.autocrlf=true", "-c", "safe.directory=" + str(root.resolve()), "show", revision + ":" + relative],
            cwd=root, capture_output=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if result.returncode != 0:
        raise V2ValidationError("status_attestation_closeout_binding_invalid")
    return result.stdout


def _json_bytes(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V2ValidationError(code) from exc
    if not isinstance(value, dict):
        raise V2ValidationError(code)
    return value


def _hash_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _artifact_reference(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"} or not isinstance(value["path"], str) or not isinstance(value["sha256"], str) or not value["sha256"].startswith("sha256:"):
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    if value["path"].startswith("/") or ".." in Path(value["path"]).parts:
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    return {"path": value["path"], "sha256": value["sha256"]}


def validate_closeout_manifest_document(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "artifacts", "profiles", "prohibited_work"}
    artifact_keys = {"baseline", "baseline_view", "claim_audit", "claim_audit_view", "closeout_review", "closeout_review_view", "leakage_validation", "status_authority", "profile_status_chain", "control_plane_proof_manifest", "public_views"}
    flags = {"session2_work_performed", "benchmark_work_performed", "case_selection_performed", "model_selection_performed", "mutation_materialization_performed", "merge_performed", "tag_created"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session1_closeout_manifest.v1" or value.get("schema_version") != "1":
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    if not all(isinstance(value.get(key), str) and len(value[key]) == 40 for key in ("implementation_commit", "implementation_tree")):
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != artifact_keys:
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    for key in artifact_keys - {"public_views"}:
        _artifact_reference(artifacts[key])
    if not isinstance(artifacts["public_views"], list) or len(artifacts["public_views"]) != 3:
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    for row in artifacts["public_views"]:
        _artifact_reference(row)
    if value["profiles"] != {"detection": "QUALIFIED", "remediation": "QUALIFIED", "overall": "QUALIFIED"}:
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    if not isinstance(value["prohibited_work"], dict) or set(value["prohibited_work"]) != flags or any(item is not False for item in value["prohibited_work"].values()):
        raise V2ValidationError("status_attestation_closeout_manifest_invalid")
    return value


def validate_status_attestation_document(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "commit_b", "commit_b_tree", "control_plane_proof_manifest_hash", "status_authority_hash", "status_chain_hash", "closeout_manifest_path", "closeout_manifest_hash"}
    hashes = {"control_plane_proof_manifest_hash", "status_authority_hash", "status_chain_hash", "closeout_manifest_hash"}
    commits = {"implementation_commit", "implementation_tree", "commit_b", "commit_b_tree"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.status_attestation.v2" or value.get("schema_version") != "2":
        raise V2ValidationError("status_attestation_invalid")
    if any(not isinstance(value[key], str) or len(value[key]) != 40 or any(char not in "0123456789abcdef" for char in value[key]) for key in commits):
        raise V2ValidationError("status_attestation_invalid")
    if any(not isinstance(value[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) for key in hashes):
        raise V2ValidationError("status_attestation_invalid")
    if value["closeout_manifest_path"] != "external_validation/proofs/session1/session1_closeout_manifest.v1.json":
        raise V2ValidationError("status_attestation_invalid")
    return value


def _validate_baseline(value: dict[str, Any], *, implementation_commit: str, implementation_tree: str) -> None:
    required = {"schema_id", "schema_version", "commit", "tree", "command", "started_at", "finished_at", "duration_seconds", "exit_code", "passed", "skipped", "status", "transcript_hash"}
    if set(value) != required or value.get("schema_id") != "external_validation.session1_final_baseline.v1" or value.get("schema_version") != "1" or value.get("commit") != implementation_commit or value.get("tree") != implementation_tree or value.get("command") != ["python", "-m", "pytest", "-q"] or value.get("status") != "PASSED" or value.get("exit_code") != 0 or not isinstance(value.get("passed"), int) or value["passed"] < 1 or not isinstance(value.get("skipped"), int) or value["skipped"] < 0 or not isinstance(value.get("duration_seconds"), (int, float)) or value["duration_seconds"] <= 0 or not isinstance(value.get("transcript_hash"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value["transcript_hash"]) is None:
        raise V2ValidationError("status_attestation_baseline_invalid")


def _validate_review(value: dict[str, Any]) -> None:
    required = {"schema_id", "schema_version", "review_verdict", "qualification_status", "open_p0_count", "open_p1_count", "findings", "reviewed_commit", "reviewed_tree"}
    if set(value) != required or value.get("schema_id") != "external_validation.session1_closeout_review.v1" or value.get("schema_version") != "1" or value.get("review_verdict") != "GO" or value.get("open_p0_count") != 0 or value.get("open_p1_count") != 0 or not isinstance(value.get("findings"), list):
        raise V2ValidationError("status_attestation_review_invalid")


def _validate_claim_audit(value: dict[str, Any], *, root: Path | None = None, implementation_commit: str | None = None, artifact_keys: set[str] | None = None) -> None:
    if set(value) != {"schema_id", "schema_version", "claims"} or value.get("schema_id") != "external_validation.session1_claim_audit.v1" or value.get("schema_version") != "1" or not isinstance(value.get("claims"), list):
        raise V2ValidationError("status_attestation_claim_audit_invalid")
    seen: set[str] = set()
    required = {"claim_id", "status", "evidence_class", "implementation_refs", "positive_proof_refs", "negative_proof_refs", "artifact_refs"}
    for row in value["claims"]:
        if not isinstance(row, dict) or set(row) != required or row.get("claim_id") not in _CLOSEOUT_CLAIMS or row.get("status") != "CLOSED" or row.get("evidence_class") not in {"privileged_runtime", "non_privileged_semantic_adversarial", "static_contract", "retained_prior_qualification", "external_root_authority"}:
            raise V2ValidationError("status_attestation_claim_audit_invalid")
        if row["claim_id"] in seen or any(not isinstance(row[key], list) or not row[key] or any(not isinstance(item, str) for item in row[key]) for key in required - {"claim_id", "status", "evidence_class"}):
            raise V2ValidationError("status_attestation_claim_audit_invalid")
        if artifact_keys is not None:
            if any(item not in artifact_keys for key in ("positive_proof_refs", "negative_proof_refs", "artifact_refs") for item in row[key]):
                raise V2ValidationError("status_attestation_claim_audit_invalid")
            for source in row["implementation_refs"]:
                if not source.startswith("shiproom/") or root is None or implementation_commit is None:
                    raise V2ValidationError("status_attestation_claim_audit_invalid")
                _committed_bytes(root, implementation_commit, root / source)
        seen.add(row["claim_id"])
    if seen != set(_CLOSEOUT_CLAIMS):
        raise V2ValidationError("status_attestation_claim_audit_invalid")


def _validate_leakage(value: dict[str, Any], *, implementation_commit: str, implementation_tree: str) -> None:
    required = {"schema_id", "schema_version", "commit", "tree", "command", "exit_code", "status", "transcript_hash"}
    if set(value) != required or value.get("schema_id") != "external_validation.session1_leakage_validation.v1" or value.get("schema_version") != "1" or value.get("commit") != implementation_commit or value.get("tree") != implementation_tree or value.get("command") != ["python", "-c", "validate_public_tree(Path('.'))"] or value.get("status") != "PASSED" or value.get("exit_code") != 0 or not isinstance(value.get("transcript_hash"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value["transcript_hash"]) is None:
        raise V2ValidationError("status_attestation_leakage_invalid")


def _validate_external_attestation(
    *, root: Path, authority_path: Path, current_path: Path, profiles: dict[str, dict[str, Any]], attestation_id: str
) -> None:
    """Validate a descriptor-safe root authority against final Commit-B bytes."""
    try:
        data = load_trusted_attestation(attestation_id).document
    except TrustedAttestationError as exc:
        raise V2ValidationError(str(exc)) from exc
    required = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "commit_b", "commit_b_tree", "control_plane_proof_manifest_hash", "status_authority_hash", "status_chain_hash", "closeout_manifest_path", "closeout_manifest_hash"}
    validate_status_attestation_document(data)
    if data["status_authority_hash"] != _committed_content_hash(root, authority_path) or data["status_chain_hash"] != _committed_content_hash(root, current_path):
        raise V2ValidationError("status_attestation_binding_invalid")
    final_rows = list(profiles.values())
    implementation_commit = final_rows[0].get("implementation_commit")
    implementation_tree = final_rows[0].get("implementation_tree")
    proof_hash = final_rows[0].get("proof_bundle_hash")
    if not all(row.get("implementation_commit") == implementation_commit and row.get("implementation_tree") == implementation_tree and row.get("proof_bundle_hash") == proof_hash for row in final_rows):
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    if data["implementation_commit"] != implementation_commit or data["implementation_tree"] != implementation_tree or data["control_plane_proof_manifest_hash"] != proof_hash:
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    proof_path = root / "external_validation/proofs/session1/control_plane_repair_proof_manifest.json"
    if _committed_content_hash(root, proof_path) != proof_hash:
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    proof = _json_bytes(_committed_bytes(root, "HEAD", proof_path), "status_attestation_proof_binding_invalid")
    if proof.get("schema_id") != "external_validation.session1_control_plane_proof_manifest.v1" or proof.get("implementation_commit") != implementation_commit or proof.get("implementation_tree") != implementation_tree or proof.get("profiles") != final_rows[0].get("expected_profiles"):
        raise V2ValidationError("status_attestation_proof_binding_invalid")
    try:
        git = ["git", "-c", "safe.directory=" + str(root.resolve())]
        commit_tree = subprocess.run([*git, "rev-parse", data["commit_b"] + "^{tree}"], cwd=root, text=True, capture_output=True, check=False, timeout=10)
        ancestor = subprocess.run([*git, "merge-base", "--is-ancestor", data["commit_b"], "HEAD"], cwd=root, capture_output=True, check=False, timeout=10)
        implementation_tree_result = subprocess.run([*git, "rev-parse", implementation_commit + "^{tree}"], cwd=root, text=True, capture_output=True, check=False, timeout=10)
        implementation_ancestor = subprocess.run([*git, "merge-base", "--is-ancestor", implementation_commit, data["commit_b"]], cwd=root, capture_output=True, check=False, timeout=10)
        commit_paths = subprocess.run([*git, "diff-tree", "--no-commit-id", "--name-only", "-r", data["commit_b"]], cwd=root, text=True, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise V2ValidationError("status_attestation_commit_check_unavailable") from exc
    if commit_tree.returncode != 0 or ancestor.returncode != 0 or commit_tree.stdout.strip() != data["commit_b_tree"]:
        raise V2ValidationError("status_attestation_commit_binding_invalid")
    if implementation_tree_result.returncode != 0 or implementation_ancestor.returncode != 0 or implementation_tree_result.stdout.strip() != implementation_tree:
        raise V2ValidationError("status_attestation_implementation_binding_invalid")
    proof_only_prefixes = ("external_validation/proofs/", "external_validation/reviews/", "external_validation/status/", "external_validation/README.md", "README.md")
    if commit_paths.returncode != 0 or any(path and not path.startswith(proof_only_prefixes) and path != "README.md" for path in commit_paths.stdout.splitlines()):
        raise V2ValidationError("status_attestation_commit_scope_invalid")
    manifest_path = root / data["closeout_manifest_path"]
    expected_manifest_path = root / "external_validation/proofs/session1/session1_closeout_manifest.v1.json"
    if manifest_path != expected_manifest_path:
        raise V2ValidationError("status_attestation_closeout_binding_invalid")
    manifest_bytes = _committed_bytes(root, data["commit_b"], manifest_path)
    if _hash_bytes(manifest_bytes) != data["closeout_manifest_hash"] or _git_blob(root, data["commit_b"], manifest_path.relative_to(root).as_posix()) != _git_blob(root, "HEAD", manifest_path.relative_to(root).as_posix()):
        raise V2ValidationError("status_attestation_closeout_binding_invalid")
    manifest = validate_closeout_manifest_document(_json_bytes(manifest_bytes, "status_attestation_closeout_manifest_invalid"))
    if manifest["implementation_commit"] != implementation_commit or manifest["implementation_tree"] != implementation_tree:
        raise V2ValidationError("status_attestation_closeout_binding_invalid")
    artifacts = manifest["artifacts"]
    for key, reference in artifacts.items():
        rows = reference if key == "public_views" else [reference]
        for row in rows:
            target = root / row["path"]
            raw = _committed_bytes(root, data["commit_b"], target)
            relative = target.relative_to(root).as_posix()
            if _hash_bytes(raw) != row["sha256"] or _git_blob(root, data["commit_b"], relative) != _git_blob(root, "HEAD", relative):
                raise V2ValidationError("status_attestation_closeout_binding_invalid")
    _validate_baseline(_json_bytes(_committed_bytes(root, data["commit_b"], root / artifacts["baseline"]["path"]), "status_attestation_baseline_invalid"), implementation_commit=implementation_commit, implementation_tree=implementation_tree)
    _validate_review(_json_bytes(_committed_bytes(root, data["commit_b"], root / artifacts["closeout_review"]["path"]), "status_attestation_review_invalid"))
    _validate_claim_audit(_json_bytes(_committed_bytes(root, data["commit_b"], root / artifacts["claim_audit"]["path"]), "status_attestation_claim_audit_invalid"), root=root, implementation_commit=implementation_commit, artifact_keys=set(artifacts))
    _validate_leakage(_json_bytes(_committed_bytes(root, data["commit_b"], root / artifacts["leakage_validation"]["path"]), "status_attestation_leakage_invalid"), implementation_commit=implementation_commit, implementation_tree=implementation_tree)


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


def resolve_status_authority(authority_path: Path, *, repository_root: Path | None = None, attestation_id: str | None = None) -> dict[str, Any]:
    """Resolve the single current authority, never whichever chain is nearby."""
    root = repository_root or authority_path.parents[2]
    try: authority = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise V2ValidationError("status_authority_unreadable") from exc
    validate_status_authority_document(authority)
    _committed_file(root, authority_path)
    histories = authority["historical_chains"]
    if not isinstance(histories, list) or len(histories) != 1 or not isinstance(histories[0], dict): raise V2ValidationError("status_authority_historical_invalid")
    historical_ref = histories[0]; historical_path = root / str(historical_ref.get("path", ""))
    if not historical_path.is_file() or historical_ref.get("hash") != _committed_content_hash(root, historical_path): raise V2ValidationError("status_authority_historical_hash_invalid")
    _committed_file(root, historical_path)
    historical = resolve_status(historical_path)
    current_ref = authority["current_chain"]
    if not isinstance(current_ref, dict) or current_ref.get("schema_id") != "external_validation.profile_status_chain.v2": raise V2ValidationError("status_authority_current_invalid")
    current_path = root / str(current_ref.get("path", ""))
    if not current_path.is_file() or current_ref.get("hash") != _committed_content_hash(root, current_path): raise V2ValidationError("status_authority_current_hash_invalid")
    _committed_file(root, current_path)
    try: chain = json.loads(current_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc: raise V2ValidationError("status_authority_current_invalid") from exc
    profiles = _profile_chain(chain, {"status_id": historical["effective_status_id"]})
    resolved = {name: row["status"] for name, row in profiles.items()}
    # A final profile record is only effective when a root/external attestation
    # binds this committed authority.  Reopening needs no external attestation.
    if any(row["status"] == "QUALIFIED" for row in profiles.values()) and authority["current_status_activation"] == "external_attestation_required":
        if attestation_id is None:
            resolved["remediation"] = "BLOCKED" if resolved["remediation"] == "QUALIFIED" else resolved["remediation"]
            resolved["overall"] = "PARTIALLY_QUALIFIED"
        else:
            _validate_external_attestation(
                root=root,
                authority_path=authority_path,
                current_path=current_path,
                profiles=profiles,
                attestation_id=attestation_id,
            )
    return {"profiles": resolved, "profile_status_ids": {name: row["status_id"] for name, row in profiles.items()}, "historical": historical}


def main() -> int:
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--chain", type=Path); group.add_argument("--authority", type=Path); parser.add_argument("--attestation-id")
    args = parser.parse_args(); print(json.dumps(resolve_status(args.chain) if args.chain else resolve_status_authority(args.authority, attestation_id=args.attestation_id), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
