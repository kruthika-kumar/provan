"""Non-privileged contract tests for final Session 1 closeout authority."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from shiproom.external_validation import status
from shiproom.external_validation.trusted_attestation import TrustedAttestationError, validate_attestation_id
from shiproom.external_validation.v2 import V2ValidationError


def _ref(name: str) -> dict[str, str]:
    return {"path": "external_validation/proofs/session1/" + name, "sha256": "sha256:" + "a" * 64}


def _manifest() -> dict[str, object]:
    return {
        "schema_id": "external_validation.session1_closeout_manifest.v1", "schema_version": "1",
        "implementation_commit": "a" * 40, "implementation_tree": "b" * 40,
        "artifacts": {
            "baseline": _ref("baseline.json"), "baseline_view": _ref("baseline.md"),
            "claim_audit": _ref("audit.json"), "claim_audit_view": _ref("audit.md"),
            "closeout_review": _ref("review.json"), "closeout_review_view": _ref("review.md"),
            "leakage_validation": _ref("leakage.json"), "status_authority": _ref("authority.json"),
            "profile_status_chain": _ref("chain.json"), "control_plane_proof_manifest": _ref("control.json"),
            "public_views": [_ref("readme.md"), _ref("external-readme.md"), _ref("effective-status.md")],
        },
        "profiles": {"detection": "QUALIFIED", "remediation": "QUALIFIED", "overall": "QUALIFIED"},
        "prohibited_work": {"session2_work_performed": False, "benchmark_work_performed": False, "case_selection_performed": False, "model_selection_performed": False, "mutation_materialization_performed": False, "merge_performed": False, "tag_created": False},
    }


def _claim_audit() -> dict[str, object]:
    return {"schema_id": "external_validation.session1_claim_audit.v1", "schema_version": "1", "claims": [{"claim_id": claim, "status": "CLOSED", "evidence_class": "static_contract", "implementation_refs": ["impl"], "positive_proof_refs": ["positive"], "negative_proof_refs": ["negative"], "artifact_refs": ["artifact"]} for claim in status._CLOSEOUT_CLAIMS]}


def test_identifier_is_exact_lowercase_content_address() -> None:
    assert validate_attestation_id("a" * 64) == "a" * 64
    for value in ("A" * 64, "sha256:" + "a" * 64, "a" * 63, " " + "a" * 64):
        with pytest.raises(TrustedAttestationError, match="status_attestation_id_invalid"):
            validate_attestation_id(value)


def test_closeout_manifest_is_acyclic_and_requires_all_public_views() -> None:
    assert status.validate_closeout_manifest_document(_manifest())["schema_id"].endswith("v1")
    bad = deepcopy(_manifest()); bad["proof_only_commit"] = "c" * 40
    with pytest.raises(V2ValidationError, match="status_attestation_closeout_manifest_invalid"):
        status.validate_closeout_manifest_document(bad)
    bad = deepcopy(_manifest()); bad["prohibited_work"]["session2_work_performed"] = True
    with pytest.raises(V2ValidationError, match="status_attestation_closeout_manifest_invalid"):
        status.validate_closeout_manifest_document(bad)
    bad = deepcopy(_manifest()); bad["artifacts"]["public_views"] = []
    with pytest.raises(V2ValidationError, match="status_attestation_closeout_manifest_invalid"):
        status.validate_closeout_manifest_document(bad)


def test_claim_audit_has_exactly_the_stable_closed_claim_set() -> None:
    audit = _claim_audit(); status._validate_claim_audit(audit)
    assert len(audit["claims"]) == 58
    duplicate = deepcopy(audit); duplicate["claims"][-1]["claim_id"] = duplicate["claims"][0]["claim_id"]
    with pytest.raises(V2ValidationError, match="status_attestation_claim_audit_invalid"):
        status._validate_claim_audit(duplicate)
    pending = deepcopy(audit); pending["claims"][0]["status"] = "PENDING"
    with pytest.raises(V2ValidationError, match="status_attestation_claim_audit_invalid"):
        status._validate_claim_audit(pending)


def test_attestation_v2_has_no_self_hash_or_unpinned_commit() -> None:
    value = {"schema_id": "external_validation.status_attestation.v2", "schema_version": "2", "implementation_commit": "a" * 40, "implementation_tree": "b" * 40, "commit_b": "c" * 40, "commit_b_tree": "d" * 40, "control_plane_proof_manifest_hash": "sha256:" + "e" * 64, "status_authority_hash": "sha256:" + "f" * 64, "status_chain_hash": "sha256:" + "0" * 64, "closeout_manifest_path": "external_validation/proofs/session1/session1_closeout_manifest.v1.json", "closeout_manifest_hash": "sha256:" + "1" * 64}
    assert status.validate_status_attestation_document(value)["commit_b"] == "c" * 40
    value["attestation_hash"] = "sha256:" + "2" * 64
    with pytest.raises(V2ValidationError, match="status_attestation_invalid"):
        status.validate_status_attestation_document(value)


def _write_json(path: Path, value: object) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def test_authorized_resolution_binds_distinct_runtime_and_closeout_identities(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A retained runtime proof may predate the final closeout implementation."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "session1@example.invalid")
    _git(tmp_path, "config", "user.name", "Session 1")
    _git(tmp_path, "config", "core.autocrlf", "false")
    (tmp_path / "shiproom").mkdir()
    (tmp_path / "shiproom" / "implementation.py").write_text("closeout = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "implementation")
    implementation_commit = _git(tmp_path, "rev-parse", "HEAD")
    implementation_tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")

    runtime_commit, runtime_tree = "1" * 40, "2" * 40
    expected_profiles = {"detection": "QUALIFIED", "remediation": "QUALIFIED", "overall": "QUALIFIED"}
    proof_path = tmp_path / "external_validation/proofs/session1/control_plane_repair_proof_manifest.json"
    proof_raw = _write_json(proof_path, {"schema_id": "external_validation.session1_control_plane_proof_manifest.v1", "implementation_commit": runtime_commit, "implementation_tree": runtime_tree, "profiles": expected_profiles})
    authority_path = tmp_path / "external_validation/status/authority.json"
    chain_path = tmp_path / "external_validation/status/chain.json"
    _write_json(authority_path, {"authority": "test"})
    _write_json(chain_path, {"chain": "test"})
    baseline_path = tmp_path / "external_validation/proofs/session1/final_baseline.v1.json"
    _write_json(baseline_path, {"schema_id": "external_validation.session1_final_baseline.v1", "schema_version": "1", "commit": implementation_commit, "tree": implementation_tree, "command": ["python", "-m", "pytest", "-q"], "started_at": "2026-07-28T00:00:00Z", "finished_at": "2026-07-28T00:00:01Z", "duration_seconds": 1, "exit_code": 0, "passed": 1, "skipped": 0, "status": "PASSED", "transcript_hash": "sha256:" + "3" * 64})
    leakage_path = tmp_path / "external_validation/proofs/session1/leakage_validation.v1.json"
    _write_json(leakage_path, {"schema_id": "external_validation.session1_leakage_validation.v1", "schema_version": "1", "commit": implementation_commit, "tree": implementation_tree, "command": ["python", "-c", "validate_public_tree(Path('.'))"], "exit_code": 0, "status": "PASSED", "transcript_hash": "sha256:" + "4" * 64})
    review_path = tmp_path / "external_validation/reviews/session1_closeout_review.v1.json"
    _write_json(review_path, {"schema_id": "external_validation.session1_closeout_review.v1", "schema_version": "1", "review_verdict": "GO", "qualification_status": "QUALIFIED", "open_p0_count": 0, "open_p1_count": 0, "findings": [], "reviewed_commit": implementation_commit, "reviewed_tree": implementation_tree})
    audit_path = tmp_path / "external_validation/reviews/session1_claim_audit.v1.json"
    audit = _claim_audit()
    for claim in audit["claims"]:
        claim["implementation_refs"] = ["shiproom/implementation.py"]
        claim["positive_proof_refs"] = ["control_plane_proof_manifest"]
        claim["negative_proof_refs"] = ["control_plane_proof_manifest"]
        claim["artifact_refs"] = ["control_plane_proof_manifest"]
    _write_json(audit_path, audit)
    views = []
    view_paths = (
        "external_validation/proofs/session1/baseline.md",
        "external_validation/proofs/session1/audit.md",
        "external_validation/proofs/session1/review.md",
        "README.md",
        "external_validation/README.md",
        "external_validation/reviews/session1_effective_status.md",
    )
    for name in view_paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name + "\n", encoding="utf-8")
        views.append(path)
    paths = {
        "baseline": baseline_path, "baseline_view": views[0], "claim_audit": audit_path,
        "claim_audit_view": views[1], "closeout_review": review_path,
        "closeout_review_view": views[2], "leakage_validation": leakage_path,
        "status_authority": authority_path, "profile_status_chain": chain_path,
        "control_plane_proof_manifest": proof_path,
    }
    def reference(path: Path) -> dict[str, str]:
        return {"path": path.relative_to(tmp_path).as_posix(), "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()}
    artifacts = {key: reference(path) for key, path in paths.items()}
    artifacts["public_views"] = [reference(path) for path in views[3:]]
    manifest_path = tmp_path / "external_validation/proofs/session1/session1_closeout_manifest.v1.json"
    manifest_raw = _write_json(manifest_path, {"schema_id": "external_validation.session1_closeout_manifest.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "artifacts": artifacts, "profiles": expected_profiles, "prohibited_work": {"session2_work_performed": False, "benchmark_work_performed": False, "case_selection_performed": False, "model_selection_performed": False, "mutation_materialization_performed": False, "merge_performed": False, "tag_created": False}})
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "proof-only closeout")
    commit_b = _git(tmp_path, "rev-parse", "HEAD")
    commit_b_tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")
    attestation = {"schema_id": "external_validation.status_attestation.v2", "schema_version": "2", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "commit_b": commit_b, "commit_b_tree": commit_b_tree, "control_plane_proof_manifest_hash": "sha256:" + hashlib.sha256(proof_raw).hexdigest(), "status_authority_hash": "sha256:" + hashlib.sha256(authority_path.read_bytes()).hexdigest(), "status_chain_hash": "sha256:" + hashlib.sha256(chain_path.read_bytes()).hexdigest(), "closeout_manifest_path": manifest_path.relative_to(tmp_path).as_posix(), "closeout_manifest_hash": "sha256:" + hashlib.sha256(manifest_raw).hexdigest()}
    monkeypatch.setattr(status, "load_trusted_attestation", lambda _: SimpleNamespace(document=attestation))
    profiles = {profile: {"implementation_commit": runtime_commit, "implementation_tree": runtime_tree, "proof_bundle_hash": attestation["control_plane_proof_manifest_hash"], "expected_profiles": expected_profiles} for profile in expected_profiles}
    status._validate_external_attestation(root=tmp_path, authority_path=authority_path, current_path=chain_path, profiles=profiles, attestation_id="a" * 64)
