"""Non-privileged contract tests for final Session 1 closeout authority."""
from __future__ import annotations

from copy import deepcopy

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
