from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from shiproom.external_validation import session2_closeout as closeout


ROOT = Path(__file__).parents[1]


def _document() -> dict:
    return json.loads((ROOT / closeout.PROOF_ROOT / "session2_partial_closeout.v1.json").read_text(encoding="utf-8"))


def test_canonical_closeout_bundle_validates() -> None:
    result = closeout.validate_repository_bundle(ROOT)
    assert result["status"] == "CLOSED_PARTIAL"
    assert result["artifact_count"] >= 8


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda value: value["active_claim"].__setitem__("candidate_outcome", "PASSED"), "active_claim_invalid"),
        (lambda value: value["execution_counts"].__setitem__("shiproom_execution_count", 1), "evaluated_work_present"),
        (lambda value: value["allocator_state"].__setitem__("real_recovery_allocation_created", True), "recovery_allocation_present"),
        (lambda value: value["portfolio"].__setitem__("controlled_pairs_completed", 3), "portfolio_invalid"),
        (lambda value: value["authority_sources"][0].__setitem__("sha256", "missing"), "evidence_ref_invalid"),
        (lambda value: value["public_claim_limitations"].append("/var/lib/private"), "private_path_leak"),
        (lambda value: value["model_usage"].__setitem__("fabricated_evaluated_result", "PASS"), "schema_invalid"),
        (lambda value: value["active_claim"].__setitem__("queue_logical_hash", "sha256:" + "1" * 64), "queue_authority_changed"),
    ],
)
def test_closeout_rejects_fabricated_or_unsafe_evidence(mutate, code: str) -> None:
    value = deepcopy(_document()); mutate(value)
    with pytest.raises(closeout.Session2CloseoutError, match=code):
        closeout.validate_partial_closeout(value)


def test_handoff_rejects_unsupported_public_example() -> None:
    value = json.loads((ROOT / closeout.HANDOFF_PATH).read_text(encoding="utf-8"))
    value["assets"][0]["classification"] = "PUBLIC_SAFE_EXAMPLE"
    with pytest.raises(closeout.Session2CloseoutError, match="public_example_unsupported"):
        closeout.validate_handoff(value)


def test_handoff_rejects_unsupported_claim_authorized_asset() -> None:
    value = json.loads((ROOT / closeout.HANDOFF_PATH).read_text(encoding="utf-8"))
    value["assets"].append({"asset_id": "invented", "classification": "PUBLIC_SAFE_CONTROL_PLANE",
                            "claim_authorized": True, "evidence_refs": [], "limitations": []})
    with pytest.raises(closeout.Session2CloseoutError, match="claim_evidence_missing"):
        closeout.validate_handoff(value)


def test_manifest_rejects_missing_or_changed_artifact(tmp_path: Path) -> None:
    target = tmp_path / "proof.json"; target.write_bytes(b"{}")
    row = {"path": "proof.json", "sha256": "sha256:" + "0" * 64}
    manifest = {"schema_id": "external_validation.session2_closeout_manifest.v1", "schema_version": "1",
                "implementation_commit": "a" * 40, "implementation_tree": "b" * 40, "status": "CLOSED_PARTIAL",
                "proof_set_root": "sha256:" + "0" * 64, "artifacts": [row]}
    with pytest.raises(closeout.Session2CloseoutError, match="manifest_hash_invalid"):
        closeout.validate_manifest(manifest, tmp_path, {"implementation_commit": "a" * 40, "implementation_tree": "b" * 40})


def test_manifest_rejects_changed_implementation_identity(tmp_path: Path) -> None:
    manifest = {"schema_id": "external_validation.session2_closeout_manifest.v1", "schema_version": "1",
                "implementation_commit": "a" * 40, "implementation_tree": "b" * 40, "status": "CLOSED_PARTIAL",
                "proof_set_root": "sha256:" + "0" * 64, "artifacts": []}
    with pytest.raises(closeout.Session2CloseoutError, match="manifest_identity_invalid"):
        closeout.validate_manifest(manifest, tmp_path, {"implementation_commit": "c" * 40, "implementation_tree": "b" * 40})


def test_state_inspection_rejects_changed_queue_bytes() -> None:
    document = _document()
    value = json.loads((ROOT / closeout.PROOF_ROOT / "session2_closeout_state_inspection.v1.json").read_text(encoding="utf-8"))
    value["queue_database_sha256"] = "sha256:" + "1" * 64
    with pytest.raises(closeout.Session2CloseoutError, match="queue_authority_changed"):
        closeout.validate_state_inspection(value, document)


def test_state_inspection_rejects_contradictory_extra_field() -> None:
    document = _document()
    value = json.loads((ROOT / closeout.PROOF_ROOT / "session2_closeout_state_inspection.v1.json").read_text(encoding="utf-8"))
    value["real_recovery_allocation_created"] = True
    with pytest.raises(closeout.Session2CloseoutError, match="state_inspection_invalid"):
        closeout.validate_state_inspection(value, document)


def test_leakage_rejects_contradictory_extra_field() -> None:
    value = json.loads((ROOT / closeout.PROOF_ROOT / "session2_leakage_validation.v1.json").read_text(encoding="utf-8"))
    value["private_payload_present"] = True
    with pytest.raises(closeout.Session2CloseoutError, match="leakage_invalid"):
        closeout.validate_leakage(value)
