from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "artifacts/session12/successor_closeout"
PROOFS = BASE / "proofs"
IMPLEMENTATION = "eb2d0781faf614c17b7af5a2f2477440d0b10402"
TREE = "8ffcf0d242ad5f92962d51533a04b6a11c33ab8f"
PROOF_DESCENDANT = "27e2e31e261cd87df47b37ea135b62b186d981e4"
WHEEL_SHA = "sha256:e158c090728bb06b5f8e2a1d686719e58ece8b1c023863c7b348f146ce1b4093"
PRE_ROOT = "sha256:a8c5bec5a6f49a1fbbd78bcd286ee034db282f51c639078db7517043368502b9"
EVIDENCE_ROOT = "sha256:c055fa361de0eabcacb41e0486ec6bdad9320a977934452cb9aef634155d8dc6"
HIDDEN_FAILED = {56, 59, 70, 71, 75, 76, 77, 79, 80, 81, 88, 89, 90}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(value: bool, code: str) -> None:
    if not value:
        raise SystemExit(code)


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), "SESSION12R_CLOSEOUT_OBJECT_INVALID")
    return value


def safe_ref(row: dict[str, object]) -> bytes:
    path = row.get("path")
    require(isinstance(path, str) and path == Path(path).as_posix() and not Path(path).is_absolute() and ".." not in Path(path).parts, "SESSION12R_CLOSEOUT_REF_PATH_UNSAFE")
    current = ROOT
    for part in Path(path).parts:
        current = current / part
        require(current.exists() and not current.is_symlink(), "SESSION12R_CLOSEOUT_REF_LINK_OR_MISSING")
    require(current.is_file() and current.resolve().is_relative_to(ROOT.resolve()), "SESSION12R_CLOSEOUT_REF_NOT_REGULAR_CONTAINED")
    raw = current.read_bytes()
    require(row.get("bytes") == len(raw) and row.get("sha256") == digest(raw), "SESSION12R_CLOSEOUT_REF_HASH_MISMATCH")
    return raw


def validate_receipt(value: dict[str, object], role: str) -> None:
    require(value.get("schema_id") == "provan.session12r_reviewer_receipt.v1" and value.get("sensitivity") == "PUBLIC_SAFE", "SESSION12R_REVIEW_RECEIPT_SURFACE_INVALID")
    require(value.get("reviewer_role") == role and value.get("reviewer_mode") == "fresh_read_only" and value.get("verdict") == "GO_PARTIAL", "SESSION12R_REVIEW_RECEIPT_IDENTITY_INVALID")
    require(value.get("reviewed_commit") == IMPLEMENTATION and value.get("reviewed_tree") == TREE and value.get("reviewed_proof_descendant") == PROOF_DESCENDANT, "SESSION12R_REVIEW_RECEIPT_IMPLEMENTATION_MISMATCH")
    require(value.get("reviewed_pre_review_root") == PRE_ROOT and value.get("reviewed_evidence_root") == EVIDENCE_ROOT and value.get("wheel_sha256") == WHEEL_SHA, "SESSION12R_REVIEW_RECEIPT_ROOT_MISMATCH")
    require(value.get("session_12_successor") == "CLOSED_PARTIAL" and value.get("go_session_13") is False, "SESSION12R_REVIEW_RECEIPT_OUTCOME_INVALID")
    require(value.get("mode_qualification") == {"standard": "IMPLEMENTED_UNQUALIFIED", "deep": "IMPLEMENTED_UNQUALIFIED"}, "SESSION12R_REVIEW_RECEIPT_MATURITY_INVALID")
    rows = value.get("claim_dispositions")
    require(isinstance(rows, list) and [row.get("claim_id") for row in rows] == [f"G12R-{n:02d}" for n in range(1, 98)], "SESSION12R_REVIEW_RECEIPT_CLAIMS_INVALID")
    expected = set(HIDDEN_FAILED) | ({61} if role == "B" else set())
    rejected = {n for n, row in enumerate(rows, 1) if row.get("result") == "REJECTED"}
    require(all(row.get("result") in {"ACCEPTED", "REJECTED"} for row in rows) and rejected == expected, "SESSION12R_REVIEW_RECEIPT_DISPOSITION_MISMATCH")


def main() -> int:
    hidden = load(PROOFS / "hidden_qualification_projection.v1.public.json")
    require(hidden.get("failure_code") == "HIDDEN_HOLDOUT_COVERAGE_MATRIX_INCOMPLETE" and hidden.get("session_12_successor") == "CLOSED_PARTIAL" and hidden.get("go_session_13") is False, "SESSION12R_HIDDEN_PARTIAL_OUTCOME_INVALID")
    receipts = {role: load(PROOFS / f"reviewer_receipt_{role.lower()}.v1.public.json") for role in ("A", "B")}
    for role, value in receipts.items():
        validate_receipt(value, role)
    claims = load(BASE / "authority/claim_registry.v1.public.json")
    matrix = load(BASE / "layer4_claim_matrix.final.v1.public.json")
    require(matrix.get("claim_registry_digest") == claims.get("registry_digest") and matrix.get("reviewed_pre_review_root") == PRE_ROOT and matrix.get("gate_result") == "CLOSED_PARTIAL", "SESSION12R_FINAL_MATRIX_BINDING_INVALID")
    rows = matrix.get("claims")
    require(isinstance(rows, list) and len(rows) == 97 and matrix.get("accepted_count") == 83 and matrix.get("rejected_count") == 14, "SESSION12R_FINAL_MATRIX_COUNTS_INVALID")
    for index, row in enumerate(rows, 1):
        require(row.get("claim_id") == f"G12R-{index:02d}" and row.get("normative_claim") == claims["claims"][index - 1]["normative_claim"], "SESSION12R_FINAL_MATRIX_WORDING_INVALID")
        expected_a = receipts["A"]["claim_dispositions"][index - 1]["result"]
        expected_b = receipts["B"]["claim_dispositions"][index - 1]["result"]
        expected_status = "REJECTED" if "REJECTED" in {expected_a, expected_b} else "ACCEPTED"
        require(row.get("reviewer_a") == expected_a and row.get("reviewer_b") == expected_b and row.get("status") == expected_status, "SESSION12R_FINAL_MATRIX_REVIEW_MISMATCH")
    manifest = load(PROOFS / "final_proof_manifest.v1.public.json")
    require(manifest.get("phase") == "FINAL_PARTIAL" and manifest.get("implementation_commit") == IMPLEMENTATION and manifest.get("implementation_tree") == TREE and manifest.get("proof_descendant") == PROOF_DESCENDANT and manifest.get("wheel_sha256") == WHEEL_SHA and manifest.get("reviewed_pre_review_root") == PRE_ROOT, "SESSION12R_FINAL_MANIFEST_BINDING_INVALID")
    entries = manifest.get("entries")
    require(isinstance(entries, list) and entries and manifest.get("reviewer_outputs_excluded") is False, "SESSION12R_FINAL_MANIFEST_ENTRIES_INVALID")
    required = {"reviewer_receipt_a.v1.public.json", "reviewer_receipt_b.v1.public.json", "layer4_claim_matrix.final.v1.public.json", "pre_review_proof_manifest.v1.public.json", "hidden_qualification_projection.v1.public.json", "session13_handoff_candidate.v2.public.json", "operational_status.v1.public.json"}
    require(required <= {Path(str(row.get("path"))).name for row in entries}, "SESSION12R_FINAL_MANIFEST_REQUIRED_SET_MISSING")
    for row in entries:
        safe_ref(row)
    require(manifest.get("proof_root") == digest(canonical(entries)), "SESSION12R_FINAL_MANIFEST_ROOT_INVALID")
    closeout = load(BASE / "closeout.v1.public.json")
    require(closeout.get("session_12_successor") == "CLOSED_PARTIAL" and closeout.get("go_session_13") is False and closeout.get("final_proof_root") == manifest.get("proof_root"), "SESSION12R_CLOSEOUT_OUTCOME_INVALID")
    require(closeout.get("implementation_commit") == IMPLEMENTATION and closeout.get("implementation_tree") == TREE and closeout.get("wheel_sha256") == WHEEL_SHA and closeout.get("reviewed_pre_review_root") == PRE_ROOT, "SESSION12R_CLOSEOUT_BINDING_INVALID")
    require(closeout.get("mode_qualification") == {"standard": "IMPLEMENTED_UNQUALIFIED", "deep": "IMPLEMENTED_UNQUALIFIED"}, "SESSION12R_CLOSEOUT_MATURITY_INVALID")
    require(closeout.get("package_published") is False and closeout.get("release_created") is False and closeout.get("tag_created") is False and closeout.get("session13_implemented") is False and closeout.get("execution_available") is False and closeout.get("challenge_available") is False, "SESSION12R_CLOSEOUT_BOUNDARY_INVALID")
    for row in closeout.get("reviewer_receipts", []):
        safe_ref(row)
    safe_ref(closeout["final_matrix"])
    status = load(BASE / "authority/operational_status.v1.public.json")
    require(status.get("session_12_successor") == "CLOSED_PARTIAL" and status.get("go_session_13") is False and status.get("historical_closeout_current_authority") is False, "SESSION12R_OPERATIONAL_STATUS_INVALID")
    note = load(BASE / "supersession_finalization.v1.public.json")
    require(note.get("successor_status") == "CLOSED_PARTIAL" and note.get("go_session_13") is False and note.get("historical_status") == "HISTORICALLY_VALID_FOR_ORIGINAL_IMPLEMENTATION_ONLY", "SESSION12R_SUPERSESSION_INVALID")
    for key in ("current_operational_status", "current_closeout", "historical_closeout_preserved"):
        safe_ref(note[key])
    print("SESSION12R_PARTIAL_CLOSEOUT_VALID", manifest["proof_root"], matrix["accepted_count"], matrix["rejected_count"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
