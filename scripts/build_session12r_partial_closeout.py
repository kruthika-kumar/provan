from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
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


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def ref(path: str) -> dict[str, object]:
    raw = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(raw), "sha256": sha(raw)}


def dispositions(role: str) -> list[dict[str, str]]:
    rejected = set(HIDDEN_FAILED)
    if role == "B":
        rejected.add(61)
    return [{"claim_id": f"G12R-{n:02d}", "result": "REJECTED" if n in rejected else "ACCEPTED"} for n in range(1, 98)]


def main() -> int:
    claims = json.loads((BASE / "authority/claim_registry.v1.public.json").read_bytes())
    hidden = json.loads((PROOFS / "hidden_qualification_projection.v1.public.json").read_bytes())
    if hidden.get("session_12_successor") != "CLOSED_PARTIAL" or hidden.get("go_session_13") is not False:
        raise SystemExit("SESSION12R_PARTIAL_OUTCOME_NOT_BOUND")
    if hidden.get("qualified_holdout_count") != 0 or hidden.get("adjudicators_executed") != 0:
        raise SystemExit("SESSION12R_PARTIAL_HIDDEN_COUNTS_INVALID")
    write(BASE / "authority/operational_status.v1.public.json", {
        "schema_id": "provan.session12r_operational_status.v1", "sensitivity": "PUBLIC_SAFE",
        "session_12_successor": "CLOSED_PARTIAL", "go_session_13": False,
        "historical_closeout_current_authority": False,
        "reason": "HIDDEN_HOLDOUT_COVERAGE_MATRIX_INCOMPLETE_BEFORE_FREEZE",
        "claim_registry_digest": claims["registry_digest"],
        "standard_maturity": "IMPLEMENTED_UNQUALIFIED", "deep_maturity": "IMPLEMENTED_UNQUALIFIED",
    })
    common = {
        "schema_id": "provan.session12r_reviewer_receipt.v1", "sensitivity": "PUBLIC_SAFE",
        "reviewer_mode": "fresh_read_only", "reviewed_commit": IMPLEMENTATION, "reviewed_tree": TREE,
        "reviewed_proof_descendant": PROOF_DESCENDANT, "reviewed_pre_review_root": PRE_ROOT,
        "reviewed_evidence_root": EVIDENCE_ROOT, "wheel_sha256": WHEEL_SHA, "verdict": "GO_PARTIAL",
        "session_12_successor": "CLOSED_PARTIAL", "go_session_13": False,
        "mode_qualification": {"standard": "IMPLEMENTED_UNQUALIFIED", "deep": "IMPLEMENTED_UNQUALIFIED"},
    }
    write(PROOFS / "reviewer_receipt_a.v1.public.json", {
        **common, "reviewer_role": "A", "findings": {"P0": 0, "P1": 0, "P2": 0, "items": []},
        "claim_dispositions": dispositions("A"),
        "limitations": ["NO_HIDDEN_SEMANTIC_RESULT", "NO_PRE_OUTCOME_REVIEW", "NO_SEMANTIC_ADJUDICATORS_EXECUTED", "EXECUTION_AND_CHALLENGE_UNAVAILABLE", "SESSION13_NOT_AUTHORIZED"],
        "identity_limitations": ["READ_ONLY_CODEX_REVIEWER_WITHOUT_EXTERNAL_ORGANISATIONAL_OR_SIGNED_MODEL_BUILD_IDENTITY_ATTESTATION"],
    })
    write(PROOFS / "reviewer_receipt_b.v1.public.json", {
        **common, "reviewer_role": "B", "findings": {"P0": 0, "P1": 1, "P2": 1, "items": ["G12R-61_NOT_ESTABLISHED_QUALIFIED_STANDARD_PATH_NOT_RUN", "PROOF_REGISTRY_TEST_BINDINGS_INCLUDE_COARSE_OR_INDIRECT_EVIDENCE"]},
        "claim_dispositions": dispositions("B"),
        "limitations": ["PROTECTED_WORKFLOW_REPRESENTED_ONLY_BY_PUBLIC_SAFE_PROJECTION", "NO_HIDDEN_BYTES_OR_OUTCOME_BEARING_OUTPUT_INSPECTED", "EXECUTION_AND_CHALLENGE_UNAVAILABLE", "SESSION13_NOT_AUTHORIZED"],
        "identity_limitations": ["READ_ONLY_CODEX_REVIEWER_WITHOUT_EXTERNAL_ORGANISATIONAL_OR_SIGNED_MODEL_BUILD_IDENTITY_ATTESTATION"],
    })
    crosswalk = json.loads((PROOFS / "claim_crosswalk.v1.public.json").read_bytes())
    rows = {row["claim_id"]: row for row in crosswalk["rows"]}
    matrix = []
    for n in range(1, 98):
        cid = f"G12R-{n:02d}"; a = "REJECTED" if n in HIDDEN_FAILED else "ACCEPTED"; b = "REJECTED" if n in HIDDEN_FAILED or n == 61 else "ACCEPTED"
        matrix.append({"claim_id": cid, "normative_claim": claims["claims"][n - 1]["normative_claim"], "proof_ids": rows[cid]["proof_ids"], "reviewer_a": a, "reviewer_b": b, "status": "REJECTED" if "REJECTED" in {a, b} else "ACCEPTED"})
    write(BASE / "layer4_claim_matrix.final.v1.public.json", {
        "schema_id": "provan.session12r_layer4_matrix.v1", "sensitivity": "PUBLIC_SAFE",
        "claim_registry_digest": claims["registry_digest"], "reviewed_pre_review_root": PRE_ROOT,
        "claims": matrix, "accepted_count": sum(r["status"] == "ACCEPTED" for r in matrix),
        "rejected_count": sum(r["status"] == "REJECTED" for r in matrix), "gate_result": "CLOSED_PARTIAL",
    })
    final_paths = [
        "artifacts/session12/successor_closeout/proofs/pre_review_proof_manifest.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/reviewer_receipt_a.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/reviewer_receipt_b.v1.public.json",
        "artifacts/session12/successor_closeout/layer4_claim_matrix.final.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/hidden_qualification_projection.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/session13_handoff_candidate.v2.public.json",
        "artifacts/session12/successor_closeout/authority/operational_status.v1.public.json",
        "docs/capability-qualification-matrix.md", "docs/contract-foundry.md",
    ]
    entries = [ref(path) for path in final_paths]
    final_manifest = {"schema_id": "provan.session12r_final_proof_manifest.v1", "sensitivity": "PUBLIC_SAFE", "phase": "FINAL_PARTIAL", "implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "proof_descendant": PROOF_DESCENDANT, "wheel_sha256": WHEEL_SHA, "reviewed_pre_review_root": PRE_ROOT, "entries": entries, "proof_root": sha(canonical(entries)), "reviewer_outputs_excluded": False}
    write(PROOFS / "final_proof_manifest.v1.public.json", final_manifest)
    write(BASE / "closeout.v1.public.json", {
        "schema_id": "provan.session12r_closeout.v1", "sensitivity": "PUBLIC_SAFE", "session_12_successor": "CLOSED_PARTIAL", "go_session_13": False,
        "implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "proof_descendant": PROOF_DESCENDANT, "wheel_sha256": WHEEL_SHA,
        "reviewed_pre_review_root": PRE_ROOT, "final_proof_root": final_manifest["proof_root"],
        "reviewer_receipts": [ref("artifacts/session12/successor_closeout/proofs/reviewer_receipt_a.v1.public.json"), ref("artifacts/session12/successor_closeout/proofs/reviewer_receipt_b.v1.public.json")],
        "final_matrix": ref("artifacts/session12/successor_closeout/layer4_claim_matrix.final.v1.public.json"), "hidden_failure_code": hidden["failure_code"],
        "mode_qualification": hidden["mode_qualification"], "package_published": False, "release_created": False, "tag_created": False,
        "session13_implemented": False, "execution_available": False, "challenge_available": False, "publication_state": "PENDING_PR_AND_MAIN_CI",
        "closed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    write(BASE / "supersession_finalization.v1.public.json", {
        "schema_id": "provan.session12r_supersession_finalization.v1", "sensitivity": "PUBLIC_SAFE",
        "current_operational_status": ref("artifacts/session12/successor_closeout/authority/operational_status.v1.public.json"),
        "current_closeout": ref("artifacts/session12/successor_closeout/closeout.v1.public.json"),
        "historical_closeout_preserved": ref("artifacts/session12/closeout.v1.public.json"),
        "historical_status": "HISTORICALLY_VALID_FOR_ORIGINAL_IMPLEMENTATION_ONLY", "successor_status": "CLOSED_PARTIAL", "go_session_13": False,
    })
    print("SESSION12R_PARTIAL_CLOSEOUT_BUILT", final_manifest["proof_root"], sum(r["status"] == "ACCEPTED" for r in matrix), sum(r["status"] == "REJECTED" for r in matrix))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
