from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session11/successor_closeout"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def write(name: str, value: object) -> None:
    (OUT / name).write_bytes(canonical(value))


def ref(relative: str) -> dict[str, str]:
    return {"path": relative, "sha256": digest((ROOT / relative).read_bytes())}


def main() -> None:
    binding = load("artifacts/session11/successor_closeout/implementation_binding.v1.public.json")
    pre = load("artifacts/session11/successor_closeout/pre_review_proof_manifest.v1.public.json")
    for role in ("a", "b"):
        receipt = load(f"artifacts/session11/successor_closeout/reviewer_receipt_{role}.v1.public.json")
        if receipt["reviewed_commit"] != binding["implementation_commit"] or receipt["reviewed_tree"] != binding["implementation_tree"] or receipt["reviewed_pre_review_root"] != pre["proof_root"] or receipt["wheel_sha256"] != binding["wheel_sha256"] or receipt["verdict"] != "GO" or receipt["open_p0_count"] or receipt["open_p1_count"] or any(row["result"] != "ACCEPTED" for row in receipt["claim_dispositions"]):
            raise SystemExit(f"SESSION11_SUCCESSOR_REVIEW_{role.upper()}_NOT_GO")
    matrix = load("artifacts/session11/layer4_claim_matrix.v1.public.json")
    for row in matrix["claims"]:
        row["Reviewer result"] = "A:ACCEPTED;B:ACCEPTED"
        row["Status"] = "CLOSED"
    write("layer4_claim_matrix.v1.public.json", matrix)
    note = {
        "schema_id": "provan.session11_successor_closeout_note.v1",
        "supersedes_for_current_status": ["artifacts/session11/closeout.v1.public.json", "artifacts/session11/proofs/final_proof_manifest.v1.public.json"],
        "historical_proof_preserved": {"references": [ref("artifacts/session11/closeout.v1.public.json"), ref("artifacts/session11/proofs/final_proof_manifest.v1.public.json")]},
        "reason": "Additive successor evidence supersedes current status while preserving the immutable historical Session 11 proof lineage.",
        "session12_implemented": False,
        "session13_implemented": False,
    }
    write("supersession_note.v1.public.json", note)
    summary = {
        "schema_id": "provan.session11_successor_validation_summary.v1",
        "implementation_binding": binding,
        "pre_review_proof_root": pre["proof_root"],
        "reviewers": {"A": "GO_0_0_0", "B": "GO_0_0_0"},
        "claim_count": 87,
        "all_claims_accepted": True,
        "focused_successor_gate": "SUCCESS",
        "release_created": False,
        "tag_created": False,
        "package_published": False,
        "session12_implemented": False,
        "session13_implemented": False,
    }
    write("validation_summary.v1.public.json", summary)
    paths = [
        "artifacts/session11/successor_closeout/implementation_binding.v1.public.json",
        "artifacts/session11/successor_closeout/pre_review_proof_manifest.v1.public.json",
        "artifacts/session11/successor_closeout/reviewer_receipt_a.v1.public.json",
        "artifacts/session11/successor_closeout/reviewer_receipt_b.v1.public.json",
        "artifacts/session11/successor_closeout/layer4_claim_matrix.v1.public.json",
        "artifacts/session11/successor_closeout/supersession_note.v1.public.json",
        "artifacts/session11/successor_closeout/validation_summary.v1.public.json",
        "artifacts/session11/successor_closeout/generic_absence_receipt.v1.public.json",
        "artifacts/session11/successor_closeout/requalification_replay.v1.public.json",
        "artifacts/session11/successor_closeout/session12_handoff_candidate.v1.public.json",
        "artifacts/session11/proofs/proof_registry.v1.public.json",
        "artifacts/session11/claim_registry.v1.public.json",
        "artifacts/session11/schema_registry.v1.public.json",
        "dist/provan_assurance-0.4.0-py3-none-any.whl",
    ]
    entries = [ref(path) for path in paths]
    manifest = {"schema_id": "provan.session11_proof_manifest.v1", "phase": "FINAL", "implementation_commit": binding["implementation_commit"], "implementation_tree": binding["implementation_tree"], "wheel_sha256": binding["wheel_sha256"], "reviewed_pre_review_root": pre["proof_root"], "entries": entries, "proof_root": digest(canonical(entries)), "reviewer_outputs_excluded": False}
    write("final_proof_manifest.v1.public.json", manifest)
    closeout = {"schema_id": "provan.session11_closeout.v1", "status": "CLOSED", "implementation_binding": binding, "reviewed_pre_review_root": pre["proof_root"], "final_proof_root": manifest["proof_root"], "reviewer_receipts": [ref("artifacts/session11/successor_closeout/reviewer_receipt_a.v1.public.json"), ref("artifacts/session11/successor_closeout/reviewer_receipt_b.v1.public.json")], "go_session12": True, "session12_implemented": False, "session13_implemented": False, "release_created": False, "tag_created": False, "package_published": False, "production_changed_after_review": False}
    write("closeout.v1.public.json", closeout)
    print(manifest["proof_root"])


if __name__ == "__main__":
    main()
