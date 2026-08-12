from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "artifacts/session11"
SUCCESSOR = BASE / "successor_closeout"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SystemExit(code)


def resolve_ref(ref: dict) -> bytes:
    path = ROOT / ref.get("path", "")
    require(path.is_file(), "SESSION11_SUCCESSOR_REF_MISSING")
    raw = path.read_bytes()
    require(digest(raw) == ref.get("sha256"), "SESSION11_SUCCESSOR_REF_HASH_MISMATCH")
    return raw


def validate() -> None:
    binding = load(BASE / "implementation_binding.v1.public.json")
    pre = load(BASE / "proofs/pre_review_proof_manifest.v1.public.json")
    jsonschema.validate(pre, load(ROOT / "provan/schemas/session11-proof-manifest.v1.json"))
    require(pre["phase"] == "PRE_REVIEW", "SESSION11_SUCCESSOR_PRE_PHASE_INVALID")
    require(pre["reviewer_outputs_excluded"] is True, "SESSION11_SUCCESSOR_REVIEW_RECURSION")
    require(pre["proof_root"] == digest(canonical(pre["entries"])), "SESSION11_SUCCESSOR_PRE_ROOT_MISMATCH")
    for ref in pre["entries"]:
        resolve_ref(ref)

    receipt_schema = load(ROOT / "provan/schemas/session11-reviewer-receipt.v1.json")
    receipts = []
    for role in ("a", "b"):
        receipt_path = SUCCESSOR / f"reviewer_receipt_{role}.v1.public.json"
        receipt = load(receipt_path)
        jsonschema.validate(receipt, receipt_schema)
        require(receipt["reviewer_role"] == role.upper(), "SESSION11_SUCCESSOR_REVIEWER_ROLE_INVALID")
        require(receipt["reviewed_commit"] == pre["implementation_commit"], "SESSION11_SUCCESSOR_REVIEW_COMMIT_MISMATCH")
        require(receipt["reviewed_tree"] == pre["implementation_tree"], "SESSION11_SUCCESSOR_REVIEW_TREE_MISMATCH")
        require(receipt["reviewed_pre_review_root"] == pre["proof_root"], "SESSION11_SUCCESSOR_REVIEW_ROOT_MISMATCH")
        require(receipt["wheel_sha256"] == pre["wheel_sha256"], "SESSION11_SUCCESSOR_REVIEW_WHEEL_MISMATCH")
        require(receipt["verdict"] == "GO" and receipt["open_p0_count"] == 0 and receipt["open_p1_count"] == 0, "SESSION11_SUCCESSOR_REVIEW_NOT_GO")
        dispositions = receipt["claim_dispositions"]
        require([row["claim_id"] for row in dispositions] == [f"G11-{n:02d}" for n in range(1, 88)], "SESSION11_SUCCESSOR_REVIEW_CLAIMS_INVALID")
        require(all(row["result"] == "ACCEPTED" for row in dispositions), "SESSION11_SUCCESSOR_REVIEW_CLAIM_REJECTED")
        receipts.append(receipt)

    matrix = load(SUCCESSOR / "layer4_claim_matrix.v1.public.json")
    jsonschema.validate(matrix, load(ROOT / "provan/schemas/session11-layer4-matrix.v1.json"))
    require([row["Claim"].split(" ", 1)[0] for row in matrix["claims"]] == [f"G11-{n:02d}" for n in range(1, 88)], "SESSION11_SUCCESSOR_MATRIX_CLAIMS_INVALID")
    require(all(row["Reviewer result"] == "A:ACCEPTED;B:ACCEPTED" and row["Status"] == "CLOSED" for row in matrix["claims"]), "SESSION11_SUCCESSOR_MATRIX_NOT_CLOSED")

    manifest = load(SUCCESSOR / "final_proof_manifest.v1.public.json")
    jsonschema.validate(manifest, load(ROOT / "provan/schemas/session11-proof-manifest.v1.json"))
    require(manifest["phase"] == "FINAL", "SESSION11_SUCCESSOR_FINAL_PHASE_INVALID")
    require(manifest["implementation_commit"] == pre["implementation_commit"] and manifest["implementation_tree"] == pre["implementation_tree"], "SESSION11_SUCCESSOR_FINAL_IMPLEMENTATION_MISMATCH")
    require(manifest["wheel_sha256"] == pre["wheel_sha256"] and manifest["reviewed_pre_review_root"] == pre["proof_root"], "SESSION11_SUCCESSOR_FINAL_BINDING_MISMATCH")
    forbidden = {"final_proof_manifest.v1.public.json", "closeout.v1.public.json"}
    require(not any(Path(ref["path"]).name in forbidden for ref in manifest["entries"]), "SESSION11_SUCCESSOR_FINAL_RECURSION")
    for ref in manifest["entries"]:
        resolve_ref(ref)
    require(manifest["proof_root"] == digest(canonical(manifest["entries"])), "SESSION11_SUCCESSOR_FINAL_ROOT_MISMATCH")

    closeout = load(SUCCESSOR / "closeout.v1.public.json")
    jsonschema.validate(closeout, load(ROOT / "provan/schemas/session11-closeout.v1.json"))
    require(closeout["implementation_binding"] == binding, "SESSION11_SUCCESSOR_CLOSEOUT_IMPLEMENTATION_MISMATCH")
    require(closeout["reviewed_pre_review_root"] == pre["proof_root"] and closeout["final_proof_root"] == manifest["proof_root"], "SESSION11_SUCCESSOR_CLOSEOUT_ROOT_MISMATCH")
    require(closeout["go_session12"] is True and closeout["production_changed_after_review"] is False, "SESSION11_SUCCESSOR_CLOSEOUT_STATUS_INVALID")
    require([json.loads(resolve_ref(ref))["reviewer_role"] for ref in closeout["reviewer_receipts"]] == ["A", "B"], "SESSION11_SUCCESSOR_CLOSEOUT_RECEIPTS_INVALID")

    note = load(SUCCESSOR / "supersession_note.v1.public.json")
    require(note.get("schema_id") == "provan.session11_successor_closeout_note.v1", "SESSION11_SUCCESSOR_NOTE_SCHEMA_INVALID")
    require(note.get("supersedes_for_current_status") == ["artifacts/session11/closeout.v1.public.json", "artifacts/session11/proofs/final_proof_manifest.v1.public.json"], "SESSION11_SUCCESSOR_NOTE_SCOPE_INVALID")
    historical = note.get("historical_proof_preserved", {})
    for ref in historical.get("references", []):
        resolve_ref(ref)
    require(note.get("session12_implemented") is False and note.get("session13_implemented") is False, "SESSION11_SUCCESSOR_BOUNDARY_INVALID")
    print("SESSION11_SUCCESSOR_CLOSEOUT_VALID")


if __name__ == "__main__":
    validate()
