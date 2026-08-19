from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

import jsonschema

from provan.session11_validators import validate_session12_handoff_serialized

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


def resolve_ref(ref: dict, *, historical_commit: str | None = None) -> bytes:
    raw_path = ref.get("path", "")
    portable = PurePosixPath(raw_path)
    candidate = Path(*portable.parts)
    require(raw_path == portable.as_posix() and not portable.is_absolute() and not portable.drive and ".." not in portable.parts and not (len(raw_path) >= 2 and raw_path[1] == ":"), "SESSION11_SUCCESSOR_REF_PATH_UNSAFE")
    root = ROOT.resolve(strict=True)
    path = ROOT / candidate
    current = ROOT
    for part in candidate.parts:
        current = current / part
        require(current.exists(), "SESSION11_SUCCESSOR_REF_MISSING")
        stat = os.lstat(current)
        require(not current.is_symlink() and not bool(getattr(stat, "st_file_attributes", 0) & 0x400), "SESSION11_SUCCESSOR_REF_PATH_UNSAFE")
    require(path.is_file() and not path.is_symlink(), "SESSION11_SUCCESSOR_REF_MISSING")
    resolved = path.resolve(strict=True)
    require(resolved == root or root in resolved.parents, "SESSION11_SUCCESSOR_REF_PATH_UNSAFE")
    require(os.path.isfile(resolved), "SESSION11_SUCCESSOR_REF_TYPE_FORBIDDEN")
    raw = resolved.read_bytes()
    if digest(raw) == ref.get("sha256"):
        return raw
    if historical_commit is not None:
        require(bool(re.fullmatch(r"[0-9a-f]{40}", historical_commit)), "SESSION11_SUCCESSOR_HISTORICAL_COMMIT_INVALID")
        result = subprocess.run(
            ["git", "show", f"{historical_commit}:{portable.as_posix()}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0 and digest(result.stdout) == ref.get("sha256"):
            return result.stdout
    raise SystemExit("SESSION11_SUCCESSOR_REF_HASH_MISMATCH")


def handoff_artifacts(value: dict) -> dict[str, bytes]:
    refs = [value["brief"], value["preparation"], *value["seed_dispositions"], value["acceptance_contract"], value["candidate_freeze"], *value["closure_requirements"], *value["verifier_contracts"], *value["receipt_contracts"], *value["protected_invariants"], value["evidence_settlement"], value["attestation"], value["reinspection"], value["layer4_matrix"], value["proof_manifest"], *value["reviewer_receipts"], value["schema_registry"], value["claim_registry"], value["implementation_binding_ref"], value["wheel"]]
    artifacts = {ref["path"]: resolve_ref(ref) for ref in refs}
    manifest = json.loads(artifacts[value["proof_manifest"]["path"]])
    for ref in manifest["entries"]:
        artifacts[ref["path"]] = resolve_ref(ref)
    return artifacts


def validate() -> None:
    binding = load(SUCCESSOR / "implementation_binding.v1.public.json")
    pre = load(SUCCESSOR / "pre_review_proof_manifest.v1.public.json")
    require(binding.get("schema_id") == "provan.session11_implementation_binding.v1", "SESSION11_SUCCESSOR_IMPLEMENTATION_SCHEMA_INVALID")
    require(binding.get("package_version") == "0.4.0" and binding.get("extension_api_major") == 1 and binding.get("maturity") == "QUALIFIED_BOUNDED" and binding.get("published") is False, "SESSION11_SUCCESSOR_IMPLEMENTATION_POLICY_INVALID")
    jsonschema.validate(pre, load(ROOT / "provan/schemas/session11-proof-manifest.v1.json"))
    require(pre["phase"] == "PRE_REVIEW", "SESSION11_SUCCESSOR_PRE_PHASE_INVALID")
    require(pre["reviewer_outputs_excluded"] is True, "SESSION11_SUCCESSOR_REVIEW_RECURSION")
    require(binding["implementation_commit"] == pre["implementation_commit"] and binding["implementation_tree"] == pre["implementation_tree"], "SESSION11_SUCCESSOR_IMPLEMENTATION_MISMATCH")
    require(binding["wheel_sha256"] == pre["wheel_sha256"], "SESSION11_SUCCESSOR_WHEEL_MISMATCH")
    claim_registry = load(BASE / "claim_registry.v1.public.json")
    schema_registry = load(BASE / "schema_registry.v1.public.json")
    require(binding["claim_registry_digest"] == digest((BASE / "claim_registry.v1.public.json").read_bytes()), "SESSION11_SUCCESSOR_CLAIM_REGISTRY_MISMATCH")
    require(binding["schema_registry_digest"] == schema_registry["registry_digest"], "SESSION11_SUCCESSOR_SCHEMA_REGISTRY_MISMATCH")
    forbidden_pre = {"reviewer_receipt_a.v1.public.json", "reviewer_receipt_b.v1.public.json", "final_proof_manifest.v1.public.json", "closeout.v1.public.json", "layer4_claim_matrix.v1.public.json", "supersession_note.v1.public.json"}
    require(not any(Path(ref["path"]).name in forbidden_pre for ref in pre["entries"]), "SESSION11_SUCCESSOR_REVIEW_RECURSION")
    require(pre["proof_root"] == digest(canonical(pre["entries"])), "SESSION11_SUCCESSOR_PRE_ROOT_MISMATCH")
    for ref in pre["entries"]:
        resolve_ref(ref, historical_commit=binding["implementation_commit"])
    expected_current = {
        "implementation_commit": binding["implementation_commit"],
        "implementation_tree": binding["implementation_tree"],
        "wheel_sha256": binding["wheel_sha256"],
    }
    absence = load(SUCCESSOR / "generic_absence_receipt.v1.public.json")
    require({key: absence.get(key) for key in expected_current} == expected_current and absence.get("result") == "PRIVATE_PLANNING_AUTHORITY_ABSENT" and absence.get("violations") == [], "SESSION11_SUCCESSOR_ABSENCE_BINDING_MISMATCH")
    replay = load(SUCCESSOR / "requalification_replay.v1.public.json")
    require(replay.get("implementation_binding") == binding and replay.get("historical_inputs_current_by_themselves") is False and replay.get("result") == "REQUALIFIED", "SESSION11_SUCCESSOR_REPLAY_BINDING_MISMATCH")
    require(replay.get("runtime_equivalence", {}).get("current_runtime_diff_empty") is True and replay.get("checks") and all(row.get("exit_code") == 0 and row.get("transcript_sha256", "").startswith("sha256:") for row in replay["checks"]), "SESSION11_SUCCESSOR_REPLAY_EVIDENCE_INVALID")
    for ref in replay.get("historical_inputs", []):
        resolve_ref(ref)
    handoff = load(SUCCESSOR / "session12_handoff_candidate.v1.public.json")
    require(handoff.get("implementation_binding") == binding and handoff.get("implementation_binding_ref", {}).get("path") == "artifacts/session11/successor_closeout/implementation_binding.v1.public.json" and handoff.get("wheel", {}).get("sha256") == binding["wheel_sha256"], "SESSION11_SUCCESSOR_HANDOFF_BINDING_MISMATCH")
    jsonschema.validate(handoff, load(ROOT / "provan/schemas/session12-handoff.v1.json"))
    validate_session12_handoff_serialized(canonical(handoff), handoff_artifacts(handoff))

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
    require([row["Claim"].split(" — ", 1)[1] for row in matrix["claims"]] == [row["normative_claim"] for row in claim_registry["claims"]], "SESSION11_SUCCESSOR_MATRIX_WORDING_DRIFT")
    require(all(row["Reviewer result"] == "A:ACCEPTED;B:ACCEPTED" and row["Status"] == "CLOSED" for row in matrix["claims"]), "SESSION11_SUCCESSOR_MATRIX_NOT_CLOSED")

    manifest = load(SUCCESSOR / "final_proof_manifest.v1.public.json")
    jsonschema.validate(manifest, load(ROOT / "provan/schemas/session11-proof-manifest.v1.json"))
    require(manifest["phase"] == "FINAL", "SESSION11_SUCCESSOR_FINAL_PHASE_INVALID")
    require(manifest["implementation_commit"] == pre["implementation_commit"] and manifest["implementation_tree"] == pre["implementation_tree"], "SESSION11_SUCCESSOR_FINAL_IMPLEMENTATION_MISMATCH")
    require(manifest["wheel_sha256"] == pre["wheel_sha256"] and manifest["reviewed_pre_review_root"] == pre["proof_root"], "SESSION11_SUCCESSOR_FINAL_BINDING_MISMATCH")
    forbidden = {"final_proof_manifest.v1.public.json", "closeout.v1.public.json"}
    require(not any(Path(ref["path"]).name in forbidden for ref in manifest["entries"]), "SESSION11_SUCCESSOR_FINAL_RECURSION")
    required_final = {
        "artifacts/session11/successor_closeout/implementation_binding.v1.public.json",
        "artifacts/session11/successor_closeout/pre_review_proof_manifest.v1.public.json",
        "artifacts/session11/successor_closeout/reviewer_receipt_a.v1.public.json",
        "artifacts/session11/successor_closeout/reviewer_receipt_b.v1.public.json",
        "artifacts/session11/successor_closeout/layer4_claim_matrix.v1.public.json",
        "artifacts/session11/successor_closeout/supersession_note.v1.public.json",
        "artifacts/session11/successor_closeout/generic_absence_receipt.v1.public.json",
        "artifacts/session11/successor_closeout/requalification_replay.v1.public.json",
        "artifacts/session11/successor_closeout/session12_handoff_candidate.v1.public.json",
    }
    require(required_final.issubset({ref["path"] for ref in manifest["entries"]}), "SESSION11_SUCCESSOR_FINAL_REQUIRED_EVIDENCE_MISSING")
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
    required_historical = {"artifacts/session11/closeout.v1.public.json", "artifacts/session11/proofs/final_proof_manifest.v1.public.json"}
    require(required_historical == {ref.get("path") for ref in historical.get("references", [])}, "SESSION11_SUCCESSOR_HISTORICAL_PROOF_REFS_INVALID")
    for ref in historical.get("references", []):
        resolve_ref(ref)
    require(note.get("session12_implemented") is False and note.get("session13_implemented") is False, "SESSION11_SUCCESSOR_BOUNDARY_INVALID")
    print("SESSION11_SUCCESSOR_CLOSEOUT_VALID")


if __name__ == "__main__":
    validate()
