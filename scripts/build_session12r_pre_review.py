from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session12/successor_closeout/proofs"
IMPLEMENTATION = "eb2d0781faf614c17b7af5a2f2477440d0b10402"
TREE = "8ffcf0d242ad5f92962d51533a04b6a11c33ab8f"
WHEEL_SHA = "sha256:e158c090728bb06b5f8e2a1d686719e58ece8b1c023863c7b348f146ce1b4093"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def ref(path: str) -> dict[str, object]:
    raw = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(raw), "sha256": digest(raw)}


def root(rows: list[dict[str, object]]) -> str:
    return digest(canonical(rows))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hidden-projection", type=Path, required=True)
    args = parser.parse_args()
    hidden = args.hidden_projection.resolve()
    if not hidden.is_file(): raise SystemExit("SESSION12R_HIDDEN_PROJECTION_MISSING")
    hidden_value = json.loads(hidden.read_bytes())
    if hidden_value.get("sensitivity") != "PUBLIC_SAFE" or hidden_value.get("raw_holdout_content_included") is not False:
        raise SystemExit("SESSION12R_HIDDEN_PROJECTION_NOT_PUBLIC_SAFE")
    target = OUT / "hidden_qualification_projection.v1.public.json"
    target.write_bytes(canonical(hidden_value))
    entries = [ref(path) for path in [
        "artifacts/session12/successor_closeout/authority/work_order.md",
        "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json",
        "artifacts/session12/successor_closeout/authority/compatibility_registry.v1.public.json",
        "artifacts/session12/successor_closeout/public/schema_registry.v1.public.json",
        "artifacts/session12/successor_closeout/public/model_policy.v1.public.json",
        "artifacts/session12/successor_closeout/public/prompt_registry.v1.public.json",
        "artifacts/session12/successor_closeout/public/semantic_scorer_policy.v1.public.json",
        "artifacts/session12/successor_closeout/public/real_use/public_semantic_evidence.v1.public.json",
        "artifacts/session12/successor_closeout/public/real_use/final_dogfood.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/fresh_install_receipt.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/implementation_binding.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/proof_registry.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/claim_crosswalk.v1.public.json",
        "artifacts/session12/successor_closeout/proofs/hidden_qualification_projection.v1.public.json",
        "dist/provan_assurance-0.5.1-py3-none-any.whl",
    ]]
    evidence_root = root(entries)
    claims = json.loads((ROOT / "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json").read_bytes())
    schemas = json.loads((ROOT / "artifacts/session12/successor_closeout/public/schema_registry.v1.public.json").read_bytes())
    dogfood_path = "artifacts/session12/successor_closeout/public/real_use/final_dogfood.v1.public.json"
    dogfood = json.loads((ROOT / dogfood_path).read_bytes())
    hidden_status = hidden_value.get("session_12_successor")
    hidden_go = hidden_value.get("go_session_13") is True
    standard = hidden_value.get("mode_qualification", {}).get("standard", "IMPLEMENTED_UNQUALIFIED")
    deep = hidden_value.get("mode_qualification", {}).get("deep", "IMPLEMENTED_UNQUALIFIED")
    handoff = {
        "schema_id": "provan.session_handoff.v2", "session": 12,
        "implementation_binding": {"implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "package_version": "0.5.1", "wheel_sha256": WHEEL_SHA, "published": False},
        "wheel": ref("dist/provan_assurance-0.5.1-py3-none-any.whl"),
        "schema_registry": {"path": "artifacts/session12/successor_closeout/public/schema_registry.v1.public.json", "sha256": digest((ROOT / "artifacts/session12/successor_closeout/public/schema_registry.v1.public.json").read_bytes()), "registry_digest": schemas["registry_digest"]},
        "claim_registry": {"path": "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json", "sha256": digest((ROOT / "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json").read_bytes()), "registry_digest": claims["registry_digest"]},
        "foundry_run": {"path": dogfood_path, "sha256": digest((ROOT / dogfood_path).read_bytes()), "run_id": dogfood["run_id"], "run_digest": dogfood["run_digest"]},
        "owner_projection": dogfood["owner_projection_ref"],
        "pattern_library": {"path": "artifacts/session12/public/verification_pattern_library.v1.public.json", "sha256": digest((ROOT / "artifacts/session12/public/verification_pattern_library.v1.public.json").read_bytes())},
        "mode_qualification": {"standard": standard, "deep": deep},
        "execution_available": False, "challenge_available": False,
        "session13_prerequisites": ["owner-confirmed Acceptance Contract", "qualified read-only verifier capability", "typed environment and command receipts", "no challenge execution", "successor GO_SESSION_13 must be true"],
        "proof_root": evidence_root, "reviewer_receipts": [],
        "limitations": list(hidden_value.get("limitations", [])) + ["SESSION13_NOT_IMPLEMENTED", "EXECUTION_UNAVAILABLE", "CHALLENGE_UNAVAILABLE", "HIDDEN_PLAINTEXT_NOT_PUBLIC"],
    }
    if not hidden_go or hidden_status != "CLOSED": handoff["limitations"].append("GO_SESSION_13_NO")
    schema = json.loads((ROOT / "provan/schemas/session-handoff.v2.json").read_bytes()); jsonschema.validate(handoff, schema)
    handoff_path = OUT / "session13_handoff_candidate.v2.public.json"; handoff_path.write_bytes(canonical(handoff))
    entries.append(ref(handoff_path.relative_to(ROOT).as_posix()))
    manifest = {"schema_id": "provan.session12r_pre_review_manifest.v1", "sensitivity": "PUBLIC_SAFE", "phase": "PRE_REVIEW_NON_RECURSIVE", "implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "wheel_sha256": WHEEL_SHA, "evidence_root": evidence_root, "entries": entries, "reviewer_outputs_excluded": True, "final_outputs_excluded": True, "root": root(entries)}
    (OUT / "pre_review_proof_manifest.v1.public.json").write_bytes(canonical(manifest))
    print("SESSION12R_PRE_REVIEW_BUILT", manifest["root"], len(entries), standard, deep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
