from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

import jsonschema

from provan.canonical import canonical_bytes, sha256_bytes
from provan.session12_validators import validate_reviewer_receipt_serialized, validate_session12_closeout_serialized

OUT = ROOT / "artifacts/session12"
PROOFS = OUT / "proofs"
FINAL_NAMES = {"reviewer_receipt_a.v1.public.json", "reviewer_receipt_b.v1.public.json", "final_proof_manifest.v1.public.json", "closeout.v1.public.json"}
SHA = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def ref(path: str) -> dict[str, str]:
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise SystemExit("SESSION12_PROOF_REF_PATH_UNSAFE")
    target = ROOT
    for part in pure.parts:
        target = target / part
        if not target.exists() or target.is_symlink() or getattr(target.lstat(), "st_file_attributes", 0) & 0x400:
            raise SystemExit("SESSION12_PROOF_REF_UNRESOLVED:" + path)
    if not target.is_file() or ROOT.resolve() not in target.resolve().parents:
        raise SystemExit("SESSION12_PROOF_REF_UNRESOLVED:" + path)
    return {"path": path, "sha256": sha256_bytes(target.read_bytes())}


def binding(args: argparse.Namespace) -> dict:
    if not COMMIT.fullmatch(args.implementation_commit) or not COMMIT.fullmatch(args.implementation_tree) or not SHA.fullmatch(args.wheel_sha256):
        raise SystemExit("SESSION12_IMPLEMENTATION_BINDING_INVALID")
    schema_registry = json.loads((OUT / "schema_registry.v1.public.json").read_bytes())
    claims = json.loads((OUT / "authority/claim_registry.v1.public.json").read_bytes())
    value = {
        "schema_id": "provan.session12_implementation_binding.v1",
        "implementation_commit": args.implementation_commit,
        "implementation_tree": args.implementation_tree,
        "package_version": "0.5.0",
        "extension_api_major": 1,
        "wheel_sha256": args.wheel_sha256,
        "schema_registry_digest": schema_registry["registry_digest"],
        "claim_registry_digest": claims["registry_digest"],
        "standard_maturity": args.standard_maturity,
        "deep_maturity": args.deep_maturity,
        "published": False,
        "execution_available": False,
        "challenge_available": False,
    }
    schema = json.loads((ROOT / "provan/schemas/session12-implementation-binding.v1.json").read_bytes())
    jsonschema.validate(value, schema)
    write(OUT / "implementation_binding.v1.public.json", value)
    return value


def pre_review(args: argparse.Namespace) -> dict:
    bound = json.loads((OUT / "implementation_binding.v1.public.json").read_bytes())
    if any(bound[key] != getattr(args, key) for key in ("implementation_commit", "implementation_tree", "wheel_sha256")):
        raise SystemExit("SESSION12_PRE_REVIEW_BINDING_MISMATCH")
    proof_registry = json.loads((PROOFS / "proof_registry.v1.public.json").read_bytes())
    proof_family_root = sha256_bytes(canonical_bytes(proof_registry["entries"]))
    qualification = json.loads((OUT / "real_use/qualification.v1.public.json").read_bytes())
    dogfood = next(row for row in qualification["cases"] if row.get("case_id")=="session12-final-dogfood")
    run_ref = dogfood["run_binding"]
    projection_ref = dogfood["owner_projection"]
    handoff = {
        "schema_id": "provan.session_handoff.v2", "session": 12,
        "implementation_binding": bound,
        "wheel": ref(args.wheel_path),
        "schema_registry": ref("artifacts/session12/schema_registry.v1.public.json"),
        "claim_registry": ref("artifacts/session12/authority/claim_registry.v1.public.json"),
        "foundry_run": run_ref, "owner_projection": projection_ref,
        "pattern_library": ref("artifacts/session12/public/verification_pattern_library.v1.public.json"),
        "mode_qualification": {"standard": bound["standard_maturity"], "deep": bound["deep_maturity"]},
        "execution_available": False, "challenge_available": False,
        "session13_prerequisites": ["qualified verifier capability", "typed read-only work order", "environment and command receipts", "owner-confirmed Acceptance Contract", "no challenge execution"],
        "proof_root": proof_family_root, "reviewer_receipts": [],
        "limitations": qualification["limitations"] + ["SESSION13_NOT_IMPLEMENTED"],
    }
    jsonschema.validate(handoff, json.loads((ROOT / "provan/schemas/session-handoff.v2.json").read_bytes()))
    write(OUT / "session_handoff.v2.public.json", handoff)
    paths = [
        "artifacts/session12/implementation_binding.v1.public.json",
        "artifacts/session12/authority/claim_registry.v1.public.json",
        "artifacts/session12/authority/work_order.v1.public.json",
        "artifacts/session12/authority/object_classification.v1.public.json",
        "artifacts/session12/authority/model_steering_correction.v1.public.json",
        "artifacts/session12/schema_registry.v1.public.json",
        "artifacts/session12/public/verification_pattern_library.v1.public.json",
        "artifacts/session12/public/routing_policy.v1.public.json",
        "artifacts/session12/public/role_prompt_registry.v1.public.json",
        "artifacts/session12/public/model_egress_allowlist.v1.public.json",
        "artifacts/session12/public/adjudication_projection.v1.public.json",
        "artifacts/session12/real_use/qualification.v1.public.json",
        "artifacts/session12/real_use/final_dogfood/foundry_run_binding.v1.public.json",
        "artifacts/session12/real_use/final_dogfood/foundry_acceptance_projection.v1.public.json",
        "artifacts/session12/proofs/generic_absence_receipt.v1.public.json",
        "artifacts/session12/proofs/validation_summary.v1.public.json",
        "artifacts/session12/proofs/proof_registry.v1.public.json",
        "artifacts/session12/proofs/claim_crosswalk.v1.public.json",
        "artifacts/session12/layer4_claim_matrix.v1.public.json",
        "artifacts/session12/session_handoff.v2.public.json",
        args.wheel_path,
    ]
    entries = [ref(path) for path in paths]
    if any(PurePosixPath(row["path"]).name in FINAL_NAMES for row in entries):
        raise SystemExit("SESSION12_PRE_REVIEW_RECURSION_FORBIDDEN")
    manifest = {
        "schema_id": "provan.session11_proof_manifest.v1", "phase": "PRE_REVIEW",
        "implementation_commit": args.implementation_commit, "implementation_tree": args.implementation_tree,
        "wheel_sha256": args.wheel_sha256, "reviewed_pre_review_root": None,
        "entries": entries, "proof_root": sha256_bytes(canonical_bytes(entries)), "reviewer_outputs_excluded": True,
    }
    jsonschema.validate(manifest, json.loads((ROOT / "provan/schemas/session11-proof-manifest.v1.json").read_bytes()))
    write(PROOFS / "pre_review_proof_manifest.v1.public.json", manifest)
    print(manifest["proof_root"])
    return manifest


def final(args: argparse.Namespace) -> dict:
    development_binding_raw = (OUT / "implementation_binding.v1.public.json").read_bytes()
    development_binding = json.loads(development_binding_raw)
    pre = json.loads((PROOFS / "pre_review_proof_manifest.v1.public.json").read_bytes())
    if any(development_binding[key] != getattr(args, key) for key in ("implementation_commit", "implementation_tree", "wheel_sha256")):
        raise SystemExit("SESSION12_FINAL_BINDING_MISMATCH")
    claim_raw = (OUT / "authority/claim_registry.v1.public.json").read_bytes()
    receipt_paths = ["artifacts/session12/proofs/reviewer_receipt_a.v1.public.json", "artifacts/session12/proofs/reviewer_receipt_b.v1.public.json"]
    receipt_values = []
    for role, path in zip(("A", "B"), receipt_paths):
        raw = (ROOT / path).read_bytes()
        receipt_values.append(validate_reviewer_receipt_serialized(raw, development_binding_raw, claim_raw, pre["proof_root"], role))
    modes = receipt_values[0]["maturity_recommendation"]
    if any(row["maturity_recommendation"][key] != modes[key] for row in receipt_values[1:] for key in ("standard", "deep")):
        raise SystemExit("SESSION12_REVIEWER_MATURITY_DISAGREEMENT")
    gate_binding = dict(development_binding)
    gate_binding["standard_maturity"] = modes["standard"]
    gate_binding["deep_maturity"] = modes["deep"]
    write(OUT / "implementation_binding.gate12.v1.public.json", gate_binding)
    matrix = json.loads((OUT / "layer4_claim_matrix.v1.public.json").read_bytes())
    for row in matrix["claims"]:
        row["Reviewer result"] = "A:ACCEPTED;B:ACCEPTED"
        row["Status"] = "CLOSED"
    write(OUT / "layer4_claim_matrix.final.v1.public.json", matrix)
    handoff = json.loads((OUT / "session_handoff.v2.public.json").read_bytes())
    handoff["implementation_binding"] = gate_binding
    handoff["mode_qualification"] = {"standard": modes["standard"], "deep": modes["deep"]}
    handoff["reviewer_receipts"] = [ref(path) for path in receipt_paths]
    write(OUT / "session_handoff.final.v2.public.json", handoff)
    final_paths = [
        "artifacts/session12/proofs/pre_review_proof_manifest.v1.public.json",
        "artifacts/session12/implementation_binding.gate12.v1.public.json",
        "artifacts/session12/layer4_claim_matrix.final.v1.public.json",
        "artifacts/session12/session_handoff.final.v2.public.json",
        "artifacts/session12/proofs/generic_absence_receipt.v1.public.json",
        "artifacts/session12/proofs/validation_summary.v1.public.json",
        "artifacts/session12/real_use/qualification.v1.public.json",
        *receipt_paths,
    ]
    entries = [ref(path) for path in final_paths]
    final_root = sha256_bytes(canonical_bytes(entries))
    manifest = {"schema_id":"provan.session11_proof_manifest.v1","phase":"FINAL","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"wheel_sha256":args.wheel_sha256,"reviewed_pre_review_root":pre["proof_root"],"entries":entries,"proof_root":final_root,"reviewer_outputs_excluded":False}
    jsonschema.validate(manifest, json.loads((ROOT / "provan/schemas/session11-proof-manifest.v1.json").read_bytes()))
    write(PROOFS / "final_proof_manifest.v1.public.json", manifest)
    receipt_refs = [ref(path) for path in receipt_paths]
    closeout = {"schema_id":"provan.session12_closeout.v1","sensitivity":"PUBLIC_SAFE","status":"CLOSED","implementation_binding":gate_binding,"reviewed_pre_review_root":pre["proof_root"],"final_proof_root":final_root,"reviewer_receipts":receipt_refs,"mode_qualification":{"standard":modes["standard"],"deep":modes["deep"]},"execution_available":False,"challenge_available":False,"go_session13":True,"session13_implemented":False,"published":False,"release_created":False,"tag_created":False,"production_changed_after_review":False,"limitations":sorted(set(modes.get("limitations", []) + receipt_values[1]["maturity_recommendation"].get("limitations", []) + ["SESSION13_NOT_IMPLEMENTED","PACKAGE_0_5_0_UNPUBLISHED"]))}
    validate_session12_closeout_serialized(canonical_bytes(closeout), canonical_bytes(gate_binding), pre["proof_root"], entries, receipt_values)
    write(OUT / "closeout.v1.public.json", closeout)
    print(final_root)
    return closeout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("binding", "pre-review", "final"), required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--implementation-tree", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--wheel-path", default="dist/provan_assurance-0.5.0-py3-none-any.whl")
    parser.add_argument("--standard-maturity", choices=("IMPLEMENTED_UNQUALIFIED", "QUALIFIED_BOUNDED", "DEGRADED", "UNAVAILABLE"), default="IMPLEMENTED_UNQUALIFIED")
    parser.add_argument("--deep-maturity", choices=("IMPLEMENTED_UNQUALIFIED", "QUALIFIED_BOUNDED", "DEGRADED", "UNAVAILABLE"), default="IMPLEMENTED_UNQUALIFIED")
    args = parser.parse_args()
    if args.phase == "binding": binding(args)
    elif args.phase == "pre-review": pre_review(args)
    else: final(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
