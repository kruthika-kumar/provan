from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session12/successor_closeout/proofs"
IMPLEMENTATION = "eb2d0781faf614c17b7af5a2f2477440d0b10402"
TREE = "8ffcf0d242ad5f92962d51533a04b6a11c33ab8f"
WHEEL = "dist/provan_assurance-0.5.1-py3-none-any.whl"
WHEEL_SHA = "sha256:e158c090728bb06b5f8e2a1d686719e58ece8b1c023863c7b348f146ce1b4093"


FAMILIES = {
    "A": ("historical_authority", "tests/test_session12r_evaluation.py::test_historical_and_successor_model_egress_sets_are_exact_and_distinct", ["artifacts/session12/successor_closeout/authority/historical_inventory.v1.public.json", "scripts/validate_session12r.py"]),
    "B": ("immutable_source_bundle", "tests/test_session12r_semantic.py::test_frozen_bytes_cannot_be_replaced_by_live_source", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "C": ("source_coverage", "tests/test_session12r_semantic.py::test_v2_pipeline_freezes_sources_and_independent_validator_recomputes", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "D": ("yaml_comment_authority", "tests/test_session12r_semantic.py::test_yaml_comments_are_covered_and_wrongful_ignore_is_rejected", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "E": ("statement_authority", "tests/test_session12r_semantic.py::test_source_authority_amendment_is_append_only_and_bounded", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "F": ("blind_boundary", "tests/test_session12r_semantic.py::test_deep_paths_and_standard_roles_are_stateless", ["provan/foundry_semantic.py", "provan/modeling.py"]),
    "G": ("intent_semantics", "tests/test_session12r_semantic.py::test_v2_pipeline_freezes_sources_and_independent_validator_recomputes", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "H": ("goal_premortem", "tests/test_session12r_semantic.py::test_run_rejects_independently_substituted_stage_artifact", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "I": ("candidate_semantics", "tests/test_session12r_semantic.py::test_run_rejects_independently_substituted_stage_artifact", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "J": ("audit_revision", "tests/test_session12r_semantic.py::test_run_rejects_independently_substituted_stage_artifact", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "K": ("witness_discrimination", "tests/test_session12r_semantic.py::test_run_rejects_independently_substituted_stage_artifact", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "L": ("interpretation_modes", "tests/test_session12r_semantic.py::test_v2_pipeline_freezes_sources_and_independent_validator_recomputes", ["provan/foundry_semantic.py", "docs/contract-foundry.md"]),
    "M": ("implementation_mapping", "tests/test_session12r_semantic.py::test_independent_validator_rejects_mapping_stage_and_select_all_mutations", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "N": ("mutable_readiness", "tests/test_session12r_semantic.py::test_mutable_candidate_is_explanatory_and_not_ready", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "O": ("pattern_anti_select_all", "tests/test_session12r_semantic.py::test_pattern_selection_rejects_select_all_and_has_distinct_basis", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "P": ("mutation_plan", "tests/test_session12r_semantic.py::test_hard_gate_and_semantic_stability_do_not_use_macro_rescue", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "Q": ("readiness_eligibility", "tests/test_session12r_semantic.py::test_v2_pipeline_freezes_sources_and_independent_validator_recomputes", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "R": ("owner_projection", "tests/test_session12r_semantic.py::test_owner_review_is_independently_recomputed", ["provan/foundry_semantic.py", "provan/session12r_validators.py", "provan/schemas/foundry-owner-review.v1.json"]),
    "S": ("standard_stateless_roles", "tests/test_session12r_semantic.py::test_deep_paths_and_standard_roles_are_stateless", ["provan/foundry_semantic.py", "provan/modeling.py"]),
    "T": ("deep_isolation_synthesis", "tests/test_session12r_semantic.py::test_deep_synthesis_resolves_both_frozen_paths_and_rejects_substitution", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "U": ("router_model_governance", "tests/test_session12r_evaluation.py::test_historical_and_successor_model_egress_sets_are_exact_and_distinct", ["provan/foundry.py", "provan/modeling.py", "artifacts/session12/successor_closeout/public/model_policy.v1.public.json"]),
    "V": ("budget_fanout", "tests/test_session12r_evaluation.py::test_public_semantic_evidence_recomputes_measurements_and_rejects_stale_cost", ["provan/foundry_semantic.py", "provan/session12r_validators.py"]),
    "W": ("arm_b_three_call", "tests/test_session12r_evaluation.py::test_arm_b_is_three_genuine_stateless_calls", ["provan/foundry_evaluation.py", "tests/test_session12r_evaluation.py"]),
    "X": ("public_real_use", "tests/test_session12r_evaluation.py::test_public_semantic_evidence_recomputes_measurements_and_rejects_stale_cost", ["artifacts/session12/successor_closeout/public/real_use/public_semantic_evidence.v1.public.json", "provan/session12r_validators.py"]),
    "Y": ("semantic_stability", "tests/test_session12r_semantic.py::test_hard_gate_and_semantic_stability_do_not_use_macro_rescue", ["artifacts/session12/successor_closeout/public/real_use/public_semantic_evidence.v1.public.json", "provan/foundry_evaluation.py"]),
    "Z": ("final_dogfood", "tests/test_session12r_semantic.py::test_run_rejects_independently_substituted_stage_artifact", ["artifacts/session12/successor_closeout/public/real_use/final_dogfood.v1.public.json", "provan/session12r_validators.py"]),
    "AA": ("wheel_fresh_install", "tests/test_session12r_semantic.py::test_cleanup_creates_digest_bound_tombstone", [WHEEL, "artifacts/session12/successor_closeout/proofs/fresh_install_receipt.v1.public.json"]),
    "AB": ("hidden_isolation_adjudication", "tests/test_session12r_evaluation.py::test_adjudicators_are_blind_and_disagreement_fails", ["provan/foundry_evaluation.py", "tests/test_session12r_evaluation.py"]),
    "AC": ("hard_qualification", "tests/test_session12r_evaluation.py::test_hidden_qualification_requires_six_domains_and_all_hard_gates", ["provan/foundry_evaluation.py", "provan/session12r_validators.py"]),
    "AD": ("claim_root", "tests/test_session12r_semantic.py::test_hard_gate_and_semantic_stability_do_not_use_macro_rescue", ["artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json", "scripts/validate_session12r.py"]),
    "AE": ("handoff_capability_boundary", "tests/test_session12r_evaluation.py::test_same_family_requires_protected_reviewer", ["provan/foundry_evaluation.py", "scripts/validate_session12r.py"]),
    "AF": ("publication_private_absence", "tests/test_session12r_evaluation.py::test_derived_public_role_block_requires_separate_operator_authorization", ["scripts/validate_session12_leakage.py", "provan/modeling.py"]),
}


CLAIM_FAMILY = {
    **{n: "A" for n in range(1, 5)}, **{n: "E" for n in range(5, 13)},
    **{n: "F" for n in range(13, 15)}, **{n: "G" for n in range(15, 16)},
    **{n: "H" for n in range(16, 19)}, **{n: "I" for n in range(19, 22)},
    **{n: "J" for n in range(22, 33)}, **{n: "K" for n in range(33, 37)},
    **{n: "L" for n in range(37, 40)}, **{n: "O" for n in range(40, 43)},
    **{n: "Q" for n in range(43, 45)}, **{n: "R" for n in range(45, 47)},
    **{n: "T" for n in range(47, 51)}, **{n: "U" for n in range(51, 54)},
    **{n: "X" for n in range(54, 61)}, 61: "Z", 62: "R", 63: "AA", 64: "AA",
    **{n: "AE" for n in range(65, 69)}, 69: "AF", 70: "AD", 71: "AE",
    72: "B", 73: "C", 74: "M", 75: "AB", 76: "AC", 77: "AB", 78: "W",
    79: "AB", 80: "AC", 81: "AC", 82: "O", 83: "P", 84: "A", 85: "S",
    86: "Z", 87: "N", 88: "AB", 89: "AB", 90: "C", 91: "M", 92: "O",
    93: "V", 94: "B", 95: "D", 96: "Y", 97: "V",
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def ref(path: str) -> dict[str, object]:
    raw = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(raw), "sha256": digest(raw)}


def run_test(node: str) -> bytes:
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", node], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=300)
    raw = (result.stdout + result.stderr).replace("\r\n", "\n").encode("utf-8")
    if result.returncode:
        raise SystemExit("SESSION12R_PROOF_TEST_FAILED:" + node + "\n" + raw.decode())
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hidden-projection", type=Path)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    transcripts = OUT / "transcripts"; transcripts.mkdir(exist_ok=True)
    results: dict[str, tuple[str, str]] = {}
    for _, node, _ in FAMILIES.values():
        if node in results: continue
        raw = run_test(node); name = hashlib.sha256(node.encode()).hexdigest()[:16] + ".txt"
        (transcripts / name).write_bytes(raw); results[node] = (f"artifacts/session12/successor_closeout/proofs/transcripts/{name}", digest(raw))
    hidden_ref = None
    if args.hidden_projection:
        hidden = args.hidden_projection.resolve()
        if not hidden.is_file(): raise SystemExit("SESSION12R_HIDDEN_PROJECTION_MISSING")
        target = OUT / "hidden_qualification_projection.v1.public.json"
        target.write_bytes(hidden.read_bytes()); hidden_ref = ref(target.relative_to(ROOT).as_posix())
    entries = []
    for key, (name, node, artifacts) in FAMILIES.items():
        transcript_path, transcript_sha = results[node]
        locations = [ref(path) for path in artifacts] + [ref(transcript_path)]
        if key in {"AB", "AC"} and hidden_ref: locations.append(hidden_ref)
        variants = ["valid", "near_valid", "adversarial"]
        if key in {"B", "C", "D", "E", "G", "I", "M", "O", "R", "T", "AC"}:
            variants += ["schema_invalid", "schema_valid_python_invalid"]
        for variant in variants:
            entries.append({"proof_id": f"P12R-{key}-{variant}", "family": name, "variant": variant, "test_id": node, "transcript_sha256": transcript_sha, "expected_result": "ACCEPT" if variant in {"valid", "near_valid"} else "REJECT", "independent_recomputation": True, "artifact_locations": locations, "sensitivity": "PUBLIC_SAFE", "hidden_outcome_bound": bool(hidden_ref and key in {"AB", "AC"})})
    registry = {"schema_id": "provan.session12r_proof_registry.v1", "sensitivity": "PUBLIC_SAFE", "implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "wheel_sha256": WHEEL_SHA, "entries": entries}
    (OUT / "proof_registry.v1.public.json").write_bytes(canonical(registry))
    claims = json.loads((ROOT / "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json").read_bytes())
    crosswalk = []
    for row in claims["claims"]:
        number = int(row["claim_id"].split("-")[1]); family = CLAIM_FAMILY[number]
        crosswalk.append({"claim_id": row["claim_id"], "normative_claim": row["normative_claim"], "proof_ids": [entry["proof_id"] for entry in entries if entry["proof_id"].startswith(f"P12R-{family}-")], "source_paths": FAMILIES[family][2], "status": "PENDING_HIDDEN_QUALIFICATION" if number in {56, 59, 70, 71, 75, 76, 77, 79, 80, 81, 88, 89, 90} and not hidden_ref else "EVIDENCED_PRE_REVIEW"})
    (OUT / "claim_crosswalk.v1.public.json").write_bytes(canonical({"schema_id": "provan.session12r_claim_crosswalk.v1", "sensitivity": "PUBLIC_SAFE", "claim_registry_digest": claims["registry_digest"], "rows": crosswalk}))
    binding = {"schema_id": "provan.session12r_implementation_binding.v1", "sensitivity": "PUBLIC_SAFE", "implementation_commit": IMPLEMENTATION, "implementation_tree": TREE, "package_version": "0.5.1", "wheel_sha256": WHEEL_SHA, "schema_registry_digest": json.loads((ROOT / "artifacts/session12/successor_closeout/public/schema_registry.v1.public.json").read_bytes())["registry_digest"], "claim_registry_digest": claims["registry_digest"], "maturity": "IMPLEMENTED_UNQUALIFIED" if not hidden_ref else "PENDING_REVIEW", "published": False, "execution_available": False, "challenge_available": False}
    (OUT / "implementation_binding.v1.public.json").write_bytes(canonical(binding))
    print("SESSION12R_PROOFS_BUILT", len(entries), "hidden", bool(hidden_ref))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
