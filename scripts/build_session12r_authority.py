from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "session12" / "successor_closeout" / "authority"


CLAIMS = {
    "G12R-01": "Historical Session 12 closeout is byte-preserved and no longer treated as current semantic authority after successor repair begins.",
    "G12R-02": "The successor closeout, not the historical closeout, determines current GO_SESSION_13.",
    "G12R-03": "Private planning/execution authority remains outside every Git repository, package, public proof, example and CI artifact.",
    "G12R-04": "Session 10/11 canonical authority and Acceptance semantics remain compatible and unchanged.",
    "G12R-05": "Foundry records statement-level source authority, not merely source-file metadata.",
    "G12R-06": "Illustrative examples cannot become exact mandatory requirements without explicit authority.",
    "G12R-07": "Explicit exact-content requirements remain exact.",
    "G12R-08": "Explicit non-goals cannot become mandatory through model inference.",
    "G12R-09": "Tech-spec mechanisms remain distinct from product outcomes unless explicitly authoritative.",
    "G12R-10": "Active source conflicts remain visible until disposition.",
    "G12R-11": "Superseded source remains historical and loses active authority.",
    "G12R-12": "Untrusted instruction-like source content cannot control Foundry roles/tools/authority.",
    "G12R-13": "Blind intent role has an operational information boundary excluding implementation/tests by default.",
    "G12R-14": "Implementation-informed mode is explicit and degraded.",
    "G12R-15": "Intent Model contains case-specific actors, outcomes, invariants, states/transitions, recovery expectations, non-goals, ambiguities and conflicts where supported.",
    "G12R-16": "Goal/Obstacle analysis is case-specific and uses semantic stopping criteria rather than fixed boilerplate/depth.",
    "G12R-17": "Pre-mortem produces causally distinct case-specific failure narratives.",
    "G12R-18": "Pre-mortem cannot create mandatory authority or implementation fixes.",
    "G12R-19": "Contract Proposer compiles independently settleable typed criteria rather than a generic owner-confirmation placeholder.",
    "G12R-20": "Every mandatory-source proposed criterion has traceable source authority.",
    "G12R-21": "Suggested enhancements remain distinguishable from mandatory-source proposals.",
    "G12R-22": "Adversarial audit inspects the actual candidate and produces case-specific findings.",
    "G12R-23": "Omitted-obligation / under-specification witness works.",
    "G12R-24": "Over-specification witness works.",
    "G12R-25": "Material ambiguity witness routes to owner.",
    "G12R-26": "Weak-oracle witness prevents false readiness/blocking.",
    "G12R-27": "Non-goal leakage is detected.",
    "G12R-28": "Implementation leakage is detected.",
    "G12R-29": "Compound criteria are detected/split where appropriate.",
    "G12R-30": "Every material audit finding receives exactly one typed disposition.",
    "G12R-31": "Standard revision cap is one.",
    "G12R-32": "Deep revision cap is two.",
    "G12R-33": "Valid witnesses pass.",
    "G12R-34": "Near-valid alternatives pass where intended.",
    "G12R-35": "Adversarial superficial behavior fails.",
    "G12R-36": "Ambiguity witnesses result in owner decision rather than silent inference.",
    "G12R-37": "Faithful mode prohibits unsupported enhancements.",
    "G12R-38": "Clarifying mode separates recommended interpretation from authority.",
    "G12R-39": "Enhanced mode keeps all added suggestions non-authoritative.",
    "G12R-40": "Verification Pattern selection is derived from criterion/failure/oracle semantics rather than a fixed global subset.",
    "G12R-41": "Material contract mutation changes verification-pattern/capability selection.",
    "G12R-42": "Non-material wording mutation does not cause spurious material selection change.",
    "G12R-43": "Contract readiness means readiness for owner confirmation, not runtime establishment.",
    "G12R-44": "NOT_ELIGIBLE remains distinct from NOT_READY.",
    "G12R-45": "Owner projection binds the actual semantic candidate/audit/witness/pattern artifacts.",
    "G12R-46": "Session 11 case-operator disposition remains the only route to Acceptance Contract authority.",
    "G12R-47": "Deep uses two frozen blind semantic paths before synthesis.",
    "G12R-48": "Each Deep path produces an independent contract candidate or structured critique in addition to intent.",
    "G12R-49": "Deep semantic calls remain stateless with no cross-path conversational state.",
    "G12R-50": "Same-provider/model-family Deep runs do not claim provider/model-family independence.",
    "G12R-51": "Current quality-critical semantic qualification uses the approved GPT-5.6 policy.",
    "G12R-52": "Historical GPT-5.2 calls remain preserved but cannot establish corrected semantic qualification.",
    "G12R-53": "No model is introduced into Session 11 evidence settlement authority.",
    "G12R-54": "Historical five-case comparison remains preserved and is classified as exposed regression evidence for the repair.",
    "G12R-55": "Final semantic evaluation scores canonical Contract Foundry outputs, not merely raw model implication/token coverage.",
    "G12R-56": "Hidden adjudication is frozen and independently reviewed before final outcome-bearing scoring.",
    "G12R-57": "Baseline evaluation is semantically neutral and does not require Provan internal identifiers.",
    "G12R-58": "Paired comparisons use the same current strong model/model family where practical and disclose compute differences.",
    "G12R-59": "At least one clean post-repair held-out comparison is preserved, or the absence of a clean heldout is explicitly disclosed and qualification narrowed.",
    "G12R-60": "Real-use cases demonstrate materially case-specific semantic output.",
    "G12R-61": "Final Provan dogfood exercises the qualified semantic Standard path, not Tier-0 no-model only.",
    "G12R-62": "Public docs and capability matrix match successor maturity.",
    "G12R-63": "One authoritative successor wheel is bound to the final corrected implementation.",
    "G12R-64": "Fresh-install behavior resolves from installed package, not checkout.",
    "G12R-65": "Execution remains unavailable.",
    "G12R-66": "Challenge execution remains unavailable.",
    "G12R-67": "Session 13 remains unimplemented.",
    "G12R-68": "Enterprise capability remains unimplemented.",
    "G12R-69": "Branch, package, proof and public-artifact sensitivity gates pass.",
    "G12R-70": "Fresh reviewers bind the exact corrected implementation, successor wheel, pre-review root and every G12R claim.",
    "G12R-71": "Successor Gate 12 sets GO_SESSION_13:YES only if the semantic correction is fully qualified.",
    "G12R-72": "Every run freezes exact source bytes in an immutable Source Bundle before statement extraction, and later reads can only verify digest continuity.",
    "G12R-73": "Source coverage accounts for every relevant span or structured node as semantic, explicitly non-semantic, explicitly ignored, or unresolved, with no silent material omission.",
    "G12R-74": "A post-blind implementation-aware stage maps frozen semantic obligations to exact Session 10 candidate surfaces without rewriting intent or creating authority.",
    "G12R-75": "Successor semantic qualification uses clean untouched holdouts spanning distinct semantic domains, including a clean no-friction control.",
    "G12R-76": "Qualification is decided by hard material-correctness gates that composite or macro scores cannot override.",
    "G12R-77": "Semantic equivalence uses deterministic checks plus at least two fresh blind arm-independent adjudicators, records disagreement, and cannot be established by one self-judge or token matcher.",
    "G12R-78": "Arm B is a genuine stateless proposer, fresh adversarial reviewer, and revision sequence with a compute budget reasonably comparable to Deep.",
    "G12R-79": "Final hidden holdouts and adjudication are operationally isolated from the implementation agent and environment.",
    "G12R-80": "Final hidden qualification is one-shot after semantic implementation and policy freeze; a material failure closes the successor partially and cannot be tuned away with replacement cases.",
    "G12R-81": "Deep is DEGRADED only after meeting the complete semantic floor without materially regressing Standard and only for declared independence limits.",
    "G12R-82": "Verification Pattern selection rejects select-all or near-universal portfolios lacking a distinct criterion, failure, oracle, or capability basis per selection.",
    "G12R-83": "Material contract mutation changes the verification plan only through portfolio membership, criterion-pattern binding, dimension, oracle, or capability semantics and does not require artificial pattern-ID churn.",
    "G12R-84": "Every proposed v2 contract has an individual compatibility justification; existing semantics are reused or narrowly accompanied where possible.",
    "G12R-85": "Successor evidence includes semantic run-to-run stability, compact owner-review rendering, actual per-case measurements, and stateless Standard audit and revision roles.",
    "G12R-86": "Semantic public real use, stability and final semantic dogfood complete before the final implementation/model/prompt/policy freeze, and hidden qualification runs only against the resulting authoritative wheel.",
    "G12R-87": "Post-blind implementation mapping binds exact immutable candidate bytes and digest; mutable candidates remain explanatory and cannot reach owner-confirmation readiness.",
    "G12R-88": "Final qualification uses at least six isolated untouched holdouts across payment/state, permission/identity, API/schema, recovery, AI/tool authority and clean/no-friction domains with a frozen semantic coverage matrix.",
    "G12R-89": "Hidden semantic equivalence prefers different qualified model/provider families; same-family agreement additionally requires a fresh protected evaluator/reviewer to verify every material disposition.",
    "G12R-90": "Qualification requires zero unaccounted material source content and zero material content wrongly classified non-semantic or ignored.",
    "G12R-91": "Every adjudicated material obligation maps to supported candidate surfaces or explicit unresolved/not-discoverable state, with zero unsupported mappings claimed as supported.",
    "G12R-92": "Every adjudicated material verification dimension is covered or explicitly unavailable/not-applicable, and no materially irrelevant pattern is selected.",
    "G12R-93": "Standard and Deep semantic-stage ceilings permit separately bounded, receipted source-classification fan-out under per-run call/token/cost and cumulative Session 12 budget limits.",
    "G12R-94": "Frozen Source Bundles are private-local, excluded from telemetry/public/client-safe/package surfaces, and governed by digest-bound cleanup/deletion semantics.",
    "G12R-95": "YAML comments are coverage-accounted contextual/untrusted spans, cannot silently create mandatory authority, and cannot disappear through parser comment loss.",
    "G12R-96": "Run-to-run stability is judged through blinded semantic equivalence of material obligations, non-goals, exact-content rules, ambiguities and verification dimensions rather than byte identity.",
    "G12R-97": "Standard and Deep report actual per-case wall time, calls, tokens and cost without unsupported percentile claims.",
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def file_ref(path: str) -> dict[str, object]:
    raw = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(raw), "sha256": digest(raw)}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    claims = [{"claim_id": key, "normative_claim": value} for key, value in CLAIMS.items()]
    bare = {"schema_id": "provan.session12r_claim_registry.v1", "sensitivity": "PUBLIC_SAFE", "frozen_range": ["G12R-01", "G12R-97"], "claims": claims}
    registry = {**bare, "registry_digest": digest(canonical(bare))}
    (OUT / "claim_registry.v1.public.json").write_bytes(canonical(registry))

    historical_paths = [
        "artifacts/session12/implementation_binding.gate12.v1.public.json",
        "artifacts/session12/proofs/final_proof_manifest.v1.public.json",
        "artifacts/session12/proofs/reviewer_receipt_a.v1.public.json",
        "artifacts/session12/proofs/reviewer_receipt_b.v1.public.json",
        "artifacts/session12/closeout.v1.public.json",
        "dist/provan_assurance-0.5.0-py3-none-any.whl",
    ]
    inventory = {
        "schema_id": "provan.session12r_historical_inventory.v1",
        "sensitivity": "PUBLIC_SAFE",
        "baseline_commit": "dc156ddccc5f94c0679b678ec6a4c6ef3c4ece98",
        "historical_implementation_commit": "7c5580df5e5c9e6632889bc7709f1b52fe04c6e7",
        "historical_implementation_tree": "21b8ee1fc162603efac2e9b65ea0a5267c91fb05",
        "historical_final_proof_root": "sha256:780adc7caf78d81e008eb422dd0f821136d57f5dc053e35a0d098ebdae9a3f8f",
        "entries": [file_ref(path) for path in historical_paths],
        "preservation": "BYTE_PRESERVED_HISTORICAL_ONLY",
    }
    (OUT / "historical_inventory.v1.public.json").write_bytes(canonical(inventory))

    compatibility = {
        "schema_id": "provan.session12r_compatibility_registry.v1",
        "sensitivity": "PUBLIC_SAFE",
        "decisions": (
            [{"object": name, "classification": "public_canonical", "rationale": reason}
            for name, reason in [
                ("source_authority_ledger.v2", "statement authority cannot be represented by the v1 file ledger"),
                ("intent_model.v2", "typed semantic categories and per-item provenance are absent from v1"),
                ("contract_candidate.v2", "independently settleable criteria and typed oracle plans are absent from v1"),
                ("verification_pattern_selection.v2", "criterion, failure, oracle, capability and dimension bindings are absent from v1"),
                ("foundry_acceptance_projection.v2", "per-term semantic provenance is absent from v1"),
                ("foundry_owner_review.v1", "owners require one canonical compact review surface"),
            ]]
            + [
                {"object": name, "classification": "reused_unchanged", "rationale": reason}
                for name, reason in [
                    ("contract_readiness.v1", "readiness enum and authority ceiling remain compatible; internal basis is separate"),
                    ("verification_pattern_library.v1", "library semantics remain sufficient"),
                    ("session10_analysis_contracts", "candidate and source-analysis authority remain sufficient"),
                    ("session11_acceptance_contracts", "owner disposition and acceptance authority remain sufficient"),
                ]
            ]
            + [{"object": "semantic_pipeline_supporting_objects", "classification": "internal_canonical", "rationale": "run-local mechanics are not extension contracts"}, {"object": "hidden_holdout_and_scoring_objects", "classification": "private_evaluation", "rationale": "hidden qualification material must remain evaluator-controlled"}]
        ),
    }
    (OUT / "compatibility_registry.v1.public.json").write_bytes(canonical(compatibility))
    marker = {
        "schema_id": "provan.session12r_operational_status.v1",
        "sensitivity": "PUBLIC_SAFE",
        "session_12_successor": "IN_PROGRESS",
        "go_session_13": False,
        "reason": "SUCCESSOR_SEMANTIC_QUALIFICATION_NOT_CLOSED",
        "historical_closeout_current_authority": False,
        "claim_registry_digest": registry["registry_digest"],
    }
    (OUT / "operational_status.v1.public.json").write_bytes(canonical(marker))
    absence = {
        "schema_id": "provan.session12r_private_planning_absence.v1",
        "sensitivity": "PUBLIC_SAFE",
        "phase": "PRE_IMPLEMENTATION_COMMIT",
        "result": "PRIVATE_PLANNING_AUTHORITY_ABSENT",
        "scopes": ["WORKTREE", "UNTRACKED", "INDEX", "PROPOSED_COMMIT", "HISTORY_DELTA", "PACKAGE", "PUBLIC_PROOFS", "EXAMPLES", "CONTROLLED_CI_ARTIFACTS"],
        "confidential_scanner_inputs_external": True,
        "gitignore_relied_upon": False,
        "limitations": ["GENERIC_PUBLIC_RESULT_ONLY", "CONFIDENTIAL_MATCH_INPUTS_NOT_RECORDED"],
    }
    (OUT / "private_planning_absence.pre_implementation.v1.public.json").write_bytes(canonical(absence))


if __name__ == "__main__":
    main()
