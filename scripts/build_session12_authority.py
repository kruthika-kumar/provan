from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
OUT = ROOT / "artifacts" / "session12" / "authority"


TOPICS = [
    "canonical Contract Foundry run descriptor", "separate owner-facing acceptance projection", "source authority ledger", "blind input boundary",
    "Fast deterministic stage order", "Standard qualified stage order", "Deep dual-path isolation", "independent Deep candidate or critique",
    "stateless semantic calls", "readiness and eligibility separation", "Gate-only maturity promotion", "Session 11 disposition projection",
    "explicit disposition of every mandatory term", "repository source-only behavior", "target byte/ref/index/object immutability", "no inspected-target execution",
    "manifest size limit", "per-source and aggregate size limits", "structured depth and node limits", "regular UTF-8 input only",
    "path traversal and link rejection", "unsupported format rejection", "source-ledger completeness", "candidate and case binding",
    "deterministic Tier 0 routing", "deterministic Tier 1 routing", "deterministic Tier 2 routing", "deterministic Tier 3 routing",
    "unresolved routing escalation", "model authority ceiling", "explicit provider allowlist", "configured model identity pinning",
    "provider availability validation only", "store-false retention limitation", "transport-framing-only adapter", "public versioned role prompts",
    "private per-run model envelopes", "no persistent response chaining", "no background semantic execution", "scripted provider nonqualification",
    "zero-call no-model behavior", "unavailable required role ineligibility", "seventy-five-dollar hard ceiling", "batch spend reservation",
    "pattern-library core-family completeness", "pattern version and preconditions", "pattern oracle requirements", "pattern test dimensions",
    "pattern capability requirements", "pattern limitations and false-inference risks", "pattern cost and research references", "pattern selection nonexecution",
    "browser and mobile future-capability boundary", "verifier and challenge future-capability boundary", "contract readiness meaning", "missing-oracle readiness handling",
    "audit finding coverage", "bounded revision caps", "witness and discrimination preservation", "independent semantic recomputation",
    "schema-invalid proof coverage", "schema-valid Python-invalid proof coverage", "private adjudication isolation", "adjudication root binding",
    "fresh independent adjudication review", "evaluation-driven adjudication invalidation", "sealed reserve-case preservation", "hidden grading exclusion",
    "frontier prompt baseline labeling", "coding-harness claim boundary", "same-family controlled comparison", "provider and model disclosure",
    "HTTPX low-risk control", "Click verification-surface control", "consequential multi-issue intent scope", "blind implementation separation",
    "complete issue-set scoring", "final implementation dogfood", "raw latency and cost reporting", "internal/client-safe sensitivity projections",
    "private planning authority absence", "no committed private scanner inputs", "supporting-object classification", "reuse of compatible Session 10/11 contracts",
    "unpublished package 0.5.0 binding", "extension API major one preservation", "Community and Enterprise dependency separation", "Enterprise scaffold-only compatibility",
    "authoritative isolated wheel", "candidate-build output isolation", "fresh-install site-packages origin", "nonrecursive pre-review root",
    "claim-source and proof binding", "substantive Session 13 handoff", "execution_available false", "challenge_available false",
    "model egress limited to an exact operator-confirmed PUBLIC_SAFE source digest closure",
    "pre-steering GPT-5.2 runs preserved as non-qualifying legacy sensitivity evidence",
    "current semantic qualification pinned to GPT-5.6 Sol with role-appropriate reasoning",
    "paired comparator arms use the same current strong model and disclose compute differences",
]


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def main() -> int:
    if len(TOPICS) < 94:
        raise RuntimeError(f"expected at least 94 frozen topics, got {len(TOPICS)}")
    claims = [{"claim_id": f"G12-{index:02d}", "normative_claim": f"Session 12 establishes {topic} with canonical evidence, independent semantic validation, and typed limitations."} for index, topic in enumerate(TOPICS, 1)]
    digest = "sha256:" + hashlib.sha256(canonical(claims)).hexdigest()
    registry = {"schema_id": "provan.session12_claim_registry.v1", "sensitivity": "PUBLIC_SAFE", "frozen_minimum": ["G12-01", "G12-94"], "additive_claims_start": "G12-95", "claims": claims, "registry_digest": digest}
    compatibility = {
        "schema_id": "provan.session12_object_classification.v1", "sensitivity": "PUBLIC_SAFE",
        "decisions": [
            {"object": "foundry_acceptance_projection", "classification": "PUBLIC_CANONICAL", "reason": "owner-disposition input requires a stable public contract"},
            {"object": "contract_foundry_run", "classification": "CANONICAL_INTERNAL", "reason": "binds complete case-local execution without becoming owner authority"},
            {"object": "source_path_manifest|blind_manifest|model_envelope|call_ledger", "classification": "INTERNAL_RUN_ARTIFACT", "reason": "may contain case-specific selected source data"},
            {"object": "hidden_adjudication|reserve_case|private_oracle", "classification": "PRIVATE_EVAL", "reason": "outcome-bearing hidden material remains in external private evaluation storage"},
            {"object": "model_usage_receipt|acceptance_preparation|seed_disposition", "classification": "REUSE_EXISTING", "reason": "Session 10/11 semantics already match"},
            {"object": "source_authority_ledger", "classification": "PUBLIC_CANONICAL", "reason": "existing context records do not bind bounded manifest membership, blind-input closure, and source-role authority"},
            {"object": "intent_model|goal_obstacle_model|premortem_analysis", "classification": "PUBLIC_CANONICAL", "reason": "existing Change Brief claims do not preserve the ordered Foundry reasoning-stage contracts"},
            {"object": "contract_candidate|contract_audit|contract_witness_set|contract_revision_record|contract_readiness", "classification": "PUBLIC_CANONICAL", "reason": "Session 11 immutable Acceptance artifacts cannot represent pre-owner proposal, critique, witnesses, revision, or owner-readiness semantics"},
            {"object": "verification_pattern|verification_pattern_selection", "classification": "PUBLIC_CANONICAL", "reason": "no inherited contract describes non-executing reusable verification pattern semantics or selection status"},
            {"object": "model_routing_receipt", "classification": "PUBLIC_CANONICAL", "reason": "the inherited usage receipt records calls but not deterministic tier/role derivation"},
            {"object": "session_handoff_v2", "classification": "PUBLIC_CANONICAL", "reason": "the inherited Session 12 handoff cannot bind Foundry run, projection, pattern library, mode qualification, or Session 13 prerequisites"},
            {"object": "session12_implementation_binding", "classification": "PUBLIC_CANONICAL", "reason": "the inherited binding cannot represent separate Standard and Deep Gate 12 maturity alongside the unpublished 0.5.0 package"},
            {"object": "foundry_real_use_qualification", "classification": "PUBLIC_CANONICAL", "reason": "the inherited real-use contract cannot bind multiple Foundry modes, adjudication root, control roles, blind boundaries, and harness-label limitations"},
            {"object": "pre_review_proof_manifest", "classification": "REUSE_EXISTING", "reason": "the Session 11 non-recursive proof-manifest semantics match without redesign"},
        ],
        "new_public_schema_rule": "EXPLICIT_SEMANTIC_INSUFFICIENCY_REQUIRED",
    }
    work_order={"schema_id":"provan.session12_work_order.v1","sensitivity":"PUBLIC_SAFE","status":"APPROVED_FOR_EXECUTION_WITH_MODEL_STEERING","baseline_commit":"6c1006c7fe546805aaefd0bc2b47a40317c19c88","package_version_expected":"0.5.0","extension_api_major":1,"boundaries":{"source_only":True,"target_read_only":True,"execution_available":False,"challenge_available":False,"session13_implemented":False,"private_planning_authority":"EXTERNAL_NOT_COPIED"},"qualification":{"development":"IMPLEMENTED_UNQUALIFIED","gate_only_promotion":True},"provider_pin":{"provider_id":"openai-responses-primary","origin":"https://api.openai.com","tier_1_model":"gpt-5.6-luna","tier_1_reasoning":"medium","tier_2_model":"gpt-5.6-sol","tier_2_reasoning":"high","tier_3_model":"gpt-5.6-sol","tier_3_reasoning":"xhigh","availability_endpoint_use":"VALIDATION_ONLY_NOT_SELECTION","store_requested":False,"retention":"NOT_ZERO_OR_ESTABLISHED","stateless":True},"legacy_model_policy":{"model":"gpt-5.2","classification":"PRE_STEERING_LEGACY_MODEL_RUN","eligible_for_final_semantic_qualification":False,"eligible_for_headline_comparison":False,"eligible_as_preserved_sensitivity_development_evidence":True},"budget":{"currency":"USD","hard_cap":75,"legacy_spend_counted":True},"public_case_categories":["low-risk-control","verification-surface-control","consequential-multi-issue","internal-dogfood"],"limitations":["NO_RUNTIME_VERIFICATION","NO_CHALLENGE_EXECUTION","UNPUBLISHED_PACKAGE","SAME_MODEL_FAMILY_DOES_NOT_ESTABLISH_PROVIDER_INDEPENDENCE"]}
    steering={"schema_id":"provan.session12_model_steering_correction.v1","sensitivity":"PUBLIC_SAFE","status":"APPLIED_BEFORE_FURTHER_OUTCOME_BEARING_CALLS","legacy":{"model":"gpt-5.2","calls":7,"classification":"PRE_STEERING_LEGACY_MODEL_RUN","eligible_for_final_semantic_qualification":False,"eligible_for_headline_arms_comparison":False,"eligible_as_preserved_sensitivity_development_evidence":True,"exact_private_inputs_outputs_receipts_preserved":True},"affected_obligations":["click-semantic-control","arm-a-frontier-prompt-baseline","arm-b-iterated-frontier-prompt-baseline","foundry-standard","foundry-deep"],"corrected":{"tier_1":{"model":"gpt-5.6-luna","reasoning":"medium","qualification_required_before_use":True},"tier_2":{"model":"gpt-5.6-sol","reasoning":"high"},"tier_3":{"model":"gpt-5.6-sol","reasoning":"xhigh"},"origin":"https://api.openai.com","stateless":True,"previous_response_id":None,"background":False},"limitations":["GPT_5_2_NOT_CURRENT_QUALIFICATION_EVIDENCE","SAME_SOL_MODEL_DOES_NOT_ESTABLISH_PROVIDER_OR_MODEL_FAMILY_INDEPENDENCE","RESPONSES_BASELINES_ARE_NOT_CODING_HARNESS_COMPARISONS"]}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "claim_registry.v1.public.json").write_bytes(canonical(registry))
    (OUT / "object_classification.v1.public.json").write_bytes(canonical(compatibility))
    (OUT / "work_order.v1.public.json").write_bytes(canonical(work_order))
    (OUT / "model_steering_correction.v1.public.json").write_bytes(canonical(steering))
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
