from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session12/successor_closeout/public"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha(raw):
    import hashlib
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(name, value):
    OUT.mkdir(parents=True, exist_ok=True); (OUT / name).write_bytes(canonical(value))


def main() -> int:
    entries = []
    for path in sorted((ROOT / "provan/schemas").glob("*.json"), key=lambda item: item.name):
        raw = path.read_bytes(); value = json.loads(raw)
        entries.append({"schema_id": value["$id"], "path": f"provan/schemas/{path.name}", "sha256": sha(raw), "normalized_sha256": sha(canonical(value)), "extension_class": "PUBLIC_CANONICAL" if path.name in {"source-authority-ledger.v2.json", "intent-model.v2.json", "contract-candidate.v2.json", "verification-pattern-selection.v2.json", "foundry-acceptance-projection.v2.json", "foundry-owner-review.v1.json"} else ("INTERNAL_CANONICAL" if path.name == "source-coverage.v1.json" else "INHERITED")})
    registry = {"schema_id": "provan.session12r_schema_registry.v1", "sensitivity": "PUBLIC_SAFE", "entries": entries, "registry_digest": sha(canonical(entries))}
    write("schema_registry.v1.public.json", registry)

    from provan.foundry import PUBLIC_PROMPTS
    prompt_rows = [{"prompt_id": key, "version": 1, "text": value, "sha256": sha(value.encode("utf-8")), "authority": "PUBLIC_COMMUNITY_POLICY_TEMPLATE"} for key, value in sorted(PUBLIC_PROMPTS.items())]
    prompts = {"schema_id": "provan.session12r_prompt_registry.v1", "sensitivity": "PUBLIC_SAFE", "policy_id": "community.contract-foundry.semantic-successor.v1", "prompts": prompt_rows, "registry_digest": sha(canonical(prompt_rows)), "per_run_payloads_public": False}
    write("prompt_registry.v1.public.json", prompts)
    model_policy = {"schema_id": "provan.session12r_model_policy.v1", "sensitivity": "PUBLIC_SAFE", "provider_id": "openai-responses-primary", "origin": "https://api.openai.com", "tier_1": {"model": "gpt-5.6-luna", "reasoning": "medium"}, "tier_2": {"model": "gpt-5.6-sol", "reasoning": "high"}, "tier_3": {"model": "gpt-5.6-sol", "reasoning": "high", "critic_required": True}, "availability_endpoint": "VALIDATION_ONLY", "dynamic_model_selection": False, "store_requested": False, "provider_retention": "PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED", "semantic_calls": {"background": False, "persistent_conversation": False, "previous_response_id": None, "stateless": True}, "structured_output": {"type": "json_schema", "strict": True, "max_items_per_class": 12, "max_string_characters": 320}, "pricing": {"policy_id": "openai-gpt-5.6-sol-public-rates-2026-08-20", "source": "https://developers.openai.com/api/docs/models/gpt-5.6-sol", "input_usd_per_million": 5.0, "cached_input_usd_per_million": 0.5, "output_usd_per_million": 30.0, "long_context_threshold_tokens": 272000, "long_context_input_multiplier": 2.0, "long_context_output_multiplier": 1.5, "status": "computed_from_provider_usage_not_invoice_attested"}, "stage_ceilings": {"standard": 8, "deep": 12}, "classification_fanout": {"calls": 16, "input_tokens": 512000, "output_tokens": 64000, "reserved_cost_usd": 2}, "run_limits": {"standard": {"calls": 24, "reserved_cost_usd": 5}, "deep": {"calls": 28, "reserved_cost_usd": 7}}, "session_hard_cap_usd": 75, "scripted_provider_semantic_qualification": False}
    write("model_policy.v1.public.json", model_policy)
    from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS
    egress = {"schema_id": "provan.session12r_model_egress_allowlist.v1", "sensitivity": "PUBLIC_SAFE", "classification": "PUBLIC_SAFE", "operator_authorization_required": True, "derived_public_artifacts_require_separate_authorization": True, "cases": [{"case_id": case_id, "source_digests": list(digests)} for case_id, digests in sorted(FROZEN_PUBLIC_MODEL_EGRESS.items())], "raw_private_inputs_public": False}
    write("model_egress_allowlist.v1.public.json", egress)
    hard_one = ["material_explicit_obligation_recall", "valid_acceptance", "near_valid_acceptance", "adversarial_rejection", "material_ambiguity_owner_routing", "material_oracle_disposition_completeness", "material_finding_disposition_coverage", "material_obligation_map_disposition", "material_verification_dimension_disposition", "material_mutation_plan_sensitivity", "non_material_mutation_stability"]
    hard_zero = ["unsupported_material_mandatory_criteria", "material_non_goal_errors", "exact_content_authority_errors", "implementation_authority_errors", "unaccounted_material_source", "wrongly_non_semantic_material_source", "wrongly_ignored_material_source", "unsupported_material_mappings_claimed_supported", "materially_irrelevant_patterns"]
    scorer = {"schema_id": "provan.session12r_semantic_scorer_policy.v1", "sensitivity": "PUBLIC_SAFE", "scorer_id": "community.contract-foundry.semantic-scorer.v1", "hard_one": hard_one, "hard_zero": hard_zero, "boolean_true": ["six_run_semantic_stability"], "macro_score_can_rescue": False, "semantic_equivalence": {"deterministic_checks": True, "fresh_blind_adjudicators": 2, "arm_identity_hidden": True, "material_disagreement": "FAIL", "same_family_requires_protected_reviewer": True}, "one_shot": True, "transport_retry": "ONLY_WHEN_NO_SEMANTIC_OUTPUT"}
    write("semantic_scorer_policy.v1.public.json", scorer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
