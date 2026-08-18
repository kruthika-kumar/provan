from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).parents[1]))
from provan.canonical import canonical_bytes,sha256_bytes


ROOT=Path(__file__).parents[1]
OUT=ROOT/"artifacts/session12/public/adjudication_projection.v1.public.json"


def main()->int:
    cases=[
        {"case_id":"httpx-pr-3699-control","category":"low_risk_no_friction_control","source_set_count":1},
        {"case_id":"click-pr-3721-control","category":"ci_verification_surface_control","source_set_count":1},
        {"case_id":"httpcore-pr-880-consequential","category":"multi_issue_consequential_behavioral_intent","source_set_count":4},
        {"case_id":"provan-public-control","category":"existing_public_product_control","source_set_count":1},
        {"case_id":"session11-controlled-patient","category":"typed_closure_control","source_set_count":1},
    ]
    authority={
        "source_snapshot_root":"sha256:7ce782b1c82ae3cfc32157a6673d85fdfac12a734f5fbc903ba103fc1df32b11",
        "frozen_case_registry_sha256":"sha256:feffa3956b5bacbe0d7316b7addf1adb57c14929b37f2d20d1d1738c2fd3d97c",
        "evaluation_policy_sha256":"sha256:0a14149edf23b2755d31ee74b856cc01e2487316fedc85be4e95acd466ba4efb",
        "review_receipt_sha256":"sha256:1352644c667b67bc89f49a0f1d3d365f785243716c9d1c35eb914460e09eee7a",
        "review_root":"sha256:a7123e5fca6fd6d6ab8a95d7d70ac1e32200af4e1481a7cd825cd6ddd48bf81e",
    }
    value={
        "schema_id":"provan.session12_adjudication_projection.v1",
        "sensitivity":"PUBLIC_SAFE",
        "disposition":"GO",
        "findings":{"P0":0,"P1":0,"P2":0},
        "case_summary":{"headline_cases":len(cases),"reserve_cases":2,"cases":cases},
        "authority_bindings":authority,
        "independence":{"fresh_read_only_review":True,"review_completed_before_outcome_runs":True,"evaluation_driven_changes_invalidate_comparisons":True},
        "coding_harness_sanity":{"status":"OBTAINED","claim_scope":"SINGLE_BLIND_SANITY_NOT_HEADLINE_COMPARISON","case_id":"httpcore-pr-880-consequential","input_scope":"FOUR_PUBLIC_INTENT_SOURCES_ONLY","implementation_material_seen":False,"output_sha256":"sha256:cbbbc517cd7f1a9c3366c5c388d3c4892c343d13f8a81b013ebadb75348e3014","receipt_sha256":"sha256:f54704e154bb20573a0cddbbf324488325b4e65cd6adbd27a3542716a40b33bd","full_harness_comparison_deferred_to_session":16},
        "deterministic_control_runs":{
            "ledger_sha256":"sha256:ae3c0a8f463d2022120ae416c1e9d51498a8251c646295e873a5067a1232aecc",
            "model_calls":0,
            "outcomes":[
                {"case_id":"httpx-pr-3699-control","tier":"TIER_0","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
                {"case_id":"click-pr-3721-control","tier":"TIER_2","run_eligibility":"NOT_ELIGIBLE","contract_readiness":"NOT_READY"},
                {"case_id":"httpcore-pr-880-consequential","tier":"TIER_3","run_eligibility":"NOT_ELIGIBLE","contract_readiness":"NOT_READY"},
            ],
            "limitations":["PRIVATE_CASE_ARTIFACTS_NOT_PROJECTED","NO_LIVE_SEMANTIC_MODEL_EXECUTION"],
        },
        "pre_steering_legacy_model_run":{"model":"gpt-5.2","calls":7,"classification":"PRE_STEERING_LEGACY_MODEL_RUN","private_ledger_sha256":"sha256:73006a2a28b04acdd845005bade1e92844593a0b2fd4c86f2f79f83810af6e63","estimated_cost_usd":0.08529675000000002,"eligible_for_final_semantic_qualification":False,"eligible_for_headline_arms_comparison":False,"eligible_as_preserved_sensitivity_development_evidence":True,"exact_private_artifacts_preserved":True},
        "live_evaluation":{
            "implementation_commit":"dd5593d15800df57b78e495853479efb50725bf5",
            "private_ledger_sha256":"sha256:bad984acf282219e24f9f89b3a3cbedefca0f16951221021ae6a1e70670728a8",
            "provider":{"id":"openai-responses-primary","origin":"https://api.openai.com","model":"gpt-5.6-sol","tier_2_reasoning":"high","tier_3_reasoning":"xhigh","store_requested":False,"provider_retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED"},
            "calls":7,"estimated_cost_usd":0.406895,"legacy_spend_counted_usd":0.08529675000000002,"total_session_estimated_cost_usd":0.49219175000000004,"hard_cap_usd":75,
            "arms":[
                {"arm":"A","label":"STRONG_CURRENT_FRONTIER_PROMPT_BASELINE","reasoning":"high","result_sha256":"sha256:35768ef5e2f4a16da829f6a3c3d1939539930005b1dc1a4dcac3e39ac7a2a87c"},
                {"arm":"B","label":"STRONG_CURRENT_FRONTIER_PROMPT_BASELINE","reasoning":"xhigh","iteration":"single_call_propose_review_revise","result_sha256":"sha256:fa24d203aed2346c4498410439c8bf1a382750614e4642f65c542983adaf3292"},
                {"arm":"C","label":"FOUNDRY_STANDARD","reasoning":"high","run_sha256":"sha256:82299629c4fba5b58d27d49a4a796023239c5a7a2d47f78ec3d7b9ac98a8238d","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
                {"arm":"D","label":"FOUNDRY_DEEP","reasoning":"xhigh","run_sha256":"sha256:dacd50a4967b766ed8eb5c66304e8afd3c959c42ce4fbcc7deee076de5da9ac5","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
            ],
            "click_control":{"run_sha256":"sha256:31f522c4a380165a6f9a104aa20f74eadcdb392346776a8a675184dbb95e4f7e","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
            "httpx_control":{"run_sha256":"sha256:6f792c8ffc6df50987569a3ccc1c00f416e9728b5964fce97320a82269877f4d","model_calls":0,"run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
            "limitations":["OUTPUT_CONTENT_PRIVATE","FRONTIER_PROMPT_BASELINES_NOT_CODING_HARNESS","ARM_B_SINGLE_CALL_INTERNAL_ITERATION","A_C_AND_B_D_SHARE_SOL_BUT_DIFFER_IN_CALL_STRUCTURE","SAME_SOL_MODEL_DOES_NOT_ESTABLISH_PROVIDER_OR_MODEL_FAMILY_INDEPENDENCE","FULL_HARNESS_COMPARISON_SESSION16"],
        },
        "exclusions":["EXACT_INPUTS_EXCLUDED","HIDDEN_ADJUDICATION_EXCLUDED","ORACLES_EXCLUDED","WITNESSES_EXCLUDED","PRIVATE_PATHS_EXCLUDED"],
    }
    value["projection_digest"]=sha256_bytes(canonical_bytes(value))
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_bytes(canonical_bytes(value));print(value["projection_digest"]);return 0


if __name__=="__main__":raise SystemExit(main())
