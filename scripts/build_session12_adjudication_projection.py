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
        "live_evaluation":{
            "implementation_commit":"0efeb9bb3fa698a3dbd14b3f1622ade5d8404f97",
            "private_ledger_sha256":"sha256:a1230c34677ea977c42fcf44f694240e0993bd6352a266f17438078a92d03282",
            "provider":{"id":"openai-responses-primary","origin":"https://api.openai.com","model":"gpt-5.2","store_requested":False,"provider_retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED"},
            "calls":7,"estimated_cost_usd":0.08490475,"hard_cap_usd":75,
            "arms":[
                {"arm":"A","label":"FRONTIER_PROMPT_BASELINE","result_sha256":"sha256:2a27c83d774426b437302f37d72620338d9f149301560d5cacb7bc66f626fc65"},
                {"arm":"B","label":"FRONTIER_PROMPT_BASELINE","result_sha256":"sha256:7988072fbdd211da0e52219c5a36ffa6c02b0b49c0335c94246a559b2b0b308d"},
                {"arm":"C","label":"FOUNDRY_STANDARD","run_sha256":"sha256:a31b9e313966ac8900bc0541fe80678cf63381f7db1774652ebc7da43fecf73b","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
                {"arm":"D","label":"FOUNDRY_DEEP","run_sha256":"sha256:1bf73e5ef433310d272d9568a1a843975f49acac15381cc66e7c309a2bea6a24","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
            ],
            "click_control":{"run_sha256":"sha256:36c00e2b5a66d4fd9dda807532829c8707478924ef9322a3b7ed57296fda762f","run_eligibility":"ELIGIBLE","contract_readiness":"READY_WITH_MATERIAL_QUESTIONS"},
            "limitations":["OUTPUT_CONTENT_PRIVATE","FRONTIER_PROMPT_BASELINES_NOT_CODING_HARNESS","FULL_HARNESS_COMPARISON_SESSION16"],
        },
        "exclusions":["EXACT_INPUTS_EXCLUDED","HIDDEN_ADJUDICATION_EXCLUDED","ORACLES_EXCLUDED","WITNESSES_EXCLUDED","PRIVATE_PATHS_EXCLUDED"],
    }
    value["projection_digest"]=sha256_bytes(canonical_bytes(value))
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_bytes(canonical_bytes(value));print(value["projection_digest"]);return 0


if __name__=="__main__":raise SystemExit(main())
