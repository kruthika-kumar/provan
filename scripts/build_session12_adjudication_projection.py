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
        "exclusions":["EXACT_INPUTS_EXCLUDED","HIDDEN_ADJUDICATION_EXCLUDED","ORACLES_EXCLUDED","WITNESSES_EXCLUDED","PRIVATE_PATHS_EXCLUDED"],
    }
    value["projection_digest"]=sha256_bytes(canonical_bytes(value))
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_bytes(canonical_bytes(value));print(value["projection_digest"]);return 0


if __name__=="__main__":raise SystemExit(main())
