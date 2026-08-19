from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from provan.canonical import canonical_bytes, sha256_bytes


ROOT = Path(__file__).parents[1]
OUT = ROOT / "artifacts/session12/public/adjudication_projection.v1.public.json"


def file_sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-session12-root", type=Path, required=True)
    parser.add_argument("--policy", default="evaluation_policy.v10.private.json")
    parser.add_argument("--review", default="adjudication_review_receipt.v6.private.json")
    parser.add_argument("--ledger", default="foundry_qualified_model_arms.v6.private.json")
    parser.add_argument("--scoring", default="foundry_qualified_model_scoring.v5.private.json")
    args = parser.parse_args(); private = args.private_session12_root.resolve()
    registry_path = private / "frozen_case_registry.v1.private.json"; source_path = private / "source_snapshot_manifest.v1.private.json"; policy_path = private / args.policy; review_path = private / args.review; ledger_path = private / args.ledger; scoring_path = private / args.scoring
    for path in (registry_path, source_path, policy_path, review_path, ledger_path, scoring_path):
        if not path.is_file(): raise SystemExit("SESSION12_PRIVATE_PROJECTION_AUTHORITY_MISSING:" + path.name)
    registry=json.loads(registry_path.read_text(encoding="utf-8"));source=json.loads(source_path.read_text(encoding="utf-8"));policy=json.loads(policy_path.read_text(encoding="utf-8"));review=json.loads(review_path.read_text(encoding="utf-8"));ledger=json.loads(ledger_path.read_text(encoding="utf-8"));scoring=json.loads(scoring_path.read_text(encoding="utf-8"))
    if not isinstance(policy.get("version"),int) or policy["version"]<1 or review.get("result")!="GO" or review.get("evaluation_policy_sha256")!=file_sha(policy_path) or ledger.get("evaluation_policy_sha256")!=file_sha(policy_path) or scoring.get("evaluation_policy_sha256")!=file_sha(policy_path) or scoring.get("model_arms_ledger_sha256")!=file_sha(ledger_path) or {"commit":ledger.get("implementation_commit"),"tree":ledger.get("implementation_tree")}!=policy.get("implementation_binding"):raise SystemExit("SESSION12_PRIVATE_PROJECTION_BINDING_INVALID")
    cases=[{"case_id":"httpx-pr-3699-control","category":"low_risk_no_friction_control","source_set_count":1},{"case_id":"click-pr-3721-control","category":"ci_verification_surface_control","source_set_count":1},{"case_id":"httpcore-pr-880-consequential","category":"multi_issue_consequential_behavioral_intent","source_set_count":4},{"case_id":"provan-public-control","category":"existing_public_product_control","source_set_count":1},{"case_id":"session11-controlled-patient","category":"typed_closure_control","source_set_count":1}]
    arm_rows=[];click=None;httpx=None
    for row in ledger["runs"]:
        if row.get("arm") in {"A","B"}:arm_rows.append({"arm":row["arm"],"label":row["label"],"reasoning":row["usage"]["reasoning_effort"],"result_sha256":row["result_sha256"],**({"iteration":row["iteration"]} if row.get("iteration") else {})})
        elif row.get("case_id")=="httpcore-pr-880-consequential":arm_rows.append({"arm":"C" if row["mode"]=="standard" else "D","label":row["label"],"reasoning":"high" if row["mode"]=="standard" else "xhigh","run_sha256":row["run_sha256"],"run_eligibility":row["eligibility"],"contract_readiness":row["readiness"]})
        elif row.get("case_id")=="click-pr-3721-control":click={"run_sha256":row["run_sha256"],"run_eligibility":row["eligibility"],"contract_readiness":row["readiness"]}
        elif row.get("case_id")=="httpx-pr-3699-control":httpx={"run_sha256":row["run_sha256"],"model_calls":0,"run_eligibility":row["eligibility"],"contract_readiness":row["readiness"]}
    if {row["arm"] for row in arm_rows}!={"A","B","C","D"} or click is None or httpx is None:raise SystemExit("SESSION12_CURRENT_ARM_SET_INCOMPLETE")
    authority={"source_snapshot_root":source["root"],"frozen_case_registry_sha256":file_sha(registry_path),"evaluation_policy_sha256":file_sha(policy_path),"review_receipt_sha256":file_sha(review_path),"review_root":review["aggregate_review_root"]}
    scoring_public={"scoring_sha256":file_sha(scoring_path),"complete_issue_set_scored":scoring["complete_issue_set_scored"],"dimensions":scoring["dimensions"],"arms":[{"arm":row["arm"],"covered":row["covered"],"total":row["total"],"score":row["score"]} for row in scoring["arm_results"]],"evaluation_driven_adjudication_change":scoring["evaluation_driven_adjudication_change"],"limitations":["AGGREGATES_ONLY_HIDDEN_CONTENT_EXCLUDED",*scoring["limitations"]]}
    provider={key:ledger["provider"][key] for key in ("id","origin","model","tier_2_reasoning","tier_3_reasoning","store_requested","retention")};provider["provider_retention"]=provider.pop("retention")
    value={"schema_id":"provan.session12_adjudication_projection.v1","sensitivity":"PUBLIC_SAFE","disposition":"GO","findings":{"P0":0,"P1":0,"P2":0},"case_summary":{"headline_cases":len(cases),"reserve_cases":2,"cases":cases},"authority_bindings":authority,"independence":{"fresh_read_only_review":True,"review_completed_before_outcome_runs":True,"evaluation_driven_changes_invalidate_comparisons":True},"coding_harness_sanity":{"status":"OBTAINED","claim_scope":"SINGLE_BLIND_SANITY_NOT_HEADLINE_COMPARISON","case_id":"httpcore-pr-880-consequential","input_scope":"FOUR_PUBLIC_INTENT_SOURCES_ONLY","implementation_material_seen":False,"output_sha256":"sha256:cbbbc517cd7f1a9c3366c5c388d3c4892c343d13f8a81b013ebadb75348e3014","receipt_sha256":"sha256:f54704e154bb20573a0cddbbf324488325b4e65cd6adbd27a3542716a40b33bd","full_harness_comparison_deferred_to_session":16},"pre_steering_legacy_model_run":{"model":"gpt-5.2","calls":7,"classification":"PRE_STEERING_LEGACY_MODEL_RUN","private_ledger_sha256":"sha256:73006a2a28b04acdd845005bade1e92844593a0b2fd4c86f2f79f83810af6e63","estimated_cost_usd":0.08529675000000002,"eligible_for_final_semantic_qualification":False,"eligible_for_headline_arm_comparison":False,"eligible_for_headline_comparison":False,"eligible_as_preserved_sensitivity_development_evidence":True,"exact_private_artifacts_preserved":True},"live_evaluation":{"implementation_commit":ledger["implementation_commit"],"evaluation_policy_version":policy["version"],"private_ledger_sha256":file_sha(ledger_path),"provider":provider,"calls":ledger["calls"],"total_latency_ms":sum(float(row.get("latency_ms") or 0) for row in ledger["usage"]),"estimated_cost_usd":ledger["estimated_cost_usd"],"prior_session_spend_counted_usd":ledger["prior_session_spend_counted_usd"],"total_session_estimated_cost_usd":ledger["total_session_estimated_cost_usd"],"hard_cap_usd":ledger["hard_cap_usd"],"arms":sorted(arm_rows,key=lambda row:row["arm"]),"click_control":click,"httpx_control":httpx,"hidden_scoring":scoring_public,"limitations":ledger["limitations"]},"exclusions":["EXACT_INPUTS_EXCLUDED","HIDDEN_ADJUDICATION_EXCLUDED","ORACLES_EXCLUDED","WITNESSES_EXCLUDED","PRIVATE_PATHS_EXCLUDED"]}
    value["live_evaluation"]["evaluation_policy_version"]=policy["version"]
    legacy=value["pre_steering_legacy_model_run"]
    legacy.pop("eligible_for_headline_arm_comparison",None)
    legacy.pop("eligible_for_headline_comparison",None)
    legacy["eligible_for_headline_arms_comparison"]=False
    value["projection_digest"]=sha256_bytes(canonical_bytes(value));OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_bytes(canonical_bytes(value));print(value["projection_digest"]);return 0


if __name__=="__main__":raise SystemExit(main())
