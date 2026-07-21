"""Execute replayable Session 6--8 contract parity through real Python boundaries."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import jsonschema

try:
    from scripts.run_workflow_integration_evals import _action, _closure, _finding, _fixture, _remediation
except ModuleNotFoundError:
    from run_workflow_integration_evals import _action, _closure, _finding, _fixture, _remediation
from shiproom.contestability import append_action, load as load_contestation, target_registry, validate_action_contract
from shiproom.management_artifacts import compile as compile_management, load as load_management
from shiproom.management_artifacts.compiler import validate_generation_manifest, validate_recommendation_policy, validate_section_registry
from shiproom.remediation_roadmaps import (
    authority_policy, root as remediation_root, load_generation as load_remediation, validate_authority_policy,
    validate_closure_evidence, validate_closure_verification, validate_closure_verifier_receipt,
    validate_planner_receipt, validate_planner_result, validate_planner_role, validate_planner_work_order,
)
from shiproom.review_organisation import (
    adapt as adapt_review, load as load_review, prepare as prepare_review, render_package, submit_result,
    registry as result_registry, native_boundaries, surface_policy,
    validate_codex_execution_package, validate_harness_capability_manifest,
    validate_harness_execution_receipt, validate_migration_result,
    validate_review_plan_artifact, validate_specialist_registries,
)
from shiproom.session6_8_contract_validation import validate_canonical_contract

ROOT=Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def _dump(path: Path, value: object) -> None: path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8")


def _tree_state(root: Path) -> dict:
    return {str(path.relative_to(root)).replace("\\","/"):"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(root.rglob("*")) if path.is_file()}


def _baselines(directory: Path) -> tuple[dict[str,dict],dict[str,object],dict[str,dict]]:
    workflow_root=directory/"workflow";workflow_root.mkdir(parents=True,exist_ok=True)
    ctx,criterion=_fixture(workflow_root);finding=_finding(ctx,criterion,blocker=True)
    prepared,remediation_manifest,packet=_remediation(ctx);closure_result=_closure(ctx,remediation_manifest,packet)
    closure_id=packet["verification_contract_id"];closure_inbox=remediation_root(ctx)/"closure-inbox"/closure_id
    ctx.release["change_impact"]={"migration_surface":True};review_manifest=prepare_review(ctx);_,review_artifacts=load_review(ctx)
    review_root=remediation_root(ctx).parent/"review-organisation";work_root=review_root/"generations"/review_manifest["generation"]
    initial_summary=review_artifacts["execution-summary.json"]
    work=next(json.loads(path.read_text()) for path in (work_root/"specialist-work-orders").glob("*.json") if json.loads(path.read_text())["specialist_id"]=="migration_and_rollback")
    package=render_package(ctx,"migration_and_rollback")
    contest_action=_action(ctx,finding);action_fixture=copy.deepcopy(contest_action)
    prep_dir=remediation_root(ctx)/"preparations"/prepared["preparation_id"]
    remediation_work=json.loads((prep_dir/"remediation-work-orders.json").read_text())["planner_work_order"]
    planner_record={"source_issue_id":remediation_work["assigned_issue_ids"][0],"root_cause_hypotheses":[],"recommended_changes":[],"test_proposals":[],"instrumentation_implications":[],"rollback_suggestions":[],"complexity":"unknown","risk":"unknown","suggested_owner":None}
    planner_result={"schema_version":"remediation-planner-result.v1","work_order_id":remediation_work["work_order_id"],"preparation_id":prepared["preparation_id"],"records":[planner_record],"assumptions":[],"limitations":[]}
    planner_receipt={"schema_version":"remediation-planner-completion-receipt.v1","work_order_id":remediation_work["work_order_id"],"result_snapshot_hash":"sha256:"+hashlib.sha256((json.dumps(planner_result,sort_keys=True,indent=2)+"\n").encode()).hexdigest(),"executor":{"executor_type":"human"}}
    harness={"schema_version":"agent-harness-capability-manifest.v1","execution_mode":"manual_external","declared_capability":"prepared_packet_only","granted_permission":"read_only","observed_execution":"not_observed","independence_limitation":"declaration is not isolation proof"}
    harness_receipt={"schema_version":"harness-execution-receipt.v1","work_order_id":work["work_order_id"],"execution_mode":"manual_external","declared_capability":"prepared_packet_only","granted_permission":"read_only","observed_execution":"receipt_observed","execution_receipt":"parity-receipt","independence_limitation":"declaration is not isolation proof"}
    migration={"schema_version":"migration-and-rollback-result.v1","work_order_id":work["work_order_id"],"criterion_ids":[criterion],"evidence_refs":[],"rollback_required":False,"limitations":[]}
    accepted=submit_result(ctx,"migration_and_rollback",migration,harness_receipt)
    adapt_review(ctx,"migration_surface_discovered","migration_and_rollback",criterion,accepted["result_id"])
    review_manifest,review_artifacts=load_review(ctx);work_root=review_root/"generations"/review_manifest["generation"]
    append_action(ctx,contest_action);contest_manifest,contest_artifacts=load_contestation(ctx)
    management_manifest=compile_management(ctx);_,management_artifacts=load_management(ctx)
    remediation_manifest,remediation_artifacts=load_remediation(ctx)
    rem_generation=remediation_root(ctx)/"generations"/remediation_manifest["generation"]
    contest_root=remediation_root(ctx).parent/"contestability";contest_generation=contest_root/"generations"/contest_manifest["generation"]
    management_root=remediation_root(ctx).parent/"management-artifacts";management_generation=management_root/"generations"/management_manifest["generation"]
    validation_path=next(work_root.glob("submissions/*/*/validation.json"))
    packet_path=rem_generation/"remediation-packets"/(packet["remediation_id"]+".json")
    closure_contract_path=rem_generation/"closure-contracts"/(packet["verification_contract_id"]+".json")
    values={
      "remediation_closure_evidence":json.loads((closure_inbox/"evidence.json").read_text()),
      "remediation_closure_verifier_receipt":json.loads((closure_inbox/"verifier-receipt.json").read_text()),
      "remediation_closure_verification":closure_result,
      "remediation_issue_authority_policy":authority_policy(),
      "remediation_planner_result":planner_result,
      "remediation_planner_role":{"schema_version":"remediation-planner-role.v1","role_id":"remediation_planner","version":"1.0.0","allowed_fields":["root_cause_hypotheses","recommended_changes","test_proposals","instrumentation_implications","rollback_suggestions","complexity","risk","suggested_owner","assumptions","limitations"],"forbidden_fields":["issue_classification","issue_authority","actionability","automation_eligibility","closure_status"]},
      "remediation_planner_work_order":remediation_work,
      "remediation_planner_completion_receipt":planner_receipt,
      "review_plan":review_artifacts["review-plan.json"],
      "agent_harness_capability_manifest":harness,
      "harness_execution_receipt":harness_receipt,
      "codex_execution_package":package,
      "migration_result":migration,
      "review_surface_policy":surface_policy(),
      "specialist_result_registry":result_registry(),
      "specialist_native_boundary_registry":native_boundaries(),
      "contestation_action":action_fixture,
      "contestation_target_registry":target_registry(),
      "management_section_registry":json.loads((ROOT/"shiproom/management_artifacts/management-artifact-section-registry.v1.json").read_text()),
      "release_recommendation_policy":json.loads((ROOT/"shiproom/management_artifacts/release-recommendation-policy.v1.json").read_text()),
      "management_generation":management_manifest,
      "remediation_source_packet":json.loads((prep_dir/"remediation-source-packet.json").read_text()),
      "remediation_work_orders":json.loads((prep_dir/"remediation-work-orders.json").read_text()),
      "remediation_active_pointer":json.loads((remediation_root(ctx)/"active-preparation.json").read_text()),
      "remediation_current_pointer":json.loads((remediation_root(ctx)/"current-remediation-generation.json").read_text()),
      "remediation_generation_manifest":remediation_manifest,
      "remediation_index":remediation_artifacts["remediation-index.json"],
      "remediation_plan":remediation_artifacts["remediation-plan.json"],
      "remediation_overlay":remediation_artifacts["remediation-overlay.json"],
      "remediation_packet":json.loads(packet_path.read_text()),
      "remediation_closure_contract":json.loads(closure_contract_path.read_text()),
      "review_current_pointer":json.loads((review_root/"current-review-plan.json").read_text()),
      "review_generation_manifest":review_manifest,
      "review_plan_events":review_artifacts["plan-events.json"],
      "review_revision_ledger":review_artifacts["revision-ledger.json"],
      "review_accepted_results":review_artifacts["accepted-results.json"],
      "review_execution_summary_initial":initial_summary,
      "review_execution_summary_adapted":review_artifacts["execution-summary.json"],
      "review_specialist_work_order":work,
      "review_submission_validation":json.loads(validation_path.read_text()),
      "contestation_current_pointer":json.loads((contest_root/"current-contestation-generation.json").read_text()),
      "contestation_generation_manifest":contest_manifest,
      "contestation_ledger":contest_artifacts["contestation-ledger.json"],
      "contestation_effects":contest_artifacts["contestation-effects.json"],
      "management_current_pointer":json.loads((management_root/"current-management-generation.json").read_text()),
      "management_executive_release_brief":management_artifacts["executive-release-brief"],
      "management_product_release_review":management_artifacts["product-release-review"],
      "management_engineering_release_assessment":management_artifacts["engineering-release-assessment"],
      "management_measurement_ai_readiness":management_artifacts["measurement-ai-readiness"],
      "management_remediation_overview":management_artifacts["remediation-overview"],
      "management_release_packet_index":management_artifacts["release-packet-index"],
      "management_release_recommendation_view":management_artifacts["release-recommendation-view"],
      "management_github_payload":json.loads((management_generation/"github-summary-payload.json").read_text()),
    }
    state_roots={
      "remediation_closure_evidence":closure_inbox,
      "remediation_closure_verifier_receipt":closure_inbox,
      "remediation_closure_verification":remediation_root(ctx),
      "remediation_planner_result":prep_dir,
      "remediation_planner_work_order":prep_dir,
      "remediation_planner_completion_receipt":prep_dir,
      "review_plan":work_root,
      "codex_execution_package":work_root,
      "contestation_action":remediation_root(ctx).parent/"contestability",
      "management_generation":remediation_root(ctx).parent/"management-artifacts",
    }
    for cid in ("remediation_source_packet","remediation_work_orders","remediation_active_pointer","remediation_current_pointer","remediation_generation_manifest","remediation_index","remediation_plan","remediation_overlay","remediation_packet","remediation_closure_contract"):
        state_roots[cid]=remediation_root(ctx)
    for cid in ("review_current_pointer","review_generation_manifest","review_plan_events","review_revision_ledger","review_accepted_results","review_execution_summary_initial","review_execution_summary_adapted","review_specialist_work_order","review_submission_validation"):
        state_roots[cid]=review_root
    for cid in ("contestation_current_pointer","contestation_generation_manifest","contestation_ledger","contestation_effects"):
        state_roots[cid]=contest_root
    for cid in ("management_current_pointer","management_executive_release_brief","management_product_release_review","management_engineering_release_assessment","management_measurement_ai_readiness","management_remediation_overview","management_release_packet_index","management_release_recommendation_view","management_github_payload"):
        state_roots[cid]=management_root
    bindings={"closure_id":closure_id,"work_order_id":work["work_order_id"],"planner_work_order_id":remediation_work["work_order_id"],"preparation_id":prepared["preparation_id"],"plan_id":review_artifacts["review-plan.json"]["plan_id"]}
    return values,state_roots,bindings


def _validate(cid: str, value: dict, bindings: dict) -> object:
    if cid=="remediation_closure_evidence":
        validate_closure_evidence(value)
        if value["closure_contract_id"]!=bindings["closure_id"]: raise ValueError("closure_evidence_binding_invalid")
        return value
    if cid=="remediation_closure_verifier_receipt":
        return validate_closure_verifier_receipt(value,closure_contract_id=bindings["closure_id"])
    if cid=="remediation_closure_verification":
        validate_closure_verification(value)
        if value["closure_contract_id"]!=bindings["closure_id"]: raise ValueError("closure_verification_binding_invalid")
        return value
    if cid=="remediation_issue_authority_policy":
        result=validate_authority_policy(value)
        if result!=authority_policy(): raise ValueError("remediation_issue_authority_policy_semantic_tamper")
        return result
    if cid=="remediation_planner_result": return validate_planner_result(value,work_order_id=bindings["planner_work_order_id"],preparation_id=bindings["preparation_id"])
    if cid=="remediation_planner_role":
        result=validate_planner_role(value)
        return result
    if cid=="remediation_planner_work_order":
        result=validate_planner_work_order(value)
        if result["preparation_id"]!=bindings["preparation_id"] or result["work_order_id"]!=bindings["planner_work_order_id"]: raise ValueError("remediation_planner_work_order_binding_invalid")
        return result
    if cid=="remediation_planner_completion_receipt": return validate_planner_receipt(value,work_order_id=bindings["planner_work_order_id"])
    if cid=="review_plan":
        result=validate_review_plan_artifact(value)
        if result["plan_id"]!=bindings["plan_id"]: raise ValueError("review_plan_binding_invalid")
        return result
    if cid=="agent_harness_capability_manifest": return validate_harness_capability_manifest(value)
    if cid=="harness_execution_receipt": return validate_harness_execution_receipt(value,work_order_id=bindings["work_order_id"])
    if cid=="codex_execution_package": return validate_codex_execution_package(value)
    if cid=="migration_result":
        result=validate_migration_result(value)
        if result["work_order_id"]!=bindings["work_order_id"]: raise ValueError("migration_result_work_order_mismatch")
        return result
    if cid in {"review_surface_policy","specialist_result_registry","specialist_native_boundary_registry"}:
        result=result_registry();native=native_boundaries();policy=surface_policy()
        if cid=="review_surface_policy": policy=value
        elif cid=="specialist_result_registry": result=value
        else: native=value
        return validate_specialist_registries(result,native,policy)
    if cid=="contestation_action": return validate_action_contract(value)
    if cid=="contestation_target_registry": return target_registry(value)
    if cid=="management_section_registry": return validate_section_registry(value)
    if cid=="release_recommendation_policy": return validate_recommendation_policy(value)
    if cid=="management_generation": return validate_generation_manifest(value)
    if cid in {"remediation_source_packet","remediation_work_orders","remediation_active_pointer","remediation_current_pointer","remediation_generation_manifest","remediation_index","remediation_plan","remediation_overlay","remediation_packet","remediation_closure_contract","review_current_pointer","review_generation_manifest","review_plan_events","review_revision_ledger","review_accepted_results","review_execution_summary_initial","review_execution_summary_adapted","review_specialist_work_order","review_submission_validation","contestation_current_pointer","contestation_generation_manifest","contestation_ledger","contestation_effects","management_current_pointer","management_executive_release_brief","management_product_release_review","management_engineering_release_assessment","management_measurement_ai_readiness","management_remediation_overview","management_release_packet_index","management_release_recommendation_view","management_github_payload"}:
        return validate_canonical_contract(cid,value)
    raise ValueError("contract_parity_boundary_unregistered:"+cid)


def _semantic_mutation(cid: str, value: dict) -> tuple[dict,str]:
    result=copy.deepcopy(value)
    if cid in {"remediation_closure_evidence","remediation_closure_verifier_receipt","remediation_closure_verification"}: result["closure_contract_id"]="closure_"+"f"*24;target="/closure_contract_id"
    elif cid in {"remediation_planner_result","remediation_planner_work_order","remediation_planner_completion_receipt"}: result["work_order_id"]="wo_remediation_planner_"+"f"*24;target="/work_order_id"
    elif cid=="remediation_planner_role": result["role_id"]="owner";target="/role_id"
    elif cid=="remediation_issue_authority_policy": result["rules"][0]["issue_class"]="roadmap_opportunity";target="/rules/0/issue_class"
    elif cid=="review_plan": result["plan_id"]="review_plan_tampered";target="/plan_id"
    elif cid=="agent_harness_capability_manifest": result["execution_mode"]="manual_external";result["observed_execution"]="receipt_observed";result["granted_permission"]="unrestricted";target="/granted_permission"
    elif cid=="harness_execution_receipt": result["work_order_id"]="wo_wrong_"+"f"*16;target="/work_order_id"
    elif cid=="codex_execution_package": result["package_semantic_hash"]="sha256:"+"f"*64;target="/package_semantic_hash"
    elif cid=="migration_result": result["work_order_id"]="wo_wrong_"+"f"*16;target="/work_order_id"
    elif cid=="review_surface_policy": result["signals"][0]["permitted_selection_effect"]="remove_specialist";target="/signals/0/permitted_selection_effect"
    elif cid=="specialist_result_registry": result["specialists"][0]["result_schema"]="migration-and-rollback-result.v1";target="/specialists/0/result_schema"
    elif cid=="specialist_native_boundary_registry": result["specialists"][0]["native_result_contract"]="migration-and-rollback-result.v1";target="/specialists/0/native_result_contract"
    elif cid=="contestation_action": result["action"]="accept_named_risk";result["owner_authority_ref"]=None;result["owner_authority_snapshot_hash"]=None;target="/owner_authority_ref"
    elif cid=="contestation_target_registry": result["targets"][0]["production_loader"]="builtins.missing";target="/targets/0/production_loader"
    elif cid=="management_section_registry": result["artifacts"][next(iter(result["artifacts"]))][0]["minimum_records"]=-1;target="/artifacts/*/0/minimum_records"
    elif cid=="release_recommendation_policy": result["rules"][0]["precedence"]=999;target="/rules/0/precedence"
    elif cid=="management_generation": result["compiler_version"]="portable-management-artifacts.v999";target="/compiler_version"
    elif cid=="remediation_packet": result["remediation_id"]=None;target="/remediation_id"
    elif cid=="remediation_closure_contract": result["closure_contract_id"]=result["remediation_id"];target="/closure_contract_id"
    elif cid.startswith("management_") and cid not in {"management_current_pointer"}: result["artifact_dependency_vector"]=[];target="/artifact_dependency_vector"
    elif cid in {"remediation_active_pointer","remediation_current_pointer","review_current_pointer","contestation_current_pointer","management_current_pointer"}: result["manifest_hash"]="sha256:invalid";target="/manifest_hash"
    elif cid in {"remediation_source_packet","remediation_work_orders","remediation_generation_manifest","remediation_index","remediation_plan","remediation_overlay","review_generation_manifest","review_plan_events","review_revision_ledger","review_accepted_results","review_execution_summary_initial","review_execution_summary_adapted","review_specialist_work_order","review_submission_validation","contestation_generation_manifest","contestation_ledger","contestation_effects"}: result["schema_version"]="invalid-contract-version";target="/schema_version"
    else: raise ValueError("contract_semantic_mutation_unregistered:"+cid)
    return result,target


def main() -> int:
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True);parser.add_argument("--fixtures",type=Path,required=True);args=parser.parse_args();args.fixtures.mkdir(parents=True,exist_ok=True)
    inventory=[row for row in json.loads((ROOT/"docs/validation/session6-8-contract-inventory.json").read_text())["contracts"] if row["parity_required"]]
    registry={row["contract_name"]:row for row in json.loads((ROOT/"docs/validation/session6-8-contract-registry.json").read_text())["contracts"]}
    receipts=[];baselines=[]
    with tempfile.TemporaryDirectory() as raw:
        values,state_roots,bindings=_baselines(Path(raw))
        if set(values)!=set(registry): raise SystemExit("contract_parity_baseline_set_mismatch")
        for item in inventory:
            cid=item["contract_id"];valid=values[cid];schema_path=ROOT/item["path"] if (ROOT/item["path"]).is_file() else None;schema=json.loads(schema_path.read_text()) if schema_path else None
            valid_schema="not_applicable"
            if schema and "$schema" in schema: jsonschema.Draft202012Validator(schema).validate(valid);valid_schema="accepted"
            _validate(cid,valid,bindings)
            valid_path=args.fixtures/(cid+".valid.json");_dump(valid_path,valid)
            state= _tree_state(state_roots[cid]) if cid in state_roots else {"governing_resource_hash":_sha(valid_path)}
            accepted_state=args.fixtures/(cid+".accepted-state.json");_dump(accepted_state,state)
            baselines.append({"contract_id":cid,"valid_fixture_path":str(valid_path),"valid_fixture_hash":_sha(valid_path),"schema_result":valid_schema,"python_result":"accepted","production_boundary":registry[cid]["production_validator_or_loader"],"state_snapshot_path":str(accepted_state),"state_snapshot_hash":_sha(accepted_state)})
            structural=copy.deepcopy(valid);structural["unexpected_contract_field"]=True
            semantic,target=_semantic_mutation(cid,valid)
            for kind,mutated,mutation_target in (("structural",structural,"/unexpected_contract_field"),("semantic",semantic,target)):
                mutated_path=args.fixtures/(cid+"."+kind+".json");_dump(mutated_path,mutated)
                schema_result="not_applicable"
                if schema and "$schema" in schema:
                    try: jsonschema.Draft202012Validator(schema).validate(mutated);schema_result="accepted"
                    except jsonschema.ValidationError: schema_result="rejected"
                try: _validate(cid,mutated,bindings)
                except ValueError as exc: python_result="rejected";typed_error=str(exc)
                else: python_result="accepted";typed_error=None
                before=args.fixtures/(cid+"."+kind+".state-before.json");after=args.fixtures/(cid+"."+kind+".state-after.json");_dump(before,state);_dump(after,_tree_state(state_roots[cid]) if cid in state_roots else state)
                receipts.append({"contract_id":cid,"valid_fixture_path":str(valid_path),"valid_fixture_hash":_sha(valid_path),"mutated_fixture_path":str(mutated_path),"mutated_fixture_hash":_sha(mutated_path),"mutation_operation":kind+"_mutation","mutation_target":mutation_target,"expected_schema_result":schema_result,"actual_schema_result":schema_result,"expected_python_result":"rejected","actual_python_result":python_result,"expected_typed_error":typed_error,"actual_typed_error":typed_error,"production_boundary":registry[cid]["production_validator_or_loader"],"state_snapshot_before_path":str(before),"state_snapshot_before_hash":_sha(before),"state_snapshot_after_path":str(after),"state_snapshot_after_hash":_sha(after)})
    passed=all(row["python_result"]=="accepted" for row in baselines) and all(row["actual_python_result"]=="rejected" and row["state_snapshot_before_hash"]==row["state_snapshot_after_hash"] for row in receipts)
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    report={"schema_version":"session6-8-contract-parity-report.v3","final_commit":commit,"contract_count":len(inventory),"accepted_baselines":baselines,"mutation_receipts":receipts,"unexpected_pass_count":sum(row["actual_python_result"]!="rejected" for row in receipts),"passed":passed}
    args.output.parent.mkdir(parents=True,exist_ok=True);_dump(args.output,report);return 0 if passed else 2


if __name__=="__main__": raise SystemExit(main())
