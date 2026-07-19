from __future__ import annotations

import hashlib, json, os, subprocess, sys
import tempfile
from pathlib import Path

from shiproom.evidence import validate_module_result
from shiproom.models import EvidenceStatus, Release
from shiproom.registry import discover, select
from shiproom.verdict import calculate, close_finding
from shiproom.external import CAPABILITIES, compile_release
from shiproom.policy import POLICY_VERSION, execute_external_operation
from shiproom.runs import LocalRunStore
from shiproom.context import compile_project_context, context_event_metadata, verify_context_handoff, verify_context_isolation
from shiproom.authority import LocalExecutionContext, bind_release_authority
from shiproom.graph import ARTIFACTS as GRAPH_ARTIFACTS, compile_bundle as graph_compile, load_bundle as graph_load, mapping_prepare, show as graph_show
from shiproom.intent import compile_bundle as intent_compile, load_bundle as intent_load, prepare as intent_prepare
from shiproom.onboarding import initialize
from shiproom.project import canonical_json, content_hash
from shiproom.assessment import compile_assessment, default_capabilities, load_assessment, load_preparation, prepare as assessment_prepare
from shiproom.measurement_ai.authority import default_applicability as measurement_applicability, domain_root as measurement_root
from shiproom.measurement_ai.preparation import prepare as measurement_prepare, load_preparation as load_measurement_preparation
from shiproom.measurement_ai.persistence import compile_generation as measurement_compile, load_generation as load_measurement
from shiproom.measurement_ai.results import normalize_result
from shiproom.measurement_ai.guidance import load_guidance_pack
from shiproom.measurement_ai.contracts import sha256_bytes
from shiproom.measurement_ai.qualification import build_qualification_task, grade_qualification_result, qualification_store, write_qualification_bundle
from shiproom.measurement_ai.verifier import prepare_verifier

def _closeout_write(name:str,value:dict)->None:
    root=os.environ.get("SHIPROOM_CLOSEOUT_ARTIFACT_ROOT")
    if not root:return
    path=Path(root);path.mkdir(parents=True,exist_ok=True);(path/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
from shiproom.graph import load_assessment_input as graph_assessment_input
try:
    from scripts.graph_acceptance_fixture import run_controlled_patient
except ModuleNotFoundError:  # direct ``python scripts/run_evals.py`` execution
    from graph_acceptance_fixture import run_controlled_patient
try:
    from scripts.assessment_acceptance_fixture import assert_read_only_state, snapshot_read_only_state, write_browser_submission, write_core_results
except ModuleNotFoundError:
    from assessment_acceptance_fixture import assert_read_only_state, snapshot_read_only_state, write_browser_submission, write_core_results


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)


def _graph_context(root: Path, *, browser_relevant: bool = False, multi_criteria: bool = False) -> LocalExecutionContext:
    repo=root/"repo"; repo.mkdir(); _git(repo,"init","-b","main"); _git(repo,"config","user.email","eval@example.com"); _git(repo,"config","user.name","Eval")
    (repo/".gitignore").write_text(".shiproom/local/\n",encoding="utf-8"); (repo/"docs").mkdir(); (repo/"docs/brief.md").write_text("# Brief\nUsers can publish cards.\napproval_required\n",encoding="utf-8"); (repo/"demo_patient").mkdir(); patient=subprocess.run(["git","show","HEAD:demo_patient/server.py"],cwd=Path(__file__).parents[1],capture_output=True,check=True).stdout; (repo/"demo_patient/server.py").write_bytes(patient); _git(repo,"add","."); _git(repo,"commit","-m","fixture")
    initialize(repo,project_name="Eval",product_purpose="Evaluate graph",primary_users=["operators"],profile="inspect",local_only=False,confirmed=True); binding,grant=bind_release_authority(repo,"https://example.test","/result")
    release=Release("rel_graph_eval",{"path":str(repo),"commit_sha":binding["repository_commit"]},{"url":grant["origin"],"generated_path":"/result","read_grant":grant},{"name":"Eval","target_user":"operators","promise":"Publish cards","critical_journey":["Publish card"],"non_goals":[]},project_authority=binding).to_dict(); ctx=LocalExecutionContext.from_release(release)
    packet=intent_prepare(ctx,["docs/brief.md"],[]); src=next(x for x in packet["sources"] if x["path"]=="docs/brief.md")
    def citation(line,quote):return {"source_id":src["source_id"],"start_line":line,"end_line":line,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}
    req=citation(2,"Users can publish cards."); claim=citation(3,"approval_required")
    proposal={"schema_version":"intent-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"source_packet_hash":packet["packet_hash"],"claims":[{"local_id":"claim","claim_key":"release.publication_mode","cardinality":"single","value":"approval_required","classification":"explicit","source_refs":[claim],"requirement_local_ids":["req"]}],"requirements":[{"local_id":"req","statement":"Users can publish cards.","classification":"explicit","status":"active","source_refs":[req],"claim_local_ids":["claim"],"related_journey_ids":["Publish card"],"materiality":"release_scope","rationale":"fixture","owner_confirmation_required":False,"ambiguity_local_ids":[]}],"criteria":[{"local_id":"criterion","parent_requirement_local_id":"req","actor":None,"preconditions":[],"action":"publish","expected_outcomes":[],"failure_behavior":None,"required_evidence_categories":["browser_or_http" if browser_relevant else "owner_confirmation"],"source_refs":[req],"field_source_refs":{},"classification":"explicit","confirmation_state":"confirmed","blocker_eligible":True,"ambiguity_local_ids":[]}],"ambiguities":[]}
    if multi_criteria: proposal["criteria"].append({**proposal["criteria"][0],"local_id":"criterion_diagnosis","action":"diagnose a failed publication","blocker_eligible":False})
    inbox=repo/".shiproom/local/releases/rel_graph_eval/product-intent/inbox/proposal.json"; inbox.parent.mkdir(parents=True,exist_ok=True); inbox.write_text(json.dumps(proposal),encoding="utf-8"); intent_compile(ctx,str(inbox))
    if browser_relevant:
        _, artifacts = intent_load(ctx); criterion_id = artifacts["acceptance-criteria.json"]["criteria"][0]["criterion_id"]
        ctx.release["checks"] = [{"check_id":"canonical-unit-pass","type":"test","criterion_id":criterion_id,"target":"tests/test_publication.py::test_publish","passed":True,"status":"passed","evidence_status":"deterministically_verified","runtime_outcome":"passed"}]
    return ctx


def _graph_behavioral_evals(check) -> None:
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); packet=mapping_prepare(ctx,["docs/brief.md"]); criterion=packet["criterion_ids"][0]; src=packet["selected_sources"][0]; quote="Users can publish cards."
        proposal={"schema_version":"evidence-mapping-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"product_intent_semantic_bundle_hash":packet["product_intent_semantic_bundle_hash"],"release_projection_hash":packet["release_projection_hash"],"mapping_packet_hash":packet["packet_hash"],"mappings":[{"mapping_id":"candidate","criterion_id":criterion,"target_type":"implementation_reference","rationale":"packet candidate","reference":{"path":src["path"],"returned_git_path":src["returned_git_path"],"git_blob_hash":src["git_blob_hash"],"start_line":2,"end_line":2,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}}]}
        path=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/requirement-evidence-graph/inbox/map.json"; path.write_text(json.dumps(proposal),encoding="utf-8"); graph_compile(ctx,str(path)); _,art=graph_load(ctx); summary=art["criterion-evidence-summary.json"]["criteria"][0]
        graph=art["requirement-evidence-graph.json"]; implementation_gap=next(g for g in art["evidence-gaps.json"]["gaps"] if g["gap_type"]=="implementation_gap")
        candidate_edges=[e for e in graph["edges"] if e["relationship"]=="may_be_implemented_by" and e["establishment_classification"]=="model_mapped_candidate"]
        deterministic_edges=[e for e in graph["edges"] if e["relationship"]=="may_be_implemented_by" and e["establishment_classification"]=="deterministically_established"]
        check("GRAPH_CANDIDATE_IS_NOT_PROOF",bool(candidate_edges) and not deterministic_edges and implementation_gap["state"]=="unknown" and summary["closure"]["closure_state"]!="closed")
        expected={"implementation":"implementation_reference","tests":"test_reference","instrumentation":"instrumentation_reference","runtime":"runtime_evidence"}; allowed={"not_inspected","candidate_present","actual","deterministic_missing"}
        complete=True
        for candidate_summary in art["criterion-evidence-summary.json"]["criteria"]:
            for key,node_type in expected.items():
                records=candidate_summary[key]; statuses={item["detail"].get("slot_status") for item in records}
                complete=complete and bool(records) and all(item["node_type"]==node_type and item["detail"].get("slot_status") in allowed for item in records) and not ("not_inspected" in statuses and len(statuses)>1)
        check("GRAPH_FOUR_SLOT_COMPLETENESS",complete)
    with tempfile.TemporaryDirectory() as raw:
        patient=run_controlled_patient(Path(raw)); pre_summary=patient["pre"]["criterion-evidence-summary.json"]["criteria"][0]; post_summary=patient["post"]["criterion-evidence-summary.json"]["criteria"][0]; pre_gap=next(g for g in patient["pre"]["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap"); post_gap=next(g for g in patient["post"]["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")
        print("GRAPH_CONTROLLED_PATIENT_PRE_SHOW\n"+patient["pre_show"]); print("GRAPH_CONTROLLED_PATIENT_POST_SHOW\n"+patient["post_show"])
        check("GRAPH_CONTROLLED_PATIENT_LINEAGE",pre_gap["state"]=="unknown" and pre_summary["closure"]["closure_state"]=="not_inspected" and post_gap["state"]=="unknown" and post_summary["closure"]["closure_state"]=="not_inspected" and {x["detail"].get("check_id") for x in post_summary["runtime"]}=={"hist-404","hist-200"} and post_summary["closure"]["closure_items"][0]["effective_classification"]=="model_mapped_candidate" and "demo_patient/server.py" in patient["post_show"] and "hist-finding" in patient["post_show"])
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); graph_compile(ctx); intent_prepare(ctx,[],[])
        try: graph_load(ctx); stale=False
        except ValueError: stale=True
        check("GRAPH_STALE_PRODUCT_INTENT_REJECTED",stale)
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); graph_compile(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/requirement-evidence-graph"; pointer=json.loads((root/"current-generation.json").read_text()); gen=root/"generations"/pointer["generation"]; artifact=gen/GRAPH_ARTIFACTS[0]; value=json.loads(artifact.read_text()); value["coverage_boundary"]="tampered"; artifact.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); manifest_path=gen/"manifest.json"; manifest=json.loads(manifest_path.read_text()); manifest["artifact_hashes"][GRAPH_ARTIFACTS[0]]="sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest(); manifest["semantic_bundle_hash"]=content_hash({"intent":manifest["product_intent_semantic_bundle_hash"],"packet":manifest["mapping_packet_hash"],"projection":manifest["release_projection_hash"],"compiler":manifest["compiler_version"],"artifacts":{k:manifest["artifact_hashes"][k] for k in sorted(GRAPH_ARTIFACTS)}}); manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"}); manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); pointer["manifest_hash"]="sha256:"+hashlib.sha256(manifest_path.read_bytes()).hexdigest(); (root/"current-generation.json").write_text(json.dumps(pointer,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        try: graph_load(ctx); tamper=False
        except ValueError: tamper=True
        check("GRAPH_SEMANTIC_TAMPER_REJECTED",tamper)


def _assessment_behavioral_evals(check) -> None:
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw),browser_relevant=True); packet=mapping_prepare(ctx,["docs/brief.md"]); criterion=packet["criterion_ids"][0]; source=packet["selected_sources"][0]; quote="Users can publish cards."
        mapping={"schema_version":"evidence-mapping-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"product_intent_semantic_bundle_hash":packet["product_intent_semantic_bundle_hash"],"release_projection_hash":packet["release_projection_hash"],"mapping_packet_hash":packet["packet_hash"],"mappings":[{"mapping_id":"assessment_candidate","criterion_id":criterion,"target_type":"implementation_reference","rationale":"Prepared source candidate only.","reference":{"path":source["path"],"returned_git_path":source["returned_git_path"],"git_blob_hash":source["git_blob_hash"],"start_line":2,"end_line":2,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}}]}
        mapping_path=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/requirement-evidence-graph/inbox/assessment.json"; mapping_path.write_text(json.dumps(mapping),encoding="utf-8"); graph_compile(ctx,str(mapping_path))
        inputs=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/assessment/inputs"; inputs.mkdir(parents=True); capabilities=default_capabilities(); capabilities["capabilities"]["browser"]["available"]=True; capabilities["permissions"]["browser"]["granted"]=True; capability_path=inputs/"eval.json"; capability_path.write_text(json.dumps(capabilities),encoding="utf-8")
        assessment_prepare(ctx,capabilities_path=str(capability_path)); preparation=load_preparation(ctx); write_core_results(ctx,preparation); before=snapshot_read_only_state(ctx); compile_assessment(ctx); _,initial=load_assessment(ctx); assert_read_only_state(ctx,before)
        effective=initial["effective-assessment-view.json"]["criteria"][0]; overlay=initial["assessment-graph-overlay.json"]; engineering=initial["engineering-assessment.json"]["payload"]["criteria"][0]; adequacy=initial["test-adequacy.json"]["payload"]["criteria"][0]
        check("ASSESSMENT_PASSING_TEST_NOT_COVERAGE",engineering["overall_adequacy"]=="inadequate" and effective["base_evidence_state"]["test"]=="closed")
        candidate_nodes=[node for node in preparation["contexts"]["engineering_assessment"]["base_graph_context"]["nodes"] if node["node_type"]=="implementation_reference" and node.get("provenance")=="mapping_proposal"]
        check("ASSESSMENT_SOURCE_CANDIDATE_NOT_PROOF",bool(candidate_nodes) and effective["base_evidence_state"]["implementation"]=="unknown")
        check("ASSESSMENT_UNIT_COVERAGE_BOUNDARY_GAP",adequacy["test_layer"]=="unit" and adequacy["assertion_adequacy"]=="adequate" and adequacy["boundary_adequacy"]=="inadequate" and adequacy["overall_adequacy"]=="partial")
        check("ASSESSMENT_NO_COMMAND_EXECUTION",all(not preparation["work_orders"][role]["permissions"]["shell"]["allowed_commands"] for role in ("product_assessment","engineering_assessment","test_adequacy","targeted_test_planning")))
        check("ASSESSMENT_MANUAL_PORTABLE_WORK_ORDER",all(node["executor_provenance"]["executor_type"]=="human" for node in overlay["nodes"]))
        base_before=effective["base_evidence_state"].copy(); write_browser_submission(ctx,preparation); compile_assessment(ctx); _,observed=load_assessment(ctx); assert_read_only_state(ctx,before); observed_effective=observed["effective-assessment-view.json"]["criteria"][0]; browser=observed_effective["assessment"]["browser_journey"]
        browser_authority=observed_effective["assessment_authority"]["browser_journey"]
        browser_ok=browser["status"]=="observed" and browser_authority["observation_authority"]=="browser_observed" and browser_authority["judgment_authority"]=="model_reviewed" and any(node.get("role_id")=="browser_journey" and node["evidence_class"]=="model_reviewed" for node in observed["assessment-graph-overlay.json"]["nodes"])
        work=preparation["work_orders"]["browser_journey"]; receipt=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/assessment/inbox"/work["preparation_id"]/work["work_order_id"]/"completion-receipt.json"; value=json.loads(receipt.read_text()); value["result_snapshot_hash"]="sha256:"+"0"*64; receipt.write_text(json.dumps(value),encoding="utf-8")
        try: compile_assessment(ctx); invalid_rejected=False
        except ValueError: invalid_rejected=True
        check("ASSESSMENT_BROWSER_PROVENANCE_BOUNDARY",browser_ok and invalid_rejected and observed_effective["base_evidence_state"]==base_before)
        check("ASSESSMENT_OVERLAY_NEVER_REFINES_BASE",observed_effective["base_evidence_state"]==base_before and before["graph_pointer"]==snapshot_read_only_state(ctx)["graph_pointer"] and json.dumps(ctx.release,sort_keys=True,separators=(",",":"))==before["release"])


def _measurement_result(ctx,prep,role,records,recommendations=None,executor=None):
    work=prep["work_orders"][role]; directory=measurement_root(ctx)/"inbox"/work["preparation_id"]/work["work_order_id"]
    value={"schema_version":"measurement-result.v3" if role=="measurement" else "ai-evaluation-result.v3","role_id":role,"role_version":"3.0.0","preparation_id":work["preparation_id"],"work_order_id":work["work_order_id"],"base_graph_semantic_hash":work["inputs"]["graph_semantic_hash"],"resolved_review_mode":work["resolved_review_mode"],"records":records,"recommendations":recommendations or [],"assumptions":[],"limitations":[]}
    raw=(json.dumps(value,sort_keys=True)+"\n").encode(); directory.mkdir(parents=True,exist_ok=True); (directory/"result.json").write_bytes(raw)
    receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":executor or {"executor_type":"human","reviewer_label":"portable reviewer"},"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"}; (directory/"completion-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")
    return raw,receipt


def _measurement_record(prep,cid,role):
    context=prep["contexts"][role]; entries=[item for item in context["basis_registry"] if cid in item["criterion_ids"]]; strong=next(item for item in entries if item["direct_fact_authority"] in {"source_verified","deterministically_established"}); paths=[item["path_id"] for item in context["basis_paths"] if item["start_basis_id"]==strong["basis_id"] and item["criterion_id"]==cid and item["required"]]
    common={"local_id":"record_"+role,"criterion_id":cid,"scope_state":"applicable","disposition":"assessed","uncertainty":"bounded","basis_ids":[strong["basis_id"]],"basis_path_ids":paths,"conclusion_evidence_class":"model_reviewed","semantic_review_authority":"model_reviewed_with_curated_guidance","summary":"Bounded portable assessment.","gaps":[]}
    if role=="measurement":
        dims=["decision_use_case_alignment","metric_role","outcome_alignment","population","opportunity_exposure","denominator","window","attribution","interpretation_rule","guardrails","inference_intent_alignment"]
        return {**common,"journey_ids":[],"contract_updates":[],"signal_assessments":[],"metric_dimensions":[{"dimension":name,"state":"adequate","rationale":"Bounded prepared context.","basis_ids":[strong["basis_id"]],"basis_path_ids":paths} for name in dims]}
    rung_names=("case_candidate","fixed_input","oracle_or_rubric","pass_condition","journey_or_criterion_linkage","prompt_or_model_binding","known_failure","fallback","malformed_output","unavailable_model","supplied_execution_result","deterministically_validated_result","production_trace_linkage")
    subtype_by_rung={"case_candidate":"ai_fixed_input_definition","fixed_input":"ai_fixed_input_definition","oracle_or_rubric":"ai_oracle_or_rubric_definition","pass_condition":"ai_pass_condition_definition","journey_or_criterion_linkage":"ai_fixed_input_definition","prompt_or_model_binding":"ai_prompt_model_binding_definition","known_failure":"ai_known_failure_case_definition"}
    rungs=[]
    for name in rung_names:
        basis=next((item for item in entries if item["basis_type"]==subtype_by_rung.get(name)),None)
        rung_paths=[item["path_id"] for item in context["basis_paths"] if basis and item["start_basis_id"]==basis["basis_id"] and item["criterion_id"]==cid and item["required"]]
        rungs.append({"local_id":"rung_"+name,"rung":name,"state":"established" if basis else "not_established","basis_ids":[basis["basis_id"]] if basis else [],"basis_path_ids":rung_paths,"limitations":[]})
    candidate=next((item for item in entries if item["direct_fact_authority"] in {"model_mapped_candidate","not_inspected"}),strong); candidate_paths=[item["path_id"] for item in context["basis_paths"] if item["start_basis_id"]==candidate["basis_id"] and item["criterion_id"]==cid and item["required"]]
    return {**common,"maturity_rungs":rungs,"judge_assessments":[],"claims":[{"local_id":"claim_local","claim_id":"claim_model_quality","claim_type":"offline_behavior","asserted_scope":"offline_behavior","claimed_evidence_class":"model_reviewed","statement":"The model is correct.","presented_as_proof":True,"basis_ids":[candidate["basis_id"]],"basis_path_ids":candidate_paths}],"observability_candidates":[]}


def _typed_source_binding(ctx,path,cid,journey,subtype):
    blob=ctx.read_release_blob(path,256*1024); text=blob["text"].removeprefix("\ufeff").replace("\r\n","\n").replace("\r","\n"); quote=text.splitlines()[0]
    raw=text.encode("utf-8")
    return {"path":path,"returned_git_path":blob["path"],"git_object_format":"sha1","git_blob_hash":blob["blob_hash"],"normalized_text_hash":sha256_bytes(raw),"start_line":1,"end_line":1,"quote":quote,"quote_hash":sha256_bytes(quote.encode()),"declared_subtype":subtype,"criterion_ids":[cid],"journey_ids":[journey]}


def _qualified_model_capabilities(ctx):
    guidance=load_guidance_pack(); task=build_qualification_task(guidance)
    answers={
      "qual_case_001":("no_material_concern_identified",[],["MEAS_COUNT_002"],["absolute_volume_decision"],"none",False,["model_reviewed_with_curated_guidance"]),"qual_case_002":("contextual_warning",["research_backed_warning"],["MEAS_COUNT_002"],["fixed_opportunity"],"non_blocking_warning",False,["model_reviewed_with_curated_guidance"]),"qual_case_003":("contextual_warning",["research_backed_warning"],["MEAS_RATIO_003"],["release_affects_denominator"],"non_blocking_warning",False,["model_reviewed_with_curated_guidance"]),"qual_case_004":("contextual_warning",["owner_confirmation_question"],["MEAS_WINDOW_005"],["immediate_outcome"],"non_blocking_warning",False,["model_reviewed_with_curated_guidance"]),"qual_case_005":("contextual_warning",["research_backed_warning"],["MEAS_PROXY_006"],["validated_diagnostic_use"],"non_blocking_warning",False,["model_reviewed_with_curated_guidance"]),"qual_case_006":("insufficient_context",["owner_confirmation_question"],["MEAS_DECISION_001"],["reporting_only"],"owner_confirmation",True,["model_reviewed_with_curated_guidance"]),"qual_case_007":("contextual_warning",["research_backed_warning"],["AI_EVAL_010"],["upstream_deterministic_execution"],"non_blocking_warning",False,["model_reviewed_with_curated_guidance"]),"qual_case_008":("insufficient_context",["contextual_hypothesis"],["MEAS_SIGNAL_009"],["single_terminal_state"],"none",True,["model_reviewed_with_curated_guidance","model_mapped_candidate"]),"qual_case_009":("insufficient_context",["owner_confirmation_question"],["MEAS_POPULATION_004"],["fixed_eligibility"],"owner_confirmation",True,["model_reviewed_with_curated_guidance"]),"qual_case_010":("insufficient_context",["contextual_hypothesis"],[],[],"none",True,["model_reviewed"])}
    cases=[]
    for case in task["cases"]:
        assessment,recommendations,rules,exceptions,effect,abstained,labels=answers[case["case_id"]]; cases.append({"case_id":case["case_id"],"semantic_assessment":assessment,"recommendation_classes":recommendations,"guidance_rule_ids":rules,"exception_ids":exceptions,"effect":effect,"abstained":abstained,"claim_codes":[],"authority_labels":labels,"automatic_replacements":[]})
    result={"schema_version":"measurement-reviewer-qualification-result.v3","task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":"eval_provider","model_id":"eval_model","requested_capabilities":task["requested_capabilities"],"case_results":cases}; raw=(json.dumps(result,sort_keys=True)+"\n").encode(); receipt=grade_qualification_result(result,task,sha256_bytes(raw),guidance["qualification_private_rubric"],guidance); bundle=write_qualification_bundle(ctx.repository_root,task,result,raw,receipt,guidance["qualification_private_rubric"]); path=bundle["directory"]
    candidate={"candidate_id":"eval_candidate","provider_id":"eval_provider","model_id":"eval_model","qualification_id":receipt["qualification_id"],"qualification_bundle_hash":bundle["qualification_bundle_hash"],"qualification_bundle_path":str(path)}
    return {"schema_version":"measurement-review-capabilities.v3","executor_type":"agent_harness","active_candidate_id":"eval_candidate","qualification_bundle_path":str(path),"configured_candidates":[candidate],"fresh_session_supported":True,"automatic_switch_allowed":False,"cost_disclosure":"Bounded evaluation fixture."}


def _expert_verifier_eval(ctx,app,cid,app_path,disposition):
    expert=json.loads(json.dumps(app)); expert["ai"]={"requirement_ids":[],"criterion_ids":[],"journey_ids":[],"paths":[],"linked_sources":[]}; expert["measurement"]["criterion_ids"]=[cid]; expert["measurement"]["contracts"][0]["criterion_ids"]=[cid]; fields=expert["measurement"]["contracts"][0]["fields"]; fields.update({name:{"value":value,"state":"owner_confirmed"} for name,value in {"decision_owner":"product owner","decision_timing":"launch review","decision_rule_or_interpretation":"compare assigned groups","unit_of_observation":"customer","eligible_population":"invited customers","observation_window":{"value":14,"unit":"days","anchor":"assignment"},"inference_intent":"causal_experiment"}.items()}); fields["decision_use_case"]={"value":"causal_experiment","state":"owner_confirmed"}; app_path.write_text(json.dumps(expert),encoding="utf-8")
    permission={"schema_version":"measurement-review-permission.v3","release_id":ctx.release["release_id"],"expert_review_granted":True,"model_switch":{"decision":"not_requested"}}; info=measurement_prepare(ctx,review_mode="expert_escalated_review",review_capabilities={"schema_version":"measurement-review-capabilities.v3","executor_type":"human","reviewer_label":"primary expert"},permission=permission,applicability_path=str(app_path)); prep=load_measurement_preparation(ctx,info["preparation_id"]); record=_measurement_record(prep,cid,"measurement"); record["semantic_review_authority"]="dual_reviewed_with_curated_guidance"; [dimension.update({"state":"material_concern"}) for dimension in record["metric_dimensions"] if dimension["dimension"]=="attribution"]
    basis=record["basis_ids"]; paths=record["basis_path_ids"]; rec={"local_id":"material","criterion_id":cid,"recommendation_class":"research_backed_warning","summary":"Causal interpretation needs assignment evidence.","basis_ids":basis,"basis_path_ids":paths,"guidance_rule_ids":["MEAS_ATTRIBUTION_008"],"exception_dispositions":[{"exception_id":name,"disposition":"ruled_out","basis_ids":basis} for name in ("descriptive_intent","randomized_assignment_defined","explicit_noncausal_comparison")],"abstained":False,"automatic_replacements":[]}; _measurement_result(ctx,prep,"measurement",[record],[rec]); verifier=prepare_verifier(ctx,info["preparation_id"],"measurement"); work=verifier["work_order"]; inbox=measurement_root(ctx)/"verifier-inbox"/verifier["verifier_preparation_id"]/work["verifier_work_order_id"]
    reviews=[{"recommendation_id":rid,"disposition":disposition,"unsupported_assumption_codes":[] if disposition=="supported" else ["unsupported_causal_assumption"],"ignored_exception_ids":[],"severity_supported":disposition=="supported","abstention_required":False,"rationale":"bounded skeptical pass"} for rid in work["material_recommendation_ids"]]; value={"schema_version":"measurement-verifier-result.v3","verifier_preparation_id":verifier["verifier_preparation_id"],"verifier_work_order_id":work["verifier_work_order_id"],"primary_result_semantic_hash":work["primary_result_semantic_hash"],"primary_result_snapshot_hash":work["primary_result_snapshot_hash"],"primary_receipt_snapshot_hash":work["primary_receipt_snapshot_hash"],"recommendation_reviews":reviews}; raw=(json.dumps(value,sort_keys=True)+"\n").encode(); inbox.mkdir(parents=True,exist_ok=True); (inbox/"result.json").write_bytes(raw); receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":{"executor_type":"human","reviewer_label":"skeptical verifier"},"work_order_id":work["verifier_work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"}; (inbox/"completion-receipt.json").write_text(json.dumps(receipt),encoding="utf-8"); measurement_compile(ctx,info["preparation_id"],[verifier["verifier_preparation_id"]]); _,artifacts=load_measurement(ctx); _closeout_write("launch-measurement-plan.json",artifacts["launch-measurement-plan.json"]); return artifacts["launch-measurement-plan.json"]["warnings"][0]["derived_effect"]


def _measurement_ai_behavioral_evals(check) -> None:
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw),multi_criteria=True); graph_compile(ctx); inputs=graph_assessment_input(ctx); criterion_ids=[item["criterion_id"] for item in inputs["intent_artifacts"]["acceptance-criteria.json"]["criteria"]]; cid,secondary_cid=criterion_ids; journey=next(node["node_id"] for node in inputs["graph_artifacts"]["requirement-evidence-graph.json"]["nodes"] if node["node_type"]=="critical_journey")
        source_path=next(node["path"] for node in inputs["graph_artifacts"]["requirement-evidence-graph.json"]["nodes"] if node.get("path")); event_binding=_typed_source_binding(ctx,source_path,cid,journey,"instrumentation_event_definition"); property_binding=_typed_source_binding(ctx,source_path,cid,journey,"instrumentation_property_definition")
        root=measurement_root(ctx)/"inputs"; root.mkdir(parents=True); app=measurement_applicability(); app["measurement"]["criterion_ids"]=criterion_ids; app["measurement"]["contracts"]=[{"local_id":"launch_metric","journey_id":journey,"criterion_ids":criterion_ids,"fields":{"decision_question":{"value":"Did onboarding improve?","state":"owner_confirmed"},"decision_use_case":{"value":"comparative_noncausal_review","state":"owner_confirmed"},"intended_outcome":{"value":"Customers onboard","state":"owner_confirmed"},"unit":{"value":{"label":"customers","kind":"count"},"state":"owner_confirmed"},"eligible_population":{"value":"invited customers","state":"owner_confirmed"},"numerator":{"value":{"definition":"total onboarded customers","population":"invited customers"},"state":"owner_confirmed"},"guardrails":{"value":[{"name":"bounded decision","definition":"No material guardrail identified for this fixture.","applicability":"not_applicable"}],"state":"owner_confirmed"},"success_condition":{"value":"customer onboarded","state":"owner_confirmed"},"failure_condition":{"value":"customer abandons","state":"owner_confirmed"}},"metric_roles":["outcome"],"required_signals":[{"name":"customer_onboarded","required_properties":["customer_id"],"event_sources":[event_binding],"property_sources":[{"property_name":"customer_id","sources":[property_binding]}]}]}]; app["ai"]["criterion_ids"]=[cid];app["ai"]["journey_ids"]=[journey];app["ai"]["linked_sources"]=[_typed_source_binding(ctx,source_path,cid,journey,subtype) for subtype in ("ai_fixed_input_definition","ai_oracle_or_rubric_definition","ai_pass_condition_definition","ai_prompt_model_binding_definition","ai_known_failure_case_definition")];app_path=root/"applicability.json"; app_path.write_text(json.dumps(app),encoding="utf-8")
        app["measurement"]["measurement_definition_paths"]=[{"path":source_path,"requirement_ids":[],"criterion_ids":[cid],"journey_ids":[journey],"declared_external":False}]; app_path.write_text(json.dumps(app),encoding="utf-8")
        review_capabilities=_qualified_model_capabilities(ctx); prepared_info=measurement_prepare(ctx,review_mode="guided_review",review_capabilities=review_capabilities,applicability_path=str(app_path)); prep=load_measurement_preparation(ctx,prepared_info["preparation_id"]); mrecord=_measurement_record(prep,cid,"measurement")
        signal=prep["source_packet"]["prepared_measurement_contracts"][0]["required_signals"][0]; registry=prep["contexts"]["measurement"]["basis_registry"]; basis_paths=prep["contexts"]["measurement"]["basis_paths"]; event_basis=next(item for item in registry if item["basis_type"]=="instrumentation_event_definition"); property_basis=next(item for item in registry if item["basis_type"]=="instrumentation_property_definition"); event_paths=[item["path_id"] for item in basis_paths if item["start_basis_id"]==event_basis["basis_id"] and item["criterion_id"]==cid and item["required"]]; property_paths=[item["path_id"] for item in basis_paths if item["start_basis_id"]==property_basis["basis_id"] and item["criterion_id"]==cid and item["required"]]; mrecord["signal_assessments"]=[{"local_id":"signal_local","signal_id":signal["signal_id"],"event_candidates":[{"local_id":"event_local","basis_ids":[event_basis["basis_id"]],"basis_path_ids":event_paths}],"property_results":[{"local_id":"property_local","property_name":"customer_id","state":"missing","basis_ids":[property_basis["basis_id"]],"basis_path_ids":property_paths}],"tests":[],"runtime_evidence":[]}]
        exceptions=[{"exception_id":eid,"disposition":"unknown","basis_ids":[]} for eid in ("absolute_volume_decision","fixed_opportunity","business_outcome_with_diagnostics","no_incremental_claim")]
        warning={"local_id":"count_warning","criterion_id":cid,"recommendation_class":"research_backed_warning","summary":"Opportunity volume may change; the count is not categorically wrong.","basis_ids":mrecord["basis_ids"],"basis_path_ids":mrecord["basis_path_ids"],"guidance_rule_ids":["MEAS_COUNT_002"],"exception_dispositions":exceptions,"abstained":True,"automatic_replacements":[]}
        unresolved_record={**mrecord,"local_id":"secondary","criterion_id":secondary_cid,"disposition":"not_inspected","uncertainty":"not_assessed","basis_ids":[],"basis_path_ids":[],"conclusion_evidence_class":"not_inspected","semantic_review_authority":"not_performed","summary":"not inspected","signal_assessments":[],"metric_dimensions":[],"gaps":[]}
        candidate=review_capabilities["configured_candidates"][0]; binding={key:candidate[key] for key in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")}; model_executor={"executor_type":"agent_harness","participant_binding":binding,"harness_id":"portable-eval","adapter_version":"1","run_id":"guided"}; _measurement_result(ctx,prep,"measurement",[mrecord,unresolved_record],[warning],model_executor);arecord=_measurement_record(prep,cid,"ai_evaluation");_measurement_result(ctx,prep,"ai_evaluation",[arecord],executor=model_executor);measurement_compile(ctx,prepared_info["preparation_id"]); _,art=load_measurement(ctx); checks={item["check_id"]:item for item in art["measurement-ai-readiness.json"]["checks"]}
        outcome_derivations=checks["DATA_OUTCOME_EVENT_DEFINED"]["record_derivations"]
        check("MEASUREMENT_OUTCOME_EVENT_DECLARED_UNVERIFIED",checks["DATA_OUTCOME_EVENT_DEFINED"]["status"]=="not_inspected" and {item["status"] for item in outcome_derivations}=={"ready","not_inspected"} and not checks["DATA_OUTCOME_EVENT_DEFINED"]["coverage_boundary"]["runtime_verified"])
        signal=art["instrumentation-coverage.json"]["signals"][0]
        check("MEASUREMENT_EVENT_PROPERTY_COMPLETENESS",signal["name"]=="customer_onboarded" and signal["required_properties"]==["customer_id"] and bool(art["instrumentation-coverage.json"]["event_candidates"]) and checks["DATA_CRITICAL_EVENT_PROPERTIES_PRESENT"]["status"]=="gap")
        compiled_warning=art["launch-measurement-plan.json"]["warnings"][0]
        supported_effect=_expert_verifier_eval(ctx,app,cid,root/"expert-supported.json","supported"); disputed_effect=_expert_verifier_eval(ctx,app,cid,root/"expert-disputed.json","disputed")
        journey_proposals=[item for item in art["launch-measurement-plan.json"]["owner_confirmation_proposals"] if item["journey_id"]==journey]
        check("MEASUREMENT_VAGUE_INTENT_AND_CONDITIONAL_COUNT_WARNING",len(journey_proposals)==1 and bool(journey_proposals[0]["field_names"]) and compiled_warning["derived_effect"]=="non_blocking_warning" and "not categorically wrong" in compiled_warning["summary"] and checks["DATA_PRIMARY_METRIC_DECISION_USEFUL"]["status"]!="gap" and prep["source_packet"]["review_resolution"]["reason"]=="qualified_model_participant" and supported_effect=="condition_candidate" and disputed_effect=="owner_confirmation")
        check("AI_QUALIFIED_FIXED_EVAL_REQUIRED",checks["AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS"]["status"]=="ready" and checks["AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF"]["status"]=="gap")
        canonical=[]; snapshots=[]; portable_manifests=[]
        executions=(({"schema_version":"measurement-review-capabilities.v3","executor_type":"human","reviewer_label":"human"},{"executor_type":"human","reviewer_label":"human"},"human"),(review_capabilities,{**model_executor,"harness_id":"hermes","run_id":"h"},"hermes"),(review_capabilities,{**model_executor,"harness_id":"codex","run_id":"c"},"codex"),(review_capabilities,{**model_executor,"harness_id":"codex","run_id":"renamed"},"renamed"))
        for capabilities,executor,label in executions:
            portable_info=measurement_prepare(ctx,review_mode="guided_review",review_capabilities=capabilities,applicability_path=str(app_path)); portable_prep=load_measurement_preparation(ctx,portable_info["preparation_id"]); records=json.loads(json.dumps([mrecord,unresolved_record])); records[0]["local_id"]=label; _measurement_result(ctx,portable_prep,"measurement",records,[warning],executor);portable_ai=_measurement_record(portable_prep,cid,"ai_evaluation");portable_ai["local_id"]="ai_"+label;_measurement_result(ctx,portable_prep,"ai_evaluation",[portable_ai],executor=executor);manifest=measurement_compile(ctx,portable_info["preparation_id"]); _,portable_art=load_measurement(ctx); canonical.append({name:value for name,value in portable_art.items() if name!="measurement-ai-compiler-receipts.json"}); portable_manifests.append(manifest); work=portable_prep["work_orders"]["measurement"]; inbox=measurement_root(ctx)/"inbox"/portable_info["preparation_id"]/work["work_order_id"]; snapshots.append((sha256_bytes((inbox/"result.json").read_bytes()),sha256_bytes((inbox/"completion-receipt.json").read_bytes())))
        check("MEASUREMENT_AI_HARNESS_NEUTRAL_PORTABILITY",all(value==canonical[0] for value in canonical[1:]) and len(set(snapshots))==4)
        if os.environ.get("SHIPROOM_CLOSEOUT_ARTIFACT_ROOT"):
            bundle=Path(review_capabilities["qualification_bundle_path"]);public_task=json.loads((bundle/"qualification-task.json").read_text());partial=json.loads((bundle/"qualification-result.json").read_text());partial["case_results"][6]["claim_codes"]=["ai_eval_proves_product_impact"];partial_raw=(json.dumps(partial,sort_keys=True)+"\n").encode();partial_receipt=grade_qualification_result(partial,public_task,sha256_bytes(partial_raw),load_guidance_pack()["qualification_private_rubric"],load_guidance_pack());_closeout_write("qualification-task.json",public_task);_closeout_write("qualification-receipt.json",partial_receipt);_closeout_write("work-order.json",prep["work_orders"]["measurement"])
            for name,value in art.items():
                if name=="launch-measurement-plan.json" and (Path(os.environ["SHIPROOM_CLOSEOUT_ARTIFACT_ROOT"])/name).exists():continue
                _closeout_write(name,value)
            packet_sources=[s for group in prep["source_packet"]["role_sources"].values() for s in group["sources"]];source_nodes=[n for n in art["measurement-ai-overlay.json"]["nodes"] if n.get("node_type")=="project_source_reference"];pairs=[]
            for node in source_nodes:
                source=next((s for s in packet_sources if s["path"]==node["path"] and s["git_blob_hash"]==node["git_blob_hash"]),None)
                if source:pairs.append({"overlay":node,"source_packet":source})
            _closeout_write("source-identity-proof.json",{"pairs":pairs})
            runs=[]
            for label,manifest,value in zip(("human","hermes","codex","renamed"),portable_manifests,canonical):runs.append({"label":label,"semantic_bundle_hash":manifest["semantic_bundle_hash"],"principal_artifacts_hash":content_hash({k:v for k,v in value.items() if k!="measurement-ai-overlay.json"}),"overlay_hash":content_hash(value["measurement-ai-overlay.json"])})
            _closeout_write("harness-neutral-proof.json",{"runs":runs})
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); graph_compile(ctx); prep=measurement_prepare(ctx); measurement_compile(ctx,prep["preparation_id"]); _,art=load_measurement(ctx); bogus=measurement_root(ctx)/"inbox"/prep["preparation_id"]/"wo_unissued_deadbeefdeadbeef"; bogus.mkdir(parents=True)
        try: measurement_compile(ctx,prep["preparation_id"]); unexpected_rejected=False
        except ValueError: unexpected_rejected=True
        check("MEASUREMENT_AI_CONVENTIONAL_PRODUCT_SKIP",prep["work_orders"]==[] and prep["skip_reason"]=="no_applicable_measurement_or_ai_surface" and all(item["status"]=="not_applicable" for item in art["measurement-ai-readiness.json"]["checks"]) and unexpected_rejected)


def main() -> int:
    cases = []
    def check(name, condition): cases.append((name, bool(condition)))
    base = Release("rel_eval", {"url": "."}, {"url": "http://example.invalid"}, {"promise": "Share a card"}).to_dict()
    check("registry discovers modules", len(discover()) == 4)
    check("irrelevant data skipped", "data" not in select(base, discover())[0])
    ai = dict(base); ai["product"] = {"promise": "AI retrieval model with eval"}
    check("AI selects data", "data" in select(ai, discover())[0])
    blocked = dict(base); blocked["findings"] = [{"blocking": True, "state": "TRIAGED"}]
    check("blocker holds", calculate(blocked)["status"] == "HOLD")
    for label, status in (("agent report cannot close", EvidenceStatus.AGENT), ("model review cannot close", EvidenceStatus.MODEL), ("missing evidence cannot close", EvidenceStatus.MISSING)):
        try: close_finding({}, {"status": status, "kind": "claim", "value": True}); ok = False
        except ValueError: ok = True
        check(label, ok)
    try: validate_module_result({"module_id": "bad"}); ok = False
    except ValueError: ok = True
    check("malformed output rejected", ok)
    verified = close_finding({"blocking": True, "state": "VERIFYING"}, {"status": EvidenceStatus.DETERMINISTIC, "kind": "http_status", "value": 200})
    check("verified exact rerun closes", verified["state"] == "CLOSED")
    owner = dict(base); owner["owner_decisions"] = [{"title": "Promise", "choice": None}]
    check("owner decision requested", calculate(owner)["status"] == "AWAITING_OWNER")
    owner["owner_decisions"][0].update({"choice": "Revise beta promise", "resolution": "accepted_condition"})
    check("owner decision preserved", calculate(owner)["status"] == "SHIP_WITH_CONDITIONS")
    blocked_owner = dict(blocked); blocked_owner["owner_decisions"] = [{"choice": "Accept", "resolution": "accepted_condition"}]
    check("owner choice cannot erase blocker", calculate(blocked_owner)["status"] == "HOLD")
    check("report evidence linkage contract", all("evidence" in f for f in [verified]))
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); fixture = root / "README.md"; fixture.write_text("redacted public fixture\n", encoding="utf-8")
        contract = {"schema_version":"external_release_contract.v1","project_name":"Redacted public project","repository_url":"https://github.com/example/public-project","live_url":"https://example.com","target_user":"public users","product_promise":"Inspect a bounded public journey","critical_journey":["Open","Inspect"],"non_goals":[],"owner_constraints":["Read only"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}}
        external = compile_release(contract); external["checks"] = [{"criterion_id":"PUBLIC_JOURNEY","required":True,"passed":False,"evidence_status":EvidenceStatus.MISSING,"policy_version":POLICY_VERSION}]
        store = LocalRunStore(root / "history"); called = []
        try: execute_external_operation(external, store, "test.run", lambda: called.append(True))
        except PermissionError: pass
        external_verdict = calculate(external)
        check("redacted external read-only failure", not called and fixture.read_text(encoding="utf-8")=="redacted public fixture\n" and not external["findings"] and external_verdict=={"status":"HOLD","reason_codes":["INSUFFICIENT_EVIDENCE"]} and store.events(external["release_id"])[0]["event_type"]=="operation_rejected")
    with tempfile.TemporaryDirectory() as raw:
        root=Path(raw); a_root=root/"a"; b_root=root/"b"; a_root.mkdir(); b_root.mkdir()
        (a_root/"AGENTS.md").write_text("Build: python alpha.py\nTest: python alpha_test.py\n",encoding="utf-8"); (b_root/"HERMES.md").write_text("Build: node beta.js\nTest: node beta_test.js\n",encoding="utf-8")
        a_ctx=compile_project_context(project_id="alpha",repository_url="https://github.com/example/alpha",commit_sha="a"*40,release_input={"promise":"alpha"},repository_root=a_root,prior_decisions=[{"id":"decision-alpha"}])
        b_ctx=compile_project_context(project_id="beta",repository_url="https://github.com/example/beta",commit_sha="b"*40,release_input={"promise":"beta"},repository_root=b_root,prior_decisions=[{"id":"decision-beta"}])
        metadata=context_event_metadata(a_ctx); handoff_events=[{"agent_id":agent,"metadata":metadata} for agent in ("manager","specialist","verifier")]
        check("CONTEXT_HANDOFF_INTEGRITY",verify_context_handoff(a_ctx,handoff_events))
        check("CONTEXT_PROJECT_ISOLATION",verify_context_isolation(a_ctx,b_ctx,a_run_id="run-a",b_run_id="run-b",a_storage="storage-a",b_storage="storage-b"))
        boundary=True
        for status in (EvidenceStatus.MODEL,EvidenceStatus.AGENT):
            try: close_finding({"blocking":True,"state":"VERIFYING"},{"status":status,"kind":"claim","value":True}); boundary=False
            except ValueError: pass
        try: validate_module_result({"module_id":"product","checks":[]}); boundary=False
        except ValueError: pass
        stale=dict(metadata); stale["project_context_id"]="ctx_stale"
        boundary = boundary and not verify_context_handoff(a_ctx,[{"agent_id":agent,"metadata":stale} for agent in ("manager","specialist","verifier")])
        check("CONTEXT_CANNOT_OVERRIDE_VERIFIED_EVIDENCE",boundary)
    _graph_behavioral_evals(check)
    _assessment_behavioral_evals(check)
    _measurement_ai_behavioral_evals(check)
    if len(cases) != 35:
        raise AssertionError(f"expected exactly 35 evals, got {len(cases)}")
    for name, passed in cases: print(f"{'PASS' if passed else 'FAIL'} {name}")
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    receipt = {"schema_version": "shiproom.behavioral-eval-receipt.v1", "final_commit": commit,
               "cases": [{"name": name, "passed": passed, "assertion_count": 1} for name, passed in cases]}
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["receipt_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    target = Path(os.environ.get("SHIPROOM_EVAL_RECEIPT", root / ".shiproom" / "local" / "behavioral-eval-receipt.json"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("receipt=" + str(target))
    return 0 if all(p for _, p in cases) else 1


if __name__ == "__main__": sys.exit(main())
