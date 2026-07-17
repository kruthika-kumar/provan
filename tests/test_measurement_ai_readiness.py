from __future__ import annotations

import json
import hashlib
import os
import subprocess
import socket
import urllib.request
from importlib import resources

import pytest
import jsonschema

from shiproom.measurement_ai.contracts import effective_basis_class
from shiproom.measurement_ai.guidance import load_guidance_pack, rule_map
from shiproom.measurement_ai.overlay import evaluate_basis_path, validate_overlay
from shiproom.measurement_ai.authority import _literal_import_candidates, _typed_field_value, default_applicability, domain_root
from shiproom.measurement_ai.preparation import prepare, load_preparation
from shiproom.measurement_ai.persistence import compile_generation, load_generation
from shiproom.measurement_ai.rendering import show
from shiproom.measurement_ai.contracts import sha256_bytes
from shiproom.measurement_ai.qualification import build_qualification_task, compile_qualification, grade_qualification_result, prepare_qualification, qualification_store, load_qualification_bundle
from shiproom.measurement_ai.contract_parity import parity_report
from shiproom.measurement_ai.results import normalize_result
from shiproom.measurement_ai.guidance import eligible_rule_ids
from shiproom.measurement_ai.verifier import prepare_verifier, load_verifier
from shiproom.measurement_ai.registries import AI_GAP_KINDS, AI_MATURITY_RUNGS, MEASUREMENT_FIELD_SPECS, MEASUREMENT_GAP_KINDS, METRIC_DIMENSIONS, PROJECTION_REGISTRY, ROLE_RESULT_SCHEMAS
from shiproom.measurement_ai.trust import ensure_directory
import shiproom.measurement_ai.persistence as measurement_persistence
import shiproom.measurement_ai.authority as measurement_authority
from scripts.measurement_ai_acceptance_fixture import snapshot_measurement_ai_read_only, assert_measurement_ai_read_only
from test_assessment import assessment_context
from test_intent import context_for, inbox, proposal
from shiproom.intent import prepare as prepare_intent, compile_bundle as compile_intent
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input


def conventional_context(tmp_path):
    ctx=context_for(tmp_path); packet=prepare_intent(ctx,["docs/brief.md"],[]); value=proposal(packet)
    value["criteria"][0]["required_evidence_categories"]=["owner_confirmation"]
    path=inbox(ctx); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value),encoding="utf-8")
    compile_intent(ctx,str(path)); compile_graph(ctx); return ctx


def test_guidance_registry_is_closed_and_packaged():
    pack = load_guidance_pack()
    rules = rule_map(pack)
    assert len(rules) == 13
    assert set(rules) == {
        "MEAS_DECISION_001", "MEAS_COUNT_002", "MEAS_RATIO_003", "MEAS_POPULATION_004",
        "MEAS_WINDOW_005", "MEAS_PROXY_006", "MEAS_GUARDRAIL_007", "MEAS_ATTRIBUTION_008",
        "MEAS_SIGNAL_009", "AI_EVAL_010", "AI_FAILURE_011", "AI_VERSION_012", "AI_JUDGE_013",
    }
    assert "automatic_ratio_replacement" in rules["MEAS_COUNT_002"]["forbidden_output_classes"]
    for name in ("measurement.json", "ai_evaluation.json", "source-discovery.v1.json"):
        assert resources.files("shiproom.measurement_ai_roles").joinpath(name).is_file()


def test_basis_authority_and_reviewer_authority_are_not_collapsed():
    assert effective_basis_class(["deterministically_established"]) == "deterministically_established"
    assert effective_basis_class(["source_verified"]) == "source_verified"
    assert effective_basis_class(["deterministically_established", "model_mapped_candidate"]) == "model_mapped_candidate"
    assert effective_basis_class(["source_verified", "deterministically_established"]) == "source_verified"
    assert effective_basis_class(["model_mapped_candidate", "not_inspected"]) == "not_inspected"


def test_overlay_path_walks_and_candidate_taints_only_basis():
    edges = {
        "edge_a": {"source_node_id":"conclusion_1","target_node_id":"runtime_1","direct_fact_authority":"model_mapped_candidate"},
        "edge_b": {"source_node_id":"runtime_1","target_node_id":"criterion_1","direct_fact_authority":"deterministically_established"},
    }
    steps = [{"edge_id":"edge_a","traversal":"forward"},{"edge_id":"edge_b","traversal":"forward"}]
    assert evaluate_basis_path(steps, edges, "conclusion_1", "criterion_1") == "model_mapped_candidate"
    with pytest.raises(ValueError, match="disconnected"):
        evaluate_basis_path(list(reversed(steps)), edges, "conclusion_1", "criterion_1")


def test_overlay_exact_schema_and_reference_validation():
    value = {
        "schema_version":"measurement-ai-overlay.v3","release_id":"rel","release_commit":"a"*40,
        "product_intent_semantic_hash":"sha256:"+"1"*64,"graph_semantic_hash":"sha256:"+"2"*64,
        "nodes":[{"node_id":"contract_1","node_type":"measurement_contract","provenance":"measurement_ai_compiler","contract_id":"contract_1","journey_id":None,"criterion_ids":["criterion_1"],"field_states":{},"metric_roles":[]}],
        "edges":[{"edge_id":"edge_1","source_node_id":"contract_1","target_node_id":"criterion_1","relationship":"governs_criterion","direct_fact_authority":"source_verified","criterion_id":"criterion_1","criterion_path":[{"edge_id":"edge_1","traversal":"forward"}],"criterion_basis_authority":"source_verified","origin":"prepared","reference_ids":[]}],"projection_verification":[],
    }
    assert validate_overlay(value,{"criterion_1"}) == value
    value["nodes"][0]["extra"] = True
    with pytest.raises(ValueError): validate_overlay(value,{"criterion_1"})


def test_foundation_json_schemas_parse():
    for name in ("measurement-ai-role.v3.json", "work-order.v6.json", "measurement-ai-overlay.v3.json"):
        assert isinstance(json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text()), dict)


def test_all_27_v3_portable_contracts_are_closed_json_schemas():
    root=resources.files("shiproom.measurement_ai_schemas")
    names=sorted(item.name for item in root.iterdir() if item.name.endswith("v3.json"))+["work-order.v6.json"]
    assert len(names)==27 and len(set(names))==27
    for name in names:
        schema=json.loads(root.joinpath(name).read_text()); jsonschema.Draft202012Validator.check_schema(schema)
        def walk(value):
            if isinstance(value,dict):
                if value.get("type")=="object": assert "additionalProperties" in value, name
                for child in value.values(): walk(child)
            elif isinstance(value,list):
                for child in value: walk(child)
        walk(schema)


def test_all_27_contracts_report_python_json_schema_parity(capsys):
    report=parity_report(); print(json.dumps(report,sort_keys=True)); captured=capsys.readouterr().out
    assert len(report["contracts"])==27 and report["totals"]=={"accepted":27,"rejected":81}
    assert "work-order.v6.json" in captured


@pytest.mark.parametrize("filename",["qualification-task.json","qualification-result.json","qualification-receipt.json"])
def test_qualification_bundle_is_regraded_not_receipt_trusted(tmp_path,filename):
    guidance=load_guidance_pack(); task=build_qualification_task(guidance); cases=[]
    for expected in task["cases"]: cases.append({"case_id":expected["case_id"],"semantic_assessment":expected["allowed_semantic_assessments"][0],"recommendation_classes":expected["required_recommendation_classes"],"guidance_rule_ids":expected["required_guidance_rules"],"exception_ids":expected["required_exception_ids"],"effect":expected["maximum_effect"],"abstained":expected["abstention_required"],"claim_codes":[],"authority_labels":expected["required_authority_labels"],"automatic_replacements":[]})
    result={"schema_version":"measurement-reviewer-qualification-result.v3","task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":"provider","model_id":"model","case_results":cases}; path=qualification_store(tmp_path)/"qualification-result.json"; path.parent.mkdir(parents=True); path.write_text(json.dumps(result),encoding="utf-8"); compiled=compile_qualification(tmp_path,path); bundle=qualification_store(tmp_path)/compiled["qualification_id"]
    assert load_qualification_bundle(bundle,guidance)["qualification_bundle_hash"]==compiled["qualification_bundle_hash"]
    value=json.loads((bundle/filename).read_text()); value["semantic_tamper"]="forged"; (bundle/filename).write_text(json.dumps(value),encoding="utf-8")
    with pytest.raises((ValueError,KeyError)): load_qualification_bundle(bundle,guidance)


def test_v3_prerelease_audit_receipt_justifies_in_place_repair():
    receipt=json.loads((resources.files("shiproom").joinpath("..","tests","measurement_ai_v3_prerelease_audit.json")).read_text())
    assert receipt["audit_commit"]=="005ac55955ea029725373889b2747b2ccb11ee55"
    assert receipt["tracked_runtime_artifacts"]==[]
    assert receipt["release_local_root_state"]=="absent"
    assert receipt["active_preparation_pointers"]==[] and receipt["active_generation_pointers"]==[]
    assert receipt["accepted_non_test_v3_preparations"]==[] and receipt["accepted_non_test_v3_generations"]==[]


def test_shared_registries_cover_data_practice_ai_roles_and_projections():
    expected_fields={"decision_question","decision_use_case","decision_owner","decision_timing","decision_rule_or_interpretation","intended_outcome","unit","unit_of_observation","expected_direction","decision_threshold_or_interpretation","eligible_population","exposure_or_opportunity_definition","experiment_exposure","numerator","denominator","denominator_state","eligible_denominator_population","zero_denominator_handling","aggregation_level","release_can_affect_denominator","observation_window","attribution_rule","outcome_delay","minimum_maturity_window","incomplete_observation_possible","censoring_limitation","journey_start","success_condition","failure_condition","guardrails","inference_intent","definition_state","execution_state","data_accuracy_state"}
    assert set(MEASUREMENT_FIELD_SPECS)==expected_fields
    assert len(METRIC_DIMENSIONS)==11 and len(AI_MATURITY_RUNGS)==13
    assert ROLE_RESULT_SCHEMAS=={"measurement":"measurement-result.v3","ai_evaluation":"ai-evaluation-result.v3"}
    measurement=json.loads(resources.files("shiproom.measurement_ai_roles").joinpath("measurement.v3.json").read_text()); ai=json.loads(resources.files("shiproom.measurement_ai_roles").joinpath("ai_evaluation.v3.json").read_text())
    assert set(measurement["gap_taxonomy"])==set(MEASUREMENT_GAP_KINDS) and set(METRIC_DIMENSIONS).issubset(measurement["required_coverage"])
    assert set(ai["gap_taxonomy"])==set(AI_GAP_KINDS) and set(AI_MATURITY_RUNGS).issubset(ai["required_coverage"])
    assert {"measurement.contract_updates","measurement.signal_assessments.event_candidates","measurement.signal_assessments.property_results","ai_evaluation.maturity_rungs","ai_evaluation.judge_assessments","common.recommendations","common.verifier_dispositions"}.issubset(PROJECTION_REGISTRY)


def test_measurement_field_registry_enforces_field_specific_types():
    _typed_field_value("decision_use_case","launch_monitoring")
    _typed_field_value("unit",{"label":"customers","kind":"count"})
    _typed_field_value("observation_window",{"value":7,"unit":"days","anchor":"exposure"})
    with pytest.raises(ValueError): _typed_field_value("decision_use_case","best_metric")
    with pytest.raises(ValueError): _typed_field_value("release_can_affect_denominator","false")
    with pytest.raises(ValueError): _typed_field_value("unit","customers")


def test_static_import_selection_is_literal_and_one_hop_only():
    py=_literal_import_candidates("app/main.py","from .helpers import fixture\nimport app.runtime\n")
    js=_literal_import_candidates("src/main.ts",'import helper from "./helper"; const cfg=require("./config");')
    assert ("from .helpers import fixture","app/helpers.py") in py and ("import app.runtime","app/runtime.py") in py
    assert any(path=="src/helper.ts" for _,path in js) and any(path=="src/config.ts" for _,path in js)


def test_trusted_directory_creation_rejects_existing_non_directory_ancestor(tmp_path):
    root=tmp_path/"repo"; root.mkdir(); (root/"blocked").write_text("not a directory")
    with pytest.raises(ValueError,match="unsafe"): ensure_directory(root,root/"blocked"/"child",label="attack path")


def test_trusted_directory_creation_rejects_symlinked_ancestor(tmp_path):
    root=tmp_path/"repo"; root.mkdir(); outside=tmp_path/"outside"; outside.mkdir(); link=root/"linked"
    try: os.symlink(outside,link,target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError,match="unsafe"): ensure_directory(root,link/"preparation",label="linked preparation")


def test_all_committed_v1_resources_are_byte_identical_to_db2b984():
    ledger=json.loads(resources.files("shiproom.measurement_ai_roles").joinpath("v1-resource-hashes.json").read_text())
    assert ledger["baseline_commit"]=="db2b9844e90645f4943794b9c341667b4f91e327"
    root=resources.files("shiproom").joinpath("..").resolve()
    for relative,expected in ledger["hashes"].items():
        current=(root/relative).read_bytes()
        baseline=subprocess.run(["git","show",ledger["baseline_commit"]+":"+relative],cwd=root,check=True,capture_output=True).stdout
        assert current==baseline
        assert "sha256:"+hashlib.sha256(current).hexdigest()==expected


@pytest.mark.parametrize("ledger_name",["v1-resource-hashes.json","v2-resource-hashes.json"])
def test_all_frozen_measurement_ai_resources_match_their_committed_ledgers(ledger_name):
    ledger=json.loads(resources.files("shiproom.measurement_ai_roles").joinpath(ledger_name).read_text())
    root=resources.files("shiproom").joinpath("..").resolve()
    for relative,expected in ledger["hashes"].items():
        current=(root/relative).read_bytes(); baseline=subprocess.run(["git","show",ledger["baseline_commit"]+":"+relative],cwd=root,check=True,capture_output=True).stdout
        assert current==baseline and "sha256:"+hashlib.sha256(current).hexdigest()==expected


def test_guidance_eligibility_is_compiler_evaluated():
    pack=load_guidance_pack()
    facts={"metric.form":"absolute_count","contract.decision_use_case":{"value":"comparative_noncausal_review","field_state":"owner_confirmed"},"contract.exposure_or_opportunity_definition":{"value":None,"field_state":"unresolved"}}
    assert "MEAS_COUNT_002" in eligible_rule_ids(pack,facts)
    facts["contract.decision_use_case"]["value"]="launch_monitoring"
    assert "MEAS_COUNT_002" not in eligible_rule_ids(pack,facts)


def test_measurement_ai_zero_role_preparation_is_exact_and_reloadable(tmp_path):
    ctx=conventional_context(tmp_path)
    result=prepare(ctx)
    assert result["work_orders"] == []
    assert result["skip_reason"] == "no_applicable_measurement_or_ai_surface"
    loaded=load_preparation(ctx)
    assert loaded["manifest"]["issued_roles"] == []
    assert loaded["manifest"]["skip_reason"] == result["skip_reason"]


def test_instrumentation_requirement_issues_only_measurement_role(tmp_path):
    ctx=assessment_context(tmp_path)
    root=domain_root(ctx)/"inputs"; root.mkdir(parents=True)
    value=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion")
    value["measurement"]["criterion_ids"]=[cid]
    path=root/"applicability.json"; path.write_text(json.dumps(value),encoding="utf-8")
    result=prepare(ctx,applicability_path=str(path))
    assert [item["role_id"] for item in result["work_orders"]] == ["measurement"]
    loaded=load_preparation(ctx,result["preparation_id"])
    assert loaded["work_orders"]["measurement"]["permissions"]["allowed_commands"] == []
    schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath("work-order.v6.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(loaded["work_orders"]["measurement"])
    role_schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath("measurement-ai-role.v3.json").read_text())
    jsonschema.Draft202012Validator(role_schema).validate(json.loads(resources.files("shiproom.measurement_ai_roles").joinpath("measurement.v3.json").read_text()))


def test_preparation_semantic_tamper_and_unlinked_definition_do_not_create_scope(tmp_path):
    ctx=conventional_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True)
    value=default_applicability(); value["measurement"]["measurement_definition_paths"]=[{"path":"docs/brief.md","requirement_ids":[],"criterion_ids":[],"journey_ids":[],"declared_external":False}]
    path=root/"applicability.json"; path.write_text(json.dumps(value),encoding="utf-8")
    result=prepare(ctx,applicability_path=str(path)); assert result["work_orders"] == []
    prep=domain_root(ctx)/"preparations"/result["preparation_id"]; packet=json.loads((prep/"measurement-ai-source-packet.json").read_text()); packet["coverage_boundary"]="widened"; (prep/"measurement-ai-source-packet.json").write_text(json.dumps(packet,indent=2)+"\n")
    with pytest.raises(ValueError,match="semantic rederivation"):
        load_preparation(ctx,result["preparation_id"])


def test_unused_assessment_is_conditional_but_malformed_pointer_fails_closed(tmp_path,monkeypatch):
    ctx=conventional_context(tmp_path); info=prepare(ctx)
    monkeypatch.setattr(measurement_authority,"load_measurement_ai_input",lambda _:{"assessment_state":"present","generation":"gen_later","manifest":{"semantic_bundle_hash":"sha256:"+"4"*64},"artifacts":{"effective-assessment-view.json":{"criteria":[]}}})
    assert load_preparation(ctx,info["preparation_id"])["source_packet"]["assessment_dependency"]["state"]=="not_used"
    monkeypatch.setattr(measurement_authority,"load_measurement_ai_input",lambda _:(_ for _ in ()).throw(ValueError("malformed assessment pointer")))
    with pytest.raises(ValueError,match="malformed assessment pointer"): load_preparation(ctx,info["preparation_id"])


def place_result(ctx, preparation_id, role, record, executor=None):
    prep=load_preparation(ctx,preparation_id); work=prep["work_orders"][role]; root=domain_root(ctx)/"inbox"/preparation_id/work["work_order_id"]
    bases=[item for item in prep["contexts"][role]["basis_registry"] if record["criterion_id"] in item["criterion_ids"]]
    basis=next((item for item in bases if item["direct_fact_authority"] in {"source_verified","deterministically_established"}),bases[0]); record["basis_ids"]=[basis["basis_id"]]; record["basis_path_ids"]=[item["path_id"] for item in prep["contexts"][role]["basis_paths"] if item["start_basis_id"]==basis["basis_id"] and item["criterion_id"]==record["criterion_id"] and item["required"]]
    value={"schema_version":"measurement-result.v3" if role=="measurement" else "ai-evaluation-result.v3","role_id":role,"role_version":"3.0.0","preparation_id":preparation_id,"work_order_id":work["work_order_id"],"base_graph_semantic_hash":work["inputs"]["graph_semantic_hash"],"resolved_review_mode":work["resolved_review_mode"],"records":[record],"recommendations":[],"assumptions":[],"limitations":[]}
    raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (root/"result.json").write_bytes(raw)
    receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":executor or {"executor_type":"human","reviewer_label":"manual reviewer"},"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"}
    (root/"completion-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")


def assessed_record(cid):
    return {"local_id":"record_1","criterion_id":cid,"journey_ids":[],"scope_state":"applicable","disposition":"assessed","uncertainty":"bounded","basis_ids":[],"basis_path_ids":[],"conclusion_evidence_class":"model_reviewed","semantic_review_authority":"not_performed","summary":"Bounded structural review.","gaps":[],"contract_updates":[],"signal_assessments":[],"metric_dimensions":[]}


def test_skip_generation_has_all_six_not_applicable_checks(tmp_path):
    ctx=conventional_context(tmp_path); prep=prepare(ctx); manifest=compile_generation(ctx,prep["preparation_id"]); assert manifest["compiler_version"]=="portable-measurement-ai.v3"
    _,artifacts=load_generation(ctx); readiness=artifacts["measurement-ai-readiness.json"]
    assert len(readiness["checks"])==6 and {item["status"] for item in readiness["checks"]}=={"not_applicable"}
    assert readiness["accepted_role_validations"]==[] and "no_applicable_measurement_or_ai_surface" in show(ctx)


def test_measurement_result_compiles_without_upgrading_prepared_authority(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); value=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); value["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(value),encoding="utf-8")
    prep=prepare(ctx,applicability_path=str(path)); place_result(ctx,prep["preparation_id"],"measurement",assessed_record(cid)); loaded=load_preparation(ctx,prep["preparation_id"]); work=loaded["work_orders"]["measurement"]; raw_path=domain_root(ctx)/"inbox"/prep["preparation_id"]/work["work_order_id"]/"result.json"; schema=json.loads((loaded["directory"]/"contract-schemas"/"measurement-result.v3.json").read_text()); jsonschema.Draft202012Validator(schema).validate(json.loads(raw_path.read_text())); compile_generation(ctx,prep["preparation_id"]); _,artifacts=load_generation(ctx)
    checks={item["check_id"]:item for item in artifacts["measurement-ai-readiness.json"]["checks"]}
    assert checks["DATA_OUTCOME_EVENT_DEFINED"]["status"]=="owner_confirmation_required"
    assert checks["DATA_OUTCOME_EVENT_DEFINED"]["check_authority"]=="compiler_derived_from_prepared_authority"


def test_v3_result_schema_and_python_both_reject_nested_extra_fields(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); app["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8"); info=prepare(ctx,applicability_path=str(path)); place_result(ctx,info["preparation_id"],"measurement",assessed_record(cid)); prep=load_preparation(ctx,info["preparation_id"]); work=prep["work_orders"]["measurement"]; inbox=domain_root(ctx)/"inbox"/info["preparation_id"]/work["work_order_id"]; value=json.loads((inbox/"result.json").read_text()); value["records"][0]["metric_dimensions"].append({"dimension":"population","state":"adequate","rationale":"bounded","basis_ids":[],"basis_path_ids":[],"extra":True}); raw=(json.dumps(value)+"\n").encode(); schema=json.loads((prep["directory"]/"contract-schemas"/"measurement-result.v3.json").read_text())
    with pytest.raises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(value)
    with pytest.raises(ValueError): normalize_result(raw,(inbox/"completion-receipt.json").read_bytes(),work,prep["contexts"]["measurement"],prep["guidance"])


def test_staged_verifier_binds_all_primary_hashes(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph_input=load_assessment_input(ctx); graph=graph_input["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); journey=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="critical_journey"); app["measurement"]["criterion_ids"]=[cid]; app["measurement"]["contracts"]=[{"local_id":"metric","journey_id":journey,"criterion_ids":[cid],"fields":{"decision_question":{"value":"Did volume change?","state":"owner_confirmed"},"decision_use_case":{"value":"comparative_noncausal_review","state":"owner_confirmed"},"numerator":{"value":{"definition":"total completed","population":"eligible customers"},"state":"owner_confirmed"}},"metric_roles":["outcome"],"required_signals":[{"name":"completed","required_properties":["id"],"event_sources":[],"property_sources":[]}]}]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8")
    app["measurement"]["contracts"][0]["fields"]["inference_intent"]={"value":"causal_experiment","state":"owner_confirmed"}; path.write_text(json.dumps(app),encoding="utf-8")
    info=prepare(ctx,review_mode="expert_escalated_review",review_capabilities={"schema_version":"measurement-review-capabilities.v3","executor_type":"human","reviewer_label":"expert"},permission={"schema_version":"measurement-review-permission.v3","release_id":ctx.release["release_id"],"expert_review_granted":True,"model_switch":{"decision":"not_requested"}},applicability_path=str(path)); prep=load_preparation(ctx,info["preparation_id"]); record=assessed_record(cid); record["semantic_review_authority"]="dual_reviewed_with_curated_guidance"; place_result(ctx,info["preparation_id"],"measurement",record); work=prep["work_orders"]["measurement"]; inbox=domain_root(ctx)/"inbox"/info["preparation_id"]/work["work_order_id"]; value=json.loads((inbox/"result.json").read_text()); basis=value["records"][0]["basis_ids"]; paths=value["records"][0]["basis_path_ids"]; dims=("decision_use_case_alignment","metric_role","outcome_alignment","population","opportunity_exposure","denominator","window","attribution","interpretation_rule","guardrails","inference_intent_alignment"); value["records"][0]["metric_dimensions"]=[{"dimension":name,"state":"material_concern" if name=="attribution" else "adequate","rationale":"bounded","basis_ids":basis,"basis_path_ids":paths} for name in dims]; value["recommendations"]=[{"local_id":"warning","criterion_id":cid,"recommendation_class":"research_backed_warning","summary":"Causal language needs bounded assignment evidence.","basis_ids":basis,"basis_path_ids":paths,"guidance_rule_ids":["MEAS_ATTRIBUTION_008"],"exception_dispositions":[{"exception_id":item,"disposition":"ruled_out","basis_ids":basis} for item in ("descriptive_intent","randomized_assignment_defined","explicit_noncausal_comparison")],"abstained":False,"automatic_replacements":[]}]; raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (inbox/"result.json").write_bytes(raw); receipt=json.loads((inbox/"completion-receipt.json").read_text()); receipt["result_snapshot_hash"]=sha256_bytes(raw); (inbox/"completion-receipt.json").write_text(json.dumps(receipt))
    verifier=prepare_verifier(ctx,info["preparation_id"],"measurement"); value["records"][0]["summary"]="mutated primary"; raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (inbox/"result.json").write_bytes(raw); receipt["result_snapshot_hash"]=sha256_bytes(raw); (inbox/"completion-receipt.json").write_text(json.dumps(receipt))
    with pytest.raises(ValueError,match="primary result changed"): load_verifier(ctx,verifier["verifier_preparation_id"])


def _expert_material_submission(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); journey=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="critical_journey"); app["measurement"]["criterion_ids"]=[cid]; fields={name:{"value":value,"state":"owner_confirmed"} for name,value in {"decision_question":"Did the release cause improvement?","decision_use_case":"causal_experiment","decision_owner":"product owner","decision_timing":"launch review","decision_rule_or_interpretation":"compare assigned groups","unit_of_observation":"customer","eligible_population":"invited customers","observation_window":{"value":14,"unit":"days","anchor":"assignment"},"inference_intent":"causal_experiment","numerator":{"definition":"completed","population":"invited customers"}}.items()}; app["measurement"]["contracts"]=[{"local_id":"metric","journey_id":journey,"criterion_ids":[cid],"fields":fields,"metric_roles":["outcome"],"required_signals":[{"name":"completed","required_properties":["id"],"event_sources":[],"property_sources":[]}]}]; path=root/"expert.json"; path.write_text(json.dumps(app),encoding="utf-8")
    before=snapshot_measurement_ai_read_only(ctx); info=prepare(ctx,review_mode="expert_escalated_review",review_capabilities={"schema_version":"measurement-review-capabilities.v3","executor_type":"human","reviewer_label":"primary"},permission={"schema_version":"measurement-review-permission.v3","release_id":ctx.release["release_id"],"expert_review_granted":True,"model_switch":{"decision":"not_requested"}},applicability_path=str(path)); record=assessed_record(cid); record["semantic_review_authority"]="dual_reviewed_with_curated_guidance"; place_result(ctx,info["preparation_id"],"measurement",record); prep=load_preparation(ctx,info["preparation_id"]); work=prep["work_orders"]["measurement"]; inbox=domain_root(ctx)/"inbox"/info["preparation_id"]/work["work_order_id"]; value=json.loads((inbox/"result.json").read_text()); basis=value["records"][0]["basis_ids"]; paths=value["records"][0]["basis_path_ids"]; dims=("decision_use_case_alignment","metric_role","outcome_alignment","population","opportunity_exposure","denominator","window","attribution","interpretation_rule","guardrails","inference_intent_alignment"); value["records"][0]["metric_dimensions"]=[{"dimension":name,"state":"material_concern" if name=="attribution" else "adequate","rationale":"bounded","basis_ids":basis,"basis_path_ids":paths} for name in dims]; value["recommendations"]=[{"local_id":"material","criterion_id":cid,"recommendation_class":"research_backed_warning","summary":"Causal interpretation needs assignment evidence.","basis_ids":basis,"basis_path_ids":paths,"guidance_rule_ids":["MEAS_ATTRIBUTION_008"],"exception_dispositions":[{"exception_id":name,"disposition":"ruled_out","basis_ids":basis} for name in ("descriptive_intent","randomized_assignment_defined","explicit_noncausal_comparison")],"abstained":False,"automatic_replacements":[]}]; raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (inbox/"result.json").write_bytes(raw); receipt=json.loads((inbox/"completion-receipt.json").read_text()); receipt["result_snapshot_hash"]=sha256_bytes(raw); (inbox/"completion-receipt.json").write_text(json.dumps(receipt)); verifier=prepare_verifier(ctx,info["preparation_id"],"measurement"); return ctx,info,cid,verifier,before


@pytest.mark.parametrize("disposition,expected_effect,expected_status",[("supported","condition_candidate","gap"),("disputed","owner_confirmation","owner_confirmation_required")])
def test_verifier_disposition_changes_canonical_effect(tmp_path,monkeypatch,disposition,expected_effect,expected_status):
    import shiproom.authority as authority_module
    monkeypatch.setattr(authority_module,"run_bounded_command",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("project command invoked"))); monkeypatch.setattr(socket,"create_connection",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("network invoked"))); monkeypatch.setattr(urllib.request,"urlopen",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("HTTP invoked")))
    ctx,info,cid,verifier,before=_expert_material_submission(tmp_path/disposition); work=verifier["work_order"]; inbox=domain_root(ctx)/"verifier-inbox"/verifier["verifier_preparation_id"]/work["verifier_work_order_id"]
    reviews=[{"recommendation_id":rid,"disposition":disposition,"unsupported_assumption_codes":[] if disposition=="supported" else ["unsupported_causal_assumption"],"ignored_exception_ids":[],"severity_supported":disposition=="supported","abstention_required":False,"rationale":"bounded verifier disposition"} for rid in work["material_recommendation_ids"]]
    value={"schema_version":"measurement-verifier-result.v3","verifier_preparation_id":verifier["verifier_preparation_id"],"verifier_work_order_id":work["verifier_work_order_id"],"primary_result_semantic_hash":work["primary_result_semantic_hash"],"primary_result_snapshot_hash":work["primary_result_snapshot_hash"],"primary_receipt_snapshot_hash":work["primary_receipt_snapshot_hash"],"recommendation_reviews":reviews}; raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (inbox/"result.json").write_bytes(raw); receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":{"executor_type":"human","reviewer_label":"skeptical verifier"},"work_order_id":work["verifier_work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"}; (inbox/"completion-receipt.json").write_text(json.dumps(receipt)); compile_generation(ctx,info["preparation_id"],[verifier["verifier_preparation_id"]]); _,artifacts=load_generation(ctx); warning=artifacts["launch-measurement-plan.json"]["warnings"][0]; check=next(item for item in artifacts["measurement-ai-readiness.json"]["checks"] if item["check_id"]=="DATA_PRIMARY_METRIC_DECISION_USEFUL"); quality=artifacts["measurement-ai-readiness.json"]["metric_quality"][0]
    assert warning["derived_effect"]==expected_effect and warning["verifier_disposition"]==disposition and check["status"]==expected_status and quality["verifier_dispositions"]==[disposition]; show(ctx); assert_measurement_ai_read_only(ctx,before)


def test_qualification_is_mechanically_graded_and_hash_bound():
    from shiproom.measurement_ai.qualification import build_qualification_task
    pack=load_guidance_pack(); task=build_qualification_task(pack); cases=[]
    for expected in task["cases"]:
        cases.append({"case_id":expected["case_id"],"semantic_assessment":expected["allowed_semantic_assessments"][0],"recommendation_classes":expected["required_recommendation_classes"],"guidance_rule_ids":expected["required_guidance_rules"],"exception_ids":expected["required_exception_ids"],"effect":expected["maximum_effect"],"abstained":expected["abstention_required"],"claim_codes":[],"authority_labels":expected["required_authority_labels"],"automatic_replacements":[]})
    value={"schema_version":"measurement-reviewer-qualification-result.v3","task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":"configured","model_id":"qualified","case_results":cases}
    receipt=grade_qualification_result(value,task,"sha256:"+"1"*64); assert "ratio_denominator_review" in receipt["qualified_capabilities"]
    for candidate,name in ((task,"measurement-reviewer-qualification-task.v3.json"),(value,"measurement-reviewer-qualification-result.v3.json"),(receipt,"measurement-reviewer-qualification-receipt.v3.json")):
        schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text()); jsonschema.Draft202012Validator(schema).validate(candidate)
    value["task_hash"]="sha256:"+"0"*64
    with pytest.raises(ValueError,match="binding mismatch"): grade_qualification_result(value,task,"sha256:"+"1"*64)


def test_forged_reviewer_authority_and_contract_only_guidance_are_rejected(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); app["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8"); info=prepare(ctx,applicability_path=str(path)); prep=load_preparation(ctx,info["preparation_id"]); work=prep["work_orders"]["measurement"]
    record=assessed_record(cid); record["conclusion_evidence_class"]="deterministically_established"; place_result(ctx,info["preparation_id"],"measurement",record); inbox=domain_root(ctx)/"inbox"/info["preparation_id"]/work["work_order_id"]
    with pytest.raises(ValueError,match="authority upgrade"): normalize_result((inbox/"result.json").read_bytes(),(inbox/"completion-receipt.json").read_bytes(),work,prep["contexts"]["measurement"],load_guidance_pack())


def test_late_generation_failure_preserves_previous_pointer(tmp_path,monkeypatch):
    ctx=conventional_context(tmp_path); first=prepare(ctx); compile_generation(ctx,first["preparation_id"]); pointer=domain_root(ctx)/"current-generation.json"; before=pointer.read_bytes(); second=prepare(ctx)
    monkeypatch.setattr(measurement_persistence,"AFTER_GENERATION_VERIFY",lambda directory: (_ for _ in ()).throw(RuntimeError("late failure")))
    with pytest.raises(RuntimeError,match="late failure"): compile_generation(ctx,second["preparation_id"])
    assert pointer.read_bytes()==before; monkeypatch.setattr(measurement_persistence,"AFTER_GENERATION_VERIFY",None); load_generation(ctx)


def test_measurement_ai_operations_preserve_complete_upstream_artifact_sets(tmp_path):
    ctx=conventional_context(tmp_path); before=snapshot_measurement_ai_read_only(ctx); info=prepare(ctx); compile_generation(ctx,info["preparation_id"]); load_generation(ctx); show(ctx); assert_measurement_ai_read_only(ctx,before)


def test_v3_schema_python_parity_for_generated_and_tampered_preparation(tmp_path):
    ctx=conventional_context(tmp_path); info=prepare(ctx); prep=load_preparation(ctx,info["preparation_id"])
    accepted=[(prep["source_packet"],"measurement-ai-source-packet.v3.json"),(prep["manifest"],"measurement-ai-work-orders.v3.json"),(prep["pointer"],"active-measurement-ai-preparation.v3.json")]
    for value,name in accepted:
        schema=json.loads((prep["directory"]/"contract-schemas"/name).read_text()); jsonschema.Draft202012Validator(schema).validate(value)
    manifest_path=prep["directory"]/"measurement-ai-work-orders.json"; original=manifest_path.read_bytes(); value=json.loads(original); value["unexpected_nested"]={}; schema=json.loads((prep["directory"]/"contract-schemas"/"measurement-ai-work-orders.v3.json").read_text())
    with pytest.raises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(value)
    manifest_path.write_text(json.dumps(value),encoding="utf-8")
    with pytest.raises(ValueError): load_preparation(ctx,info["preparation_id"])
    manifest_path.write_bytes(original); load_preparation(ctx,info["preparation_id"])


def test_old_preparation_and_pointer_fail_closed_without_mutation(tmp_path):
    ctx=conventional_context(tmp_path); info=prepare(ctx); prep_manifest=domain_root(ctx)/"preparations"/info["preparation_id"]/"measurement-ai-work-orders.json"; value=json.loads(prep_manifest.read_text()); value["compiler_version"]="measurement-ai-preparation.v2"; prep_manifest.write_text(json.dumps(value),encoding="utf-8")
    with pytest.raises(ValueError,match="stale_measurement_ai_preparation_compiler_version.*new v3 preparation"): load_preparation(ctx,info["preparation_id"])
    # Recreate a valid v3 preparation/generation, then make the current pointer
    # target a syntactically valid old generation.  The stale load is read-only.
    info=prepare(ctx); compile_generation(ctx,info["preparation_id"]); pointer=domain_root(ctx)/"current-generation.json"; pointer_value=json.loads(pointer.read_text()); generation=domain_root(ctx)/"generations"/pointer_value["generation"]; manifest=generation/"manifest.json"; old=json.loads(manifest.read_text()); old["compiler_version"]="portable-measurement-ai.v2"; manifest.write_text(json.dumps(old),encoding="utf-8"); before=pointer.read_bytes()
    with pytest.raises(ValueError,match="stale_measurement_ai_generation_compiler_version.*new v3 preparation"): load_generation(ctx)
    assert pointer.read_bytes()==before and generation.exists()


def test_canonical_artifacts_ignore_preparation_handles_and_local_labels(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); app["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8")
    artifacts=[]
    submissions=(("human_local",{"executor_type":"human","reviewer_label":"human"}),("hermes_local",{"executor_type":"agent_harness","candidate_id":"hermes_candidate","provider_id":"provider","model_id":"model","harness_id":"hermes","adapter_version":"1","run_id":"h"}),("codex_local",{"executor_type":"agent_harness","candidate_id":"codex_candidate","provider_id":"provider","model_id":"model","harness_id":"codex","adapter_version":"1","run_id":"c"}),("renamed_local_id",{"executor_type":"human","reviewer_label":"renamed"}))
    bundles=[]
    for label,executor in submissions:
        info=prepare(ctx,applicability_path=str(path)); record=assessed_record(cid); record["local_id"]=label; place_result(ctx,info["preparation_id"],"measurement",record,executor); manifest=compile_generation(ctx,info["preparation_id"]); _,current=load_generation(ctx); artifacts.append({name:value for name,value in current.items() if name!="measurement-ai-compiler-receipts.json"}); bundles.append(manifest["semantic_bundle_hash"])
    assert all(value==artifacts[0] for value in artifacts[1:]) and len(set(bundles))==1


def test_domain_core_records_zero_external_operations(tmp_path,monkeypatch):
    import shiproom.authority as authority_module
    monkeypatch.setattr(authority_module,"run_bounded_command",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("project command invoked")))
    monkeypatch.setattr(socket,"create_connection",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("network invoked")))
    monkeypatch.setattr(urllib.request,"urlopen",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("HTTP invoked")))
    ctx=conventional_context(tmp_path); before=snapshot_measurement_ai_read_only(ctx); task=prepare_qualification(ctx.repository_root); cases=[]
    for expected in task["cases"]: cases.append({"case_id":expected["case_id"],"semantic_assessment":expected["allowed_semantic_assessments"][0],"recommendation_classes":expected["required_recommendation_classes"],"guidance_rule_ids":expected["required_guidance_rules"],"exception_ids":expected["required_exception_ids"],"effect":expected["maximum_effect"],"abstained":expected["abstention_required"],"claim_codes":[],"authority_labels":expected["required_authority_labels"],"automatic_replacements":[]})
    result={"schema_version":"measurement-reviewer-qualification-result.v3","task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":"guarded","model_id":"guarded","case_results":cases}; result_path=qualification_store(ctx.repository_root)/"qualification-result.json"; result_path.write_text(json.dumps(result),encoding="utf-8"); compile_qualification(ctx.repository_root,result_path); info=prepare(ctx); compile_generation(ctx,info["preparation_id"]); _,artifacts=load_generation(ctx); show(ctx); assert_measurement_ai_read_only(ctx,before)
    operations=[item for item in artifacts["measurement-ai-compiler-receipts.json"]["validations"] if item["kind"]=="external_operation"]
    assert {item["operation"] for item in operations}=={"model","command","network","browser","sql","external_service"} and all(item["count"]==0 for item in operations)


def test_shiproom_skill_documents_v3_authority_and_staged_verifier():
    skill=(resources.files("shiproom").joinpath("..","skills","shiproom","SKILL.md")).read_text(encoding="utf-8")
    for value in ("shiproom.work-order.v6","shiproom.measurement-ai-role.v3","required criterion-path IDs","contract_declaration","immutable v3 verifier preparation","supported`, `downgrade`, `disputed`, or `owner_confirmation_required"):
        assert value in skill
