from __future__ import annotations

import json
import hashlib
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import socket
import urllib.request
from importlib import resources

import pytest
import jsonschema

from shiproom.measurement_ai.contracts import effective_basis_class
from shiproom.measurement_ai.guidance import load_guidance_pack, rule_map
from shiproom.measurement_ai.overlay import evaluate_basis_path, validate_overlay
from shiproom.measurement_ai.authority import _literal_import_candidates, _typed_field_value, default_applicability, domain_root, reject_external_operation, validate_applicability, source_record, normalize_text
from shiproom.measurement_ai.preparation import prepare, load_preparation, _review_resolution
from shiproom.measurement_ai.persistence import compile_generation, load_generation, load_generation_directory
from shiproom.measurement_ai.rendering import show
from shiproom.measurement_ai.contracts import load_json_bytes, render_json, semantic_without_local_ids, sha256_bytes
from shiproom.measurement_ai.qualification import build_qualification_task, compile_qualification, grade_qualification_result, prepare_qualification, qualification_store, load_qualification_bundle
from shiproom.measurement_ai.contract_parity import BoundaryResult, parity_report, private_rubric_parity
from shiproom.measurement_ai.closeout import CLAIMS, resolve_claims
from shiproom.measurement_ai.results import normalize_result, _claim_honesty, _assert_signal_basis, _typed_authority, _validate_receipt
from shiproom.measurement_ai.results import validate_executor
from shiproom.measurement_ai.guidance import eligible_rule_ids
from shiproom.measurement_ai.verifier import prepare_verifier, load_verifier
from shiproom.measurement_ai.registries import AI_GAP_KINDS, AI_MATURITY_RUNGS, MEASUREMENT_FIELD_SPECS, MEASUREMENT_GAP_KINDS, METRIC_DIMENSIONS, PROJECTION_REGISTRY, ROLE_RESULT_SCHEMAS
from shiproom.measurement_ai.compiler import _aggregate
from shiproom.measurement_ai.projection import verify_projected_records
from shiproom.measurement_ai.trust import ensure_approved_write_target, ensure_directory, safe_atomic_path
import shiproom.measurement_ai.persistence as measurement_persistence
import shiproom.measurement_ai.authority as measurement_authority
from scripts.measurement_ai_acceptance_fixture import snapshot_measurement_ai_read_only, assert_measurement_ai_read_only
from test_assessment import assessment_context
from test_intent import context_for, inbox, proposal
from shiproom.intent import prepare as prepare_intent, compile_bundle as compile_intent
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input
from measurement_ai_public_responses import qualification_result
from shiproom.project import content_hash


def conventional_context(tmp_path):
    ctx=context_for(tmp_path); packet=prepare_intent(ctx,["docs/brief.md"],[]); value=proposal(packet)
    value["criteria"][0]["required_evidence_categories"]=["owner_confirmation"]
    path=inbox(ctx); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value),encoding="utf-8")
    compile_intent(ctx,str(path)); compile_graph(ctx); return ctx

def _emit_closeout_artifact(name,value):
    root=os.environ.get("SHIPROOM_CLOSEOUT_ARTIFACT_ROOT")
    if root:
        path=Path(root);path.mkdir(parents=True,exist_ok=True);(path/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")


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


def test_production_boundary_parity_executes_all_27_contracts(tmp_path,capsys):
    report=parity_report(_ProductionBoundaryRunner(tmp_path)); print(json.dumps(report,sort_keys=True)); captured=capsys.readouterr().out
    assert len(report["contracts"])==27 and report["totals"]["accepted"]==27
    assert report["totals"]["boundaries_invoked"]==27 and not report["unexpected_passes"]
    assert all(item["boundary_invoked"] and item["production_boundary"].startswith("shiproom.measurement_ai.") for item in report["contracts"].values())
    assert "work-order.v6.json" in captured
    _emit_closeout_artifact("contract-parity-report.json",report)

def test_private_rubric_has_separate_schema_python_parity():
    report=private_rubric_parity()
    assert report["accepted"]==1 and report["boundary_invoked"] and len(report["semantic_mutations"])>=2 and all(item["python_rejected"] for item in report["semantic_mutations"])
    _emit_closeout_artifact("private-rubric-parity-report.json",report)

def test_production_boundary_report_rejects_unexecuted_or_passing_mutation():
    class Unexecuted:
        def accepted(self,name): return BoundaryResult({},False,())
        def rejected(self,name,mutation_name,value): return False
    with pytest.raises(AssertionError,match="not invoked"): parity_report(Unexecuted())

def test_closeout_claim_registry_resolves_symbols_tests_and_artifacts():
    passed={test for claim in CLAIMS for test in claim["positive_test_ids"]+claim["negative_test_ids"]}
    with pytest.raises(ValueError,match="artifact"):
        resolve_claims(passed,{})


@pytest.mark.parametrize("filename",["qualification-task.json","qualification-result.json","qualification-receipt.json"])
def test_qualification_bundle_is_regraded_not_receipt_trusted(tmp_path,filename):
    guidance=load_guidance_pack(); task=build_qualification_task(guidance); result=qualification_result(task); path=qualification_store(tmp_path)/"qualification-result.json"; path.parent.mkdir(parents=True); path.write_text(json.dumps(result),encoding="utf-8"); compiled=compile_qualification(tmp_path,path); bundle=qualification_store(tmp_path)/compiled["qualification_id"]
    assert load_qualification_bundle(bundle,guidance)["qualification_bundle_hash"]==compiled["qualification_bundle_hash"]
    value=json.loads((bundle/filename).read_text()); value["semantic_tamper"]="forged"; (bundle/filename).write_text(json.dumps(value),encoding="utf-8")
    with pytest.raises((ValueError,KeyError)): load_qualification_bundle(bundle,guidance)

def test_qualification_packet_is_blind_and_capabilities_are_independent():
    pack=load_guidance_pack(); task=build_qualification_task(pack)
    forbidden={"allowed_semantic_assessments","required_guidance_rules","required_exception_ids","maximum_effect","qualified_capabilities"}
    assert all(not (set(case)&forbidden) and case["case_id"].startswith("qual_case_") for case in task["cases"])
    value=qualification_result(task); failed=next(item for item in value["case_results"] if item["case_id"]=="qual_case_007"); failed["claim_codes"]=["ai_eval_proves_product_impact"]
    receipt=grade_qualification_result(value,task,"sha256:"+"1"*64,pack["qualification_private_rubric"],pack)
    assert "absolute_count_opportunity_review" in receipt["passed_capabilities"]
    assert "ai_claim_authority_review" in receipt["failed_capabilities"]

def test_primary_executor_truth_table_rejects_bidirectional_impersonation():
    human_work={"resolved_review_mode":"guided_review","review_participants":[{"type":"human"}],"required_qualification_capabilities":[]}
    model={"type":"model","candidate_id":"candidate","provider_id":"provider","model_id":"model","qualification_id":"qualification","qualification_bundle_hash":"sha256:"+"1"*64,"qualified_capabilities":["metric_decision_alignment"],"model_switch":False}
    model_work={"resolved_review_mode":"guided_review","review_participants":[model],"required_qualification_capabilities":["metric_decision_alignment"]}
    harness={"executor_type":"agent_harness","participant_binding":{key:model[key] for key in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")},"harness_id":"h","adapter_version":"1","run_id":"r"}
    with pytest.raises(ValueError,match="human participant"): validate_executor(harness,human_work)
    with pytest.raises(ValueError,match="human cannot"): validate_executor({"executor_type":"human","reviewer_label":"person"},model_work)
    validate_executor(harness,model_work)
    harness["participant_binding"]["qualification_id"]="wrong"
    with pytest.raises(ValueError,match="binding mismatch"): validate_executor(harness,model_work)

def test_public_response_fixtures_do_not_depend_on_private_grader():
    source=(resources.files("shiproom").joinpath("..","tests","measurement_ai_public_responses.py")).read_text(encoding="utf-8")
    assert "qualification_private_rubric" not in source and "measurement_ai.qualification" not in source and "allowed_semantic_assessments" not in source


def test_v3_prerelease_audit_receipt_justifies_in_place_repair():
    receipt=json.loads((resources.files("shiproom").joinpath("..","tests","measurement_ai_v3_prerelease_audit.json")).read_text())
    assert receipt["audit_commit"]=="81b322ee46da2fc6237d8bce821adb576f110e96"
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

def test_measurement_ai_write_boundary_rejects_outside_repository_and_unapproved_roots(tmp_path):
    root=tmp_path/"repo";root.mkdir();outside=tmp_path/"outside"
    with pytest.raises(ValueError,match="escapes"):ensure_approved_write_target(root,outside,label="outside write")
    with pytest.raises(ValueError,match="approved ignored roots"):ensure_approved_write_target(root,root/"src"/"output",label="tracked-tree write")

def test_atomic_write_rejects_unsafe_temporary_path(tmp_path):
    root=tmp_path/"repo";root.mkdir();parent=root/".shiproom"/"local"/"measurement-reviewer-qualifications";parent.mkdir(parents=True);temporary=parent/"receipt.json.tmp";temporary.mkdir()
    with pytest.raises(ValueError,match="unsafe"):safe_atomic_path(root,parent/"receipt.json",label="qualification receipt")


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

def test_downstream_definition_scope_is_exact(tmp_path):
    ctx=assessment_context(tmp_path); inputs=load_assessment_input(ctx); cid=next(item["criterion_id"] for item in inputs["intent_artifacts"]["acceptance-criteria.json"]["criteria"]); rid=next(item["requirement_id"] for item in inputs["intent_artifacts"]["requirements.json"]["requirements"]); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); app["measurement"]["criterion_ids"]=[cid]; app["measurement"]["measurement_definition_paths"]=[{"path":"docs/brief.md","requirement_ids":[rid],"criterion_ids":[cid],"journey_ids":[],"declared_external":False}]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8"); info=prepare(ctx,applicability_path=str(path)); record=assessed_record(cid); place_result(ctx,info["preparation_id"],"measurement",record); compile_generation(ctx,info["preparation_id"]); _,artifacts=load_generation(ctx); definition=artifacts["measurement-contract.json"]["downstream_definitions"][0]
    assert definition["criterion_ids"]==[cid] and definition["requirement_ids"]==[rid] and definition["git_object_format"]=="sha1" and len(definition["git_blob_hash"])==40 and definition["definition_content_authority"]=="source_verified" and definition["definition_assertion_scope"]=="source_definition" and definition["execution_state"]==definition["data_accuracy_state"]=="not_inspected"
    _emit_closeout_artifact("measurement-contract.json",artifacts["measurement-contract.json"])

def test_projection_references_are_scoped_and_resolved(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); cid=next(item["node_id"] for item in load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]["nodes"] if item["node_type"]=="acceptance_criterion"); app["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8"); info=prepare(ctx,applicability_path=str(path)); place_result(ctx,info["preparation_id"],"measurement",assessed_record(cid)); compile_generation(ctx,info["preparation_id"]); _,artifacts=load_generation(ctx); refs=[node for node in artifacts["measurement-ai-overlay.json"]["nodes"] if node["node_type"]=="projection_reference"]
    assert refs and all(node["criterion_ids"]==[cid] and node["canonical_record_id"]==node["target_record_id"] for node in refs)
    _emit_closeout_artifact("measurement-ai-overlay.json",artifacts["measurement-ai-overlay.json"])

def test_projection_rejects_orphan_placeholders():
    value={"schema_version":"measurement-ai-overlay.v3","release_id":"r","release_commit":"a"*40,"product_intent_semantic_hash":"sha256:"+"1"*64,"graph_semantic_hash":"sha256:"+"2"*64,"nodes":[{"node_id":"p","node_type":"projection_reference","provenance":"measurement_ai_compiler","criterion_ids":[],"journey_id":None,"record_kind":"gap","canonical_record_id":"g","destination_artifact":"launch-measurement-plan.json","target_record_id":"g","authority":"not_inspected"}],"edges":[],"projection_verification":[]}
    with pytest.raises(ValueError,match="scoped projection"): validate_overlay(value,{"criterion"})


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


def _not_inspected_ai_record(cid):
    return {"local_id":"ai_record","criterion_id":cid,"scope_state":"applicable","disposition":"not_inspected","uncertainty":"not_assessed","basis_ids":[],"basis_path_ids":[],"conclusion_evidence_class":"not_inspected","semantic_review_authority":"not_performed","summary":"not_inspected","maturity_rungs":[],"judge_assessments":[],"claims":[],"observability_candidates":[],"gaps":[]}

def _place_not_inspected_ai(ctx,preparation_id,cid):
    prep=load_preparation(ctx,preparation_id);work=prep["work_orders"]["ai_evaluation"];root=domain_root(ctx)/"inbox"/preparation_id/work["work_order_id"]
    value={"schema_version":"ai-evaluation-result.v3","role_id":"ai_evaluation","role_version":"3.0.0","preparation_id":preparation_id,"work_order_id":work["work_order_id"],"base_graph_semantic_hash":work["inputs"]["graph_semantic_hash"],"resolved_review_mode":work["resolved_review_mode"],"records":[_not_inspected_ai_record(cid)],"recommendations":[],"assumptions":[],"limitations":[]};raw=render_json(value);(root/"result.json").write_bytes(raw);receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":{"executor_type":"human","reviewer_label":"manual reviewer"},"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"};(root/"completion-receipt.json").write_bytes(render_json(receipt))


class _ProductionBoundaryRunner:
    """Persist mutations and invoke the same production loaders used by the CLI."""
    TEST_ID="test_production_boundary_parity_executes_all_27_contracts"
    def __init__(self,tmp_path):
        self.ctx=assessment_context(tmp_path/"portable"); inputs=load_assessment_input(self.ctx); self.cid=next(item["criterion_id"] for item in inputs["intent_artifacts"]["acceptance-criteria.json"]["criteria"])
        root=domain_root(self.ctx)/"inputs";root.mkdir(parents=True);app=default_applicability();app["measurement"]["criterion_ids"]=[self.cid];app["ai"]["criterion_ids"]=[self.cid];path=root/"parity-applicability.json";path.write_text(json.dumps(app),encoding="utf-8")
        self.info=prepare(self.ctx,applicability_path=str(path));place_result(self.ctx,self.info["preparation_id"],"measurement",assessed_record(self.cid));_place_not_inspected_ai(self.ctx,self.info["preparation_id"],self.cid);self.manifest=compile_generation(self.ctx,self.info["preparation_id"]);self.prep=load_preparation(self.ctx,self.info["preparation_id"]);self.generation=domain_root(self.ctx)/"generations"/self.manifest["generation"]
        qtask=build_qualification_task(load_guidance_pack());submitted=qualification_store(self.ctx.repository_root)/"parity-submitted.json";submitted.parent.mkdir(parents=True,exist_ok=True);submitted.write_text(json.dumps(qualification_result(qtask)),encoding="utf-8");qcompiled=compile_qualification(self.ctx.repository_root,submitted);self.qbundle=qualification_store(self.ctx.repository_root)/qcompiled["qualification_id"]
        self.verifier_ctx,self.verifier_info,_,self.verifier,_=_expert_material_submission(tmp_path/"verifier");self._complete_verifier();self.verifier_dir=domain_root(self.verifier_ctx)/"verifier-preparations"/self.verifier["verifier_preparation_id"]
        self.review_capabilities={"schema_version":"measurement-review-capabilities.v3","executor_type":"human","reviewer_label":"parity reviewer"};self.permission={"schema_version":"measurement-review-permission.v3","release_id":self.ctx.release["release_id"],"expert_review_granted":True,"model_switch":{"decision":"not_requested"}}

    def _complete_verifier(self):
        work=self.verifier["work_order"];inbox=domain_root(self.verifier_ctx)/"verifier-inbox"/self.verifier["verifier_preparation_id"]/work["verifier_work_order_id"]
        reviews=[{"recommendation_id":rid,"disposition":"supported","unsupported_assumption_codes":[],"ignored_exception_ids":[],"severity_supported":True,"abstention_required":False,"rationale":"bounded"} for rid in work["material_recommendation_ids"]]
        value={"schema_version":"measurement-verifier-result.v3","verifier_preparation_id":self.verifier["verifier_preparation_id"],"verifier_work_order_id":work["verifier_work_order_id"],"primary_result_semantic_hash":work["primary_result_semantic_hash"],"primary_result_snapshot_hash":work["primary_result_snapshot_hash"],"primary_receipt_snapshot_hash":work["primary_receipt_snapshot_hash"],"recommendation_reviews":reviews};raw=render_json(value);(inbox/"result.json").write_bytes(raw);receipt={"schema_version":"measurement-ai-completion-receipt.v3","executor":{"executor_type":"human","reviewer_label":"verifier"},"work_order_id":work["verifier_work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"};(inbox/"completion-receipt.json").write_bytes(render_json(receipt));load_verifier(self.verifier_ctx,self.verifier["verifier_preparation_id"])

    def _path(self,name):
        wm=self.prep["work_orders"]["measurement"];wa=self.prep["work_orders"]["ai_evaluation"];prep=self.prep["directory"]
        mapping={"measurement-ai-capabilities.v3.json":prep/"capabilities.json","measurement-ai-applicability.v3.json":prep/"applicability.json","measurement-ai-role.v3.json":prep/"role-definitions"/"measurement.json","work-order.v6.json":prep/"work-orders"/(wm["work_order_id"]+".json"),"measurement-reviewer-qualification-task.v3.json":self.qbundle/"qualification-task.json","measurement-reviewer-qualification-result.v3.json":self.qbundle/"qualification-result.json","measurement-reviewer-qualification-receipt.v3.json":self.qbundle/"qualification-receipt.json","measurement-result.v3.json":domain_root(self.ctx)/"inbox"/self.info["preparation_id"]/wm["work_order_id"]/"result.json","ai-evaluation-result.v3.json":domain_root(self.ctx)/"inbox"/self.info["preparation_id"]/wa["work_order_id"]/"result.json","measurement-ai-completion-receipt.v3.json":domain_root(self.ctx)/"inbox"/self.info["preparation_id"]/wm["work_order_id"]/"completion-receipt.json","measurement-ai-source-packet.v3.json":prep/"measurement-ai-source-packet.json","measurement-ai-role-context.v3.json":prep/"role-context"/"measurement.json","measurement-ai-work-orders.v3.json":prep/"measurement-ai-work-orders.json","active-measurement-ai-preparation.v3.json":domain_root(self.ctx)/"active-preparation.json","measurement-verifier-preparation.v3.json":self.verifier_dir/"manifest.json","measurement-verifier-work-order.v3.json":self.verifier_dir/"work-order.json","measurement-verifier-result.v3.json":domain_root(self.verifier_ctx)/"verifier-inbox"/self.verifier["verifier_preparation_id"]/self.verifier["work_order"]["verifier_work_order_id"]/"result.json","measurement-contract.v3.json":self.generation/"measurement-contract.json","instrumentation-coverage.v3.json":self.generation/"instrumentation-coverage.json","measurement-ai-readiness.v3.json":self.generation/"measurement-ai-readiness.json","launch-measurement-plan.v3.json":self.generation/"launch-measurement-plan.json","measurement-ai-overlay.v3.json":self.generation/"measurement-ai-overlay.json","measurement-ai-compiler-receipts.v3.json":self.generation/"measurement-ai-compiler-receipts.json","portable-measurement-ai-manifest.v3.json":self.generation/"manifest.json","current-portable-measurement-ai.v3.json":domain_root(self.ctx)/"current-generation.json"}
        return mapping[name]

    def accepted(self,name):
        if name=="measurement-review-capabilities.v3.json":_review_resolution("guided_review",self.review_capabilities,None,self.ctx.repository_root,load_guidance_pack());return BoundaryResult(deepcopy(self.review_capabilities),True,(self.TEST_ID,))
        if name=="measurement-review-permission.v3.json":_review_resolution("expert_escalated_review",self.review_capabilities,self.permission,self.ctx.repository_root,load_guidance_pack());return BoundaryResult(deepcopy(self.permission),True,(self.TEST_ID,))
        path=self._path(name);value=load_json_bytes(path.read_bytes());self._invoke(name,value);return BoundaryResult(value,True,(self.TEST_ID,))

    def _invoke(self,name,value):
        if name in {"measurement-review-capabilities.v3.json","measurement-review-permission.v3.json"}:
            caps=value if name.startswith("measurement-review-capabilities") else self.review_capabilities;permission=value if name.startswith("measurement-review-permission") else None;_review_resolution("expert_escalated_review" if permission else "guided_review",caps,permission,self.ctx.repository_root,load_guidance_pack());return
        if name.startswith("measurement-reviewer-qualification-"):
            if name.endswith("task.v3.json"):
                if value!=build_qualification_task(load_guidance_pack()):raise ValueError("task mismatch")
            elif name.endswith("result.v3.json"):grade_qualification_result(value,build_qualification_task(load_guidance_pack()),"sha256:"+"1"*64,load_guidance_pack()["qualification_private_rubric"],load_guidance_pack())
            else:load_qualification_bundle(self.qbundle,load_guidance_pack())
            return
        if name in {"measurement-result.v3.json","ai-evaluation-result.v3.json"}:
            role="measurement" if name.startswith("measurement-result") else "ai_evaluation";work=self.prep["work_orders"][role];receipt_path=self._path("measurement-ai-completion-receipt.v3.json") if role=="measurement" else self._path(name).parent/"completion-receipt.json";receipt=load_json_bytes(receipt_path.read_bytes());raw=render_json(value);receipt["result_snapshot_hash"]=sha256_bytes(raw);normalize_result(raw,render_json(receipt),work,self.prep["contexts"][role],self.prep["guidance"]);return
        if name=="measurement-ai-completion-receipt.v3.json":_validate_receipt(value,self.prep["work_orders"]["measurement"],self._path("measurement-result.v3.json").read_bytes());return
        if name.startswith("measurement-verifier-"):load_verifier(self.verifier_ctx,self.verifier["verifier_preparation_id"]);return
        if name in {"measurement-ai-source-packet.v3.json","measurement-ai-role-context.v3.json","measurement-ai-work-orders.v3.json","active-measurement-ai-preparation.v3.json","work-order.v6.json"}:load_preparation(self.ctx,self.info["preparation_id"] if name!="active-measurement-ai-preparation.v3.json" else None);return
        if name=="current-portable-measurement-ai.v3.json":load_generation(self.ctx);return
        load_generation_directory(self.ctx,self.generation)

    def rejected(self,name,mutation_name,value):
        if name in {"measurement-review-capabilities.v3.json","measurement-review-permission.v3.json"}:
            try:self._invoke(name,value)
            except Exception:return True
            return False
        path=self._path(name);original=path.read_bytes();path.write_bytes(render_json(value))
        try:
            try:self._invoke(name,value)
            except Exception:return True
            return False
        finally:path.write_bytes(original)


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
    _emit_closeout_artifact("launch-measurement-plan.json",artifacts["launch-measurement-plan.json"])


def test_qualification_is_mechanically_graded_and_hash_bound():
    from shiproom.measurement_ai.qualification import build_qualification_task
    pack=load_guidance_pack(); task=build_qualification_task(pack); value=qualification_result(task,"configured","qualified")
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
    _emit_closeout_artifact("stale-pointer-proof.json",{"snapshots":[before.hex(),pointer.read_bytes().hex()],"stale_error_code":"stale_measurement_ai_generation_compiler_version"})


def test_canonical_artifacts_ignore_preparation_handles_and_local_labels(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); app=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); app["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(app),encoding="utf-8")
    artifacts=[]
    submissions=(("human_local",{"executor_type":"human","reviewer_label":"human"}),("hermes_local",{"executor_type":"agent_harness","participant_binding":None,"harness_id":"hermes","adapter_version":"1","run_id":"h"}),("codex_local",{"executor_type":"agent_harness","participant_binding":None,"harness_id":"codex","adapter_version":"1","run_id":"c"}),("renamed_local_id",{"executor_type":"human","reviewer_label":"renamed"}))
    bundles=[]
    for label,executor in submissions:
        info=prepare(ctx,applicability_path=str(path)); record=assessed_record(cid); record["local_id"]=label; place_result(ctx,info["preparation_id"],"measurement",record,executor); manifest=compile_generation(ctx,info["preparation_id"]); _,current=load_generation(ctx); artifacts.append({name:value for name,value in current.items() if name!="measurement-ai-compiler-receipts.json"}); bundles.append(manifest["semantic_bundle_hash"])
    assert all(value==artifacts[0] for value in artifacts[1:]) and len(set(bundles))==1
    _emit_closeout_artifact("harness-neutral-proof.json",{"runs":[{"semantic_bundle_hash":bundle,"principal_artifacts_hash":content_hash({k:v for k,v in artifact.items() if k!="measurement-ai-overlay.json"}),"overlay_hash":content_hash(artifact["measurement-ai-overlay.json"])} for bundle,artifact in zip(bundles,artifacts)]})


def test_domain_core_records_zero_external_operations(tmp_path,monkeypatch):
    import shiproom.authority as authority_module
    monkeypatch.setattr(authority_module,"run_bounded_command",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("project command invoked")))
    monkeypatch.setattr(socket,"create_connection",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("network invoked")))
    monkeypatch.setattr(urllib.request,"urlopen",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("HTTP invoked")))
    ctx=conventional_context(tmp_path); before=snapshot_measurement_ai_read_only(ctx); task=prepare_qualification(ctx.repository_root); result=qualification_result(task,"guarded","guarded"); result_path=qualification_store(ctx.repository_root)/"qualification-result.json"; result_path.write_text(json.dumps(result),encoding="utf-8"); compile_qualification(ctx.repository_root,result_path); info=prepare(ctx); compile_generation(ctx,info["preparation_id"]); _,artifacts=load_generation(ctx); show(ctx); assert_measurement_ai_read_only(ctx,before)
    operations=[item for item in artifacts["measurement-ai-compiler-receipts.json"]["validations"] if item["kind"]=="external_operation"]
    assert {item["operation"] for item in operations}=={"model","command","network","browser","sql","external_service"} and all(item["count"]==0 for item in operations)
    _emit_closeout_artifact("measurement-ai-compiler-receipts.json",artifacts["measurement-ai-compiler-receipts.json"])


def test_shiproom_skill_documents_v3_authority_and_staged_verifier():
    skill=(resources.files("shiproom").joinpath("..","skills","shiproom","SKILL.md")).read_text(encoding="utf-8")
    for value in ("shiproom.work-order.v6","shiproom.measurement-ai-role.v3","required criterion-path IDs","contract_declaration","immutable v3 verifier preparation","supported`, `downgrade`, `disputed`, or `owner_confirmation_required"):
        assert value in skill


# Claim-specific closeout proofs.  These fixtures are authored from public
# contracts and never import or derive responses from the private rubric.
def test_blind_qualification_claim_specific_proofs():
    pack=load_guidance_pack(); task=build_qualification_task(pack); result=qualification_result(task)
    receipt=grade_qualification_result(result,task,"sha256:"+"1"*64,pack["qualification_private_rubric"],pack)
    assert task["cases"] and all(item["case_id"].startswith("qual_case_") for item in task["cases"])
    assert receipt["passed_capabilities"] and set(receipt["passed_capabilities"])==set(receipt["qualified_capabilities"])
    partial=deepcopy(result);partial["case_results"][1]["automatic_replacements"]=["automatic_ratio_replacement"];partial_receipt=grade_qualification_result(partial,task,"sha256:"+"2"*64,pack["qualification_private_rubric"],pack);assert partial_receipt["passed_capabilities"] and partial_receipt["failed_capabilities"]
    _emit_closeout_artifact("qualification-task.json",task);_emit_closeout_artifact("qualification-receipt.json",partial_receipt)


def test_blind_qualification_adversarial_answers_and_rubric_tamper(tmp_path):
    pack=load_guidance_pack(); task=build_qualification_task(pack); result=qualification_result(task)
    categorical=deepcopy(result); categorical["case_results"][1]["automatic_replacements"]=["automatic_ratio_replacement"]
    receipt=grade_qualification_result(categorical,task,"sha256:"+"2"*64,pack["qualification_private_rubric"],pack)
    assert "absolute_count_opportunity_review" in receipt["failed_capabilities"]
    copied=deepcopy(result); copied["case_results"][0]={**copied["case_results"][0],"semantic_assessment":task["cases"][0]["scenario"]}
    copied_receipt=grade_qualification_result(copied,task,"sha256:"+"3"*64,pack["qualification_private_rubric"],pack)
    assert copied_receipt["failed_capabilities"]
    result_path=qualification_store(tmp_path)/"submitted.json"; result_path.parent.mkdir(parents=True); result_path.write_text(json.dumps(result),encoding="utf-8")
    compiled=compile_qualification(tmp_path,result_path); altered=deepcopy(pack); altered["qualification_private_rubric"]["cases"][0]["maximum_effect"]="blocker_candidate"
    with pytest.raises(ValueError,match="regrading"):
        load_qualification_bundle(qualification_store(tmp_path)/compiled["qualification_id"],altered)


def test_qualification_regrading_rejects_task_result_receipt_and_rubric_tamper(tmp_path):
    pack=load_guidance_pack(); task=build_qualification_task(pack); result=qualification_result(task); submitted=qualification_store(tmp_path)/"submitted.json"; submitted.parent.mkdir(parents=True); submitted.write_text(json.dumps(result),encoding="utf-8"); compiled=compile_qualification(tmp_path,submitted); bundle=qualification_store(tmp_path)/compiled["qualification_id"]
    for filename in ("qualification-task.json","qualification-result.json","qualification-receipt.json"):
        clone=tmp_path/("copy_"+filename); clone.mkdir();
        for source in bundle.iterdir(): (clone/source.name).write_bytes(source.read_bytes())
        value=json.loads((clone/filename).read_text()); value["tampered"]=True; (clone/filename).write_text(json.dumps(value),encoding="utf-8")
        with pytest.raises((ValueError,KeyError)): load_qualification_bundle(clone,pack)
    altered=deepcopy(pack); altered["qualification_private_rubric"]["grading_engine_version"]="forged"
    with pytest.raises(ValueError): load_qualification_bundle(bundle,altered)


def _model_work():
    model={"type":"model","candidate_id":"candidate","provider_id":"provider","model_id":"model","qualification_id":"qualification","qualification_bundle_hash":"sha256:"+"1"*64,"qualified_capabilities":["metric_decision_alignment"],"model_switch":False}
    return {"resolved_review_mode":"guided_review","review_participants":[model],"required_qualification_capabilities":["metric_decision_alignment"]},model


def test_executor_truth_table_complete():
    validate_executor({"executor_type":"human","reviewer_label":"reviewer"},{"resolved_review_mode":"guided_review","review_participants":[{"type":"human"}],"required_qualification_capabilities":[]})
    work,model=_model_work(); validate_executor({"executor_type":"agent_harness","participant_binding":{k:model[k] for k in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")},"harness_id":"h","adapter_version":"1","run_id":"r"},work)
    for executor in ({"executor_type":"human","reviewer_label":"manual"},{"executor_type":"agent_harness","participant_binding":None,"harness_id":"h","adapter_version":"1","run_id":"r"}): validate_executor(executor,{"resolved_review_mode":"contract_only","review_participants":[],"required_qualification_capabilities":[]})
    validate_executor({"executor_type":"human","reviewer_label":"expert"},{"resolved_review_mode":"expert_escalated_review","review_participants":[{"type":"human"}],"required_qualification_capabilities":[]})
    expert,participant=_model_work();expert["resolved_review_mode"]="expert_escalated_review";validate_executor({"executor_type":"agent_harness","participant_binding":{k:participant[k] for k in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")},"harness_id":"h","adapter_version":"1","run_id":"r"},expert)
    _emit_closeout_artifact("work-order.json",{**expert,"review_participants":[participant]})

def test_verifier_executor_truth_table_and_isolated_rejections():
    human_work={"resolved_review_mode":"expert_escalated_review","review_participants":[{"type":"human"}],"required_qualification_capabilities":["skeptical_material_review"]};validate_executor({"executor_type":"human","reviewer_label":"verifier"},human_work)
    participant={"type":"model","candidate_id":"candidate","provider_id":"provider","model_id":"model","qualification_id":"qualification","qualification_bundle_hash":"sha256:"+"1"*64,"qualified_capabilities":["skeptical_material_review"],"model_switch":True};model_work={"resolved_review_mode":"expert_escalated_review","review_participants":[participant],"required_qualification_capabilities":["skeptical_material_review"]};base={"executor_type":"agent_harness","participant_binding":{k:participant[k] for k in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")},"harness_id":"h","adapter_version":"1","run_id":"r"};validate_executor(base,model_work)
    with pytest.raises(ValueError,match="human participant"):validate_executor(base,human_work)
    with pytest.raises(ValueError,match="human cannot"):validate_executor({"executor_type":"human","reviewer_label":"person"},model_work)
    for key in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash"):
        bad=deepcopy(base);bad["participant_binding"][key]="sha256:"+"2"*64 if "hash" in key else "wrong"
        with pytest.raises(ValueError,match="binding mismatch"):validate_executor(bad,model_work)
    with pytest.raises(ValueError,match="participant work|binding mismatch"):validate_executor({**base,"participant_binding":None},model_work)
    lacking=deepcopy(model_work);lacking["review_participants"][0]["qualified_capabilities"]=[]
    with pytest.raises(ValueError,match="binding mismatch"):validate_executor(base,lacking)


def test_executor_binding_adversarial_matrix():
    work,model=_model_work(); base={"executor_type":"agent_harness","participant_binding":{k:model[k] for k in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")},"harness_id":"h","adapter_version":"1","run_id":"r"}
    with pytest.raises(ValueError):validate_executor({"executor_type":"human","reviewer_label":"human"},work)
    for key in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash"):
        bad=deepcopy(base);bad["participant_binding"][key]="sha256:"+"2"*64 if key=="qualification_bundle_hash" else "wrong"
        with pytest.raises(ValueError):validate_executor(bad,work)
    with pytest.raises(ValueError):validate_executor({**base,"participant_binding":None},work)


def _real_binding(ctx,cid,journey,subtype="instrumentation_event_definition",property_name=None):
    record=source_record(ctx,"docs/brief.md",mandatory=True,rules=["owner_exact_path"],reason="test",provenance="test"); quote=record["text"].splitlines()[0]
    return {"path":record["path"],"returned_git_path":record["returned_git_path"],"git_object_format":record["git_object_format"],"git_blob_hash":record["git_blob_hash"],"normalized_text_hash":record["normalized_text_hash"],"start_line":1,"end_line":1,"quote":quote,"quote_hash":sha256_bytes(quote.encode()),"declared_subtype":subtype,"criterion_ids":[cid],"journey_ids":[journey]}


def _typed_app(ctx):
    graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"];cid=next(n["node_id"] for n in graph["nodes"] if n["node_type"]=="acceptance_criterion");journey=next(n["node_id"] for n in graph["nodes"] if n["node_type"]=="critical_journey");app=default_applicability();app["measurement"]["criterion_ids"]=[cid];event=_real_binding(ctx,cid,journey);prop=_real_binding(ctx,cid,journey,"instrumentation_property_definition");app["measurement"]["contracts"]=[{"local_id":"metric","journey_id":journey,"criterion_ids":[cid],"fields":{},"metric_roles":["outcome"],"required_signals":[{"name":"completed","required_properties":["id"],"event_sources":[event],"property_sources":[{"property_name":"id","sources":[prop]}]}]}];return app,event,prop,cid,journey


def test_typed_source_identity_contract_accepts_real_sha1_binding(tmp_path):
    ctx=assessment_context(tmp_path);app,event,prop,_,_=_typed_app(ctx);assert validate_applicability(app);assert event["git_object_format"]=="sha1" and len(event["git_blob_hash"])==40 and event["normalized_text_hash"].startswith("sha256:");_emit_closeout_artifact("source-identity-proof.json",{"pairs":[{"source_packet":event,"overlay":event}]})


def test_typed_source_identity_contract_rejects_hash_mutations(tmp_path):
    ctx=assessment_context(tmp_path);app,_,_,_,_=_typed_app(ctx)
    for key,value in (("git_object_format","sha256"),("git_blob_hash","0"*64),("normalized_text_hash","sha256:"+"0"*64),("quote_hash","sha256:"+"0"*64)):
        bad=deepcopy(app);bad["measurement"]["contracts"][0]["required_signals"][0]["event_sources"][0][key]=value
        if key in {"normalized_text_hash","quote_hash"}:
            # Input syntax accepts a well-formed digest; preparation must
            # recompute and reject the semantic mismatch.
            root=domain_root(ctx)/"inputs";root.mkdir(parents=True,exist_ok=True);path=root/(key+".json");path.write_text(json.dumps(bad),encoding="utf-8")
            with pytest.raises(ValueError,match="identity mismatch|quote binding mismatch"):prepare(ctx,applicability_path=str(path))
        else:
            with pytest.raises(ValueError):validate_applicability(bad)


def test_typed_basis_compatibility_positive_matrix():
    context={"basis_registry":[{"basis_id":"event","signal_id":"signal","property_name":None},{"basis_id":"property","signal_id":"signal","property_name":"id"}]}
    _assert_signal_basis({"basis_ids":["event"]},context,"signal");_assert_signal_basis({"basis_ids":["property"]},context,"signal","id")
    authority={"criterion_scoped_basis_authority":"source_verified"};_emit_closeout_artifact("instrumentation-coverage.json",{"event_candidates":[{"basis_ids":["event"],"compiled_authority":authority}],"property_assessments":[{"basis_ids":["property"],"compiled_authority":authority}]})


def test_typed_basis_compatibility_rejects_generic_cross_signal_and_candidate():
    context={"basis_registry":[{"basis_id":"generic","basis_type":"source_reference","signal_id":None,"property_name":None},{"basis_id":"wrong","basis_type":"instrumentation_property_definition","signal_id":"other","property_name":"id"}]}
    with pytest.raises(ValueError):_assert_signal_basis({"basis_ids":["generic"]},context,"signal")
    with pytest.raises(ValueError):_assert_signal_basis({"basis_ids":["wrong"]},context,"signal","id")

@pytest.mark.parametrize(("kind","basis_type"),[("event_candidate","instrumentation_event_definition"),("property","instrumentation_property_definition"),("fixed_input","ai_fixed_input_definition"),("oracle_or_rubric","ai_oracle_or_rubric_definition"),("pass_condition","ai_pass_condition_definition"),("prompt_or_model_binding","ai_prompt_model_binding_definition"),("supplied_execution_result","ai_execution"),("production_trace_linkage","production_trace")])
def test_candidate_tainted_typed_basis_cannot_establish_state_or_readiness(kind,basis_type):
    role="measurement" if kind in {"event_candidate","property"} else "ai_evaluation";context={"basis_registry":[{"basis_id":"basis","basis_type":basis_type,"role_ids":[role],"criterion_ids":["criterion"],"direct_fact_authority":"source_verified","signal_id":"signal","property_name":"id" if kind=="property" else None}],"basis_paths":[{"path_id":"path","role_ids":[role],"criterion_id":"criterion","start_basis_id":"basis","required":True,"effective_authority":"model_mapped_candidate"}]};record={"criterion_id":"criterion","semantic_review_authority":"model_reviewed_with_curated_guidance"};item={"state":"established","basis_ids":["basis"],"basis_path_ids":["path"]}
    with pytest.raises(ValueError,match="weak criterion authority"):_typed_authority(item,record,context,role,kind)


def _claim_context(basis_type,scope="source_definition",origin="project_source"):
    return {"basis_registry":[{"basis_id":"b","basis_type":basis_type,"assertion_scope":scope,"origin":origin}]}


def test_ai_claim_scope_honesty_positive_configuration():
    claim={"claim_type":"configuration","presented_as_proof":True,"basis_ids":["b"]};authority={"criterion_scoped_basis_authority":"source_verified"};assert _claim_honesty(claim,authority,_claim_context("ai_prompt_model_binding_definition"))==("honest",[])


def test_ai_claim_scope_honesty_rejects_behavioral_proof_substitution():
    authority={"criterion_scoped_basis_authority":"source_verified"}
    for kind,basis in (("offline_behavior","source_reference"),("runtime_behavior","ai_execution"),("product_outcome","ai_execution")):
        state,reasons=_claim_honesty({"claim_type":kind,"presented_as_proof":True,"basis_ids":["b"]},authority,_claim_context(basis));assert state=="unsupported_proof" and reasons


def _derivation(cid,status):
    return {"criterion_id":cid,"status":status,"reason_codes":[status],"semantic_review_authority":"not_performed","criterion_scoped_basis_authority":"source_verified" if status=="ready" else "not_inspected","direct_fact_authorities":["source_verified"],"criterion_path_authorities":["source_verified"],"reviewer_conclusion_authority":"not_inspected","readiness_scope":["contract_definition"]}


def test_multi_record_aggregation_is_conservative():
    value=_aggregate("DATA_OUTCOME_EVENT_DEFINED",[_derivation("c1","ready"),_derivation("c2","owner_confirmation_required"),_derivation("c3","not_inspected")]);assert value["status"]=="owner_confirmation_required" and len(value["record_derivations"])==3;_emit_closeout_artifact("measurement-ai-readiness.json",{"ai_evaluation":[{"claims":[{"honesty_state":"honest","honesty_reason_codes":["compatible_configuration_basis"]}]}],"checks":[value]})


def test_aggregate_ready_rejects_lower_precedence_records():
    for lower in ("gap","owner_confirmation_required","not_inspected"):
        assert _aggregate("DATA_OUTCOME_EVENT_DEFINED",[_derivation("c1","ready"),_derivation("c2",lower)])["status"]==lower


def test_projection_rejects_orphan_authority_scope_duplicate_and_target_tamper():
    base={"schema_version":"measurement-ai-overlay.v3","release_id":"r","release_commit":"a"*40,"product_intent_semantic_hash":"sha256:"+"1"*64,"graph_semantic_hash":"sha256:"+"2"*64,"nodes":[{"node_id":"p","node_type":"projection_reference","provenance":"measurement_ai_compiler","criterion_ids":[],"journey_id":None,"record_kind":"gap","canonical_record_id":"g","destination_artifact":"launch-measurement-plan.json","target_record_id":"other","authority":"not_inspected"}],"edges":[],"projection_verification":[]}
    with pytest.raises(ValueError):validate_overlay(base,{"criterion"})

def _valid_projection_overlay():
    node={"node_id":"projection","node_type":"projection_reference","provenance":"measurement_ai_compiler","criterion_ids":["criterion"],"journey_id":None,"record_kind":"gap","canonical_record_id":"record","destination_artifact":"launch-measurement-plan.json","target_record_id":"record","authority":"source_verified"}
    edge={"edge_id":"projection_edge","source_node_id":"projection","target_node_id":"criterion","relationship":"projects_record_for_criterion","direct_fact_authority":"source_verified","criterion_id":"criterion","criterion_path":[{"edge_id":"projection_edge","traversal":"forward"}],"criterion_basis_authority":"source_verified","origin":"projection_registry","reference_ids":["record","launch-measurement-plan.json"]}
    verification={"record_id":"record","record_kind":"gap","criterion_id":"criterion","journey_id":None,"authority":"source_verified","destination":"launch-measurement-plan.json","target_record_id":"record"}
    return {"schema_version":"measurement-ai-overlay.v3","release_id":"r","release_commit":"a"*40,"product_intent_semantic_hash":"sha256:"+"1"*64,"graph_semantic_hash":"sha256:"+"2"*64,"nodes":[node],"edges":[edge],"projection_verification":[verification]}

@pytest.mark.parametrize(("case","message"),[("empty_scope","scoped"),("unknown_criterion","dangling"),("wrong_criterion","criterion mismatch"),("duplicate","duplicate"),("wrong_authority","authority mismatch"),("missing_destination","destination"),("wrong_destination","destination"),("record_target_mismatch","record and target"),("missing_edge","typed edge"),("edge_wrong_criterion","criterion mismatch")])
def test_projection_invariants_fail_in_isolation(case,message):
    value=_valid_projection_overlay();base={"criterion"}
    if case=="empty_scope":value["nodes"][0]["criterion_ids"]=[]
    elif case=="unknown_criterion":value["nodes"][0]["criterion_ids"]=["unknown"];value["edges"][0]["target_node_id"]=value["edges"][0]["criterion_id"]="unknown";value["projection_verification"][0]["criterion_id"]="unknown"
    elif case in {"wrong_criterion","edge_wrong_criterion"}:base.add("other");value["edges"][0]["target_node_id"]=value["edges"][0]["criterion_id"]="other";value["edges"][0]["criterion_path"][0]["edge_id"]="projection_edge"
    elif case=="duplicate":other=deepcopy(value["nodes"][0]);other["node_id"]="projection_2";value["nodes"].append(other)
    elif case=="wrong_authority":value["nodes"][0]["authority"]="not_inspected"
    elif case=="missing_destination":value["nodes"][0]["destination_artifact"]=""
    elif case=="wrong_destination":value["nodes"][0]["destination_artifact"]="unknown.json"
    elif case=="record_target_mismatch":value["nodes"][0]["target_record_id"]="other"
    elif case=="missing_edge":value["edges"]=[]
    with pytest.raises(ValueError,match=message):validate_overlay(value,base)

def test_projection_verifier_rejects_absent_destination_and_altered_value():
    authority={"criterion_scoped_basis_authority":"source_verified"};gap={"local_id":"g","gap_id":"gap","gap_kind":"critical_property_gap","aspect_code":"property","summary":"missing","basis_ids":["b"],"basis_path_ids":["p"],"compiled_authority":authority,"permitted_check_id":"DATA_CRITICAL_EVENT_PROPERTIES_PRESENT","confirmed_contradiction":True,"readiness_effect":"gap","derived_effect":"none"};results={"measurement":{"normalized":{"records":[{"criterion_id":"criterion","journey_ids":[],"compiled_authority":authority,"gaps":[gap]}],"recommendations":[]}}}
    artifacts={"measurement-contract.json":{"contracts":[]},"instrumentation-coverage.json":{"event_candidates":[],"property_assessments":[],"test_candidates":[],"runtime_bindings":[]},"measurement-ai-readiness.json":{"metric_quality":[],"ai_evaluation":[]},"launch-measurement-plan.json":{"gaps":[],"warnings":[],"owner_confirmation_proposals":[]},"measurement-ai-overlay.json":{"nodes":[]}}
    with pytest.raises(ValueError,match="missing canonical projection"):verify_projected_records(results,artifacts)
    artifacts["launch-measurement-plan.json"]["gaps"]=[semantic_without_local_ids(gap)];artifacts["launch-measurement-plan.json"]["gaps"][0]["summary"]="altered"
    with pytest.raises(ValueError,match="altered canonical projection"):verify_projected_records(results,artifacts)

def test_projection_positive_covers_every_required_substantive_record_kind():
    kinds=("contract_proposal","property_assertion","metric_dimension","ai_maturity_rung","ai_claim_assessment","llm_judge_assessment","recommendation","exception_analysis","verifier_disposition","owner_confirmation_proposal")
    value=_valid_projection_overlay();value["nodes"]=[];value["edges"]=[];value["projection_verification"]=[]
    for index,kind in enumerate(kinds):
        rid=f"record_{index}";nid=f"projection_{index}";eid=f"projection_edge_{index}";destination="measurement-ai-readiness.json" if kind in {"metric_dimension","ai_maturity_rung","ai_claim_assessment","llm_judge_assessment","verifier_disposition"} else "measurement-contract.json" if kind=="contract_proposal" else "launch-measurement-plan.json"
        value["nodes"].append({"node_id":nid,"node_type":"projection_reference","provenance":"measurement_ai_compiler","criterion_ids":["criterion"],"journey_id":"journey" if kind in {"contract_proposal","owner_confirmation_proposal"} else None,"record_kind":kind,"canonical_record_id":rid,"destination_artifact":destination,"target_record_id":rid,"authority":"source_verified"})
        value["edges"].append({"edge_id":eid,"source_node_id":nid,"target_node_id":"criterion","relationship":"projects_record_for_criterion","direct_fact_authority":"source_verified","criterion_id":"criterion","criterion_path":[{"edge_id":eid,"traversal":"forward"}],"criterion_basis_authority":"source_verified","origin":"projection_registry","reference_ids":[rid,destination]})
        value["projection_verification"].append({"record_id":rid,"record_kind":kind,"criterion_id":"criterion","journey_id":"journey" if kind in {"contract_proposal","owner_confirmation_proposal"} else None,"authority":"source_verified","destination":destination,"target_record_id":rid})
    assert validate_overlay(value,{"criterion"})==value

def test_typed_basis_cannot_cross_measurement_and_ai_roles():
    measurement={"basis_registry":[{"basis_id":"ai","basis_type":"ai_fixed_input_definition","role_ids":["ai_evaluation"],"criterion_ids":["criterion"],"direct_fact_authority":"source_verified"}],"basis_paths":[]};record={"criterion_id":"criterion","semantic_review_authority":"model_reviewed_with_curated_guidance"};item={"state":"established","basis_ids":["ai"],"basis_path_ids":[]}
    with pytest.raises(ValueError,match="unavailable prepared basis"):_typed_authority(item,record,measurement,"measurement","event_candidate")
    ai={"basis_registry":[{"basis_id":"event","basis_type":"instrumentation_event_definition","role_ids":["measurement"],"criterion_ids":["criterion"],"direct_fact_authority":"source_verified"}],"basis_paths":[]};item["basis_ids"]=["event"]
    with pytest.raises(ValueError,match="unavailable prepared basis"):_typed_authority(item,record,ai,"ai_evaluation","fixed_input")


def test_declared_external_definition_is_not_source_content_proof(tmp_path):
    ctx=assessment_context(tmp_path);inputs=load_assessment_input(ctx);cid=next(i["criterion_id"] for i in inputs["intent_artifacts"]["acceptance-criteria.json"]["criteria"]);root=domain_root(ctx)/"inputs";root.mkdir(parents=True);app=default_applicability();app["measurement"]["criterion_ids"]=[cid];app["measurement"]["measurement_definition_paths"]=[{"path":"external/metric-contract.md","requirement_ids":[],"criterion_ids":[cid],"journey_ids":[],"declared_external":True}];path=root/"external.json";path.write_text(json.dumps(app),encoding="utf-8");info=prepare(ctx,applicability_path=str(path));place_result(ctx,info["preparation_id"],"measurement",assessed_record(cid));compile_generation(ctx,info["preparation_id"]);_,artifacts=load_generation(ctx);definition=artifacts["measurement-contract.json"]["downstream_definitions"][0]
    assert definition["declaration_authority"]=="deterministically_established" and definition["definition_content_authority"]=="not_inspected" and definition["definition_assertion_scope"]=="external_definition_declaration" and definition["execution_state"]==definition["data_accuracy_state"]=="not_inspected"


def test_external_execution_and_out_of_root_writes_are_forbidden(tmp_path,monkeypatch):
    import shiproom.authority as authority_module
    monkeypatch.setattr(authority_module,"run_bounded_command",lambda *a,**k:(_ for _ in ()).throw(AssertionError("command forbidden")));monkeypatch.setattr(socket,"create_connection",lambda *a,**k:(_ for _ in ()).throw(AssertionError("network forbidden")));monkeypatch.setattr(urllib.request,"urlopen",lambda *a,**k:(_ for _ in ()).throw(AssertionError("HTTP forbidden")))
    ctx=conventional_context(tmp_path);info=prepare(ctx);compile_generation(ctx,info["preparation_id"]);load_generation(ctx);show(ctx)

def test_each_prohibited_external_operation_is_attempted_rejected_and_side_effect_free():
    for operation in ("model_execution","project_command","network_socket","http_or_browser","sql_execution","warehouse_or_bi_client","tracing_or_external_service","external_evaluation_execution"):
        receipt=[]
        with pytest.raises(PermissionError,match=operation):reject_external_operation(operation,receipt)
        assert receipt==[{"operation":operation,"attempted":True,"rejected":True,"external_side_effect":False,"reason_code":"measurement_ai_external_operation_forbidden"}]


def test_recomputed_superficial_hash_tamper_preserves_pointer(tmp_path):
    ctx=conventional_context(tmp_path);info=prepare(ctx);compile_generation(ctx,info["preparation_id"]);pointer=domain_root(ctx)/"current-generation.json";before=pointer.read_bytes();generation=domain_root(ctx)/"generations"/json.loads(before)["generation"];artifact=generation/"measurement-ai-readiness.json";value=json.loads(artifact.read_text());value["checks"][0]["status"]="ready";artifact.write_text(json.dumps(value),encoding="utf-8")
    with pytest.raises(ValueError):load_generation(ctx)
    assert pointer.read_bytes()==before
    _emit_closeout_artifact("stale-pointer-proof.json",{"snapshots":[before.hex(),pointer.read_bytes().hex()],"stale_error_code":"semantic_generation_tamper"})
