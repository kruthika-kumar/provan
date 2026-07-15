from __future__ import annotations

import json
from importlib import resources

import pytest

from shiproom.measurement_ai.contracts import effective_basis_class
from shiproom.measurement_ai.guidance import load_guidance_pack, rule_map
from shiproom.measurement_ai.overlay import evaluate_basis_path, validate_overlay
from shiproom.measurement_ai.authority import default_applicability, domain_root
from shiproom.measurement_ai.preparation import prepare, load_preparation
from shiproom.measurement_ai.persistence import compile_generation, load_generation
from shiproom.measurement_ai.rendering import show
from shiproom.measurement_ai.contracts import sha256_bytes
from shiproom.measurement_ai.qualification import grade_qualification_result
from shiproom.measurement_ai.results import normalize_result
import shiproom.measurement_ai.persistence as measurement_persistence
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
    assert effective_basis_class(["source_verified", "model_reviewed"]) == "model_reviewed"


def test_overlay_path_walks_and_candidate_taints_only_basis():
    edges = {
        "edge_a": {"source_node_id":"conclusion_1","target_node_id":"runtime_1","basis_evidence_class":"model_mapped_candidate"},
        "edge_b": {"source_node_id":"runtime_1","target_node_id":"criterion_1","basis_evidence_class":"deterministically_established"},
    }
    steps = [{"edge_id":"edge_a","traversal":"forward"},{"edge_id":"edge_b","traversal":"forward"}]
    assert evaluate_basis_path(steps, edges, "conclusion_1", "criterion_1") == "model_mapped_candidate"
    with pytest.raises(ValueError, match="disconnected"):
        evaluate_basis_path(list(reversed(steps)), edges, "conclusion_1", "criterion_1")


def test_overlay_exact_schema_and_reference_validation():
    value = {
        "schema_version":"measurement-ai-overlay.v1","release_id":"rel","release_commit":"a"*40,
        "product_intent_semantic_hash":"sha256:"+"1"*64,"graph_semantic_hash":"sha256:"+"2"*64,
        "nodes":[{"node_id":"contract_1","node_type":"measurement_contract","provenance":"measurement_ai_compiler","detail":{}}],
        "edges":[{"edge_id":"edge_1","source_node_id":"contract_1","target_node_id":"criterion_1","relationship":"governs_criterion","basis_evidence_class":"source_verified","origin":"prepared","references":[]}],
    }
    assert validate_overlay(value,{"criterion_1"}) == value
    value["nodes"][0]["extra"] = True
    with pytest.raises(ValueError): validate_overlay(value,{"criterion_1"})


def test_foundation_json_schemas_parse():
    for name in ("measurement-ai-role.v1.json", "work-order.v4.json", "measurement-ai-overlay.v1.json"):
        assert isinstance(json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text()), dict)


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


def test_preparation_semantic_tamper_and_unlinked_definition_do_not_create_scope(tmp_path):
    ctx=conventional_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True)
    value=default_applicability(); value["measurement"]["measurement_definition_paths"]=[{"path":"docs/brief.md","requirement_ids":[],"criterion_ids":[],"journey_ids":[],"declared_external":False}]
    path=root/"applicability.json"; path.write_text(json.dumps(value),encoding="utf-8")
    result=prepare(ctx,applicability_path=str(path)); assert result["work_orders"] == []
    prep=domain_root(ctx)/"preparations"/result["preparation_id"]; packet=json.loads((prep/"measurement-ai-source-packet.json").read_text()); packet["coverage_boundary"]="widened"; (prep/"measurement-ai-source-packet.json").write_text(json.dumps(packet,indent=2)+"\n")
    with pytest.raises(ValueError,match="semantic rederivation"):
        load_preparation(ctx,result["preparation_id"])


def place_result(ctx, preparation_id, role, record):
    prep=load_preparation(ctx,preparation_id); work=prep["work_orders"][role]; root=domain_root(ctx)/"inbox"/preparation_id/work["work_order_id"]
    value={"schema_version":"measurement-result.v1" if role=="measurement" else "ai-evaluation-result.v1","role_id":role,"role_version":"1.0.0","preparation_id":preparation_id,"work_order_id":work["work_order_id"],"base_graph_semantic_hash":work["inputs"]["graph_semantic_hash"],"resolved_review_mode":work["resolved_review_mode"],"records":[record],"warnings":[],"proposals":[],"assumptions":[],"limitations":[]}
    raw=(json.dumps(value,sort_keys=True)+"\n").encode(); (root/"result.json").write_bytes(raw)
    receipt={"schema_version":"shiproom.assessment-completion-receipt.v2","executor":{"executor_type":"human","reviewer_label":"manual reviewer"},"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":sha256_bytes(raw),"started_at":"2026-01-01T00:00:00+00:00","completed_at":"2026-01-01T00:01:00+00:00"}
    (root/"completion-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")


def assessed_record(cid):
    return {"local_id":"record_1","criterion_id":cid,"disposition":"assessed","uncertainty":"bounded","direct_bases":[{"reference_type":"criterion","reference_id":cid,"classification":"source_verified"}],"criterion_basis_paths":[],"conclusion_evidence_class":"model_reviewed","semantic_review_authority":"model_reviewed","summary":"Bounded review.","gaps":[],"contract_updates":{},"signal_assessments":[],"metric_dimensions":[],"ai_maturity":{},"claims":[]}


def test_skip_generation_has_all_six_not_applicable_checks(tmp_path):
    ctx=conventional_context(tmp_path); prep=prepare(ctx); manifest=compile_generation(ctx,prep["preparation_id"]); assert manifest["compiler_version"]=="portable-measurement-ai.v1"
    _,artifacts=load_generation(ctx); readiness=artifacts["measurement-ai-readiness.json"]
    assert len(readiness["checks"])==6 and {item["status"] for item in readiness["checks"]}=={"not_applicable"}
    assert readiness["accepted_role_validations"]==[] and "no_applicable_measurement_or_ai_surface" in show(ctx)


def test_measurement_result_compiles_without_upgrading_prepared_authority(tmp_path):
    ctx=assessment_context(tmp_path); root=domain_root(ctx)/"inputs"; root.mkdir(parents=True); value=default_applicability(); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]; cid=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="acceptance_criterion"); value["measurement"]["criterion_ids"]=[cid]; path=root/"applicability.json"; path.write_text(json.dumps(value),encoding="utf-8")
    prep=prepare(ctx,applicability_path=str(path)); place_result(ctx,prep["preparation_id"],"measurement",assessed_record(cid)); compile_generation(ctx,prep["preparation_id"]); _,artifacts=load_generation(ctx)
    checks={item["check_id"]:item for item in artifacts["measurement-ai-readiness.json"]["checks"]}
    assert checks["DATA_OUTCOME_EVENT_DEFINED"]["status"]=="owner_confirmation_required"
    assert checks["DATA_OUTCOME_EVENT_DEFINED"]["check_authority"]=="compiler_derived_from_model_reviewed_assessment"


def test_qualification_is_mechanically_graded_and_hash_bound():
    pack=load_guidance_pack(); cases=[]
    for case in pack["qualification_suite"]["cases"]:
        expected=case["expected_constraints"]
        cases.append({"case_id":case["case_id"],"semantic_assessment":expected["allowed_semantic_assessments"][0],"recommendation_classes":expected["required_recommendation_classes"],"guidance_rule_ids":expected["required_guidance_rules"],"exceptions_considered":expected["required_exceptions"],"effect":expected["maximum_effect"],"abstained":expected["abstention_required"],"claims":[],"authority_labels":expected["required_authority_labels"]})
    value={"schema_version":"measurement-reviewer-qualification-result.v1","provider_id":"configured","model_id":"qualified","role_prompt_version":"1","guidance_pack_hash":pack["pack_hash"],"recommendation_policy_hash":pack["snapshots"]["recommendation-policy.v1.json"]["semantic_hash"],"result_schema_version":"measurement-result.v1","qualification_suite_version":pack["qualification_suite"]["suite_version"],"qualification_suite_hash":pack["snapshots"]["qualification-suite.v1.json"]["semantic_hash"],"case_results":cases}
    receipt=grade_qualification_result(value,pack); assert "ratio_denominator_review" in receipt["qualified_capabilities"]
    value["guidance_pack_hash"]="sha256:"+"0"*64
    with pytest.raises(ValueError,match="binding mismatch"): grade_qualification_result(value,pack)


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
