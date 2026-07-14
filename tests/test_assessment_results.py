from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import shiproom.assessment as assessment_module
from shiproom.assessment import CORE_ROLES, compile_assessment, compile_core_results, load_assessment, load_preparation, prepare as prepare_assessment, show_assessment
from test_assessment import assessment_context, write_json


def common(local_id: str, id_field: str, record: dict, disposition: str = "assessed") -> dict:
    return {"local_id": local_id, id_field: record[id_field], "disposition": disposition, "scope_status": record["scope_status"], "evidence_class": "model_reviewed" if disposition == "assessed" else "not_inspected", "uncertainty": "bounded" if disposition == "assessed" else "not_assessed", "rationale": "Bounded reviewer conclusion from the prepared packet.", "basis_node_ids": [record[id_field]] if disposition == "assessed" else [], "basis_edge_ids": [], "basis_gap_ids": [], "basis_source_refs": []}


def payload(role: str, context: dict) -> dict:
    if role == "product_assessment":
        requirements = [{**common(f"req_{index}", "requirement_id", item), "intended_user_outcome": "The declared release outcome is preserved.", "partial_or_missing": "No additional deterministic conclusion."} for index, item in enumerate(context["assigned_requirements"])]
        journeys = [{**common(f"journey_{index}", "journey_id", item), "journey_completeness": "Only prepared evidence was assessed.", "declared_vs_evidence_assessed_scope": "Declared scope exceeds observed deterministic evidence."} for index, item in enumerate(context["assigned_journeys"])]
        criteria = [{**common(f"product_criterion_{index}", "criterion_id", item), "implementation_status": "plausibly_present", "honest_success_state": "Success is not independently established.", "honest_failure_state": "Failure remains possible.", "evidence_required_after_launch": ["Bounded runtime observation."]} for index, item in enumerate(context["assigned_criteria"])]
        return {"requirements": requirements, "journeys": journeys, "criteria": criteria, "gaps": [], "decision_candidates": []}
    if role == "engineering_assessment":
        criteria = [{**common(f"engineering_{index}", "criterion_id", item), "probable_component_node_ids": [], "existing_test_node_ids": [], "test_layer": "unit", "assertion_adequacy": "partial", "boundary_adequacy": "inadequate", "overall_adequacy": "partial", "mocks_or_bypasses": [], "negative_cases": [], "recovery_cases": [], "state_transition_cases": [], "runtime_evidence_node_ids": [], "dependency_isolation": "Not inspected.", "rollback_concern": "Not applicable to prepared scope.", "migration_concern": "Not applicable to prepared scope.", "remaining_gap": "Boundary coverage remains.", "required_closure_evidence": ["Boundary-level evidence."]} for index, item in enumerate(context["assigned_criteria"])]
        return {"criteria": criteria, "gaps": []}
    if role == "test_adequacy":
        criteria = [{**common(f"adequacy_{index}", "criterion_id", item), "existing_test_node_ids": [], "test_layer": "unit", "assertion_adequacy": "adequate", "boundary_adequacy": "inadequate", "overall_adequacy": "partial", "negative_cases": [], "recovery_cases": [], "state_transition_cases": [], "mock_boundaries": []} for index, item in enumerate(context["assigned_criteria"])]
        gaps = []
        if context["assigned_criteria"]:
            cid = context["assigned_criteria"][0]["criterion_id"]
            gaps.append({"local_id":"boundary_gap","criterion_id":cid,"gap_kind":"boundary_coverage_gap","aspect_code":"public_route","actionability":"actionable","recommended_release_effect":"recommendation","summary":"Unit coverage does not establish the public boundary.","uncertainty":"bounded","evidence_class":"model_reviewed","basis_node_ids":[cid],"basis_edge_ids":[],"basis_gap_ids":[],"basis_source_refs":[]})
        return {"criteria": criteria, "gaps": gaps}
    criteria = [{**common(f"planning_{index}", "criterion_id", item), "recommendation_summary": "A bounded boundary test is recommended."} for index, item in enumerate(context["assigned_criteria"])]
    specs = []
    if context["assigned_criteria"]:
        cid = context["assigned_criteria"][0]["criterion_id"]
        specs.append({"local_id":"public_route_spec","criterion_id":cid,"risk_addressed":"Public route may not open.","test_layer":"integration","setup":"Persist a public card.","action":"Open the returned URL.","assertions":["The response succeeds.","The public content is present."],"negative_cases":["Unknown card returns a bounded failure."],"recovery_cases":["Retry after transient failure."],"required_fixtures":["Persisted public card."],"external_boundaries":["HTTP boundary."],"recommended_priority":"high","aspect_code":"public_route","addresses_gap_key":f"test_adequacy|{cid}|boundary_coverage_gap|public_route","uncertainty":"bounded","rationale":"Targets the exact boundary gap.","basis_node_ids":[],"basis_edge_ids":[],"basis_gap_ids":[],"basis_source_refs":[]})
    return {"criteria": criteria, "specifications": specs}


def issue_results(ctx, *, harness_role: str | None = None):
    preparation = load_preparation(ctx)
    for role in CORE_ROLES:
        work = preparation["work_orders"][role]; result = {"schema_version": {"product_assessment":"product-assessment-result.v2","engineering_assessment":"engineering-assessment-result.v2","test_adequacy":"test-adequacy-result.v2","targeted_test_planning":"targeted-test-result.v2"}[role], "role_id":role,"role_version":work["role_version"],"preparation_id":work["preparation_id"],"preparation_semantic_hash":work["preparation_semantic_hash"],"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"base_graph_generation":work["inputs"]["base_graph_generation"],"base_graph_semantic_hash":work["inputs"]["base_graph_semantic_hash"],"payload":payload(role, preparation["contexts"][role]),"assumptions":[],"limitations":[]}
        inbox = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/inbox" / work["preparation_id"] / work["work_order_id"]; result_path = inbox / "result.json"; write_json(result_path, result)
        executor = {"executor_type":"agent_harness","harness_id":"portable-harness","adapter_version":"1.0.0","run_id":f"run-{role}","model_id":None} if role == harness_role else {"executor_type":"human","reviewer_label":"Manual reviewer"}
        receipt = {"schema_version":"shiproom.assessment-completion-receipt.v2","executor":executor,"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":"sha256:"+hashlib.sha256(result_path.read_bytes()).hexdigest(),"started_at":"2026-07-14T10:00:00+00:00","completed_at":"2026-07-14T10:05:00+00:00"}; write_json(inbox / "completion-receipt.json", receipt)
    return preparation


def prepared_results(tmp_path: Path):
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); issue_results(ctx); return ctx


def test_core_results_compile_without_publishing_assessment_generation(tmp_path: Path):
    ctx = prepared_results(tmp_path); compiled = compile_core_results(ctx)
    assert set(compiled["artifacts"]) == set(CORE_ROLES)
    assert compiled["artifacts"]["test_adequacy"]["payload"]["criteria"][0]["overall_adequacy"] == "partial"
    root = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment"
    assert not (root / "current-assessment.json").exists() and not (root / "generations").exists()


def test_missing_result_and_completeness_omission_fail(tmp_path: Path):
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); preparation = issue_results(ctx)
    role = "engineering_assessment"; work = preparation["work_orders"][role]; inbox = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/inbox" / work["preparation_id"] / work["work_order_id"]
    (inbox / "completion-receipt.json").unlink()
    with pytest.raises(ValueError, match="missing required"): compile_core_results(ctx)
    issue_results(ctx); result_path = inbox / "result.json"; result = json.loads(result_path.read_text()); result["payload"]["criteria"] = []; write_json(result_path, result)
    receipt = json.loads((inbox / "completion-receipt.json").read_text()); receipt["result_snapshot_hash"] = "sha256:"+hashlib.sha256(result_path.read_bytes()).hexdigest(); write_json(inbox / "completion-receipt.json", receipt)
    with pytest.raises(ValueError, match="incomplete"): compile_core_results(ctx)


def test_model_result_cannot_request_deterministic_or_source_authority(tmp_path: Path):
    ctx = prepared_results(tmp_path); preparation = load_preparation(ctx); work = preparation["work_orders"]["product_assessment"]; path = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/inbox" / work["preparation_id"] / work["work_order_id"] / "result.json"; result = json.loads(path.read_text()); result["payload"]["criteria"][0]["evidence_class"] = "deterministically_established"; write_json(path, result)
    receipt_path = path.parent / "completion-receipt.json"; receipt = json.loads(receipt_path.read_text()); receipt["result_snapshot_hash"] = "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); write_json(receipt_path, receipt)
    with pytest.raises(ValueError, match="evidence_class"): compile_core_results(ctx)


def test_receipt_is_non_self_referential_and_manual_and_harness_variants_work(tmp_path: Path):
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); issue_results(ctx, harness_role="engineering_assessment"); compiled = compile_core_results(ctx)
    assert compiled["completion_receipts"]["product_assessment"]["executor"]["executor_type"] == "human"
    assert compiled["completion_receipts"]["engineering_assessment"]["executor"]["executor_type"] == "agent_harness"
    assert all("result_hash" not in result for result in compiled["submitted_results"].values())


def test_role_inclusive_gap_key_and_exact_targeted_link_key_are_preserved(tmp_path: Path):
    ctx = prepared_results(tmp_path); compiled = compile_core_results(ctx); gap = compiled["artifacts"]["test_adequacy"]["payload"]["gaps"][0]; spec = compiled["artifacts"]["targeted_test_planning"]["payload"]["specifications"][0]
    assert gap["gap_key"].startswith("test_adequacy|") and spec["addresses_gap_key"] == gap["gap_key"]


def test_complete_assessment_generation_preserves_base_authority_dimensions(tmp_path: Path):
    ctx = prepared_results(tmp_path); graph_pointer = (ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/current-generation.json").read_bytes(); release = json.dumps(ctx.release, sort_keys=True)
    manifest = compile_assessment(ctx); loaded, artifacts = load_assessment(ctx)
    assert loaded == manifest and artifacts["effective-assessment-view.json"]["authority"] == {"base_graph":"authoritative_evidence_graph","assessment_overlay":"authoritative_assessment_record","effective_view":"derived_only"}
    assert (ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/current-generation.json").read_bytes() == graph_pointer
    assert json.dumps(ctx.release, sort_keys=True) == release
    assert "Base evidence:" in show_assessment(ctx)


def test_published_v2_artifacts_match_checked_in_schema_mirrors(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema")
    ctx = prepared_results(tmp_path); manifest = compile_assessment(ctx); _, artifacts = load_assessment(ctx)
    schema_root = Path(__file__).parents[1] / "schemas"
    mirrors = {
        "assessment-graph-overlay.json": "assessment-graph-overlay.v2.json",
        "effective-assessment-view.json": "effective-assessment-view.v2.json",
        "assessment-compiler-receipts.json": "assessment-compiler-receipts.v2.json",
    }
    for artifact_name, schema_name in mirrors.items():
        jsonschema.validate(artifacts[artifact_name], json.loads((schema_root / schema_name).read_text()))
    jsonschema.validate(manifest, json.loads((schema_root / "portable-assessment-manifest.v2.json").read_text()))


def test_overlay_gap_linking_is_exact_and_unmatched_spec_remains_criterion_only(tmp_path: Path):
    ctx = prepared_results(tmp_path); compile_assessment(ctx); _, artifacts = load_assessment(ctx); overlay = artifacts["assessment-graph-overlay.json"]
    assert any(edge["relationship"] == "addresses_assessment_gap" for edge in overlay["edges"])
    preparation = load_preparation(ctx); role = "targeted_test_planning"; work = preparation["work_orders"][role]; path = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/inbox" / work["preparation_id"] / work["work_order_id"] / "result.json"; result=json.loads(path.read_text()); result["payload"]["specifications"][0]["addresses_gap_key"]="test_adequacy|missing|boundary_coverage_gap|public_route"; result["payload"]["specifications"][0]["basis_node_ids"]=[result["payload"]["specifications"][0]["criterion_id"]]; write_json(path,result); receipt_path=path.parent/"completion-receipt.json"; receipt=json.loads(receipt_path.read_text()); receipt["result_snapshot_hash"]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); write_json(receipt_path,receipt)
    compile_assessment(ctx); _, artifacts = load_assessment(ctx); overlay=artifacts["assessment-graph-overlay.json"]
    assert any(edge["relationship"] == "proposes_test_for" for edge in overlay["edges"]) and not any(edge["relationship"] == "addresses_assessment_gap" for edge in overlay["edges"])


def test_assessment_load_rederives_semantics_and_rejects_artifact_tamper(tmp_path: Path):
    ctx = prepared_results(tmp_path); compile_assessment(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment"; pointer=json.loads((root/"current-assessment.json").read_text()); directory=root/"generations"/pointer["generation"]; path=directory/"effective-assessment-view.json"; artifact=json.loads(path.read_text()); artifact["criteria"][0]["base_evidence_state"]["test"]="open"; write_json(path,artifact)
    manifest_path=directory/"manifest.json"; manifest=json.loads(manifest_path.read_text()); manifest["artifact_hashes"][path.name]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); manifest["semantic_bundle_hash"]=assessment_module.content_hash({"compiler_version":assessment_module.ASSESSMENT_COMPILER_VERSION,"preparation_semantic_hash":manifest["preparation_semantic_hash"],"base_graph_semantic_hash":manifest["base_graph_semantic_hash"],"artifact_hashes":{key:manifest["artifact_hashes"][key] for key in sorted(manifest["artifact_hashes"])}}); manifest["bundle_hash"]=assessment_module.content_hash({key:value for key,value in manifest.items() if key!="bundle_hash"}); write_json(manifest_path,manifest); pointer["manifest_hash"]="sha256:"+hashlib.sha256(manifest_path.read_bytes()).hexdigest(); write_json(root/"current-assessment.json",pointer)
    with pytest.raises(ValueError, match="semantic artifacts are stale"): load_assessment(ctx)


def test_late_pointer_failure_preserves_prior_assessment(tmp_path: Path, monkeypatch):
    ctx=prepared_results(tmp_path); compile_assessment(ctx); pointer_path=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/current-assessment.json"; before=pointer_path.read_bytes()
    def fail(_directory): raise RuntimeError("late persistence failure")
    monkeypatch.setattr(assessment_module,"_BEFORE_ASSESSMENT_POINTER_REPLACE",fail)
    with pytest.raises(RuntimeError,match="late persistence"): compile_assessment(ctx)
    assert pointer_path.read_bytes()==before
    monkeypatch.setattr(assessment_module,"_BEFORE_ASSESSMENT_POINTER_REPLACE",None); load_assessment(ctx)


def test_semantic_assessment_ids_ignore_harness_run_provenance(tmp_path: Path):
    ctx=assessment_context(tmp_path); prepare_assessment(ctx); issue_results(ctx,harness_role="engineering_assessment"); compile_assessment(ctx); _,first=load_assessment(ctx); first_ids={node["node_id"] for node in first["assessment-graph-overlay.json"]["nodes"] if node.get("role_id")=="engineering_assessment"}
    preparation=load_preparation(ctx); work=preparation["work_orders"]["engineering_assessment"]; receipt_path=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/inbox"/work["preparation_id"]/work["work_order_id"]/"completion-receipt.json"; receipt=json.loads(receipt_path.read_text()); receipt["executor"]["run_id"]="another-run"; write_json(receipt_path,receipt); compile_assessment(ctx); _,second=load_assessment(ctx); second_ids={node["node_id"] for node in second["assessment-graph-overlay.json"]["nodes"] if node.get("role_id")=="engineering_assessment"}
    assert first_ids==second_ids


def test_generated_results_and_receipts_validate_against_snapshotted_v2_schemas(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema"); ctx=prepared_results(tmp_path); preparation=load_preparation(ctx)
    for role in CORE_ROLES:
        work=preparation["work_orders"][role]; inbox=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/inbox"/work["preparation_id"]/work["work_order_id"]
        result_schema=json.loads((preparation["directory"]/work["required_output"]["schema_path"]).read_text()); receipt_schema=json.loads((preparation["directory"]/work["required_output"]["completion_receipt_schema_path"]).read_text())
        jsonschema.validate(json.loads((inbox/"result.json").read_text()),result_schema); jsonschema.validate(json.loads((inbox/"completion-receipt.json").read_text()),receipt_schema)


def test_packet_source_quote_basis_is_role_bound_and_duplicates_rejected(tmp_path: Path):
    ctx=assessment_context(tmp_path); prepare_assessment(ctx,owner_paths=["product_assessment:docs/brief.md"]); preparation=issue_results(ctx); work=preparation["work_orders"]["product_assessment"]; path=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/inbox"/work["preparation_id"]/work["work_order_id"]/"result.json"; result=json.loads(path.read_text()); source=preparation["contexts"]["product_assessment"]["sources"][0]; quote=source["text"].split("\n")[0]; ref={key:source[key] for key in ("path","returned_git_path","git_blob_hash","normalized_text_hash")}|{"start_line":1,"end_line":1,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}; record=result["payload"]["criteria"][0]; record["basis_node_ids"]=[]; record["basis_source_refs"]=[ref]; write_json(path,result); receipt_path=path.parent/"completion-receipt.json"; receipt=json.loads(receipt_path.read_text()); receipt["result_snapshot_hash"]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); write_json(receipt_path,receipt); compile_core_results(ctx)
    result["payload"]["criteria"][0]["basis_source_refs"]=[ref,ref]; write_json(path,result); receipt["result_snapshot_hash"]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); write_json(receipt_path,receipt)
    with pytest.raises(ValueError,match="duplicate packet source"): compile_core_results(ctx)

    engineering=preparation["work_orders"]["engineering_assessment"]; engineering_path=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/inbox"/engineering["preparation_id"]/engineering["work_order_id"]/"result.json"; engineering_result=json.loads(engineering_path.read_text()); engineering_result["payload"]["criteria"][0]["basis_source_refs"]=[ref]; engineering_result["payload"]["criteria"][0]["basis_node_ids"]=[]; write_json(engineering_path,engineering_result); engineering_receipt_path=engineering_path.parent/"completion-receipt.json"; engineering_receipt=json.loads(engineering_receipt_path.read_text()); engineering_receipt["result_snapshot_hash"]="sha256:"+hashlib.sha256(engineering_path.read_bytes()).hexdigest(); write_json(engineering_receipt_path,engineering_receipt)
    result["payload"]["criteria"][0]["basis_source_refs"]=[ref]; write_json(path,result); receipt["result_snapshot_hash"]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest(); write_json(receipt_path,receipt)
    with pytest.raises(ValueError,match="escapes role context"): compile_core_results(ctx)


def test_published_generation_is_independent_of_live_preparation_and_active_pointer(tmp_path: Path):
    ctx=prepared_results(tmp_path); manifest=compile_assessment(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment"; shutil.rmtree(root/"preparations"/manifest["preparation_id"]); (root/"active-preparation.json").unlink(); loaded,_=load_assessment(ctx); assert loaded==manifest


def test_result_hashes_are_semantic_snapshot_and_receipt_specific(tmp_path: Path):
    ctx=prepared_results(tmp_path); compiled=compile_core_results(ctx)
    for hashes in compiled["snapshot_hashes"].values():
        assert set(hashes)=={"result_semantic_hash","result_snapshot_hash","completion_receipt_snapshot_hash"}
        assert len(set(hashes.values()))==3


def test_embedded_preparation_snapshot_tampering_fails_closed(tmp_path: Path):
    ctx=prepared_results(tmp_path); compile_assessment(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment"; pointer=json.loads((root/"current-assessment.json").read_text()); directory=root/"generations"/pointer["generation"]; schema=directory/"preparation-snapshot/contract-schemas/work-order.v2.json"; schema.write_bytes(schema.read_bytes()+b" ")
    with pytest.raises(ValueError,match="preparation semantic rederivation failed|preparation snapshot is stale"): load_assessment(ctx)


def test_newer_preparation_does_not_stale_published_generation(tmp_path: Path):
    ctx=prepared_results(tmp_path); manifest=compile_assessment(ctx); prepare_assessment(ctx); loaded,_=load_assessment(ctx); assert loaded==manifest


def test_pre_pointer_generation_verification_rejects_tamper_and_preserves_pointer(tmp_path: Path,monkeypatch):
    ctx=prepared_results(tmp_path); compile_assessment(ctx); pointer=ctx.repository_root/".shiproom/local/releases/rel_intent/assessment/current-assessment.json"; before=pointer.read_bytes()
    def tamper(directory):
        path=directory/"effective-assessment-view.json"; value=json.loads(path.read_text()); value["criteria"][0]["base_evidence_state"]["runtime"]="open"; write_json(path,value)
    monkeypatch.setattr(assessment_module,"_BEFORE_ASSESSMENT_GENERATION_VERIFY",tamper)
    with pytest.raises(ValueError,match="artifact"): compile_assessment(ctx)
    assert pointer.read_bytes()==before
