from __future__ import annotations

import hashlib, json, re
from pathlib import Path

import pytest
import shiproom.graph as graph_module

from shiproom.graph import _validate_proposal, compile_bundle, load_bundle, mapping_prepare, show
from shiproom.intent import compile_bundle as compile_intent, prepare
from shiproom.cli import main
from test_intent import context_for, inbox, proposal, ref
from shiproom.project import content_hash
from scripts.graph_acceptance_fixture import run_controlled_patient


def _rewrite_manifest_and_pointer(root: Path, pointer: dict, manifest_path: Path, manifest: dict) -> None:
    manifest["bundle_hash"] = content_hash({k:v for k,v in manifest.items() if k != "bundle_hash"}); manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    pointer["manifest_hash"] = "sha256:"+hashlib.sha256(manifest_path.read_bytes()).hexdigest(); (root/"current-generation.json").write_text(json.dumps(pointer, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def _intent_context(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], [])
    path = inbox(ctx); path.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    compile_intent(ctx, str(path)); return ctx


def test_graph_compile_without_mapping_packet_emits_not_inspected_slots(tmp_path: Path):
    ctx = _intent_context(tmp_path); manifest = compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    assert manifest["mapping_packet_state"] == "absent"
    summary = artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert {key for key in ("implementation", "tests", "instrumentation", "runtime")} and all(values[0]["detail"]["slot_status"] == "not_inspected" for values in (summary["implementation"], summary["tests"], summary["instrumentation"], summary["runtime"]))
    assert "Implementation: not_inspected" in show(ctx)


def test_mapping_packet_candidate_is_not_proof_and_stale_packet_fails(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"])
    criterion = packet["criterion_ids"][0]; source = packet["selected_sources"][0]
    quote = "approval_required"
    proposal_data = {"schema_version": "evidence-mapping-proposal.v1", "release_id": packet["release_id"], "release_commit": packet["release_commit"], "product_intent_semantic_bundle_hash": packet["product_intent_semantic_bundle_hash"], "release_projection_hash": packet["release_projection_hash"], "mapping_packet_hash": packet["packet_hash"], "mappings": [{"mapping_id": "route", "criterion_id": criterion, "target_type": "implementation_reference", "rationale": "Exact candidate text.", "reference": {"path": source["path"], "returned_git_path": source["returned_git_path"], "git_blob_hash": source["git_blob_hash"], "start_line": 4, "end_line": 4, "quote": quote, "quote_hash": "sha256:" + __import__("hashlib").sha256(quote.encode()).hexdigest()}}]}
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/map.json"; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(proposal_data), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx); graph = artifacts["requirement-evidence-graph.json"]
    assert any(e["establishment_classification"] == "model_mapped_candidate" for e in graph["edges"])
    active = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/mapping-source-packet.json"; data = json.loads(active.read_text()); data["release_projection_hash"] = "sha256:bad"; active.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError): load_bundle(ctx)


def test_graph_rerun_ids_are_index_resolved_before_sorting(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [{"type":"http","target":"/result/demo","criterion_id": "HISTORICAL", "status": 404, "passed": False, "evidence_status": "deterministically_verified"}, {"type":"http","target":"/result/demo","criterion_id": "HISTORICAL", "status": 200, "passed": True, "evidence_status": "deterministically_verified", "rerun_of": 0}]
    ctx.release["findings"] = [{"id": "finding_hist", "criterion_id": "HISTORICAL", "blocking": True, "state": "CLOSED", "evidence": []}]
    compile_bundle(ctx); _, artifacts = load_bundle(ctx); nodes = artifacts["requirement-evidence-graph.json"]["nodes"]
    assert any(n["node_type"] == "closure_evidence" and n["original_check_id"] != n["rerun_check_id"] for n in nodes)


def _mapping(packet: dict, criterion_id: str, mapping_id: str, target_type: str, reference: dict | None = None, canonical_id: str | None = None) -> dict:
    result = {"mapping_id": mapping_id, "criterion_id": criterion_id, "target_type": target_type, "rationale": "Bounded mapping candidate."}
    if reference: result["reference"] = reference
    if canonical_id: result["canonical_id"] = canonical_id
    return result


def _mapping_proposal(packet: dict, mappings: list[dict]) -> dict:
    return {"schema_version": "evidence-mapping-proposal.v1", "release_id": packet["release_id"], "release_commit": packet["release_commit"], "product_intent_semantic_bundle_hash": packet["product_intent_semantic_bundle_hash"], "release_projection_hash": packet["release_projection_hash"], "mapping_packet_hash": packet["packet_hash"], "mappings": mappings}


def _reference(source: dict, line: int, quote: str) -> dict:
    import hashlib
    return {"path": source["path"], "returned_git_path": source["returned_git_path"], "git_blob_hash": source["git_blob_hash"], "start_line": line, "end_line": line, "quote": quote, "quote_hash": "sha256:" + hashlib.sha256(quote.encode()).hexdigest()}


def test_multiple_candidate_references_replace_single_slot_placeholder(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md", "docs/other.md"]); criterion = packet["criterion_ids"][0]
    brief, other = packet["selected_sources"]
    data = _mapping_proposal(packet, [
        _mapping(packet, criterion, "implementation-brief", "implementation_reference", _reference(brief, 3, "Users can publish cards.")),
        _mapping(packet, criterion, "implementation-other", "implementation_reference", _reference(other, 1, "disabled")),
    ])
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/multiple.json"; path.write_text(json.dumps(data), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx)
    implementation = artifacts["criterion-evidence-summary.json"]["criteria"][0]["implementation"]
    assert len(implementation) == 2 and {item["detail"]["slot_status"] for item in implementation} == {"candidate_present"}


def test_historical_product_criterion_to_intent_criterion_is_candidate_only(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [{"check_id": "check_404", "type":"http", "target":"/result/demo", "criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS", "status": 404, "passed": False, "evidence_status":"deterministically_verified"}]
    packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    data = _mapping_proposal(packet, [_mapping(packet, criterion, "historical", "runtime_evidence", canonical_id="check_404")])
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/historical.json"; path.write_text(json.dumps(data), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx); graph = artifacts["requirement-evidence-graph.json"]
    historical = [edge for edge in graph["edges"] if edge["relationship"] == "has_runtime_evidence"]
    assert any(edge["establishment_classification"] == "model_mapped_candidate" for edge in historical)
    assert not any(edge["establishment_classification"] == "deterministically_established" for edge in historical)


def test_requirement_journey_context_is_inherited_without_direct_criterion_inference(tmp_path: Path):
    ctx = _intent_context(tmp_path); compile_bundle(ctx); _, artifacts = load_bundle(ctx); graph = artifacts["requirement-evidence-graph.json"]
    criterion_id = artifacts["criterion-evidence-summary.json"]["criteria"][0]["criterion_id"]
    summary = artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert summary["critical_journey_context"] == ["Publish card"]
    criterion_node = next(node["node_id"] for node in graph["nodes"] if node.get("criterion_id") == criterion_id)
    assert not any(edge["source_node_id"] == criterion_node and edge["relationship"] == "affects_critical_journey" for edge in graph["edges"])


def test_source_conflict_gap_carries_product_intent_ambiguity_ids_and_omission_is_not_missing(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md", "docs/other.md"], []); data = proposal(packet)
    data["claims"].append({"local_id": "other", "claim_key": "release.publication_mode", "cardinality": "single", "value": "disabled", "classification": "explicit", "source_refs": [ref(packet, "docs/other.md")], "requirement_local_ids": ["publish"]})
    data["requirements"][0]["claim_local_ids"].append("other")
    intent_proposal = inbox(ctx, "graph-conflict.json"); intent_proposal.write_text(json.dumps(data), encoding="utf-8"); compile_intent(ctx, str(intent_proposal))
    compile_bundle(ctx); _, artifacts = load_bundle(ctx); gaps = artifacts["evidence-gaps.json"]["gaps"]
    conflict = next(gap for gap in gaps if gap["gap_type"] == "source_conflict")
    assert conflict["product_intent_ambiguity_ids"]
    assert any(gap["gap_type"] == "implementation_gap" and gap["state"] == "unknown" for gap in gaps)


def test_mapping_packet_safe_projections_and_remediation_compatibility_fields(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [{"criterion_id": "legacy", "target": "/result/demo", "status": 404, "passed": False, "deployment_grant_hash": "sha256:grant"}]
    ctx.release["findings"] = [{"id": "finding_legacy", "criterion_id": "legacy", "blocking": True, "state": "TRIAGED", "evidence": []}]
    ctx.release["remediation_tasks"] = [{"id": "task_legacy", "class": "compatibility", "base_branch": "main", "branch": "remediation/demo", "status": "closed", "auto_merge": False, "commit_sha": "abc"}]
    packet = mapping_prepare(ctx, ["docs/brief.md"])
    assert packet["canonical_checks"][0]["target"] == "/result/demo" and "read_grant" not in packet["canonical_checks"][0]
    compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    task = next(node for node in artifacts["requirement-evidence-graph.json"]["nodes"] if node["node_type"] == "remediation_plan")
    assert task["base_branch"] == "main" and task["commit_sha"] == "abc"


def test_graph_mapping_prepare_compile_show_cli_smoke(tmp_path: Path, capsys):
    ctx = _intent_context(tmp_path); release = tmp_path / "release.json"; release.write_text(json.dumps(ctx.release), encoding="utf-8")
    assert main(["graph", "mapping", "prepare", "--release", str(release), "--path", "docs/brief.md"]) == 0; capsys.readouterr()
    assert main(["graph", "compile", "--release", str(release)]) == 0; capsys.readouterr()
    assert main(["graph", "show", "--release", str(release)]) == 0
    assert "Requirement:" in capsys.readouterr().out


def test_unknown_check_is_import_limitation_and_unrelated_404_never_opens_gap(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [
        {"check_id": "unknown", "type": "model_review", "criterion_id": "other", "passed": False},
        {"check_id": "other404", "type": "http", "target": "/other", "criterion_id": "other", "status": 404, "passed": False, "evidence_status": "deterministically_verified"},
    ]
    compile_bundle(ctx); _, artifacts = load_bundle(ctx); graph = artifacts["requirement-evidence-graph.json"]
    assert graph["import_limitations"] == [{"kind": "unsupported_check", "check_id": "unknown", "check_type": "model_review", "criterion_id": "other"}]
    assert all(gap["gap_type"] != "runtime_evidence_gap" or gap["state"] == "unknown" for gap in artifacts["evidence-gaps.json"]["gaps"])


def test_candidate_404_is_unknown_but_exact_deterministic_404_is_open(tmp_path: Path):
    ctx = _intent_context(tmp_path); criterion = load_bundle(ctx)[1]["criterion-evidence-summary.json"]["criteria"][0]["criterion_id"] if False else None
    packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    ctx.release["checks"] = [{"check_id": "historic", "type": "http", "target": "/result", "criterion_id": "HISTORIC", "status": 404, "passed": False, "evidence_status": "deterministically_verified"}]
    packet = mapping_prepare(ctx, ["docs/brief.md"]); data = _mapping_proposal(packet, [_mapping(packet, criterion, "candidate", "runtime_evidence", canonical_id="historic")])
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/candidate404.json"; path.write_text(json.dumps(data), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx)
    runtime = next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"] == "runtime_evidence_gap"); assert runtime["state"] == "unknown" and runtime["candidate_linked_failure"]
    ctx.release["checks"][0]["criterion_id"] = criterion; mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    assert next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"] == "runtime_evidence_gap")["state"] == "open"


def test_load_rederives_and_rejects_semantic_artifact_tamper(tmp_path: Path):
    ctx = _intent_context(tmp_path); compile_bundle(ctx); root = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph"; pointer = json.loads((root / "current-generation.json").read_text()); generation=root/"generations"/pointer["generation"]; graph = generation / "requirement-evidence-graph.json"
    value = json.loads(graph.read_text()); value["coverage_boundary"] = "tampered"; graph.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n", encoding="utf-8"); manifest_path=generation/"manifest.json"; manifest=json.loads(manifest_path.read_text()); manifest["artifact_hashes"]["requirement-evidence-graph.json"]="sha256:"+hashlib.sha256(graph.read_bytes()).hexdigest(); manifest["semantic_bundle_hash"]=content_hash({"intent":manifest["product_intent_semantic_bundle_hash"],"packet":manifest["mapping_packet_hash"],"projection":manifest["release_projection_hash"],"compiler":manifest["compiler_version"],"artifacts":{k:manifest["artifact_hashes"][k] for k in sorted(manifest["artifact_hashes"])}}); _rewrite_manifest_and_pointer(root,pointer,manifest_path,manifest)
    with pytest.raises(ValueError): load_bundle(ctx)


def test_exact_runtime_rerun_resolves_only_its_failed_final_criterion_lineage(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    ctx.release["checks"] = [
        {"check_id": "failed-final", "type": "http", "target": "/result/demo", "criterion_id": criterion, "status": 404, "passed": False, "evidence_status": "deterministically_verified"},
        {"check_id": "unrelated-success", "type": "http", "target": "/elsewhere", "criterion_id": criterion, "status": 200, "passed": True, "evidence_status": "deterministically_verified"},
        {"check_id": "rerun-final", "type": "http", "target": "/result/demo", "criterion_id": criterion, "status": 200, "passed": True, "evidence_status": "deterministically_verified", "rerun_of": 0},
    ]
    ctx.release["findings"] = [{"id": "closed-final", "criterion_id": criterion, "blocking": True, "state": "CLOSED", "evidence": []}]
    mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    runtime = next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"] == "runtime_evidence_gap")
    assert runtime["state"] == "closed"


def test_fully_rehashed_v7_generation_fails_distinct_v8_compiler_gate(tmp_path: Path):
    ctx = _intent_context(tmp_path); compile_bundle(ctx)
    root = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph"; pointer = json.loads((root / "current-generation.json").read_text())
    manifest_path = root / "generations" / pointer["generation"] / "manifest.json"; manifest = json.loads(manifest_path.read_text()); manifest["compiler_version"] = "requirement-evidence-graph.v7"; manifest["semantic_bundle_hash"]=content_hash({"intent":manifest["product_intent_semantic_bundle_hash"],"packet":manifest["mapping_packet_hash"],"projection":manifest["release_projection_hash"],"compiler":manifest["compiler_version"],"artifacts":{k:manifest["artifact_hashes"][k] for k in sorted(manifest["artifact_hashes"])}}); _rewrite_manifest_and_pointer(root,pointer,manifest_path,manifest)
    with pytest.raises(ValueError, match="^stale_graph_compiler_version$"): load_bundle(ctx)


def test_packet_journey_mapping_creates_the_candidate_journey_edge(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    mapping = {"mapping_id":"journey","criterion_id":criterion,"target_type":"critical_journey","rationale":"Exact packet journey.","journey_id":packet["critical_journeys"][0]["journey_id"]}
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/journey.json"; path.write_text(json.dumps(_mapping_proposal(packet, [mapping])), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx)
    summary = artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert len(summary["direct_journeys"]) == 1 and summary["direct_journeys"][0]["direct_classification"] == "model_mapped_candidate"


def test_candidate_finding_keeps_downstream_decision_and_remediation_candidate(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["findings"] = [{"id":"hist","criterion_id":"HIST","blocking":True,"state":"TRIAGED","evidence":[]}]
    ctx.release["owner_decisions"] = [{"id":"dec","title":"Decision","choice":None,"resolution":None,"evidence":[{"reference":"hist"}]}]
    ctx.release["remediation_tasks"] = [{"id":"task","class":"compatibility","base_branch":"main","branch":"x","status":"open","auto_merge":False,"evidence":[{"reference":"hist"}]}]
    packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/finding.json"; path.write_text(json.dumps(_mapping_proposal(packet, [_mapping(packet, criterion, "finding", "finding", canonical_id="hist")])), encoding="utf-8")
    compile_bundle(ctx, str(path)); _, artifacts = load_bundle(ctx); summary = artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert summary["owner_decisions"][0]["effective_classification"] == "model_mapped_candidate"
    assert summary["remediation"][0]["effective_classification"] == "model_mapped_candidate"
    assert not any(g["gap_type"] == "owner_decision_required" for g in artifacts["evidence-gaps.json"]["gaps"])


def test_direct_deterministic_http_200_closes_runtime_gap(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    ctx.release["checks"] = [{"check_id":"direct-200","evidence_kind":"http","target":"/result","criterion_id":criterion,"status":200,"passed":True,"evidence_status":"deterministically_verified"}]
    mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    gap = next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"] == "runtime_evidence_gap")
    runtime = artifacts["criterion-evidence-summary.json"]["criteria"][0]["runtime"][0]
    assert gap["state"] == "closed" and runtime["detail"]["routed_kind"] == "runtime_http"


@pytest.mark.parametrize("kind", ["http", "test", "instrumentation"])
def test_deterministic_missing_variants_compile_and_reload(tmp_path: Path, kind: str):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    ctx.release["checks"] = [{"check_id":"missing-"+kind,"type":kind,"criterion_id":criterion,"evidence_status":"missing_evidence","error_type":"not collected"}]
    mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    assert any(n.get("slot_status") == "deterministic_missing" and n.get("routed_kind") for n in artifacts["requirement-evidence-graph.json"]["nodes"])
    if kind == "http":
        assert next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")["state"] == "open"
        assert artifacts["criterion-evidence-summary.json"]["criteria"][0]["closure"]["closure_state"] == "not_inspected"


def test_successful_predecessor_has_no_closure_and_route_conflict_is_limited(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); criterion = packet["criterion_ids"][0]
    ctx.release["checks"] = [
        {"check_id":"already-good","type":"http","target":"/result","criterion_id":criterion,"status":200,"passed":True,"evidence_status":"deterministically_verified"},
        {"check_id":"rerun-good","type":"http","target":"/result","criterion_id":criterion,"status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":0},
        {"check_id":"conflict","type":"test","evidence_kind":"http","criterion_id":criterion,"passed":True,"evidence_status":"deterministically_verified"},
    ]
    ctx.release["findings"] = [{"id":"closed","criterion_id":criterion,"state":"CLOSED","blocking":False,"evidence":[]}]
    mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx); graph = artifacts["requirement-evidence-graph.json"]
    assert not any(e["relationship"] in {"closes","fails_to_close"} for e in graph["edges"])
    assert {x["kind"] for x in graph["import_limitations"]} == {"conflicting_check_route"}


def test_summary_paths_are_explicit_and_walkable(tmp_path: Path):
    ctx = _intent_context(tmp_path); compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    item = artifacts["criterion-evidence-summary.json"]["criteria"][0]["implementation"][0]
    assert set(item) == {"node_id","node_type","node_provenance","direct_relationships","criterion_path","direct_classification","effective_classification","detail"}
    assert item["criterion_path"] == item["direct_relationships"] and item["criterion_path"][0]["traversal"] == "reverse"


def test_partial_runtime_lineage_and_later_failure_keep_closure_failed(tmp_path: Path):
    ctx = _intent_context(tmp_path); packet = mapping_prepare(ctx, ["docs/brief.md"]); cid = packet["criterion_ids"][0]
    ctx.release["checks"] = [
        {"check_id":"first-failure","type":"http","target":"/result","criterion_id":cid,"status":404,"passed":False,"evidence_status":"deterministically_verified"},
        {"check_id":"first-rerun","type":"http","target":"/result","criterion_id":cid,"status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":0},
        {"check_id":"later-failure","type":"http","target":"/result","criterion_id":cid,"status":500,"passed":False,"evidence_status":"deterministically_verified"},
    ]; ctx.release["findings"] = [{"id":"finding","criterion_id":cid,"state":"CLOSED","blocking":True,"evidence":[{"reference":"first-failure"}]}]
    mapping_prepare(ctx, ["docs/brief.md"]); compile_bundle(ctx); _, artifacts = load_bundle(ctx); summary=artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")["state"] == "open"
    assert summary["closure"]["closure_state"] == "failed" and summary["closure"]["closure_items"]


def test_historical_closed_lineage_candidate_crosswalk_does_not_close_new_criterion(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [
        {"check_id":"hist-fail","type":"http","target":"/result","criterion_id":"HIST","status":404,"passed":False,"evidence_status":"deterministically_verified"},
        {"check_id":"hist-pass","type":"http","target":"/result","criterion_id":"HIST","status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":0},
    ]; ctx.release["findings"]=[{"id":"hist-finding","criterion_id":"HIST","state":"CLOSED","blocking":True,"evidence":[{"reference":"hist-fail"}]}]
    packet=mapping_prepare(ctx,["docs/brief.md"]); cid=packet["criterion_ids"][0]; data=_mapping_proposal(packet,[_mapping(packet,cid,"runtime","runtime_evidence",canonical_id="hist-pass"),_mapping(packet,cid,"finding","finding",canonical_id="hist-finding")]); path=ctx.repository_root/".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/historical-closed.json"; path.write_text(json.dumps(data),encoding="utf-8")
    compile_bundle(ctx,str(path)); _, artifacts=load_bundle(ctx); summary=artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")["state"]=="unknown"
    assert summary["closure"]["closure_state"]=="not_inspected" and summary["closure"]["closure_items"][0]["effective_classification"]=="model_mapped_candidate"


def test_partial_owner_decision_remains_open_on_deterministic_finding_path(tmp_path: Path):
    ctx=_intent_context(tmp_path); packet=mapping_prepare(ctx,["docs/brief.md"]); cid=packet["criterion_ids"][0]; ctx.release["findings"]=[{"id":"finding","criterion_id":cid,"state":"TRIAGED","blocking":True,"evidence":[]}]; ctx.release["owner_decisions"]=[{"id":"decision","title":"Owner","choice":"accept","resolution":None,"evidence":[{"reference":"finding"}]}]
    mapping_prepare(ctx,["docs/brief.md"]); compile_bundle(ctx); _, artifacts=load_bundle(ctx)
    assert any(g["gap_type"]=="owner_decision_required" and g["state"]=="open" for g in artifacts["evidence-gaps.json"]["gaps"])


def test_failed_graph_compile_preserves_current_pointer(tmp_path: Path):
    ctx=_intent_context(tmp_path); packet=mapping_prepare(ctx,["docs/brief.md"]); compile_bundle(ctx); pointer=ctx.repository_root/".shiproom/local/releases/rel_intent/requirement-evidence-graph/current-generation.json"; before=pointer.read_bytes(); bad=_mapping_proposal(packet,[]); bad["mapping_packet_hash"]="sha256:wrong"; path=ctx.repository_root/".shiproom/local/releases/rel_intent/requirement-evidence-graph/inbox/bad-binding.json"; path.write_text(json.dumps(bad),encoding="utf-8")
    with pytest.raises(ValueError):compile_bundle(ctx,str(path))
    assert pointer.read_bytes()==before


def test_late_persistence_failure_preserves_current_pointer_and_readable_generation(tmp_path: Path, monkeypatch):
    ctx=_intent_context(tmp_path); compile_bundle(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_intent/requirement-evidence-graph"; pointer=root/"current-generation.json"; before=pointer.read_bytes(); generations_before=set((root/"generations").iterdir())
    def fail_after_generation(_directory):raise RuntimeError("late persistence seam")
    monkeypatch.setattr(graph_module,"_BEFORE_POINTER_REPLACE",fail_after_generation)
    with pytest.raises(RuntimeError,match="late persistence seam"):compile_bundle(ctx)
    assert pointer.read_bytes()==before and len(set((root/"generations").iterdir())-generations_before)==1
    monkeypatch.setattr(graph_module,"_BEFORE_POINTER_REPLACE",None); load_bundle(ctx)


def test_failed_rerun_is_attempt_and_later_success_resolves_root(tmp_path: Path):
    ctx=_intent_context(tmp_path); packet=mapping_prepare(ctx,["docs/brief.md"]); cid=packet["criterion_ids"][0]; ctx.release["checks"]=[
        {"check_id":"root","type":"http","target":"/result","criterion_id":cid,"status":404,"passed":False,"evidence_status":"deterministically_verified"},
        {"check_id":"failed-attempt","type":"http","target":"/result","criterion_id":cid,"status":500,"passed":False,"evidence_status":"deterministically_verified","rerun_of":0},
        {"check_id":"successful-attempt","type":"http","target":"/result","criterion_id":cid,"status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":1},
    ]; ctx.release["findings"]=[{"id":"finding","criterion_id":cid,"state":"CLOSED","blocking":True,"evidence":[{"reference":"successful-attempt"}]}]
    mapping_prepare(ctx,["docs/brief.md"]); compile_bundle(ctx); _,artifacts=load_bundle(ctx); summary=artifacts["criterion-evidence-summary.json"]["criteria"][0]; lineage=summary["runtime_lineage"]
    assert lineage["roots"]==[{"root_check_id":"root","attempt_check_ids":["root","failed-attempt","successful-attempt"],"state":"resolved"}]
    assert next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")["state"]=="closed"


def test_real_controlled_patient_pre_post_candidate_crosswalk_and_show(tmp_path: Path):
    result=run_controlled_patient(tmp_path); cid=result["criterion_id"]
    for phase in ("pre","post"):
        artifacts=result[phase]; summary=next(x for x in artifacts["criterion-evidence-summary.json"]["criteria"] if x["criterion_id"]==cid); criterion=next(x for x in artifacts["requirement-evidence-graph.json"]["nodes"] if x["node_id"]==cid); runtime=next(g for g in artifacts["evidence-gaps.json"]["gaps"] if g["criterion_id"]==cid and g["gap_type"]=="runtime_evidence_gap")
        assert criterion["action"]=="Open the returned public URL." and criterion["expected_outcomes"]==["The returned public URL opens successfully."]
        assert summary["implementation"][0]["detail"]["path"]=="demo_patient/server.py"
        assert summary["tests"][0]["detail"]["slot_status"]=="candidate_present" and summary["instrumentation"][0]["detail"]["slot_status"]=="candidate_present"
        assert runtime["state"]=="unknown" and summary["closure"]["closure_state"]=="not_inspected"
    assert {x["detail"].get("check_id") for x in result["pre"]["criterion-evidence-summary.json"]["criteria"][0]["runtime"]}=={"hist-404"}
    post=result["post"]["criterion-evidence-summary.json"]["criteria"][0]; assert {x["detail"].get("check_id") for x in post["runtime"]}=={"hist-404","hist-200"}
    assert post["closure"]["closure_items"] and all(x["effective_classification"]=="model_mapped_candidate" for x in post["closure"]["closure_items"])
    rendered=result["post_show"]
    for expected in ("demo_patient/server.py","hist-404","hist-200","hist-finding","runtime_http","status=404","status=200","model_mapped_candidate","Closure: not_inspected","Gaps:"):
        assert expected in rendered


def test_exact_skill_mapping_examples_validate_with_active_packet_values(tmp_path: Path):
    ctx=_intent_context(tmp_path); ctx.release["checks"]=[{"check_id":"documented-check","type":"http","target":"/result","criterion_id":"HIST","status":200,"passed":True,"evidence_status":"deterministically_verified"}]; ctx.release["findings"]=[{"id":"documented-finding","criterion_id":"HIST","state":"TRIAGED","blocking":False,"evidence":[]}]
    packet=mapping_prepare(ctx,["docs/brief.md"]); source=packet["selected_sources"][0]; criterion=packet["criterion_ids"][0]; journey=packet["critical_journeys"][0]["journey_id"]; runtime=packet["canonical_runtime_evidence"][0]["runtime_evidence_id"]
    skill=(Path(__file__).parents[1]/"skills/shiproom/SKILL.md").read_text(encoding="utf-8"); examples=[json.loads(x) for x in re.findall(r"```json\s*(\{.*?\})\s*```",skill,re.S) if '"target_type"' in x]
    assert {x["target_type"] for x in examples}=={"implementation_reference","runtime_evidence","finding","critical_journey"}
    for example in examples:
        example["criterion_id"]=criterion
        if example["target_type"]=="implementation_reference":
            quote=source["text"].split("\n")[0]; example["reference"]={"path":source["path"],"returned_git_path":source["returned_git_path"],"git_blob_hash":source["git_blob_hash"],"start_line":1,"end_line":1,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}
        elif example["target_type"]=="runtime_evidence":example["canonical_id"]=runtime
        elif example["target_type"]=="finding":example["canonical_id"]="documented-finding"
        else:example["journey_id"]=journey
        _validate_proposal(_mapping_proposal(packet,[example]),packet)
