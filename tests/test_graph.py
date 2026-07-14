from __future__ import annotations

import json
from pathlib import Path

import pytest

from shiproom.graph import compile_bundle, load_bundle, mapping_prepare, show
from shiproom.intent import compile_bundle as compile_intent, prepare
from shiproom.cli import main
from test_intent import context_for, inbox, proposal, ref


def _intent_context(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], [])
    path = inbox(ctx); path.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    compile_intent(ctx, str(path)); return ctx


def test_graph_compile_without_mapping_packet_emits_not_inspected_slots(tmp_path: Path):
    ctx = _intent_context(tmp_path); manifest = compile_bundle(ctx); _, artifacts = load_bundle(ctx)
    assert manifest["mapping_packet_state"] == "absent"
    summary = artifacts["criterion-evidence-summary.json"]["criteria"][0]
    assert {key for key in ("implementation", "tests", "instrumentation", "runtime")} and all(values[0]["slot_status"] == "not_inspected" for values in (summary["implementation"], summary["tests"], summary["instrumentation"], summary["runtime"]))
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
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [{"criterion_id": "HISTORICAL", "status": 404, "passed": False, "evidence_status": "deterministically_verified"}, {"criterion_id": "HISTORICAL", "status": 200, "passed": True, "evidence_status": "deterministically_verified", "rerun_of": 0}]
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
    assert len(implementation) == 2 and {item["slot_status"] for item in implementation} == {"candidate_present"}


def test_historical_product_criterion_to_intent_criterion_is_candidate_only(tmp_path: Path):
    ctx = _intent_context(tmp_path); ctx.release["checks"] = [{"check_id": "check_404", "criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS", "status": 404, "passed": False}]
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
    assert not any(gap["gap_type"] in {"implementation_gap", "test_evidence_gap", "instrumentation_gap"} for gap in gaps)


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
