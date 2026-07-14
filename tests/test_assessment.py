from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import shiproom.assessment as assessment_module

from shiproom.assessment import (
    ALL_ROLES,
    AssessmentPreparationError,
    _load_json_bytes,
    _python_imports,
    _javascript_imports,
    _test_matches,
    load_discovery_registry,
    _work_order_hash,
    load_preparation,
    load_role_definitions,
    prepare as prepare_assessment,
)
from shiproom.cli import main
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input, mapping_prepare
from shiproom.intent import compile_bundle as compile_intent, prepare as prepare_intent
from test_intent import context_for, inbox, proposal


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def assessment_context(tmp_path: Path, *, mapped: bool = False):
    ctx = context_for(tmp_path)
    packet = prepare_intent(ctx, ["docs/brief.md"], [])
    proposal_path = inbox(ctx)
    proposal_path.parent.mkdir(parents=True, exist_ok=True)
    proposal_path.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    compile_intent(ctx, str(proposal_path))
    if mapped:
        mapping_prepare(ctx, ["docs/brief.md"])
    compile_graph(ctx)
    return ctx


def test_graph_public_assessment_accessor_returns_complete_validated_chain(tmp_path: Path):
    ctx = assessment_context(tmp_path, mapped=True)
    value = load_assessment_input(ctx)
    assert set(value) == {
        "graph_generation", "graph_manifest", "graph_artifacts", "mapping_packet_snapshot",
        "intent_manifest", "intent_artifacts", "intent_source_packet",
    }
    assert value["mapping_packet_snapshot"]["packet_hash"] == value["graph_manifest"]["mapping_packet_hash"]
    assert value["intent_manifest"]["semantic_bundle_hash"] == value["graph_manifest"]["product_intent_semantic_bundle_hash"]


def test_prepare_issues_four_required_portable_work_orders_without_assessment_pointer(tmp_path: Path):
    ctx = assessment_context(tmp_path)
    result = prepare_assessment(ctx)
    loaded = load_preparation(ctx)
    assert result["preparation_id"].startswith("prep_")
    assert {entry["role_id"] for entry in result["work_orders"] if entry["issued"]} == set(ALL_ROLES) - {"browser_journey"}
    browser = next(entry for entry in result["work_orders"] if entry["role_id"] == "browser_journey")
    assert browser["reason_code"] == "not_browser_relevant"
    root = loaded["directory"].parents[1]
    assert not (root / "current-assessment.json").exists()
    for entry in loaded["manifest"]["work_orders"]:
        if not entry["issued"]:
            continue
        raw = (loaded["directory"] / entry["work_order_path"]).read_bytes()
        work = _load_json_bytes(raw)
        assert work["work_order_hash"] == _work_order_hash(work)
        assert entry["work_order_snapshot_hash"] != work["work_order_hash"]
        assert work["permissions"]["repository"] == "read_only"
        assert work["required_output"]["output_path"].startswith(f".shiproom/local/releases/{ctx.release['release_id']}/assessment/inbox/{result['preparation_id']}/")


def test_identical_semantics_use_distinct_handles_and_stable_work_order_ids(tmp_path: Path):
    ctx = assessment_context(tmp_path)
    first = prepare_assessment(ctx); first_loaded = load_preparation(ctx, first["preparation_id"])
    second = prepare_assessment(ctx); second_loaded = load_preparation(ctx, second["preparation_id"])
    assert first["preparation_id"] != second["preparation_id"]
    assert first["preparation_semantic_hash"] == second["preparation_semantic_hash"]
    first_ids = {entry["role_id"]: entry["work_order_id"] for entry in first_loaded["manifest"]["work_orders"]}
    second_ids = {entry["role_id"]: entry["work_order_id"] for entry in second_loaded["manifest"]["work_orders"]}
    assert first_ids == second_ids
    assert load_preparation(ctx)["manifest"]["preparation_id"] == second["preparation_id"]
    assert load_preparation(ctx, first["preparation_id"])["manifest"]["preparation_id"] == first["preparation_id"]


def test_role_paths_are_commit_pinned_and_one_hop_does_not_recurse(tmp_path: Path):
    ctx = assessment_context(tmp_path)
    repo = ctx.repository_root
    # These files are deliberately added after the release commit and cannot become release authority.
    (repo / "late.py").write_text("import secret\n", encoding="utf-8")
    with pytest.raises(AssessmentPreparationError, match="assessment_source_missing"):
        prepare_assessment(ctx, owner_paths=["engineering_assessment:late.py"])
    result = prepare_assessment(ctx, owner_paths=["product_assessment:docs/brief.md"])
    packet = load_preparation(ctx, result["preparation_id"])["source_packet"]
    source = next(item for item in packet["role_sources"]["product_assessment"]["sources"] if item["path"] == "docs/brief.md")
    assert source["mandatory"] and source["git_blob_hash"] == git(repo, "rev-parse", f"{ctx.authority_binding['repository_commit']}:docs/brief.md")


def test_source_discovery_registry_is_closed_and_one_hop_only():
    available = {
        "package/foo.py", "tests/test_foo.py", "package/test_foo.py", "package/foo_test.py",
        "package/helper.py", "package/deeper.py", "src/foo.ts", "src/helper.ts", "src/deeper.ts",
        "src/foo.test.ts", "src/__tests__/foo.ts",
    }
    assert {path for path, _, _ in _test_matches("package/foo.py", available)} == {"tests/test_foo.py", "package/test_foo.py", "package/foo_test.py"}
    assert {path for path, _, _ in _test_matches("src/foo.ts", available)} == {"src/foo.test.ts", "src/__tests__/foo.ts"}
    python_imports, limitation = _python_imports("package/foo.py", "from . import helper", available)
    assert limitation is None and python_imports == ["package/helper.py"]
    js_imports, limitation = _javascript_imports("src/foo.ts", 'import helper from "./helper"', available)
    assert limitation is None and js_imports == ["src/helper.ts"]
    # Callers inspect only these original seeds; imports of the returned helper are never traversed here.
    assert "package/deeper.py" not in python_imports and "src/deeper.ts" not in js_imports


def test_capabilities_are_release_local_strict_json_and_snapshotted(tmp_path: Path):
    ctx = assessment_context(tmp_path); root = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment"
    outside = tmp_path / "capabilities.json"; outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="assessment/inputs"):
        prepare_assessment(ctx, capabilities_path=str(outside))
    inputs = root / "inputs"; inputs.mkdir(parents=True)
    capabilities = {
        "schema_version": "shiproom.assessment-capabilities.v1",
        "substrate": {"id": "human-review", "execution_mode": "manual_external"},
        "capabilities": {name: {"available": name in {"file_read", "browser"}} for name in ("file_read", "browser", "shell", "network")},
        "permissions": {"file_read": {"granted": True, "scope": "prepared_packet_only"}, "browser": {"granted": True}, "shell": {"granted": False, "allowed_command_ids": []}, "network": {"granted": False}},
    }
    path = inputs / "manual.json"; path.write_text(json.dumps(capabilities), encoding="utf-8")
    result = prepare_assessment(ctx, capabilities_path=str(path))
    path.write_text("{}", encoding="utf-8")
    loaded = load_preparation(ctx, result["preparation_id"])
    assert loaded["capabilities"] == capabilities


def test_duplicate_json_keys_and_invalid_full_base_are_rejected(tmp_path: Path):
    ctx = assessment_context(tmp_path)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        _load_json_bytes(b'{"a":1,"a":2}')
    with pytest.raises(AssessmentPreparationError, match="full SHA"):
        prepare_assessment(ctx, base_commit="HEAD~1")


def test_mandatory_overflow_fails_and_supplemental_overflow_is_explicit(monkeypatch):
    def fake_source(ctx, path, mandatory, rules, reason, provenance):
        return {"path": path, "returned_git_path": path, "git_blob_hash": "a" * 40, "normalized_text_hash": "sha256:x", "size_bytes": 1, "text": "x", "mandatory": mandatory, "selection_rule_ids": rules, "selection_reason": reason, "provenance": provenance}
    monkeypatch.setattr(assessment_module, "_source", fake_source)
    monkeypatch.setattr(assessment_module, "_ci_candidates", lambda *args: [])
    with pytest.raises(AssessmentPreparationError, match="mandatory_source_budget"):
        assessment_module._role_sources(None, "product_assessment", set(), {f"src/{index}.py" for index in range(65)}, [], [])
    monkeypatch.setattr(assessment_module, "ROLE_FILE_LIMIT", 2)
    monkeypatch.setattr(assessment_module, "_config_candidates", lambda *args: [(f"cfg/{index}.toml", "relevant_configuration", 20) for index in range(3)])
    sources, coverage, _ = assessment_module._role_sources(None, "product_assessment", set(), {"src/main.txt"}, [], [])
    assert len(sources) == 2
    assert coverage["coverage_status"] == "bounded_incomplete" and coverage["files_omitted_due_to_cap"] == 2
    assert coverage["omitted_paths"] == ["cfg/1.toml", "cfg/2.toml"]


def test_assessment_prepare_cli_publishes_preparation_only(tmp_path: Path, capsys):
    ctx = assessment_context(tmp_path); release = tmp_path / "release.json"; release.write_text(json.dumps(ctx.release), encoding="utf-8")
    assert main(["assessment", "prepare", "--release", str(release), "--path", "product_assessment:docs/brief.md"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["preparation_id"].startswith("prep_")
    root = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment"
    assert (root / "active-preparation.json").is_file() and not (root / "current-assessment.json").exists()


def test_role_definitions_are_hashable_portable_method_contracts():
    roles = load_role_definitions()
    assert set(roles) == set(ALL_ROLES)
    for role, wrapped in roles.items():
        value = wrapped["value"]
        assert value["role_id"] == role and value["assessment_method"] and value["completion_rules"]
        assert value["forbidden_claims"] and value["reasoning_examples"]["adequate"] and value["reasoning_examples"]["inadequate"]
        assert wrapped["semantic_hash"].startswith("sha256:") and wrapped["snapshot_hash"].startswith("sha256:")
    discovery = load_discovery_registry()
    assert discovery["value"]["schema_version"] == "assessment-source-discovery.v1"
    assert "recursive import discovery" in discovery["value"]["unsupported"]
