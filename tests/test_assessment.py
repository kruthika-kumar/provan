from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import venv
from importlib import resources
from pathlib import Path

import pytest
import shiproom.assessment as assessment_module

from shiproom.assessment import (
    ALL_ROLES,
    AssessmentPreparationError,
    _load_json_bytes,
    _python_imports,
    _javascript_imports,
    _browser_placeholder,
    _authorized_browser_target,
    _canonical_browser_url,
    _test_matches,
    _validate_work_order,
    load_discovery_registry,
    _work_order_hash,
    default_capabilities,
    load_preparation,
    load_role_definitions,
    prepare as prepare_assessment,
)
from shiproom.cli import main
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input, mapping_prepare
from shiproom.intent import _load_packet, compile_bundle as compile_intent, prepare as prepare_intent
from test_intent import context_for, inbox, proposal
from shiproom.project import content_hash


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def assessment_context(tmp_path: Path, *, mapped: bool = False):
    tmp_path.mkdir(parents=True, exist_ok=True)
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


def browser_assessment_context(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True); ctx = context_for(tmp_path); packet = prepare_intent(ctx, ["docs/brief.md"], []); data = proposal(packet); data["criteria"][0]["required_evidence_categories"] = ["browser_or_http"]
    path = inbox(ctx); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data), encoding="utf-8"); compile_intent(ctx, str(path)); compile_graph(ctx)
    inputs = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/inputs"; inputs.mkdir(parents=True)
    capabilities = default_capabilities(); capabilities["capabilities"]["browser"]["available"] = True; capabilities["permissions"]["browser"]["granted"] = True
    capability_path = inputs / "browser.json"; write_json(capability_path, capabilities)
    return ctx, capability_path


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def rehash_preparation(ctx, preparation_id: str) -> Path:
    root = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment"
    directory = root / "preparations" / preparation_id
    source_path = directory / "assessment-source-packet.json"; source = json.loads(source_path.read_text())
    source["packet_hash"] = content_hash({key: value for key, value in source.items() if key != "packet_hash"}); write_json(source_path, source)
    contexts = {}
    for path in (directory / "role-context").glob("*.json"):
        value = json.loads(path.read_text()); value["packet_hash"] = content_hash({key: item for key, item in value.items() if key != "packet_hash"}); write_json(path, value); contexts[value["role_id"]] = value
    works = {}
    for path in (directory / "work-orders").glob("*.json"):
        value = json.loads(path.read_text()); role = value["role_id"]
        if role in contexts: value["inputs"]["packet_hash"] = contexts[role]["packet_hash"]
        value["work_order_hash"] = _work_order_hash(value); write_json(path, value); works[value["work_order_id"]] = (value, path)
    manifest_path = directory / "assessment-work-orders.json"; manifest = json.loads(manifest_path.read_text())
    manifest["source_packet_hash"] = source["packet_hash"]
    for entry in manifest["work_orders"]:
        if entry["work_order_id"] in works:
            work, path = works[entry["work_order_id"]]; entry["work_order_hash"] = work["work_order_hash"]; entry["work_order_snapshot_hash"] = sha(path)
    manifest["manifest_hash"] = content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"}); write_json(manifest_path, manifest)
    pointer_path = root / "active-preparation.json"; pointer = json.loads(pointer_path.read_text()); pointer["preparation_semantic_hash"] = manifest["preparation_semantic_hash"]; pointer["manifest_snapshot_hash"] = sha(manifest_path); write_json(pointer_path, pointer)
    return directory


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


@pytest.mark.parametrize("tamper", ["graph_fact", "allowed_path", "shell_command", "browser_target", "assigned_id", "role"])
def test_fully_rehashed_role_and_work_order_semantic_tampering_is_rejected(tmp_path: Path, tamper: str):
    ctx = assessment_context(tmp_path); result = prepare_assessment(ctx); directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]
    product_context = directory / "role-context/product_assessment.json"; context = json.loads(product_context.read_text())
    product_entry = next(item for item in result["work_orders"] if item["role_id"] == "product_assessment"); work_path = directory / product_entry["work_order_path"]; work = json.loads(work_path.read_text())
    if tamper == "graph_fact": context["base_graph_context"]["nodes"][0]["provenance"] = "canonical_release_state"
    elif tamper == "allowed_path": work["inputs"]["allowed_paths"].append("docs/other.md")
    elif tamper == "shell_command": work["permissions"]["shell"]["allowed_commands"] = [{"command_id":"invented","criterion_id":"invented","required_for_release":False,"argv":["python","-V"],"cwd":".","purpose":"Invented command","source":{"ref":"docs/brief.md","hash":"sha256:"+"1"*64},"timeout_seconds":10,"output_limit_bytes":1024,"allowed_environment":{}}]
    elif tamper == "browser_target": work["permissions"]["browser"]["allowed_targets"] = [{"url":"https://example.test/admin","origin":"https://example.test","path_pattern":"/admin","authority":"deployment_grant"}]
    elif tamper == "assigned_id": work["inputs"]["criterion_ids"] = ["criterion_fabricated"]
    else: work["role_id"] = "engineering_assessment"
    write_json(product_context, context); write_json(work_path, work); rehash_preparation(ctx, result["preparation_id"])
    with pytest.raises(ValueError): load_preparation(ctx)


def test_fully_rehashed_change_impact_and_manifest_role_tampering_is_rejected(tmp_path: Path):
    ctx = assessment_context(tmp_path); result = prepare_assessment(ctx); directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]
    source_path = directory / "assessment-source-packet.json"; source = json.loads(source_path.read_text()); source["change_impact"] = {"status":"unavailable","authority":"none","reason_code":"tampered"}; write_json(source_path, source)
    for path in (directory / "role-context").glob("*.json"):
        value = json.loads(path.read_text()); value["change_impact"] = source["change_impact"]; write_json(path, value)
    rehash_preparation(ctx, result["preparation_id"])
    with pytest.raises(ValueError): load_preparation(ctx)

    ctx = assessment_context(tmp_path / "roles"); result = prepare_assessment(ctx); directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]
    manifest_path = directory / "assessment-work-orders.json"; manifest = json.loads(manifest_path.read_text()); manifest["work_orders"][1]["role_id"] = manifest["work_orders"][0]["role_id"]; write_json(manifest_path, manifest); rehash_preparation(ctx, result["preparation_id"])
    with pytest.raises(ValueError): load_preparation(ctx)


def test_manifest_role_set_removal_and_swap_are_rejected(tmp_path: Path):
    for mode in ("remove", "swap"):
        ctx = assessment_context(tmp_path / mode); result = prepare_assessment(ctx); directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]
        path = directory / "assessment-work-orders.json"; manifest = json.loads(path.read_text())
        if mode == "remove": manifest["work_orders"].pop()
        else: manifest["work_orders"][0], manifest["work_orders"][1] = manifest["work_orders"][1], manifest["work_orders"][0]
        write_json(path, manifest); rehash_preparation(ctx, result["preparation_id"])
        with pytest.raises(ValueError): load_preparation(ctx)


def test_role_contexts_are_bounded_specific_and_do_not_embed_complete_artifacts(tmp_path: Path):
    ctx = assessment_context(tmp_path); result = prepare_assessment(ctx, owner_paths=["product_assessment:docs/brief.md"]); loaded = load_preparation(ctx)
    product = loaded["contexts"]["product_assessment"]; engineering = loaded["contexts"]["engineering_assessment"]; browser = loaded["contexts"]["browser_journey"]
    for context in loaded["contexts"].values():
        assert "intent_artifacts" not in context and "base_graph_artifacts" not in context and "mapping_packet_snapshot" not in context
        assert len(json.dumps({"intent":context["intent_context"],"graph":context["base_graph_context"]}).encode()) <= 2 * 1024 * 1024
    assert product["intent_context"]["product_intent"] is not None and engineering["intent_context"]["product_intent"] is None
    assert [item["path"] for item in product["sources"]] == ["docs/brief.md"]
    assert browser["sources"] == [] and browser["assigned_criteria"] == []


def test_browser_assignment_is_criterion_targeted_and_repository_free_by_default(tmp_path: Path):
    ctx, capability_path = browser_assessment_context(tmp_path)
    result = prepare_assessment(ctx, capabilities_path=str(capability_path)); loaded = load_preparation(ctx); browser = loaded["contexts"]["browser_journey"]
    assert len(browser["assigned_criteria"]) == 1 and browser["assigned_criteria"][0]["required_evidence_categories"] == ["browser_or_http"]
    assert browser["assigned_journeys"] and browser["browser_criterion_targets"][0]["criterion_id"] == browser["assigned_criteria"][0]["criterion_id"]
    assert browser["sources"] == []
    work = loaded["work_orders"]["browser_journey"]
    assert work["inputs"]["criterion_ids"] == [browser["assigned_criteria"][0]["criterion_id"]] and work["permissions"]["browser"]["allowed_targets"]


def test_fully_rehashed_browser_target_widening_is_rejected(tmp_path: Path):
    ctx, capability_path = browser_assessment_context(tmp_path); result = prepare_assessment(ctx, capabilities_path=str(capability_path)); directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]
    entry = next(item for item in result["work_orders"] if item["role_id"] == "browser_journey"); path = directory / entry["work_order_path"]; work = json.loads(path.read_text()); work["permissions"]["browser"]["allowed_targets"].append({"url":"https://example.test/admin","origin":"https://example.test","path_pattern":"/admin","authority":"deployment_grant"}); write_json(path, work); rehash_preparation(ctx, result["preparation_id"])
    with pytest.raises(ValueError): load_preparation(ctx)


def test_pointer_semantic_hash_binding_is_directly_validated(tmp_path: Path):
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); path = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/active-preparation.json"; pointer = json.loads(path.read_text()); pointer["preparation_semantic_hash"] = "sha256:" + "f" * 64; write_json(path, pointer)
    with pytest.raises(ValueError, match="pointer semantic binding"): load_preparation(ctx)


def test_loader_uses_snapshotted_roles_and_has_explicit_compiler_gate(tmp_path: Path, monkeypatch):
    ctx = assessment_context(tmp_path); result = prepare_assessment(ctx)
    monkeypatch.setattr(assessment_module, "load_role_definitions", lambda: (_ for _ in ()).throw(AssertionError("installed roles must not be loaded")))
    assert load_preparation(ctx, result["preparation_id"])["manifest"]["preparation_id"] == result["preparation_id"]
    directory = ctx.repository_root / ".shiproom/local/releases/rel_intent/assessment/preparations" / result["preparation_id"]; manifest_path = directory / "assessment-work-orders.json"; manifest = json.loads(manifest_path.read_text()); manifest["compiler_version"] = "assessment-preparation.v5"; write_json(manifest_path, manifest); rehash_preparation(ctx, result["preparation_id"])
    with pytest.raises(ValueError, match="stale_assessment_preparation_compiler_version"): load_preparation(ctx)


def test_phase4a_json_schema_mirrors_accept_generated_contracts_and_reject_extras(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema")
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); loaded = load_preparation(ctx)
    contracts = [
        ("assessment-capabilities.v1.json", loaded["capabilities"]),
            ("assessment-source-packet.v3.json", loaded["source_packet"]),
            ("assessment-work-orders.v3.json", loaded["manifest"]),
    ]
    contracts.extend(("assessment-role.v1.json", item["value"]) for item in load_role_definitions().values())
    contracts.extend(("work-order.v3.json", item) for item in loaded["work_orders"].values())
    for schema_name, value in contracts:
        schema = json.loads(resources.files("shiproom.assessment_schemas").joinpath(schema_name).read_text(encoding="utf-8")); jsonschema.validate(value, schema)
        invalid = dict(value); invalid["unexpected"] = True
        with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)


def test_work_order_v3_role_versions_and_result_schemas_are_role_conditional(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema"); ctx, capability_path = browser_assessment_context(tmp_path); prepare_assessment(ctx, capabilities_path=str(capability_path)); loaded = load_preparation(ctx)
    schema = json.loads(resources.files("shiproom.assessment_schemas").joinpath("work-order.v3.json").read_text())
    for role, work in loaded["work_orders"].items():
        jsonschema.validate(work, schema)
        assert work["role_version"] == ("3.0.0" if role == "browser_journey" else "2.0.0")
        assert work["required_output"]["schema_path"].endswith("browser-journey-result.v3.json" if role == "browser_journey" else "-result.v2.json")
        invalid=json.loads(json.dumps(work)); invalid["role_version"]="2.0.0" if role=="browser_journey" else "3.0.0"; invalid["work_order_hash"]=_work_order_hash(invalid)
        with pytest.raises(ValueError, match="role version"): _validate_work_order(invalid)
        with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)


def test_canonical_browser_url_preserves_query_and_rejects_fragments_and_escapes():
    assert _canonical_browser_url("HTTPS://Example.TEST:443/result?id=A%20B")[0] == "https://example.test/result?id=A%20B"
    for invalid in ("https://example.test/result#route", "https://example.test/a/%2e%2e/b", "https://example.test/a%2fb", "https://user@example.test/a", "https://example.test/a\\b", "https://exämple.test/a"):
        with pytest.raises(ValueError): _canonical_browser_url(invalid)


def test_browser_target_issuance_uses_strict_canonical_urls():
    valid=_authorized_browser_target("https://example.test",["/result"],"HTTPS://EXAMPLE.TEST:443/result?view=full","canonical_runtime_target")
    assert valid == {"url":"https://example.test/result?view=full","origin":"https://example.test","path_pattern":"/result","authority":"canonical_runtime_target"}
    invalid=("https://example.test/result#route","https://example.test/re sult","https://example.test/a%2fb","https://example.test/a/%2e%2e/b","https://user@example.test/result","https://exämple.test/result","/a/../result","//result")
    assert all(_authorized_browser_target("https://example.test",["/result", "/a/*"],value,"canonical_runtime_target") is None for value in invalid)


@pytest.mark.parametrize("role", ["product_assessment", "test_adequacy", "targeted_test_planning"])
def test_role_graph_context_gap_basis_is_referentially_closed(tmp_path: Path, role: str):
    ctx = assessment_context(tmp_path); prepare_assessment(ctx); role_context = load_preparation(ctx)["contexts"][role]; context = role_context["base_graph_context"]
    node_ids = {item["node_id"] for item in context["nodes"]}; edge_ids = {item["edge_id"] for item in context["edges"]}
    assert context["gaps"]
    assert all(item["source_node_id"] in node_ids and item["target_node_id"] in node_ids for item in context["edges"])
    assert all(gap["criterion_id"] in {item["criterion_id"] for item in role_context["assigned_criteria"]} and set(gap["basis_node_ids"]) <= node_ids and set(gap["basis_edge_ids"]) <= edge_ids for gap in context["gaps"])


def test_explicit_release_browser_target_authority_is_rejected_by_python_and_schema(tmp_path: Path):
    jsonschema = pytest.importorskip("jsonschema"); ctx, capability_path = browser_assessment_context(tmp_path); prepare_assessment(ctx, capabilities_path=str(capability_path)); work = load_preparation(ctx)["work_orders"]["browser_journey"]
    invalid = json.loads(json.dumps(work)); invalid["permissions"]["browser"]["allowed_targets"][0]["authority"] = "explicit_release_browser_target"; invalid["work_order_hash"] = _work_order_hash(invalid)
    with pytest.raises(ValueError, match="browser target"): _validate_work_order(invalid)
    schema = json.loads(resources.files("shiproom.assessment_schemas").joinpath("work-order.v3.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)


def test_assessment_contracts_are_packaged_resources_and_browser_v1_is_unchanged():
    names={item.name for item in resources.files("shiproom.assessment_schemas").iterdir() if item.name.endswith(".json")}
    assert {"work-order.v1.json","work-order.v2.json","work-order.v3.json","browser-journey-result.v1.json","browser-journey-result.v2.json","browser-journey-result.v3.json","browser-journey.v2.json","browser-journey.v3.json","effective-assessment-view.v3.json","portable-assessment-manifest.v3.json"}.issubset(names)
    legacy=json.loads(resources.files("shiproom.assessment_schemas").joinpath("browser-journey-result.v1.json").read_text())
    assert legacy["$id"] == "browser-journey-result.v1.json"


def test_installed_wheel_prepares_assessment_outside_source_checkout(tmp_path: Path):
    project=Path(__file__).resolve().parents[1]; build_source=tmp_path/"wheel-source"; build_source.mkdir()
    shutil.copy2(project/"pyproject.toml",build_source/"pyproject.toml")
    shutil.copy2(project/"LICENSE",build_source/"LICENSE")
    shutil.copytree(project/"shiproom",build_source/"shiproom")
    shutil.copytree(project/"demo_patient",build_source/"demo_patient")
    wheelhouse=tmp_path/"wheelhouse"; wheelhouse.mkdir()
    build_python=Path(sys.executable)
    if importlib.util.find_spec("wheel") is None:
        bundled=Path.home()/".cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe"
        if not bundled.is_file(): pytest.skip("wheel build backend is unavailable")
        build_python=bundled
    build_env={**os.environ,"PIP_NO_CACHE_DIR":"1"}
    subprocess.run([str(build_python),"-m","pip","wheel","--no-deps","--no-build-isolation","-w",str(wheelhouse),str(build_source)],env=build_env,check=True,capture_output=True,text=True)
    environment=tmp_path/"installed"; venv.EnvBuilder(with_pip=True,system_site_packages=True).create(environment)
    python=environment/("Scripts/python.exe" if os.name=="nt" else "bin/python"); command=environment/("Scripts/shiproom.exe" if os.name=="nt" else "bin/shiproom")
    wheel=next(wheelhouse.glob("shiproom-*.whl")); subprocess.run([str(python),"-m","pip","install","--no-deps",str(wheel)],check=True,capture_output=True,text=True)
    ctx=assessment_context(tmp_path/"external-repository")
    # This external-wheel patient has one canonical, actionable finding.  The
    # installed commands below therefore exercise the connected Session 6--8
    # lifecycle rather than merely the empty-generation happy path.
    graph = load_assessment_input(ctx)
    criterion = graph["intent_artifacts"]["acceptance-criteria.json"]["criteria"][0]["criterion_id"]
    ctx.release["findings"] = [{"id":"finding_wheel","criterion_id":criterion,"requirement_id":"requirement_wheel","journey_ids":[],"blocker":True,"state":"OPEN","evidence_class":"deterministically_established","criterion_authority":"deterministically_established","owner_decision_required":False,"automation_class":"exact_route_mismatch"}]
    compile_graph(ctx)
    release_path=ctx.repository_root/"release.json"; write_json(release_path,ctx.release)
    env={key:value for key,value in os.environ.items() if key not in {"PYTHONPATH","PYTHONHOME"}}
    wheel_commands=[]; evidence_target=os.environ.get("SHIPROOM_WHEEL_SMOKE_EVIDENCE"); log_root=(Path(evidence_target).parent/"wheel-command-logs") if evidence_target else tmp_path/"wheel-command-logs"; log_root.mkdir(parents=True,exist_ok=True)
    def installed(arguments, *, expect=0):
        completed=subprocess.run(arguments,cwd=ctx.repository_root,env=env,check=False,capture_output=True,text=True)
        index=len(wheel_commands);stdout_path=log_root/f"{index:02d}.stdout.txt";stderr_path=log_root/f"{index:02d}.stderr.txt";stdout_path.write_bytes(completed.stdout.encode("utf-8"));stderr_path.write_bytes(completed.stderr.encode("utf-8"))
        wheel_commands.append({"command":arguments[1:] if len(arguments)>1 else arguments,"exit_code":completed.returncode,"stdout_path":str(stdout_path),"stderr_path":str(stderr_path),"stdout_hash":"sha256:"+hashlib.sha256(completed.stdout.encode()).hexdigest(),"stderr_hash":"sha256:"+hashlib.sha256(completed.stderr.encode()).hexdigest(),"status":"passed" if completed.returncode==expect else "unexpected"})
        assert completed.returncode==expect, completed.stderr
        return completed
    imported=installed([str(python),"-c","import shiproom; print(shiproom.__file__)" ]).stdout.strip()
    assert str(project).lower() not in imported.lower() and "site-packages" in imported.lower()
    installed([str(command),"assessment","prepare","--release",str(release_path)])
    installed([str(command),"measurement-ai","prepare","--release",str(release_path),"--review-mode","contract_only"])
    installed([str(command),"measurement-ai","compile","--release",str(release_path)])
    shown=installed([str(command),"measurement-ai","show","--release",str(release_path)]).stdout
    assert "Measurement & AI Readiness" in shown and "no_applicable_measurement_or_ai_surface" in shown
    # Sessions 6--8 must remain operable from the installed distribution, not
    # merely importable from it.  These commands consume the persisted native
    # Product Intent/graph state created above.
    installed([str(command),"remediation-roadmap","prepare","--release",str(release_path)])
    installed([str(command),"remediation-roadmap","compile","--release",str(release_path)])
    remediation_show = installed([str(command),"remediation-roadmap","show","--release",str(release_path)])
    assert "remediation-index" in remediation_show.stdout
    remediation_root = ctx.repository_root / ".shiproom/local/releases" / ctx.release["release_id"] / "remediation"
    remediation_pointer = json.loads((remediation_root / "current-remediation-generation.json").read_text(encoding="utf-8"))
    remediation_plan = json.loads((remediation_root / "generations" / remediation_pointer["generation"] / "remediation-plan.json").read_text(encoding="utf-8"))
    packet = remediation_plan["packets"][0]; closure_id = packet["verification_contract_id"]
    closure_dir = remediation_root / "closure-inbox" / closure_id; closure_dir.mkdir(parents=True)
    branch = ctx.release.get("repository", {}).get("branch") or ctx.release.get("branch") or "owner_action_required"
    evidence = {"schema_version":"remediation-closure-evidence.v1","closure_contract_id":closure_id,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"branch":branch,"fixer_id":"wheel_fixer","reruns":[{"check_id":packet["source_issue_id"],"passed":True,"evidence_class":"deterministically_established"}],"regression_results":[],"test_results":[],"instrumentation_results":[],"protected_invariant_outcomes":[{"invariant":"canonical_findings_unchanged","passed":True}]}
    invalid_evidence={**evidence,"reruns":[{"check_id":"wrong_check","passed":True,"evidence_class":"deterministically_established"}]};invalid_raw=(json.dumps(invalid_evidence,sort_keys=True,indent=2)+"\n").encode("utf-8")
    (closure_dir/"evidence.json").write_bytes(invalid_raw);write_json(closure_dir/"verifier-receipt.json",{"schema_version":"remediation-closure-verifier-receipt.v1","closure_contract_id":closure_id,"evidence_snapshot_hash":"sha256:"+hashlib.sha256(invalid_raw).hexdigest(),"verifier_id":"wheel_verifier","executor_type":"human"})
    rejected_closure=installed([str(command),"remediation-roadmap","closure-verify","--release",str(release_path),"--closure-contract",closure_id]);assert json.loads(rejected_closure.stdout)["status"]=="unsatisfied"
    evidence_raw=(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode("utf-8")
    closure_receipt={"schema_version":"remediation-closure-verifier-receipt.v1","closure_contract_id":closure_id,"evidence_snapshot_hash":"sha256:"+hashlib.sha256(evidence_raw).hexdigest(),"verifier_id":"wheel_verifier","executor_type":"human"}
    (closure_dir / "evidence.json").write_bytes(evidence_raw); write_json(closure_dir / "verifier-receipt.json", closure_receipt)
    closure = installed([str(command),"remediation-roadmap","closure-verify","--release",str(release_path),"--closure-contract",closure_id])
    assert json.loads(closure.stdout)["status"] == "satisfied_candidate"
    installed([str(command),"review-plan","prepare","--release",str(release_path)])
    package=installed([str(command),"review-plan","render-package","--release",str(release_path),"--specialist","product_intent"])
    package_value=json.loads(package.stdout); assert package_value["schema_version"] == "codex-execution-package.v1"
    work_order_id=package_value["native_work_order"]["work_order_id"]
    review_inbox=ctx.repository_root / ".shiproom/local/releases" / ctx.release["release_id"] / "review-organisation" / "inbox" / work_order_id
    review_inbox.mkdir(parents=True)
    # Attempt one is structurally invalid and must create a compiler-owned
    # revision record; no generic result path is accepted by the CLI.
    write_json(review_inbox / "result.json", {}); write_json(review_inbox / "completion-receipt.json", {})
    invalid_submit=installed([str(command),"review-plan","submit-result","--release",str(release_path),"--specialist","product_intent","--result",str(review_inbox / "result.json"),"--receipt",str(review_inbox / "completion-receipt.json")])
    assert json.loads(invalid_submit.stdout)["status"] == "revision_required"
    corrected_package=json.loads(installed([str(command),"review-plan","render-package","--release",str(release_path),"--specialist","product_intent"]).stdout)
    corrected_order=corrected_package["native_work_order"]["work_order_id"]
    corrected_inbox=ctx.repository_root / ".shiproom/local/releases" / ctx.release["release_id"] / "review-organisation" / "inbox" / corrected_order
    corrected_inbox.mkdir(parents=True, exist_ok=True)
    intent_packet, _ = _load_packet(ctx); corrected_result=proposal(intent_packet)
    corrected_receipt={"schema_version":"harness-execution-receipt.v1","work_order_id":corrected_order,"execution_mode":"manual_external","declared_capability":"prepared_packet_only","granted_permission":"read_only","observed_execution":"receipt_observed","execution_receipt":"wheel-connected","independence_limitation":"declared capability is not proof of isolation"}
    write_json(corrected_inbox / "result.json", corrected_result); write_json(corrected_inbox / "completion-receipt.json", corrected_receipt)
    corrected_submit=installed([str(command),"review-plan","submit-result","--release",str(release_path),"--specialist","product_intent","--result",str(corrected_inbox / "result.json"),"--receipt",str(corrected_inbox / "completion-receipt.json")])
    corrected_value=json.loads(corrected_submit.stdout); assert corrected_value["status"] == "accepted"
    # A real accepted native result can drive a successor plan.  The CLI owns
    # the trigger validation and publishes the successor pointer last.
    adapted=installed([str(command),"review-plan","adapt","--release",str(release_path),"--trigger","migration_surface_discovered","--specialist","product_intent","--criterion",criterion,"--evidence-id",corrected_value["result_id"]])
    assert json.loads(adapted.stdout)["status"] == "accepted"
    installed([str(command),"review-plan","show","--release",str(release_path)])
    # Contestation reads a release-bound owner authority; it never accepts an
    # actor label as proof.  Use a non-owner defer action for the wheel route.
    action_path=ctx.repository_root / ".shiproom/local/releases" / ctx.release["release_id"] / "contestation-action.json"
    write_json(action_path,{"action_id":"wheel_defer","release_id":ctx.release["release_id"],"actor_type":"reviewer","actor_label":"wheel","action":"defer","target_type":"finding","target_id":"finding_wheel","source_generation":"release_state","submitted_evidence":None,"rationale":"connected wheel lifecycle","created_at":"2026-01-01T00:00:00+00:00","owner_authority_ref":None,"owner_authority_snapshot_hash":None})
    installed([str(command),"contestation","add","--release",str(release_path),"--input",str(action_path)])
    installed([str(command),"contestation","show","--release",str(release_path)])
    installed([str(command),"management-artifacts","compile","--release",str(release_path)])
    installed([str(command),"management-artifacts","show","--release",str(release_path)])
    if evidence_target:
        artifact_root=ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]
        artifact_rows=[]
        for artifact in sorted(path for path in artifact_root.rglob("*") if path.is_file()):
            artifact_rows.append({"relative_path":artifact.relative_to(ctx.repository_root).as_posix(),"sha256":"sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest(),"size_bytes":artifact.stat().st_size})
        Path(evidence_target).write_text(json.dumps({"wheel_sha256":"sha256:"+hashlib.sha256(wheel.read_bytes()).hexdigest(),"installed_distribution":wheel.name,"shiproom_executable":str(command),"shiproom_module_path":imported,"site_packages_root":str(environment/"Lib/site-packages"),"source_checkout_not_on_sys_path":str(project).lower() not in imported.lower(),"external_working_directory":str(ctx.repository_root),"artifacts":artifact_rows,"commands":wheel_commands},sort_keys=True,indent=2),encoding="utf-8")


def test_browser_placeholders_are_criterion_specific():
    criteria=[
        {"criterion_id":"criterion_issued","required_evidence_categories":["browser_or_http"]},
        {"criterion_id":"criterion_limited","required_evidence_categories":["browser_or_http"]},
        {"criterion_id":"criterion_unrelated","required_evidence_categories":["owner_confirmation"]},
        {"criterion_id":"criterion_unauthorized","required_evidence_categories":["browser_or_http"]},
    ]
    target={"url":"https://example.test/result/1","origin":"https://example.test","path_pattern":"/result/1","authority":"deployment_grant"}
    preparation={"source_packet":{"population":{"criteria":criteria},"browser_work_order":{"issued":True,"reason_code":None,"assigned_criterion_ids":["criterion_issued"],"scope_limited_criterion_ids":["criterion_limited"],"criterion_targets":[{"criterion_id":"criterion_issued","targets":[target]}]}},"manifest":{"work_orders":[{"role_id":"browser_journey","work_order_id":"wo_browser_journey_0123456789abcdef"}]}}
    records={item["criterion_id"]:item for item in _browser_placeholder(preparation)["criteria"]}
    assert records["criterion_issued"]["status"] == "not_inspected" and records["criterion_issued"]["authorized_targets"] == [target]
    assert records["criterion_limited"]["reason_code"] == "browser_scope_insufficient"
    assert records["criterion_unrelated"]["reason_code"] == "not_browser_relevant"
    assert records["criterion_unauthorized"]["reason_code"] == "no_authorized_browser_target"
