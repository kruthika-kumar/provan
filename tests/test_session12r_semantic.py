from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest

from provan.canonical import canonical_bytes, sha256_bytes
from provan.errors import ProvanError
from provan.foundry import foundry, pattern_library
from provan.change_brief import explain
from provan.foundry_semantic import cleanup_source_bundle, create_source_authority_amendment, pattern_selection, verify_live_source_continuity
from provan.session12r_validators import hard_qualification, semantic_stability, validate_pattern_selection_serialized, validate_run_serialized, validate_source_coverage_serialized
from provan.state import secure_read, secure_write


def brief(home: Path, *, mutable: bool = False) -> dict:
    repo = home / "candidate-repo"; repo.mkdir()
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True, encoding="utf-8").stdout.strip()
    git("init"); git("config", "user.email", "fixture"); git("config", "user.name", "Fixture")
    (repo / "api").mkdir(); (repo / "api" / "schema.json").write_text('{"version":1}\n', encoding="utf-8")
    git("add", "."); git("commit", "-m", "base"); base = git("rev-parse", "HEAD")
    (repo / "api" / "schema.json").write_text('{"version":2}\n', encoding="utf-8")
    if not mutable:
        git("add", "."); git("commit", "-m", "head"); head = git("rev-parse", "HEAD")
    else:
        head = None
    return explain(repo=str(repo), base=base, head=head, working_tree=mutable, brief_text="The API schema must remain backward compatible.", agent_claim=None, context_files=[], aliases=[], journeys=[], journey_files=[], previous_brief=None, previous_manifest=None, provider_id=None, no_model=True)


def manifest(tmp_path: Path, *, yaml_source: bool = False) -> Path:
    if yaml_source:
        (tmp_path / "intent.yaml").write_text("# owner context must be reviewed\noutcome: API schema must remain backward compatible\nnon_goal: runtime execution is out of scope\n", encoding="utf-8")
        name = "intent.yaml"
    else:
        (tmp_path / "intent.md").write_text("The API schema must remain backward compatible.\nRuntime execution is a non-goal.\nFor example, old clients may retry.\n", encoding="utf-8")
        name = "intent.md"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"sources": [{"path": name, "role": "intent"}]}), encoding="utf-8")
    return path


def artifact_inputs(run: dict, brief_value: dict) -> tuple[dict, bytes]:
    root = Path("outputs/contract-foundry") / run["run_id"]
    bundle_raw = secure_read(root / "source-bundle.json")
    bundle = json.loads(bundle_raw)
    blobs = {row["source_id"]: secure_read(Path(row["blob_ref"]["path"]), allowed_suffixes=frozenset({".blob"})) for row in bundle["sources"]}
    artifacts = {
        "source_bundle": bundle_raw,
        "source_coverage": secure_read(root / "source-coverage.json"),
        "source_ledger": secure_read(root / "source-authority-ledger.json"),
        "intent": secure_read(root / "intent-model.json"),
        "candidate": secure_read(root / "contract-candidate.json"),
        "selection": canonical_bytes(run["pattern_selection"]),
        "projection": secure_read(root / "foundry-acceptance-projection.json"),
        "blobs": blobs,
    }
    return artifacts, canonical_bytes(brief_value)


def test_v2_pipeline_freezes_sources_and_independent_validator_recomputes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path)
    run, rendered = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), depth="standard", no_model=True, information_boundary="blind", view="owner-review", format_name="markdown")
    assert run["schema_id"] == "provan.internal.contract_foundry_run.v2"
    assert run["package_version"] == "0.5.1" and run["run_eligibility"] == "NOT_ELIGIBLE"
    assert run["measurements"]["cost_status"] == "unavailable" and run["measurements"]["cost_usd"] is None
    assert "Sources require" in rendered and run["execution_available"] is False
    artifacts, brief_raw = artifact_inputs(run, value)
    validate_run_serialized(canonical_bytes(run), artifacts, brief_raw, pattern_library())
    assert all(row["input_digests"] == [run["source_ledger_ref"]["sha256"]] for row in run["stage_execution"] if row["stage"] in {"blind_path_a", "blind_path_b"})


def test_yaml_comments_are_covered_and_wrongful_ignore_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path, yaml_source=True), no_model=True, information_boundary="blind")
    artifacts, _ = artifact_inputs(run, value); coverage = json.loads(artifacts["source_coverage"])
    comments = [row for row in coverage["items"] if row.get("reason_code") == "YAML_COMMENT_CONTEXTUAL_UNTRUSTED"]
    assert comments and all(row["classification"] == "untrusted_instruction" for row in comments)
    expected = {comments[0]["coverage_id"]: "untrusted_instruction"}
    validate_source_coverage_serialized(artifacts["source_coverage"], artifacts["source_bundle"], artifacts["blobs"], adjudicated_material=expected)
    bad = copy.deepcopy(coverage); next(row for row in bad["items"] if row["coverage_id"] == comments[0]["coverage_id"])["classification"] = "ignored"; bad["counts"]["classified_semantic"] -= 1; bad["counts"]["explicit_ignored"] += 1
    with pytest.raises(ProvanError, match="SESSION12R_MATERIAL_COVERAGE_MISCLASSIFIED"):
        validate_source_coverage_serialized(canonical_bytes(bad), artifacts["source_bundle"], artifacts["blobs"], adjudicated_material=expected)


def test_frozen_bytes_cannot_be_replaced_by_live_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path); source_manifest = manifest(tmp_path)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=source_manifest, no_model=True, information_boundary="blind")
    root = Path("outputs/contract-foundry") / run["run_id"]; bundle = json.loads(secure_read(root / "source-bundle.json")); original = json.loads(source_manifest.read_text()); rows = [{"source_id": "source-1", "sha256": bundle["sources"][0]["sha256"]}]
    verify_live_source_continuity(rows, bundle)
    rows[0]["sha256"] = sha256_bytes(b"replacement")
    with pytest.raises(ProvanError, match="FOUNDRY_LIVE_SOURCE_DIGEST_CHANGED"): verify_live_source_continuity(rows, bundle)


def test_mutable_candidate_is_explanatory_and_not_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path, mutable=True)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), no_model=True, information_boundary="blind")
    assert run["implementation_map"]["mutable_explanatory_only"] is True
    assert run["contract_readiness"] == "NOT_READY"


def test_deep_paths_and_standard_roles_are_stateless(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); monkeypatch.setenv("PROVAN_ALLOW_SCRIPTED_PROVIDER", "1"); value = brief(tmp_path)
    deep, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), depth="deep", provider_id="scripted-test", information_boundary="blind")
    assert deep["run_eligibility"] == "NOT_ELIGIBLE" and "SCRIPTED_PROVIDER_SEMANTICALLY_UNQUALIFIED" in deep["limitations"]
    trace = {row["stage"]: row for row in deep["stage_execution"]}
    assert trace["blind_path_a"]["input_digests"] == trace["blind_path_b"]["input_digests"] == [deep["source_ledger_ref"]["sha256"]]
    assert trace["blind_paths_freeze"]["input_digests"] == [row["output_digest"] for row in deep["deep_paths"]]
    assert trace["deep_synthesis"]["input_digests"] == trace["blind_paths_freeze"]["output_digests"]
    standard, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), depth="standard", provider_id="scripted-test", information_boundary="blind")
    roles = [row["role"] for row in standard["role_receipts"]]
    assert roles == ["blind_intent", "goal_premortem", "contract_proposer", "adversarial_auditor", "revision"]
    assert all(row["conversation_state"] is None and row["previous_response_id"] is None and row["background"] is False for row in standard["role_receipts"])


def test_source_authority_amendment_is_append_only_and_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), no_model=True, information_boundary="blind")
    root = Path("outputs/contract-foundry") / run["run_id"]; ledger = json.loads(secure_read(root / "source-authority-ledger.json")); statement = ledger["statements"][0]
    amendment = create_source_authority_amendment(run["run_id"], ledger, [{"statement_id": statement["statement_id"], "action": "reclassify", "reason": "case operator corrected contextual meaning"}], {"actor_label": "operator", "authority_scope": "case_source_interpretation", "identity_assurance": "self_asserted_label"})
    assert amendment["append_only"] is True and amendment["creates_owner_authority"] is False
    with pytest.raises(ProvanError, match="FOUNDRY_SOURCE_AMENDMENT_INVALID"):
        create_source_authority_amendment(run["run_id"], ledger, [{"statement_id": "missing", "action": "reclassify", "reason": "x"}], {"actor_label": "operator", "authority_scope": "case_source_interpretation"})


def test_pattern_selection_rejects_select_all_and_has_distinct_basis():
    candidate = {"candidate_id": "id", "criteria": [{"criterion_id": "c", "semantic_obligation": "API schema permission retry recovery AI state", "statement_refs": ["s"], "oracle_plan": {"status": "owner_confirmation_required", "oracle": "typed"}}]}
    selection = pattern_selection(candidate, pattern_library())
    assert len(selection["items"]) < len(pattern_library()["patterns"])
    assert len({(row["criterion_ref"], row["distinct_verification_contribution"]) for row in selection["items"]}) == len(selection["items"])


def test_independent_validator_rejects_mapping_stage_and_select_all_mutations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), no_model=True, information_boundary="blind"); artifacts, brief_raw = artifact_inputs(run, value)
    bad = copy.deepcopy(run); bad["stage_execution"][1]["input_digests"] = []
    with pytest.raises(ProvanError, match="SESSION12R_STAGE_DATAFLOW_INVALID"): validate_run_serialized(canonical_bytes(bad), artifacts, brief_raw, pattern_library())
    bad = copy.deepcopy(run); bad["implementation_map"]["criterion_mappings"][0] = {"criterion_id": bad["implementation_map"]["criterion_mappings"][0]["criterion_id"], "status": "supported", "surface_refs": [{"path": "missing", "surface_classes": ["api"]}], "reason_code": "invented"}
    with pytest.raises(ProvanError, match="SESSION12R_IMPLEMENTATION_MAP_UNSUPPORTED"): validate_run_serialized(canonical_bytes(bad), artifacts, brief_raw, pattern_library())
    candidate = json.loads(artifacts["candidate"]); library = pattern_library(); selection = json.loads(artifacts["selection"]); criterion = candidate["criteria"][0]
    selection["items"] = [{"pattern_ref": {"id": row["pattern_id"], "version": row["version"]}, "criterion_ref": criterion["criterion_id"], "failure_dimension": row["family"], "applicability_basis": criterion["statement_refs"], "oracle_need": criterion["oracle_plan"], "capability_requirement": row["capability_requirements"], "distinct_verification_contribution": row["family"], "limitations": row["limitations"], "status": "owner_confirmation_required"} for row in library["patterns"]]
    with pytest.raises(ProvanError, match="SESSION12R_PATTERN_SELECT_ALL_FORBIDDEN"): validate_pattern_selection_serialized(canonical_bytes(selection), artifacts["candidate"], library)


def test_cleanup_creates_digest_bound_tombstone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = brief(tmp_path)
    run, _ = foundry(brief_id=value["brief_id"], source_manifest=manifest(tmp_path), no_model=True, information_boundary="blind")
    tombstone = cleanup_source_bundle(run["run_id"])
    assert tombstone["raw_bytes_retained"] is False and tombstone["deleted"]
    with pytest.raises(FileNotFoundError): secure_read(Path("outputs/contract-foundry") / run["run_id"] / "source-bundle" / "blobs" / f"{tombstone['deleted'][0]['source_id'].removeprefix('sha256:')}.blob", allowed_suffixes=frozenset({".blob"}))


def test_hard_gate_and_semantic_stability_do_not_use_macro_rescue():
    ones = {key: 1 for key in ("material_explicit_obligation_recall", "valid_acceptance", "near_valid_acceptance", "adversarial_rejection", "material_ambiguity_owner_routing", "material_oracle_disposition_completeness", "material_finding_disposition_coverage", "material_obligation_map_disposition", "material_verification_dimension_disposition", "material_mutation_plan_sensitivity", "non_material_mutation_stability")}
    zeros = {key: 0 for key in ("unsupported_material_mandatory_criteria", "material_non_goal_errors", "exact_content_authority_errors", "implementation_authority_errors", "unaccounted_material_source", "wrongly_non_semantic_material_source", "wrongly_ignored_material_source", "unsupported_material_mappings_claimed_supported", "materially_irrelevant_patterns")}
    metrics = {**ones, **zeros, "six_run_semantic_stability": True}
    assert hard_qualification(metrics) == "PASS"
    metrics["material_explicit_obligation_recall"] = .999
    assert hard_qualification(metrics) == "FAIL"
    semantic = {"material_obligations": ["a"], "non_goals": ["b"], "exact_content_rules": ["c"], "material_ambiguities": ["d"], "core_verification_dimensions": ["e"]}
    stable = semantic_stability([semantic, {**semantic, "wording": "different"}, {**semantic, "wording": "another"}])
    assert stable["semantic_stable"] is True and stable["byte_identity_required"] is False
