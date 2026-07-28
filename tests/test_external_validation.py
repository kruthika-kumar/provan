from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from shiproom.external_validation.identity import cost_view_id, observation_key, schedule_id, case_id, attempt_id
from shiproom.external_validation.registry import registrations_are_resolvable
from shiproom.external_validation.security import validate_public_tree, validate_case_paths
from shiproom.external_validation.validators import ValidationError, validate_artifact
from shiproom.external_validation.runner import DockerPolicy, docker_argv, validate_docker_argv, run_container, create_remediation_worktree, tree_snapshot
from shiproom.external_validation.scheduler import RunScheduler
from shiproom.external_validation.adapters import ARMS, ArmContext, SyntheticAdapter, assert_context_equivalence
from shiproom.external_validation.corpus import validate_corpus
from shiproom.external_validation.receipts import finalize_receipt
from shiproom.external_validation.synthetic import SCENARIOS, five_arm_smoke, scenario_output
from shiproom.external_validation.cache import dependency_cache, arm_output_root, reject_derived_cache
from shiproom.external_validation.materialize import materialize_snapshot
from importlib import resources


SHA = "a" * 40
HASH = "sha256:" + "b" * 64
APPLICABILITY = {name: ("applicable" if name == "ENGINEERING_EXECUTION" else "not_applicable") for name in ("ENGINEERING_EXECUTION", "PRODUCT_JOURNEY", "PRODUCT_MEASUREMENT", "DATA_CONTRACT_PIPELINE", "AI_EVAL")}


def _case(schema_id: str = "external_validation.beta_case") -> dict:
    dataset = {"external_validation.beta_case": "beta", "external_validation.controlled_pair_case": "controlled", "external_validation.natural_pr_case": "natural"}[schema_id]
    authority = {"dataset": dataset, "snapshot": HASH, "repository": "public/repo", "commit_sha": SHA, "manifest_version": "1", "release_surfaces":["ENGINEERING_EXECUTION"], "applicability":APPLICABILITY}
    item = {"schema_id": schema_id, "schema_version": "1", "case_id": case_id(authority), "case_authority": authority, "repository": "public/repo", "commit_sha": SHA, "snapshot_hash": HASH, "release_surfaces": ["ENGINEERING_EXECUTION"], "applicability": APPLICABILITY, "visible_patient_root": "/patient"}
    if schema_id == "external_validation.controlled_pair_case":
        item.update({"buggy_sha": SHA, "fixed_sha": "c" * 40, "target_id": "t1", "oracle_ref": "/private/oracle", "oracle_commitment": HASH, "release_packet_hash": HASH, "target_clearance": "named_target_only"})
        authority.update({"buggy_sha": SHA, "fixed_sha": "c" * 40, "target_id": "t1", "oracle_commitment": HASH, "release_packet_hash": HASH})
    if schema_id == "external_validation.natural_pr_case": item.update({"pr_number": 1, "context_refs": ["README.md"]}); authority.update({"pr_number":1,"context_refs":["README.md"]})
    item["case_id"] = case_id(authority)
    return item


def _seal(item: dict) -> dict:
    """Test-side supervisor equivalent; production recomputes independently."""
    item = copy.deepcopy(item)
    item["receipt_id"] = ""; item["hashes"]["receipt"] = ""
    payload = dict(item); payload.pop("receipt_id"); hashes = dict(payload["hashes"]); hashes.pop("receipt"); payload["hashes"] = hashes
    digest = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    item["hashes"]["receipt"] = digest; item["receipt_id"] = "receipt_" + digest.removeprefix("sha256:")
    return item


def _receipt() -> dict:
    case = _case(); obs = {"case_id":case["case_id"],"snapshot_hash":HASH,"arm":"NATIVE_CHECKS_ONLY","system_version":"s1","prompt_version":"p1","policy_version":"p1","model":"none","model_settings":{},"model_sampling_seed":None,"tool_policy_version":"t1","execution_policy_version":"e1","cache_mode":"cold"}; observation = observation_key(obs)
    item = {"schema_id": "external_validation.run_receipt", "schema_version": "1", "receipt_id": "", "observation_key": observation, "observation_inputs": obs, "attempt_id": attempt_id(observation,1), "attempt_lineage":1, "case_id": case["case_id"], "dataset": "beta", "snapshot_type": "buggy", "arm": "NATIVE_CHECKS_ONLY", "repository": "public/repo", "pr_number": None, "maturity_band":"beta", "base_sha": SHA, "target_sha":SHA, "commit_sha": SHA, "release_surfaces": ["ENGINEERING_EXECUTION"], "applicability":APPLICABILITY, "hashes": {"source": HASH, "release_packet": HASH, "output": HASH, "receipt": ""}, "versions": {"shiproom_commit":"s1","container_image":"img@sha256:a","model":"none","model_version":"none","prompt_version":"p1","policy_version":"p1","execution_policy_version":"e1","tool_policy_version":"t1","price_version":"not_applicable"}, "started_at": "2026-07-24T00:00:00Z", "completed_at": "2026-07-24T00:00:01Z", "terminal_state": "completed", "termination":"completed", "checks": {"attempted": [], "passed": [], "failed": [], "skipped": [], "skip_reasons":{},"duration_seconds":0}, "model_usage": {"state": "not_applicable"}, "cost": {"state": "not_applicable"}, "totals":{"wall_time_seconds":1,"local_compute_seconds":0,"model_cost_usd":0,"external_tool_cost_usd":0}, "findings": [], "logs": {"command_log": HASH}, "supervisor": "host_supervisor"}
    return _seal(item)


def test_case_validators_are_independent_from_jsonschema(monkeypatch):
    import shiproom.external_validation.validators as validators
    monkeypatch.setitem(__import__("sys").modules, "jsonschema", None)
    assert validate_artifact(_case())["case_id"].startswith("case_")
    invalid = _case(); invalid["commit_sha"] = "main"
    with pytest.raises(ValidationError, match="immutable_commit_required"):
        validate_artifact(invalid)
    assert validators.validate_artifact(_receipt())["terminal_state"] == "completed"


def test_pair_and_natural_claim_boundaries_fail_closed():
    pair = _case("external_validation.controlled_pair_case"); pair["fixed_sha"] = SHA; pair["case_authority"]["fixed_sha"] = SHA; pair["case_id"] = case_id(pair["case_authority"])
    with pytest.raises(ValidationError, match="paired_snapshot_identical"):
        validate_artifact(pair)
    natural = _case("external_validation.natural_pr_case"); natural["true_negative"] = True
    with pytest.raises(ValidationError):
        validate_artifact(natural)


def test_receipt_preserves_failure_and_rejects_model_only_closure():
    failed = _receipt(); failed["terminal_state"] = "timeout"; failed = _seal(failed)
    assert validate_artifact(failed)["terminal_state"] == "timeout"
    invalid = _receipt(); invalid["findings"] = [{"finding_id":"f1","target_id":"t1","origin":"shiproom_semantic","severity":"high","evidence_state": "model_reviewed", "evidence_refs":[],"reproduction_status":"not_reproduced","adjudication": "blocker_closed"}]; invalid = _seal(invalid)
    with pytest.raises(ValidationError, match="insufficient_evidence_for_closure"):
        validate_artifact(invalid)


def test_identity_separates_observation_schedule_and_repricing():
    inputs = {"case_id": "case_1", "snapshot_hash": HASH, "arm": "SHIPROOM_FULL", "system_version": "s1", "prompt_version": "p1", "policy_version": "p1", "model": "m1", "model_settings": {"temperature": 0}, "model_sampling_seed": 4, "tool_policy_version": "t1", "execution_policy_version": "e1", "cache_mode": "cold"}
    first = observation_key(inputs)
    assert first == observation_key(json.loads(json.dumps(inputs, indent=2)))
    assert schedule_id("sha256:" + "c" * 64, "1", "a") != schedule_id("sha256:" + "c" * 64, "1", "b")
    assert cost_view_id("receipt_a", "prices_1") != cost_view_id("receipt_a", "prices_2")
    with pytest.raises(ValueError, match="observation_key_fields_invalid"):
        observation_key(inputs | {"price_version": "prices_1"})


def test_registry_entries_resolve_and_receipt_hash_is_recomputed():
    assert registrations_are_resolvable()
    tampered = _receipt(); tampered["checks"] = {"attempted": ["changed"], "passed": [], "failed": [], "skipped": []}
    with pytest.raises(ValidationError, match="receipt_identity_mismatch"):
        validate_artifact(tampered)


def test_public_tree_allows_governance_reviews_but_rejects_private_marker(tmp_path: Path):
    root = tmp_path / "repo"; (root / "external_validation" / "reviews").mkdir(parents=True)
    (root / "external_validation" / "reviews" / "session1_part_a_review.md").write_text("safe")
    assert validate_public_tree(root) == []
    (root / "external_validation" / "reviews" / "oracle_review.md").write_text("target")
    assert any("private_path_marker" in item for item in validate_public_tree(root))
    (root / "external_validation" / "neutral.json").write_text(json.dumps({"schema_id":"external_validation.run_receipt"}))
    assert any("private_runtime_artifact" in item for item in validate_public_tree(root))


def test_natural_identity_binds_pr_context_and_applicability():
    natural = _case("external_validation.natural_pr_case"); changed = copy.deepcopy(natural); changed["pr_number"] = 2
    with pytest.raises(ValidationError, match="case_identity_mismatch"):
        validate_artifact(changed)


def test_docker_contract_is_argument_vector_and_rejects_forbidden_options(tmp_path: Path, monkeypatch):
    for name in ("patient", "packet", "output"): (tmp_path / name).mkdir()
    args = docker_argv(DockerPolicy("example.invalid/shiproom@sha256:" + "a" * 64), *(tmp_path / name for name in ("patient", "packet", "output")))
    assert "--network=none" in args and "--read-only" in args and "--cap-drop=ALL" in args
    with pytest.raises(ValueError, match="forbidden_docker_option"): validate_docker_argv(["docker", "run", "--privileged"])
    shiproom = tmp_path / "shiproom"; shiproom.mkdir(); evidence = tmp_path / "evidence"; evidence.mkdir(); (evidence / "output").mkdir(); monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(evidence))
    monkeypatch.setattr("shiproom.external_validation.runner.docker_available", lambda: False)
    with pytest.raises(RuntimeError, match="docker_linux_engine_unavailable"):
        run_container(DockerPolicy("example.invalid/shiproom@sha256:" + "a" * 64), tmp_path / "patient", tmp_path / "packet", evidence / "output", ["true"], shiproom_root=shiproom)
    with pytest.raises(PermissionError, match="remediation_worktree_required"):
        docker_argv(DockerPolicy("example.invalid/shiproom@sha256:" + "a" * 64), tmp_path / "patient", tmp_path / "packet", tmp_path / "output", remediation=True)


def test_scheduler_preserves_ambiguous_provider_call(tmp_path: Path):
    scheduler = RunScheduler(tmp_path / "runs.sqlite")
    assert scheduler.enqueue("obs_1", "attempt_1") == "QUEUED"
    with pytest.raises(ValueError, match="operation_state_forbidden"): scheduler.begin_operation("obs_1", "before_freeze")
    scheduler.freeze_schedule(["obs_1"], "public-seed")
    scheduler.begin_operation("obs_1", "provider_call_1"); scheduler.mark_ambiguous("provider_call_1")
    scheduler.finalize("obs_1", "receipt_1")
    assert scheduler.db.execute("SELECT state,receipt_id FROM runs WHERE observation_key='obs_1'").fetchone() == ("INDETERMINATE_IN_FLIGHT", None)
    with pytest.raises(ValueError, match="retry_state_forbidden"):
        scheduler.infrastructure_retry("obs_1", "attempt_2", "container_startup")


def test_scheduler_persists_seeded_order_attempt_history_and_safe_recovery(tmp_path: Path):
    scheduler = RunScheduler(tmp_path / "runs.sqlite")
    for number in range(3): scheduler.enqueue(f"obs_{number}", f"attempt_{number}")
    order = scheduler.freeze_schedule(["obs_0", "obs_1", "obs_2"], "public-seed")
    assert order == scheduler.freeze_schedule(["obs_0", "obs_1", "obs_2"], "public-seed")
    with pytest.raises(ValueError, match="schedule_reseed_forbidden"): scheduler.freeze_schedule(["obs_0", "obs_1", "obs_2"], "other-seed")
    with pytest.raises(ValueError, match="schedule_closed_to_new_observations"): scheduler.enqueue("obs_late", "attempt_late")
    scheduler.mark_infrastructure_failure("obs_0", "container_startup")
    scheduler.infrastructure_retry("obs_0", "attempt_0b", "container_startup")
    assert scheduler.index()["records"][next(index for index, item in enumerate(scheduler.index()["records"]) if item["observation_key"] == "obs_0")]["attempts"][0]["state"] == "SUPERSEDED"
    with pytest.raises(ValueError, match="schedule_id_authority_mismatch"): scheduler.index("schedule")
    scheduler.begin_operation("obs_1", "op_1", "provider-1")
    with pytest.raises(ValueError, match="retry_state_forbidden"): scheduler.infrastructure_retry("obs_1", "attempt_1b", "container_startup")
    assert "obs_0" in scheduler.recover_interrupted()
    assert scheduler.db.execute("SELECT state FROM runs WHERE observation_key='obs_1'").fetchone()[0] == "INDETERMINATE_IN_FLIGHT"


def test_all_five_adapters_share_context_and_no_core_cannot_leak():
    context = ArmContext("case_1", HASH, HASH, HASH, HASH, HASH, HASH)
    assert_context_equivalence({arm: context for arm in ARMS})
    with pytest.raises(ValueError, match="deterministic_core_leak"):
        SyntheticAdapter("SHIPROOM_NO_DETERMINISTIC_CORE", lambda _: {"terminal_state": "completed", "deterministic_results": []}).run(context)


def test_corpus_rejects_duplicate_final_receipts(tmp_path: Path, monkeypatch):
    root = tmp_path / "evidence"; root.mkdir(); shiproom = tmp_path / "shiproom"; shiproom.mkdir()
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(root))
    first = _receipt(); (root / "one.json").write_text(json.dumps(first))
    (root / "two.json").write_text(json.dumps(first))
    with pytest.raises(ValueError, match="duplicate_"):
        validate_corpus(root, shiproom, case_manifest_ledger={first["case_id"]: _case()})
    second = _receipt(); second["arm"] = "SHIPROOM_FULL"; second["observation_inputs"]["arm"] = "SHIPROOM_FULL"; second["observation_key"] = observation_key(second["observation_inputs"]); second["attempt_id"] = attempt_id(second["observation_key"], 1); second = _seal(second)
    (root / "two.json").write_text(json.dumps(second))
    assert validate_corpus(root, shiproom, case_manifest_ledger={first["case_id"]: _case()})["receipt_count"] == 2


def test_corpus_requires_case_authority_ledger(tmp_path: Path, monkeypatch):
    root, shiproom = tmp_path / "evidence", tmp_path / "shiproom"; root.mkdir(); shiproom.mkdir(); monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(root))
    receipt = _receipt(); (root / "receipt.json").write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="case_authority_ledger_required"):
        validate_corpus(root, shiproom)


def test_beta_schema_and_manual_validator_reject_structural_tampering():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(resources.files("shiproom.external_validation").joinpath("schemas/beta-case.v1.json").read_text())
    valid = _case(); jsonschema.validate(valid, schema); validate_artifact(valid)
    invalid = _case(); invalid.pop("case_authority")
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)
    with pytest.raises(ValidationError): validate_artifact(invalid)


def test_receipt_schema_and_manual_validator_reject_missing_identity():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(resources.files("shiproom.external_validation").joinpath("schemas/run-receipt.v1.json").read_text())
    valid = _receipt(); jsonschema.validate(valid, schema); validate_artifact(valid)
    invalid = _receipt(); invalid.pop("observation_inputs"); invalid = _seal(invalid)
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)
    with pytest.raises(ValidationError): validate_artifact(invalid)


@pytest.mark.parametrize("schema_id,filename", [("external_validation.beta_case", "beta-case.v1.json"), ("external_validation.controlled_pair_case", "controlled-pair-case.v1.json"), ("external_validation.natural_pr_case", "natural-pr-case.v1.json")])
def test_case_schema_and_validator_parity(schema_id: str, filename: str):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(resources.files("shiproom.external_validation").joinpath("schemas", filename).read_text())
    valid = _case(schema_id); jsonschema.validate(valid, schema); validate_artifact(valid)
    invalid = copy.deepcopy(valid); invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)
    with pytest.raises(ValidationError): validate_artifact(invalid)


def test_applicability_schema_and_validator_parity():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(resources.files("shiproom.external_validation").joinpath("schemas/applicability.v1.json").read_text())
    valid = {"schema_id":"external_validation.applicability","schema_version":"1","decisions":APPLICABILITY}; jsonschema.validate(valid, schema); validate_artifact(valid)
    invalid = copy.deepcopy(valid); invalid["decisions"].pop("AI_EVAL")
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)
    with pytest.raises(ValidationError): validate_artifact(invalid)


def test_price_and_run_index_validator_contracts():
    price = {"schema_id":"external_validation.price_table","schema_version":"1","provider":"p","model":"m","effective_date":"2026-01-01","currency":"USD","source":"official","rates":{"input":0.1}}
    assert validate_artifact(price)["provider"] == "p"
    broken = copy.deepcopy(price); broken["rates"]["input"] = -1
    with pytest.raises(ValueError, match="price_rate_invalid"): validate_artifact(broken)
    index = {"schema_id":"external_validation.run_index","schema_version":"1","schedule_id":"schedule_x","records":[{"observation_key":"obs_a"}]}
    assert validate_artifact(index)["schedule_id"] == "schedule_x"
    index["records"].append({"observation_key":"obs_a"})
    with pytest.raises(ValidationError, match="duplicate_observation"): validate_artifact(index)


def test_case_path_validation_uses_trusted_root_not_manifest_root(tmp_path: Path, monkeypatch):
    evidence, shiproom, patient = tmp_path / "evidence", tmp_path / "shiproom", tmp_path / "patient"
    for path in (evidence, shiproom, patient, evidence / "oracle"): path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(evidence))
    manifest = _case("external_validation.controlled_pair_case"); manifest["visible_patient_root"] = str(patient); manifest["oracle_ref"] = str(evidence / "oracle")
    validate_case_paths(manifest, evidence, shiproom, patient)
    manifest["oracle_ref"] = str(patient / "oracle")
    with pytest.raises(PermissionError, match="oracle_visible_to_patient"):
        validate_case_paths(manifest, evidence, shiproom, patient)
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(tmp_path / "other"))
    with pytest.raises(PermissionError, match="external_validation_root_not_configured"):
        validate_case_paths(manifest, evidence, shiproom, patient)


def test_all_synthetic_terminal_scenarios_and_five_arm_smoke():
    assert {scenario_output(name)["terminal_state"] for name in SCENARIOS} >= {"completed", "timeout", "malformed_output", "budget_exceeded", "unsafe_execution", "error", "indeterminate_in_flight"}
    context = ArmContext("case", HASH, HASH, HASH, HASH, HASH, HASH)
    results = five_arm_smoke(context)
    assert set(results) == set(ARMS) and all(result["terminal_state"] == "completed" for result in results.values())


def test_every_synthetic_terminal_scenario_flows_through_scheduler_finalizer_and_corpus(tmp_path: Path, monkeypatch):
    evidence, shiproom = tmp_path / "evidence", tmp_path / "shiproom"; evidence.mkdir(); shiproom.mkdir(); monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(evidence))
    from shiproom.external_validation.security import sha256_file
    source, packet = evidence / "source.bin", evidence / "packet.bin"; source.write_bytes(b"source"); packet.write_bytes(b"packet")
    scheduler = RunScheduler(evidence / "terminal.sqlite")
    prepared = {}
    for scenario in SCENARIOS:
        receipt = _receipt(); receipt["observation_inputs"]["model_settings"] = {"synthetic_scenario": scenario}; receipt["observation_key"] = observation_key(receipt["observation_inputs"]); receipt["attempt_id"] = attempt_id(receipt["observation_key"], 1)
        receipt["terminal_state"] = scenario_output(scenario)["terminal_state"]; receipt["termination"] = receipt["terminal_state"]
        output = evidence / f"output-{scenario}.bin"; output.write_text(scenario)
        receipt["hashes"].update({"source": sha256_file(source), "release_packet": sha256_file(packet), "output": sha256_file(output)})
        prepared[receipt["observation_key"]] = (_seal(receipt), output)
        scheduler.enqueue(receipt["observation_key"], receipt["attempt_id"])
    scheduler.freeze_schedule(list(prepared), "terminal-public-seed")
    for key in scheduler.recover_interrupted():
        receipt, output = prepared[key]; scheduler.begin_operation(key, "synthetic_" + key)
        finalized = finalize_receipt(receipt, evidence / "receipts" / f"{key}.json", evidence, shiproom, artifact_paths={"source": source, "release_packet": packet, "output": output}, case_manifest=_case())
        scheduler.finalize(key, finalized["receipt_id"])
    assert validate_corpus(evidence, shiproom, case_manifest_ledger={_case()["case_id"]: _case()})["receipt_count"] == len(SCENARIOS)


def test_supervisor_finalization_rehashes_real_artifacts(tmp_path: Path, monkeypatch):
    evidence, shiproom = tmp_path / "evidence", tmp_path / "shiproom"; evidence.mkdir(); shiproom.mkdir(); monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(evidence))
    paths = {}
    for key in ("source", "release_packet", "output"):
        path = evidence / f"{key}.bin"; path.write_bytes(key.encode()); paths[key] = path
    receipt = _receipt()
    from shiproom.external_validation.security import sha256_file
    for key, path in paths.items(): receipt["hashes"][key] = sha256_file(path)
    receipt = _seal(receipt)
    finalized = finalize_receipt(receipt, evidence / "receipts" / "one.json", evidence, shiproom, artifact_paths=paths, case_manifest=_case())
    assert finalized["receipt_id"].startswith("receipt_")
    receipt["hashes"]["output"] = HASH
    with pytest.raises(ValueError, match="receipt_artifact_hash_mismatch"):
        finalize_receipt(receipt, evidence / "receipts" / "two.json", evidence, shiproom, artifact_paths=paths, case_manifest=_case())


def test_cache_isolation_allows_dependencies_not_derived_outputs(tmp_path: Path):
    root=tmp_path / "root"; root.mkdir()
    assert dependency_cache(root, "python").is_dir()
    assert arm_output_root(root, "obs_" + "a" * 64).is_dir()
    with pytest.raises(FileExistsError): arm_output_root(root, "obs_" + "a" * 64)
    with pytest.raises(PermissionError, match="derived_cache_forbidden"): reject_derived_cache(root / "findings-cache")


def test_remediation_worktree_is_separate_and_auditable(tmp_path: Path):
    patient = tmp_path / "patient"; patient.mkdir(); (patient / "file.txt").write_text("immutable")
    remediation = create_remediation_worktree(patient, tmp_path / "remediation")
    before = tree_snapshot(remediation); (remediation / "file.txt").write_text("changed")
    assert tree_snapshot(patient)["file.txt"] != tree_snapshot(remediation)["file.txt"] and before["file.txt"] != tree_snapshot(remediation)["file.txt"]


def test_safe_materialization_exports_only_verified_commit(tmp_path: Path, monkeypatch):
    work, mirror = tmp_path / "work", tmp_path / "mirror.git"; work.mkdir()
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=work, check=True, capture_output=True, text=True).stdout.strip()
    git("init"); git("config", "user.email", "test@example.invalid"); git("config", "user.name", "Test")
    (work / "tracked.txt").write_text("tracked"); git("add", "tracked.txt"); git("commit", "-m", "fixture")
    commit = git("rev-parse", "HEAD")
    subprocess.run(["git", "clone", "--bare", str(work), str(mirror)], check=True, capture_output=True, text=True)
    exported = materialize_snapshot(mirror, commit, tmp_path / "export")
    assert (exported / "tracked.txt").read_text() == "tracked"
    with pytest.raises(ValueError, match="immutable_commit_required"): materialize_snapshot(mirror, "HEAD", tmp_path / "branch")
    with pytest.raises(ValueError, match="immutable_checkout_mismatch"): materialize_snapshot(mirror, "b" * 40, tmp_path / "wrong")
    import shiproom.external_validation.materialize as materialize
    monkeypatch.setattr(materialize, "_git", lambda _root, *args: commit if args[0] == "rev-parse" else "160000 commit " + commit + "\tdep")
    with pytest.raises(ValueError, match="submodules_not_qualified"): materialize.materialize_snapshot(mirror, commit, tmp_path / "submodule")


def test_safe_materialization_preserves_only_internal_archived_symlink_entries(tmp_path: Path):
    probe = tmp_path / "symlink-capability-probe"
    try:
        os.symlink("not-present", probe)
    except OSError:
        pytest.skip("platform does not permit creating test symlinks")
    else:
        probe.unlink()
    work, mirror = tmp_path / "work", tmp_path / "mirror.git"; work.mkdir()
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=work, check=True, capture_output=True, text=True).stdout.strip()
    git("init"); git("config", "user.email", "test@example.invalid"); git("config", "user.name", "Test")
    (work / "tracked.txt").write_text("tracked"); git("add", "tracked.txt"); git("commit", "-m", "fixture")
    parent = git("rev-parse", "HEAD")
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=work, input="tracked.txt", check=True, capture_output=True, text=True).stdout.strip()
    git("update-index", "--add", "--cacheinfo", f"120000,{blob},internal-link")
    tree = git("write-tree")
    evil = subprocess.run(["git", "commit-tree", tree, "-p", parent, "-m", "symlink"], cwd=work, check=True, capture_output=True, text=True).stdout.strip()
    git("update-ref", "refs/heads/evil", evil)
    subprocess.run(["git", "clone", "--bare", str(work), str(mirror)], check=True, capture_output=True, text=True)
    target = materialize_snapshot(mirror, evil, tmp_path / "export")
    link = target / "internal-link"
    assert link.is_symlink() and os.readlink(link) == "tracked.txt" and link.read_text() == "tracked"
    bad_blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=work, input="../outside", check=True, capture_output=True, text=True).stdout.strip()
    git("update-index", "--add", "--cacheinfo", f"120000,{bad_blob},escaped-link")
    bad_tree = git("write-tree")
    bad = subprocess.run(["git", "commit-tree", bad_tree, "-p", evil, "-m", "bad symlink"], cwd=work, check=True, capture_output=True, text=True).stdout.strip()
    git("update-ref", "refs/heads/evil", bad)
    subprocess.run(["git", "clone", "--bare", str(work), str(tmp_path / "bad-mirror.git")], check=True, capture_output=True, text=True)
    with pytest.raises(ValueError, match="unsafe_patient_tree_entry"):
        materialize_snapshot(tmp_path / "bad-mirror.git", bad, tmp_path / "bad-export")


def test_public_synthetic_proof_receipt_is_schema_and_validator_backed():
    jsonschema = pytest.importorskip("jsonschema")
    proof = json.loads(Path("external_validation/proofs/session1/docker_five_arm_lifecycle.receipt.json").read_text())
    schema = json.loads(resources.files("shiproom.external_validation").joinpath("schemas/synthetic-proof-receipt.v1.json").read_text())
    jsonschema.validate(proof, schema)
    assert validate_artifact(proof)["corpus"]["receipt_count"] == 5
