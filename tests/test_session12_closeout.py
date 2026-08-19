from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

from provan.canonical import canonical_bytes, sha256_bytes
from provan.errors import ProvanError
from provan.session12_validators import (
    validate_generic_absence_receipt_serialized,
    validate_foundry_run_binding_serialized,
    validate_implementation_binding_serialized,
    validate_pre_review_manifest_serialized,
    validate_projection_serialized,
    validate_real_use_qualification_serialized,
    validate_reviewer_receipt_serialized,
    validate_session12_closeout_serialized,
    validate_session13_handoff_serialized,
    validate_validation_summary_serialized,
)
from scripts.run_session12_authoritative_gate import quarantine_local_test_outputs

ROOT = Path(__file__).parents[1]
CLASSES = ("valid", "near-valid", "adversarial", "schema-invalid", "schema-valid-python-invalid")
INVARIANTS = ("session11-projection", "real-use", "sensitivity", "package", "state-safety", "pre-review", "handoff")


def _bundle():
    claim_raw = (ROOT / "artifacts/session12/authority/claim_registry.v1.public.json").read_bytes()
    schema_raw = (ROOT / "artifacts/session12/schema_registry.v1.public.json").read_bytes()
    claims = json.loads(claim_raw); registry = json.loads(schema_raw)
    binding = {"schema_id":"provan.session12_implementation_binding.v1","implementation_commit":"1"*40,"implementation_tree":"2"*40,"package_version":"0.5.0","extension_api_major":1,"wheel_sha256":"sha256:"+"3"*64,"schema_registry_digest":registry["registry_digest"],"claim_registry_digest":claims["registry_digest"],"standard_maturity":"QUALIFIED_BOUNDED","deep_maturity":"DEGRADED","published":False,"execution_available":False,"challenge_available":False}
    binding_raw = canonical_bytes(binding)
    projection = {"schema_id":"provan.foundry_acceptance_projection.v1","projection_id":"11111111-1111-4111-8111-111111111111","sensitivity":"PUBLIC_SAFE","run_id":"22222222-2222-4222-8222-222222222222","brief_ref":{"id":"33333333-3333-4333-8333-333333333333","sha256":"sha256:"+"4"*64},"case_id":"sha256:"+"5"*64,"candidate_digest":"sha256:"+"6"*64,"proposed_contract_terms":{},"contract_readiness":"READY_WITH_MATERIAL_QUESTIONS","run_eligibility":"ELIGIBLE","owner_confirmation_required":True,"creates_authority":False,"execution_available":False,"challenge_available":False,"limitations":["OWNER_CONFIRMATION_REQUIRED"]}
    adjudication = json.loads((ROOT / "artifacts/session12/public/adjudication_projection.v1.public.json").read_bytes())
    adjudication["live_evaluation"]["implementation_commit"] = binding["implementation_commit"]
    adjudication["live_evaluation"]["evaluation_policy_version"] = 999
    adjudication["live_evaluation"]["total_latency_ms"] = 123.5
    adjudication_core = dict(adjudication); adjudication_core.pop("projection_digest", None)
    adjudication["projection_digest"] = sha256_bytes(canonical_bytes(adjudication_core))
    cases = [{"case_id":case,"predeclared":True} for case in ("httpx-pr-3699-control","click-pr-3721-control","httpcore-pr-880-consequential","provan-public-control","session11-controlled-patient","session12-final-dogfood")]
    qualification = {"schema_id":"provan.foundry_real_use_qualification.v1","sensitivity":"PUBLIC_SAFE","implementation_binding":binding,"adjudication_root":adjudication["authority_bindings"]["review_root"],"adjudication_projection_sha256":sha256_bytes(canonical_bytes(adjudication)),"cases":cases,"arms":[{"label":"FOUNDRY_STANDARD"}],"coding_harness_sanity":{"claim_scope":"SINGLE_BLIND_SANITY_NOT_HEADLINE_COMPARISON"},"outcome_bearing_runs_completed":True,"evaluation_driven_adjudication_change":False,"raw_measurements":[{"metric":"current_model_calls","value":adjudication["live_evaluation"]["calls"]},{"metric":"current_model_total_latency_ms","value":adjudication["live_evaluation"]["total_latency_ms"]},{"metric":"current_model_estimated_cost_usd","value":adjudication["live_evaluation"]["estimated_cost_usd"]},{"metric":"total_session_model_estimated_cost_usd","value":adjudication["live_evaluation"]["total_session_estimated_cost_usd"]},{"metric":"final_dogfood_model_calls","value":0}],"limitations":["DEEP_DEGRADED"]}
    scopes=("history_delta","working_tree","package","proofs_examples","controlled_ci")
    absence={"schema_id":"provan.session10_generic_absence_receipt.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":binding["implementation_commit"],"implementation_tree":binding["implementation_tree"],"wheel_sha256":binding["wheel_sha256"],"checks":[{"scope":scope,"items_inspected":1,"inventory_digest":"sha256:"+str(index)*64,"generic_violation_count":0} for index,scope in enumerate(scopes,1)],"result":"PRIVATE_PLANNING_AUTHORITY_ABSENT","confidential_fingerprint_known":False}
    summary={"schema_id":"provan.session12_validation_summary.v1","implementation_binding":binding,"authoritative_full_gate":"SUCCESS","target_mutation_detected":False,"execution_available":False,"challenge_available":False,"session13_implemented":False,"checks":[{"label":"full","exit_code":0,"transcript_sha256":"sha256:"+"9"*64}]}
    run_binding={"schema_id":"provan.foundry_run_binding.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":binding["implementation_commit"],"implementation_tree":binding["implementation_tree"],"run_id":projection["run_id"],"run_sha256":"sha256:"+"7"*64,"case_id":projection["case_id"],"candidate":{"candidate_digest":projection["candidate_digest"]},"owner_projection_ref":{"path":"projection.json","sha256":sha256_bytes(canonical_bytes(projection))},"stage_digests":[{"name":f"stage-{i}","sha256":"sha256:"+str(i)*64} for i in range(1,9)],"internal_state":"PRIVATE_LOCAL_STATE_RETAINED","bootstrap_dogfood":True,"execution_available":False,"challenge_available":False,"limitations":["INTERNAL"]}
    artifacts={"a.json":canonical_bytes({"a":1}),"wheel.whl":b"wheel","run.json":canonical_bytes(run_binding),"projection.json":canonical_bytes(projection),"patterns.json":canonical_bytes({"patterns":1}),"schema.json":schema_raw,"claims.json":claim_raw}
    entries=[{"path":path,"sha256":sha256_bytes(raw)} for path,raw in artifacts.items()]
    manifest={"schema_id":"provan.session11_proof_manifest.v1","phase":"PRE_REVIEW","implementation_commit":binding["implementation_commit"],"implementation_tree":binding["implementation_tree"],"wheel_sha256":binding["wheel_sha256"],"reviewed_pre_review_root":None,"entries":entries,"proof_root":sha256_bytes(canonical_bytes(entries)),"reviewer_outputs_excluded":True}
    proof_registry={"entries":[{"proof_id":"P12-valid"}]};proof_raw=canonical_bytes(proof_registry)
    handoff={"schema_id":"provan.session_handoff.v2","session":12,"implementation_binding":binding,"wheel":{"path":"wheel.whl","sha256":sha256_bytes(artifacts["wheel.whl"])},"schema_registry":{"path":"schema.json","sha256":sha256_bytes(schema_raw)},"claim_registry":{"path":"claims.json","sha256":sha256_bytes(claim_raw)},"foundry_run":{"path":"run.json","sha256":sha256_bytes(artifacts["run.json"])},"owner_projection":{"path":"projection.json","sha256":sha256_bytes(artifacts["projection.json"])},"pattern_library":{"path":"patterns.json","sha256":sha256_bytes(artifacts["patterns.json"])},"mode_qualification":{"standard":"QUALIFIED_BOUNDED","deep":"DEGRADED"},"execution_available":False,"challenge_available":False,"session13_prerequisites":["a","b","c","d","e"],"proof_root":sha256_bytes(canonical_bytes(proof_registry["entries"])),"reviewer_receipts":[],"limitations":["SESSION13_NOT_IMPLEMENTED"]}
    return locals()


@pytest.mark.parametrize("fixture_class", CLASSES)
@pytest.mark.parametrize("invariant", INVARIANTS)
def test_proof_final_artifact_layers(invariant: str, fixture_class: str):
    data = _bundle(); value = copy.deepcopy(data[{"session11-projection":"projection","real-use":"qualification","sensitivity":"absence","package":"binding","state-safety":"summary","pre-review":"manifest","handoff":"handoff"}[invariant]])
    if fixture_class == "schema-invalid": value.pop("schema_id")
    elif fixture_class in {"adversarial", "schema-valid-python-invalid"}:
        if invariant == "session11-projection": value["creates_authority"] = True
        elif invariant == "real-use": value["implementation_binding"]["implementation_commit"] = "f"*40
        elif invariant == "sensitivity": value["checks"][0]["generic_violation_count"] = 1
        elif invariant == "package": value["schema_registry_digest"] = "sha256:"+"f"*64
        elif invariant == "state-safety": value["target_mutation_detected"] = True
        elif invariant == "pre-review": value["entries"].append({"path":"reviewer_receipt_a.v1.public.json","sha256":"sha256:"+"f"*64})
        elif invariant == "handoff": value["mode_qualification"]["deep"] = "QUALIFIED_BOUNDED"
    raw=canonical_bytes(value)
    if fixture_class == "schema-invalid":
        with pytest.raises(ProvanError):
            validate_projection_serialized(raw) if invariant=="session11-projection" else validate_implementation_binding_serialized(raw,data["schema_raw"],data["claim_raw"]) if invariant=="package" else validate_real_use_qualification_serialized(raw,data["binding_raw"],canonical_bytes(data["adjudication"])) if invariant=="real-use" else validate_generic_absence_receipt_serialized(raw,data["binding_raw"]) if invariant=="sensitivity" else validate_validation_summary_serialized(raw,data["binding_raw"]) if invariant=="state-safety" else validate_pre_review_manifest_serialized(raw,data["artifacts"],data["binding_raw"]) if invariant=="pre-review" else validate_session13_handoff_serialized(raw,data["artifacts"],data["binding_raw"],data["proof_raw"])
        print("PROOF_SCHEMA_ERROR:required-schema-id")
        return
    call=lambda: validate_projection_serialized(raw) if invariant=="session11-projection" else validate_implementation_binding_serialized(raw,data["schema_raw"],data["claim_raw"]) if invariant=="package" else validate_real_use_qualification_serialized(raw,data["binding_raw"],canonical_bytes(data["adjudication"])) if invariant=="real-use" else validate_generic_absence_receipt_serialized(raw,data["binding_raw"]) if invariant=="sensitivity" else validate_validation_summary_serialized(raw,data["binding_raw"]) if invariant=="state-safety" else validate_pre_review_manifest_serialized(raw,data["artifacts"],data["binding_raw"]) if invariant=="pre-review" else validate_session13_handoff_serialized(raw,data["artifacts"],data["binding_raw"],data["proof_raw"])
    if fixture_class in {"adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError): call()
    else: call()


def test_authoritative_gate_quarantines_local_outputs_before_leakage(tmp_path):
    repo = tmp_path / "repo"; transcripts = tmp_path / "private-transcripts"
    local = repo / ".shiproom" / "local"; local.mkdir(parents=True)
    (local / "receipt.json").write_text('{"local_path":"C:/private/user"}', encoding="utf-8")
    count, public_raw = quarantine_local_test_outputs(repo, transcripts)
    assert count == 1
    assert public_raw == b"LOCAL_TEST_BYPRODUCTS_QUARANTINED:1\n"
    assert list(local.iterdir()) == []
    quarantined = list((transcripts / "local-byproducts").iterdir())
    assert len(quarantined) == 1 and (quarantined[0] / "receipt.json").is_file()


def test_real_use_binds_exact_adjudication_projection_without_policy_version_constant():
    data = _bundle()
    validate_real_use_qualification_serialized(
        canonical_bytes(data["qualification"]), data["binding_raw"], canonical_bytes(data["adjudication"])
    )
    mutated = copy.deepcopy(data["adjudication"])
    mutated["live_evaluation"]["evaluation_policy_version"] += 1
    core = dict(mutated); core.pop("projection_digest", None)
    mutated["projection_digest"] = sha256_bytes(canonical_bytes(core))
    with pytest.raises(ProvanError, match="SESSION12_REAL_USE_BINDING_MISMATCH"):
        validate_real_use_qualification_serialized(
            canonical_bytes(data["qualification"]), data["binding_raw"], canonical_bytes(mutated)
        )


def test_adjudication_projection_builder_accepts_explicit_content_addressed_authority_files():
    source = (ROOT / "scripts/build_session12_adjudication_projection.py").read_text(encoding="utf-8")
    for option in ("--policy", "--review", "--ledger", "--scoring"):
        assert option in source
    assert 'policy.get("version")!=10' not in source


def test_release_gate_workflow_is_yaml_parseable_with_isolated_candidate_build():
    workflow_path = ROOT / ".github/workflows/release-gate.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["test-and-eval"]["steps"]
    commands = [step.get("run", "") for step in steps]
    assert any("python -m build --outdir candidate-dist" in command for command in commands)
    assert any("Version: 0.5.0" in command for command in commands)


def test_release_gate_quarantines_local_eval_outputs_before_publication_checks():
    workflow = (ROOT / ".github/workflows/release-gate.yml").read_text(encoding="utf-8")
    integration = workflow.index("python scripts/run_workflow_integration_evals.py")
    quarantine = workflow.index("python scripts/quarantine_session12_ci_byproducts.py")
    build = workflow.index("python -m build --outdir candidate-dist")
    validation = workflow.index("python scripts/validate_session12.py --phase final")
    assert integration < quarantine < build < validation


def test_ci_quarantine_moves_local_byproducts_outside_repository(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    local = repo / ".shiproom" / "local"
    local.mkdir(parents=True)
    (local / "generated.json").write_text('{"local":"path"}\n', encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    spec = importlib.util.spec_from_file_location(
        "session12_ci_quarantine", ROOT / "scripts/quarantine_session12_ci_byproducts.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", repo)
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    assert module.main() == 0
    assert local.is_dir() and not any(local.iterdir())
    quarantined = list((runner_temp / "provan-session12-ci-quarantine" / "local-byproducts").rglob("generated.json"))
    assert len(quarantined) == 1


@pytest.mark.parametrize("metric", [
    "current_model_calls",
    "current_model_total_latency_ms",
    "current_model_estimated_cost_usd",
    "total_session_model_estimated_cost_usd",
    "final_dogfood_model_calls",
])
def test_real_use_recomputes_exact_measurements_from_adjudication(metric: str):
    data = _bundle()
    qualification = copy.deepcopy(data["qualification"])
    row = next(item for item in qualification["raw_measurements"] if item["metric"] == metric)
    row["value"] += 1
    with pytest.raises(ProvanError, match="SESSION12_REAL_USE_MEASUREMENT_MISMATCH"):
        validate_real_use_qualification_serialized(
            canonical_bytes(qualification), data["binding_raw"], canonical_bytes(data["adjudication"])
        )


def test_authoritative_gate_quarantines_before_session12_implementation():
    source = (ROOT / "scripts/run_session12_authoritative_gate.py").read_text(encoding="utf-8")
    quarantine = source.index('if label == "session12_implementation"')
    execution = source.index("result=subprocess.run(command", quarantine)
    assert quarantine < execution


def test_inherited_session11_successor_schema_boundary_is_byte_preserving():
    result = subprocess.run(
        [sys.executable, "scripts/validate_session11.py", "--phase", "final", "--successor"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _reviewer(data, role="A"):
    return {"schema_id":"provan.session12_reviewer_receipt.v1","sensitivity":"PUBLIC_SAFE","reviewer_role":role,"reviewer_mode":"fresh_read_only","reviewed_commit":data["binding"]["implementation_commit"],"reviewed_tree":data["binding"]["implementation_tree"],"reviewed_pre_review_root":data["manifest"]["proof_root"],"wheel_sha256":data["binding"]["wheel_sha256"],"verdict":"GO","findings":{"P0":0,"P1":0,"P2":0,"items":[]},"claim_dispositions":[{"claim_id":row["claim_id"],"result":"ACCEPTED"} for row in data["claims"]["claims"]],"maturity_recommendation":{"standard":"QUALIFIED_BOUNDED","deep":"DEGRADED","limitations":["SAME_MODEL_FAMILY_INDEPENDENCE_NOT_ESTABLISHED"]},"review_started_at":"2026-08-19T00:00:00Z","review_completed_at":"2026-08-19T00:01:00Z","identity_limitations":["READ_ONLY_CODEX_REVIEWER_WITHOUT_EXTERNAL_ORGANISATIONAL_IDENTITY_ATTESTATION"]}


@pytest.mark.parametrize("fixture_class", CLASSES)
def test_proof_reviewer_receipt_layers(fixture_class: str):
    data=_bundle();value=_reviewer(data)
    if fixture_class=="schema-invalid":value.pop("schema_id")
    elif fixture_class=="adversarial":value["reviewed_pre_review_root"]="sha256:"+"f"*64
    elif fixture_class=="schema-valid-python-invalid":value["claim_dispositions"]=value["claim_dispositions"][:-1]
    elif fixture_class=="near-valid":value["findings"]={"P0":0,"P1":0,"P2":1,"items":[{"severity":"P2","summary":"bounded documentation limitation"}]}
    call=lambda:validate_reviewer_receipt_serialized(canonical_bytes(value),data["binding_raw"],data["claim_raw"],data["manifest"]["proof_root"],"A")
    if fixture_class in {"schema-invalid","adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError):call()
    else:call()


@pytest.mark.parametrize("fixture_class", CLASSES)
def test_proof_gate12_closeout_layers(fixture_class: str):
    data=_bundle();reviewers=[_reviewer(data,"A"),_reviewer(data,"B")];entries=[{"path":"reviewer-a.json","sha256":"sha256:"+"a"*64},{"path":"reviewer-b.json","sha256":"sha256:"+"b"*64}]
    value={"schema_id":"provan.session12_closeout.v1","sensitivity":"PUBLIC_SAFE","status":"CLOSED","implementation_binding":data["binding"],"reviewed_pre_review_root":data["manifest"]["proof_root"],"final_proof_root":sha256_bytes(canonical_bytes(entries)),"reviewer_receipts":entries,"mode_qualification":{"standard":"QUALIFIED_BOUNDED","deep":"DEGRADED"},"execution_available":False,"challenge_available":False,"go_session13":True,"session13_implemented":False,"published":False,"release_created":False,"tag_created":False,"production_changed_after_review":False,"limitations":["SESSION13_NOT_IMPLEMENTED"]}
    if fixture_class=="schema-invalid":value.pop("schema_id")
    elif fixture_class=="adversarial":value["execution_available"]=True
    elif fixture_class=="schema-valid-python-invalid":value["mode_qualification"]["deep"]="QUALIFIED_BOUNDED"
    elif fixture_class=="near-valid":value["limitations"].append("DEEP_PROVIDER_INDEPENDENCE_NOT_ESTABLISHED")
    call=lambda:validate_session12_closeout_serialized(canonical_bytes(value),data["binding_raw"],data["manifest"]["proof_root"],entries,reviewers)
    if fixture_class in {"schema-invalid","adversarial","schema-valid-python-invalid"}:
        with pytest.raises(ProvanError):call()
    else:call()
