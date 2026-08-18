from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from provan.canonical import canonical_bytes, sha256_bytes
from provan.errors import ProvanError
from provan.session12_validators import (
    validate_generic_absence_receipt_serialized,
    validate_foundry_run_binding_serialized,
    validate_implementation_binding_serialized,
    validate_pre_review_manifest_serialized,
    validate_projection_serialized,
    validate_real_use_qualification_serialized,
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
    cases = [{"case_id":case,"predeclared":True} for case in ("httpx-pr-3699-control","click-pr-3721-control","httpcore-pr-880-consequential","provan-public-control","session11-controlled-patient","session12-final-dogfood")]
    qualification = {"schema_id":"provan.foundry_real_use_qualification.v1","sensitivity":"PUBLIC_SAFE","implementation_binding":binding,"adjudication_root":adjudication["authority_bindings"]["review_root"],"cases":cases,"arms":[{"label":"FOUNDRY_STANDARD"}],"coding_harness_sanity":{"claim_scope":"SINGLE_BLIND_SANITY_NOT_HEADLINE_COMPARISON"},"outcome_bearing_runs_completed":True,"evaluation_driven_adjudication_change":False,"raw_measurements":[],"limitations":["DEEP_DEGRADED"]}
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
