from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shiproom.session6_8_proof_execution import PROOF_CASES, execute_proof, _derive_rejection


ROOT=Path(__file__).resolve().parents[1]
PROOF_IDS=tuple(PROOF_CASES)


def _run_authentic_evidence_producer(*arguments: str) -> None:
    """Produce every retained artifact consumed by the proof registry.

    These proofs deliberately inspect artifacts created at real production
    boundaries.  The producer sequence is therefore an explicit test
    prerequisite, rather than an accidental dependency on ignored files left
    by a previous local closeout run.
    """
    completed = subprocess.run(
        [sys.executable, *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, (
        "authentic evidence producer failed: "
        + " ".join(arguments)
        + "\nstdout:\n"
        + completed.stdout
        + "\nstderr:\n"
        + completed.stderr
    )


@pytest.fixture(scope="module", autouse=True)
def authentic_proof_evidence():
    """Build the complete proof corpus from the checked-out source tree."""
    local = ROOT / ".shiproom" / "local"
    _run_authentic_evidence_producer("scripts/run_evals.py")
    _run_authentic_evidence_producer("scripts/run_workflow_integration_evals.py")
    _run_authentic_evidence_producer(
        "scripts/run_session6_8_security_attacks.py",
        "--output",
        str(local / "session6-8-security-receipt.json"),
        "--evidence-root",
        str(local / "security-evidence"),
    )
    _run_authentic_evidence_producer(
        "scripts/run_session6_8_contract_parity.py",
        "--output",
        str(local / "session6-8-contract-parity-report.json"),
        "--fixtures",
        str(local / "parity-fixtures"),
    )
    _run_authentic_evidence_producer(
        "scripts/run_session6_8_wheel_smoke.py",
        "--output",
        str(local / "session6-8-installed-wheel-receipt.json"),
    )


@pytest.fixture(scope="module")
def capacity_rejection_event():
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    return execute_proof("proof_shared_capacity_limits_adversarial_invalid",final_commit=commit)


@pytest.mark.parametrize("proof_id",PROOF_IDS,ids=PROOF_IDS)
def test_requirement_proof(proof_id):
    if proof_id in {
        "proof_shared_installed_wheel_lifecycle_valid",
        "proof_shared_installed_wheel_lifecycle_near_valid",
    } and 'name = "provan-assurance"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8"):
        pytest.skip("historical Shiproom wheel lifecycle is excluded from the current Provan wheel")
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    event=execute_proof(proof_id,final_commit=commit)
    assert event["passed"]
    assert event["actual_record_count"] >= event["minimum_record_count"]
    assert event["production_invocation_ids"]


def test_proof_registry_has_no_prefix_dispatch_or_inventory_resolution():
    source=(ROOT/"shiproom/session6_8_proof_execution.py").read_text(encoding="utf-8")
    assert "startswith(\"S" not in source
    assert "requirement_row_resolves" not in source
    assert "session6-8-requirement-inventory" not in source
    assert len(PROOF_CASES)==318
    assert "session6_8_requirement_boundaries" not in source
    assert "/measurements/" not in source
    assert "_observed_code" not in source
    assert "rejection_evidence" not in source


def test_requirement_proof_registry_is_exact_and_fingerprint_unique():
    registry=json.loads((ROOT/"docs/validation/session6-8-requirement-proof-registry.json").read_text(encoding="utf-8"))
    audit=json.loads((ROOT/"docs/validation/session6-8-proof-fingerprint-audit.json").read_text(encoding="utf-8"))
    rows=registry["proofs"]
    assert len(rows)==len({row["proof_id"] for row in rows})==318
    assert {row["fixture_class"] for row in rows}=={"valid","near_valid","adversarial_invalid"}
    assert all(row["artifact_queries"] for row in rows)
    assert audit["proof_count"]==audit["unique_fingerprint_count"]==318
    assert audit["unjustified_duplicate_count"]==0 and audit["status"]=="passed"


def test_requirement_proofs_measure_instead_of_copying_configured_minimums(tmp_path,monkeypatch):
    monkeypatch.setenv("SHIPROOM_PROOF_EVENT_ROOT",str(tmp_path))
    event=execute_proof("proof_s6_remediation_cardinality_valid",final_commit="f"*40)
    artifact=json.loads((ROOT/".shiproom/local"/event["artifact_paths"][0]).read_text(encoding="utf-8"))
    assert len(artifact["packets"])==3
    assert event["actual_record_count"]==3
    source=(ROOT/"shiproom/session6_8_proof_execution.py").read_text(encoding="utf-8")
    assert "actual_record_count\": case.minimum_record_count" not in source


def test_all_adversarial_proofs_bind_real_production_rejections():
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    rows=[]
    for proof_id,case in PROOF_CASES.items():
        if case.fixture_class!="adversarial_invalid":continue
        event=execute_proof(proof_id,final_commit=commit)
        matches=[item for item in event["production_invocations"] if item["invocation_id"]==event["rejection_invocation_id"]]
        assert len(matches)==1
        invocation=matches[0]
        assert invocation["subcase_id"]==proof_id
        assert invocation["qualified_function"]==event["outcome_evidence"]["production_function"]
        assert invocation["typed_status_or_error"]==event["actual_error_code"]==case.expected_error
        assert invocation["exception_type"]==event["actual_exception"]=="ValueError"
        assert event["fixture_binding"]["base_hash"]!=event["fixture_binding"]["mutated_hash"]
        assert event["fixture_binding"]["mutated_semantic_hash"] in invocation["input_component_hashes"]
        rows.append(event)
    assert len(rows)==106


@pytest.mark.parametrize("proof_id",[
    "proof_shared_capacity_limits_adversarial_invalid",
    "proof_shared_closeout_generation_adversarial_invalid",
    "proof_shared_independent_validation_adversarial_invalid",
    "proof_s6_remediation_cardinality_adversarial_invalid",
])
def test_reported_false_rejection_examples_now_call_production(proof_id):
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    event=execute_proof(proof_id,final_commit=commit)
    invocation=next(item for item in event["production_invocations"] if item["invocation_id"]==event["rejection_invocation_id"])
    assert invocation["typed_status_or_error"]==event["outcome_evidence"]["expected_status_or_error"]
    assert invocation["exception_type"]==event["outcome_evidence"]["expected_exception"]
    assert event["actual_acceptance"] is False


def test_rejection_without_matching_invocation_is_rejected(capacity_rejection_event):
    event=capacity_rejection_event;case=PROOF_CASES[event["proof_id"]]
    with pytest.raises(ValueError,match="proof_rejection_invocation_missing"):
        _derive_rejection(ROOT/".shiproom/local",case,[],event["fixture_binding"])


def test_rejection_from_another_subcase_is_rejected(capacity_rejection_event):
    event=json.loads(json.dumps(capacity_rejection_event));case=PROOF_CASES[event["proof_id"]]
    for invocation in event["production_invocations"]:
        if invocation["invocation_id"]==event["rejection_invocation_id"]:invocation["subcase_id"]="other_subcase"
    with pytest.raises(ValueError,match="proof_rejection_invocation_missing"):
        _derive_rejection(ROOT/".shiproom/local",case,event["production_invocations"],event["fixture_binding"])


def test_rejection_status_mismatch_is_rejected(capacity_rejection_event):
    event=json.loads(json.dumps(capacity_rejection_event));case=PROOF_CASES[event["proof_id"]]
    for invocation in event["production_invocations"]:
        if invocation["invocation_id"]==event["rejection_invocation_id"]:invocation["typed_status_or_error"]="successful_schema_version"
    with pytest.raises(ValueError,match="proof_rejection_outcome_mismatch"):
        _derive_rejection(ROOT/".shiproom/local",case,event["production_invocations"],event["fixture_binding"])


def test_mutation_absent_from_invocation_input_is_rejected(capacity_rejection_event):
    event=json.loads(json.dumps(capacity_rejection_event));case=PROOF_CASES[event["proof_id"]]
    for invocation in event["production_invocations"]:
        if invocation["invocation_id"]==event["rejection_invocation_id"]:invocation["input_component_hashes"]=[]
    with pytest.raises(ValueError,match="proof_rejection_mutation_unbound"):
        _derive_rejection(ROOT/".shiproom/local",case,event["production_invocations"],event["fixture_binding"])
