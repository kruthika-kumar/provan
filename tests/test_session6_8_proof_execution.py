from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shiproom.session6_8_proof_execution import PROOF_CASES, execute_proof


ROOT=Path(__file__).resolve().parents[1]
PROOF_IDS=tuple(PROOF_CASES)


@pytest.mark.parametrize("proof_id",PROOF_IDS,ids=PROOF_IDS)
def test_requirement_proof(proof_id):
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
    artifact=json.loads(Path(event["artifact_paths"][0]).read_text(encoding="utf-8"))
    assert len(artifact["packets"])==3
    assert event["actual_record_count"]==3
    source=(ROOT/"shiproom/session6_8_proof_execution.py").read_text(encoding="utf-8")
    assert "actual_record_count\": case.minimum_record_count" not in source
