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
    assert event["actual_record_count"] >= 1
    assert event["production_invocation_ids"]


def test_proof_registry_has_no_prefix_dispatch_or_inventory_resolution():
    source=(ROOT/"shiproom/session6_8_proof_execution.py").read_text(encoding="utf-8")
    assert "startswith(\"S" not in source
    assert "requirement_row_resolves" not in source
    assert "session6-8-requirement-inventory" not in source
    assert len(PROOF_CASES)==318
    assert len({case.assertion_id for case,_kind in PROOF_CASES.values()})==106
