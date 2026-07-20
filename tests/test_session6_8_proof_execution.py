from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shiproom.session6_8_proof_execution import execute_requirement_proof


ROOT=Path(__file__).resolve().parents[1]
REQUIREMENTS=[item["requirement_id"] for item in json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text())["requirements"]]


@pytest.mark.parametrize("requirement_id,fixture_class",[(rid,kind) for rid in REQUIREMENTS for kind in ("valid","near_valid","adversarial_invalid")],ids=[f"{rid}-{kind}" for rid in REQUIREMENTS for kind in ("valid","near_valid","adversarial_invalid")])
def test_requirement_proof(requirement_id,fixture_class):
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    event=execute_requirement_proof(requirement_id,fixture_class,final_commit=commit)
    assert event["passed"]
    assert event["actual_record_count"] >= 1
    assert event["production_invocation_ids"]
