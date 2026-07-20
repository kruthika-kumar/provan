from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
from scripts.validate_session6_8_security_receipt import validate
from shiproom.workflow_trust import PROHIBITED_PRIVATE_ALPHA_OPERATIONS

ROOT=Path(__file__).resolve().parents[1]
def test_security_registry_is_frozen_and_receipt_replays(tmp_path):
    subprocess.run([sys.executable,"scripts/build_session6_8_security_registry.py"],cwd=ROOT,check=True)
    registry=json.loads((ROOT/"docs/validation/session6-8-security-surface-registry.json").read_text())
    assert len(registry["records"])==4*len(PROHIBITED_PRIVATE_ALPHA_OPERATIONS)
    output=tmp_path/"security.json"; subprocess.run([sys.executable,"scripts/run_session6_8_security_attacks.py","--output",str(output)],cwd=ROOT,check=True)
    result=validate(output); assert result["status"]=="passed" and result["record_count"]==len(registry["records"])
