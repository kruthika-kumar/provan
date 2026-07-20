from __future__ import annotations
import subprocess,sys
from pathlib import Path
from scripts.validate_session6_8_contract_parity import validate
ROOT=Path(__file__).resolve().parents[1]
def test_every_inventory_contract_has_replayable_structural_and_semantic_mutation(tmp_path):
    report=tmp_path/"parity.json";fixtures=tmp_path/"fixtures"
    subprocess.run([sys.executable,"scripts/run_session6_8_contract_parity.py","--output",str(report),"--fixtures",str(fixtures)],cwd=ROOT,check=True)
    result=validate(report);assert result=={"schema_version":"session6-8-contract-parity-validation.v2","contract_count":21,"mutation_count":42,"unexpected_pass_count":0,"status":"passed"}
    value=__import__("json").loads(report.read_text())
    assert len(value["accepted_baselines"])==21
    assert all(row["python_result"]=="accepted" for row in value["accepted_baselines"])
    assert all(row["actual_python_result"]=="rejected" for row in value["mutation_receipts"])
