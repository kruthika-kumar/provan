from __future__ import annotations
import ast
from pathlib import Path

from scripts.run_session6_8_tamper_attacks import ATTACKS


def test_independent_closeout_validator_has_at_least_22_distinct_tamper_rejections():
    assert len(ATTACKS)==35
    assert len({attack for attack,_error in ATTACKS})==len(ATTACKS)
    assert len({error for _attack,error in ATTACKS})==len(ATTACKS)


def test_independent_closeout_validator_import_boundary():
    path=Path(__file__).resolve().parents[1]/"scripts/validate_session6_8_closeout_independently.py"
    tree=ast.parse(path.read_text(encoding="utf-8"));imports=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):imports.update(alias.name for alias in node.names)
        elif isinstance(node,ast.ImportFrom) and node.module:imports.add(node.module)
    forbidden={"scripts.report_session6_8_closeout","scripts.resolve_session6_8_claims","shiproom.session6_8_proof_execution","scripts.run_workflow_integration_evals","scripts.run_session6_8_contract_parity","scripts.run_session6_8_security_attacks"}
    assert imports.isdisjoint(forbidden)
