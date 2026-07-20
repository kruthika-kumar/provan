from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from shiproom.workflow_audit import invoke, session
from shiproom.session6_8_semantics import validate_requirement_inventory, validate_workflow_contracts


ROOT = Path(__file__).resolve().parents[1]


def test_authoritative_requirement_inventory_has_exact_frozen_cardinality():
    value=json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text(encoding="utf-8"))
    rows=value["requirements"]
    groups={"6":0,"7":0,"8_contestability":0,"8_management":0,"shared":0}
    for row in rows: groups[row["session"]] += 1
    assert value["expected_requirement_count"] == 106
    assert len(rows) == len({row["requirement_id"] for row in rows}) == 106
    assert groups == {"6":22,"7":30,"8_contestability":17,"8_management":22,"shared":15}
    validate_requirement_inventory(value)


def test_approved_requirement_semantics_reject_isolated_weakening():
    value=json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text(encoding="utf-8"))
    mutations=(
        ("normative_behavior", "replacement text"),
        ("forbidden_substitutions", []),
        ("required_artifacts", []),
        ("minimum_cardinalities", {}),
    )
    for field,replacement in mutations:
        changed=json.loads(json.dumps(value)); changed["requirements"][0][field]=replacement
        with pytest.raises(ValueError): validate_requirement_inventory(changed)


def test_approved_workflow_semantics_are_frozen_and_reject_weakened_cardinality():
    value=json.loads((ROOT/"docs/validation/session6-8-workflow-contracts.json").read_text(encoding="utf-8"))
    validate_workflow_contracts(value)
    changed=json.loads(json.dumps(value)); first=next(iter(changed["cases"][0]["minimum_record_counts"])); changed["cases"][0]["minimum_record_counts"][first]=0
    with pytest.raises(ValueError,match="cardinality_reduced"): validate_workflow_contracts(changed)


def test_requirement_maps_and_claims_are_exact_and_non_vacuous():
    inventory=json.loads((ROOT/"docs/validation/session6-8-requirement-inventory.json").read_text())["requirements"]
    ids={row["requirement_id"] for row in inventory}
    completion=json.loads((ROOT/"docs/validation/session6-8-completion-map.json").read_text())["requirements"]
    execution=json.loads((ROOT/"docs/validation/session6-8-execution-map.json").read_text())["requirements"]
    proofs=json.loads((ROOT/"docs/validation/session6-8-proof-manifest.json").read_text())["proofs"]
    claims=json.loads((ROOT/"docs/validation/session6-8-claim-registry.json").read_text())["claims"]
    assert ids == {row["requirement_id"] for row in completion} == {row["requirement_id"] for row in execution} == {row["requirement_id"] for row in proofs} == {rid for claim in claims for rid in claim["requirement_ids"]}
    assert len(proofs) == 318
    assert all({row["fixture_class"] for row in proofs if row["requirement_id"] == rid} == {"valid","near_valid","adversarial_invalid"} for rid in ids)
    assert all(all(count >= 1 for count in claim["minimum_record_counts"].values()) for claim in claims)
    assert len(claims)==106 and all(len(claim["requirement_ids"])==1 for claim in claims)


def test_workflow_runner_has_no_case_boolean_assertion_fallback():
    tree=ast.parse((ROOT/"scripts/run_workflow_integration_evals.py").read_text(encoding="utf-8"))
    calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
    assert not any(isinstance(call.func,ast.Name) and call.func.id=="bool" and call.args and isinstance(call.args[0],ast.Name) and call.args[0].id=="passed" for call in calls)


def test_workflow_audit_derives_real_callable_identity_and_is_noop_when_disabled(tmp_path: Path):
    def boundary(value): return {"status":"ok","value":value}
    assert invoke(boundary,3)["value"] == 3
    with session(ROOT,"case") as records:
        assert invoke(boundary,4)["value"] == 4
    assert len(records)==1
    assert records[0]["module"] == __name__
    assert records[0]["qualified_function"].endswith("test_workflow_audit_derives_real_callable_identity_and_is_noop_when_disabled.<locals>.boundary")
    assert records[0]["output_semantic_hash"].startswith("sha256:")


def test_independent_validator_has_static_import_separation():
    path=ROOT/"scripts/validate_session6_8_closeout_independently.py"
    tree=ast.parse(path.read_text(encoding="utf-8"))
    imported={alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names}
    imported|={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom) and node.module}
    forbidden={"scripts.report_session6_8_closeout","scripts.resolve_session6_8_claims","shiproom.semantic_closure"}
    assert imported.isdisjoint(forbidden)
