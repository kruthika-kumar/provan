"""Independent structural parity checks for every currently portable S6--S8 schema.

JSON Schema proves the public shape; these tests also exercise the production
validator where one exists.  They intentionally do not mistake schema validity
for stateful authority validity.
"""
from __future__ import annotations

import json
from importlib import resources

import jsonschema
import pytest

from shiproom.review_organisation import validate_migration_result
from shiproom.remediation_roadmaps import validate_planner_work_order


SCHEMA_PACKAGES = ("shiproom.remediation_schemas", "shiproom.contestability_schemas", "shiproom.review_organisation")


def _schemas():
    values = []
    for package in SCHEMA_PACKAGES:
        for path in resources.files(package).iterdir():
            if path.name.endswith(".json"):
                value = json.loads(path.read_text(encoding="utf-8"))
                if "$schema" in value:
                    values.append((package, path.name, value))
    return values


def test_all_current_session6_8_portable_schemas_parse_and_are_closed():
    schemas = _schemas()
    assert schemas
    for _, name, schema in schemas:
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema.get("type") == "object", name
        assert schema.get("additionalProperties") is False, name


def test_migration_result_schema_and_python_boundary_reject_isolated_extra_field():
    schema = json.loads(resources.files("shiproom.review_organisation").joinpath("migration-and-rollback-result.v1.json").read_text(encoding="utf-8"))
    valid = {"schema_version": "migration-and-rollback-result.v1", "work_order_id": "wo_1", "criterion_ids": ["criterion_1"],
             "evidence_refs": [], "rollback_required": False, "limitations": []}
    jsonschema.Draft202012Validator(schema).validate(valid)
    assert validate_migration_result(valid) == valid
    invalid = {**valid, "details": {}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)
    with pytest.raises(ValueError, match="migration_result_shape_invalid"):
        validate_migration_result(invalid)


def test_closure_evidence_schema_rejects_an_untyped_outcome_instead_of_a_generic_object():
    schema = json.loads(resources.files("shiproom.remediation_schemas").joinpath("remediation-closure-evidence.v1.json").read_text(encoding="utf-8"))
    valid = {"schema_version": "remediation-closure-evidence.v1", "closure_contract_id": "closure_" + "a" * 24,
             "release_id": "release", "release_commit": "a" * 40, "branch": "main", "fixer_id": "fixer",
             "reruns": [{"check_id": "finding_1", "passed": True, "evidence_class": "deterministically_established"}],
             "regression_results": [], "test_results": [], "instrumentation_results": [], "protected_invariant_outcomes": []}
    jsonschema.Draft202012Validator(schema).validate(valid)
    invalid = {**valid, "test_results": [{"anything": True}]}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_planner_work_order_schema_and_python_validator_have_the_same_closed_binding_boundary():
    schema = json.loads(resources.files("shiproom.remediation_schemas").joinpath("remediation-planner-work-order.v1.json").read_text(encoding="utf-8"))
    binding = {"schema_version":"v1","semantic_hash":"sha256:"+"1"*64,"snapshot_hash":"sha256:"+"2"*64}
    valid = {"schema_version":"remediation-planner-work-order.v1","work_order_id":"wo_remediation_planner_"+"a"*24,"preparation_id":"prep_"+"b"*32,"release_id":"release","assigned_issue_ids":["issue_1"],"forbidden_fields":["issue_authority"],"source_packet_hash":"sha256:"+"3"*64,"contract_bindings":{name:dict(binding) for name in ("remediation-planner-role.v1.json","remediation-planner-result.v1.json","remediation-planner-completion-receipt.v1.json")}}
    jsonschema.Draft202012Validator(schema).validate(valid)
    assert validate_planner_work_order(valid) == valid
    invalid = {**valid, "contract_bindings": {"remediation-planner-role.v1.json": binding}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)
    with pytest.raises(ValueError, match="remediation_planner_work_order_invalid"):
        validate_planner_work_order(invalid)
