"""Frozen semantic bindings for the Sessions 6--8 evidence closeout."""
from __future__ import annotations

import hashlib
import json
from typing import Any


REQUIREMENT_FIELDS = (
    "requirement_id",
    "normative_behavior",
    "forbidden_substitutions",
    "required_artifacts",
    "minimum_cardinalities",
    "near_valid_behavior",
    "adversarial_behavior",
    "adversarial_error_code",
    "owning_production_entrypoint",
)
WORKFLOW_FIELDS = (
    "preconditions",
    "required_production_functions",
    "assertions",
    "required_artifacts",
    "minimum_record_counts",
    "forbidden_substitutions",
)


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def requirement_semantic_hash(row: dict[str, Any]) -> str:
    if set(REQUIREMENT_FIELDS) - set(row):
        raise ValueError("approved_requirement_semantics_incomplete")
    if not isinstance(row["normative_behavior"], str) or not row["normative_behavior"].strip():
        raise ValueError("approved_requirement_behavior_invalid")
    if not isinstance(row["forbidden_substitutions"], list) or not row["forbidden_substitutions"]:
        raise ValueError("approved_requirement_forbidden_substitutions_weakened")
    if not isinstance(row["required_artifacts"], list) or not row["required_artifacts"]:
        raise ValueError("approved_requirement_artifacts_removed")
    cardinalities = row["minimum_cardinalities"]
    if not isinstance(cardinalities, dict) or set(cardinalities) != set(row["required_artifacts"]):
        raise ValueError("approved_requirement_cardinality_scope_invalid")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in cardinalities.values()):
        raise ValueError("approved_requirement_cardinality_reduced")
    for field in ("near_valid_behavior", "adversarial_behavior", "adversarial_error_code", "owning_production_entrypoint"):
        if not isinstance(row[field], str) or not row[field].strip():
            raise ValueError("approved_requirement_semantics_incomplete")
    return canonical_hash({field: row[field] for field in REQUIREMENT_FIELDS})


def validate_requirement_inventory(value: dict[str, Any]) -> dict[str, Any]:
    rows = value.get("requirements") if isinstance(value, dict) else None
    if value.get("expected_requirement_count") != 106 or not isinstance(rows, list) or len(rows) != 106:
        raise ValueError("approved_requirement_count_changed")
    if len({row.get("requirement_id") for row in rows}) != 106:
        raise ValueError("approved_requirement_id_set_changed")
    for row in rows:
        if row.get("approved_semantic_hash") != requirement_semantic_hash(row):
            raise ValueError("approved_requirement_semantics_changed:" + str(row.get("requirement_id")))
    return value


def workflow_semantic_hash(row: dict[str, Any]) -> str:
    if set(WORKFLOW_FIELDS) - set(row):
        raise ValueError("approved_workflow_semantics_incomplete")
    if not row["required_production_functions"] or not row["assertions"] or not row["required_artifacts"]:
        raise ValueError("approved_workflow_semantics_weakened")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in row["minimum_record_counts"].values()):
        raise ValueError("approved_workflow_cardinality_reduced")
    return canonical_hash({field: row[field] for field in WORKFLOW_FIELDS})


def validate_workflow_contracts(value: dict[str, Any]) -> dict[str, Any]:
    rows = value.get("cases") if isinstance(value, dict) else None
    if not isinstance(rows, list) or len(rows) != 18 or len({row.get("case_name") for row in rows}) != 18:
        raise ValueError("approved_workflow_contract_set_changed")
    for row in rows:
        if row.get("approved_semantic_hash") != workflow_semantic_hash(row):
            raise ValueError("approved_workflow_semantics_changed:" + str(row.get("case_name")))
    return value
