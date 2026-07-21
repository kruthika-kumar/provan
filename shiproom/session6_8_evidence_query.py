"""Closed, deterministic queries over persisted Sessions 6--8 evidence.

This module deliberately knows nothing about requirement identifiers or proof
outcomes.  It only reopens canonical artifacts and performs a small set of
deterministic comparisons.  Proof generators and independent validators may
share the query *contract*, but not a recorded result.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


OPERATORS = frozenset(
    {
        "equals",
        "not_equals",
        "count_equals",
        "count_at_least",
        "set_equals",
        "unique",
        "ordered_equals",
        "foreign_keys_complete",
        "hash_equals",
        "unchanged",
        "file_set_equals",
        "pointer_targets",
    }
)


class EvidenceQueryError(ValueError):
    """Typed rejection raised by the closed evidence-query boundary."""


@dataclass(frozen=True)
class QueryResult:
    actual: Any
    expected: Any
    passed: bool
    cardinality: int


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise EvidenceQueryError("evidence_query_pointer_invalid")
    current = value
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError) as exc:
                raise EvidenceQueryError("evidence_query_pointer_unresolved") from exc
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise EvidenceQueryError("evidence_query_pointer_unresolved")
    return current


def load_json(root: Path, relative_path: str) -> Any:
    candidate = (root / relative_path).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise EvidenceQueryError("evidence_query_path_escape")
    if not candidate.is_file() or candidate.is_symlink():
        raise EvidenceQueryError("evidence_query_artifact_missing")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceQueryError("evidence_query_artifact_invalid") from exc


def _cardinality(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, (str, bytes, list, tuple, set, dict)):
        return len(value)
    return 1


def evaluate(root: Path, query: dict[str, Any]) -> QueryResult:
    required = {"artifact", "selector", "operator", "expected"}
    if not isinstance(query, dict) or set(query) != required:
        raise EvidenceQueryError("evidence_query_shape_invalid")
    operator = query["operator"]
    if operator not in OPERATORS:
        raise EvidenceQueryError("evidence_query_operator_invalid")
    document = load_json(root, query["artifact"])
    actual = _pointer(document, query["selector"])
    expected = query["expected"]
    if operator == "equals":
        passed = actual == expected
    elif operator == "not_equals":
        passed = actual != expected
    elif operator == "count_equals":
        passed = _cardinality(actual) == expected
    elif operator == "count_at_least":
        passed = _cardinality(actual) >= expected
    elif operator == "set_equals":
        passed = isinstance(actual, list) and set(actual) == set(expected)
    elif operator == "unique":
        passed = isinstance(actual, list) and len(actual) == len({canonical_bytes(item) for item in actual})
    elif operator == "ordered_equals":
        passed = actual == expected
    elif operator == "hash_equals":
        passed = sha256_bytes(canonical_bytes(actual)) == expected
    elif operator == "unchanged":
        passed = actual == expected
    elif operator == "file_set_equals":
        directory = (root / query["artifact"]).resolve()
        if not directory.is_dir() or directory.is_symlink():
            raise EvidenceQueryError("evidence_query_artifact_missing")
        actual = sorted(path.name for path in directory.iterdir())
        passed = actual == sorted(expected)
    elif operator == "foreign_keys_complete":
        if not isinstance(actual, list) or not isinstance(expected, dict):
            raise EvidenceQueryError("evidence_query_foreign_key_shape_invalid")
        source_field = expected.get("source_field")
        target_values = set(expected.get("target_values", []))
        passed = bool(source_field) and all(isinstance(row, dict) and row.get(source_field) in target_values for row in actual)
    elif operator == "pointer_targets":
        passed = isinstance(actual, str) and actual == expected
    else:  # pragma: no cover - OPERATORS and branches are kept exhaustive.
        raise EvidenceQueryError("evidence_query_operator_invalid")
    return QueryResult(actual=actual, expected=expected, passed=passed, cardinality=_cardinality(actual))


def validate_query(value: dict[str, Any]) -> dict[str, Any]:
    required = {"artifact", "selector", "operator", "expected"}
    if not isinstance(value, dict) or set(value) != required:
        raise EvidenceQueryError("evidence_query_shape_invalid")
    if value["operator"] not in OPERATORS:
        raise EvidenceQueryError("evidence_query_operator_invalid")
    artifact = value["artifact"]
    if (
        not isinstance(artifact, str)
        or not artifact
        or Path(artifact).is_absolute()
        or ".." in Path(artifact).parts
    ):
        raise EvidenceQueryError("evidence_query_artifact_invalid")
    if not isinstance(value["selector"], str) or (value["selector"] and not value["selector"].startswith("/")):
        raise EvidenceQueryError("evidence_query_pointer_invalid")
    return value
