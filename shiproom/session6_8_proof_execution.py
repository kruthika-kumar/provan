"""Execute the frozen requirement-specific Sessions 6--8 proof registry."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from shiproom.workflow_audit import invoke, session


FIXTURE_CLASSES = ("valid", "near_valid", "adversarial_invalid")


def _hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_registry() -> dict:
    path = Path(__file__).with_name("session6_8_requirement_proof_registry.json")
    value = json.loads(path.read_text(encoding="utf-8"))
    rows = value.get("proofs")
    if value.get("schema_version") != "session6-8-requirement-proof-registry.v1" or not isinstance(rows, list) or len(rows) != 318:
        raise ValueError("requirement_proof_registry_invalid")
    if len({row.get("proof_id") for row in rows}) != 318:
        raise ValueError("requirement_proof_registry_duplicate")
    return value


def _resolve(reference: str) -> Callable[..., Any]:
    module_name, separator, attribute = reference.rpartition(".")
    if not separator:
        raise ValueError("requirement_proof_symbol_invalid")
    target = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(target):
        raise ValueError("requirement_proof_symbol_missing")
    return target


def _count(value: Any) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, (list, tuple, set, dict, str)):
        return len(value)
    return 1 if value is not None else 0


@dataclass(frozen=True)
class RequirementProofCase:
    proof_id: str
    requirement_id: str
    fixture_class: str
    proof_callable: Callable[[dict[str, Any]], Any]
    production_callable: Callable[[], dict[str, Any]]
    assertion_id: str
    canonical_artifact: str
    minimum_record_count: int
    expected_acceptance: bool
    expected_error: str | None
    semantic_fingerprint: str
    artifact_selector: str
    fixture_mutation: str


def _case(row: dict) -> RequirementProofCase:
    selector = row["artifact_selectors"]
    functions = row["production_functions"]
    if len(selector) != 1 or len(functions) != 1:
        raise ValueError("requirement_proof_binding_invalid")
    return RequirementProofCase(
        proof_id=row["proof_id"],
        requirement_id=row["requirement_id"],
        fixture_class=row["fixture_class"],
        proof_callable=_resolve(row["proof_callable"]),
        production_callable=_resolve(functions[0]),
        assertion_id=row["proof_callable"].rsplit(".", 1)[1],
        canonical_artifact=row["canonical_artifact"],
        minimum_record_count=row["minimum_cardinality"],
        expected_acceptance=row["expected_acceptance"],
        expected_error=row["expected_error"],
        semantic_fingerprint=row["semantic_fingerprint"],
        artifact_selector=selector[0],
        fixture_mutation=row["fixture_mutation"],
    )


PROOF_CASES = {row["proof_id"]: _case(row) for row in _load_registry()["proofs"]}


def execute_proof(proof_id: str, *, final_commit: str) -> dict:
    try:
        case = PROOF_CASES[proof_id]
    except KeyError as exc:
        raise ValueError("proof_id_unregistered") from exc
    actual_acceptance = True
    actual_exception = actual_error = None
    observed: Any = None
    snapshot: dict[str, Any] | None = None
    before_hash = after_hash = None
    with session(Path.cwd(), "proof:" + proof_id) as invocations:
        try:
            snapshot = invoke(case.production_callable)
            before_hash = _hash(snapshot)
            submitted = copy.deepcopy(snapshot)
            if case.fixture_class == "near_valid":
                submitted["proof_limitation"] = "bounded_near_valid_variant"
            elif case.fixture_class == "adversarial_invalid":
                key = case.assertion_id.removeprefix("assert_")
                submitted["measurements"][key]["observed"] = None
            observed = invoke(case.proof_callable, submitted)
            after_hash = _hash(snapshot)
        except ValueError as exc:
            actual_acceptance = False
            actual_exception = type(exc).__name__
            actual_error = str(exc)
            if snapshot is not None:
                after_hash = _hash(snapshot)
    actual_count = _count(observed)
    source_unchanged = before_hash is not None and before_hash == after_hash
    artifact = {
        "schema_version": "session6-8-requirement-proof-artifact.v2",
        "proof_id": proof_id,
        "requirement_id": case.requirement_id,
        "fixture_class": case.fixture_class,
        "assertion_id": case.assertion_id,
        "artifact_selector": case.artifact_selector,
        "fixture_mutation": case.fixture_mutation,
        "semantic_fingerprint": case.semantic_fingerprint,
        "measured_value": observed,
        "measured_cardinality": actual_count,
        "source_snapshot_hash_before": before_hash,
        "source_snapshot_hash_after": after_hash,
        "source_unchanged": source_unchanged,
        "actual_acceptance": actual_acceptance,
        "actual_error_code": actual_error,
    }
    output = os.environ.get("SHIPROOM_PROOF_EVENT_ROOT")
    artifact_paths: list[str] = []
    artifact_hashes: dict[str, str] = {}
    if output:
        root = Path(output)
        root.mkdir(parents=True, exist_ok=True)
        artifact_path = root / (proof_id + ".artifact.json")
        raw = (json.dumps(artifact, sort_keys=True, indent=2) + "\n").encode("utf-8")
        artifact_path.write_bytes(raw)
        artifact_paths = [str(artifact_path)]
        artifact_hashes[str(artifact_path)] = "sha256:" + hashlib.sha256(raw).hexdigest()
    expected_acceptance = case.expected_acceptance
    event = {
        "proof_id": proof_id,
        "requirement_id": case.requirement_id,
        "fixture_class": case.fixture_class,
        "subcase_id": case.assertion_id + ":" + case.fixture_class,
        "semantic_fingerprint": case.semantic_fingerprint,
        "actual_acceptance": actual_acceptance,
        "actual_exception": actual_exception,
        "actual_error_code": actual_error,
        "actual_schema_result": "not_applicable",
        "artifact_paths": artifact_paths,
        "artifact_hashes": artifact_hashes,
        "artifact_assertions": [
            {"assertion_id": case.assertion_id, "selector": case.artifact_selector, "comparator": "equals", "expected": expected_acceptance, "actual": actual_acceptance},
            {"assertion_id": case.assertion_id + "_source_unchanged", "selector": "/source_unchanged", "comparator": "equals", "expected": True, "actual": source_unchanged},
        ],
        "actual_record_count": actual_count,
        "measured_record_count": actual_count,
        "minimum_record_count": case.minimum_record_count,
        "side_effect_observed": not source_unchanged,
        "production_invocation_ids": [item["invocation_id"] for item in invocations],
        "production_invocations": invocations,
        "final_commit": final_commit,
    }
    typed_rejection_ok = case.fixture_class != "adversarial_invalid" or (
        actual_exception == "ValueError" and actual_error == case.expected_error
    )
    cardinality_ok = case.fixture_class == "adversarial_invalid" or actual_count >= case.minimum_record_count
    event["passed"] = actual_acceptance == expected_acceptance and typed_rejection_ok and cardinality_ok and source_unchanged and bool(event["production_invocation_ids"])
    if output:
        path = Path(output) / (proof_id + ".event." + uuid.uuid4().hex + ".json")
        path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    return event
