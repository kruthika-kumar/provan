from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import yaml

from .errors import ProvanError
from .modeling import FROZEN_PUBLIC_MODEL_EGRESS


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SEMANTIC = {
    "outcome", "invariant", "recovery_requirement", "technical_contract",
    "implementation_constraint", "exact_content", "example", "suggestion",
    "implementation_description", "historical_context", "non_goal",
    "untrusted_instruction", "unresolved_conflict", "unresolved",
}
STANDARD = (
    "source_bundle", "source_coverage", "source_authority_ledger", "blind_intent",
    "goal_obstacle", "pre_mortem", "contract_candidate", "adversarial_audit",
    "revision", "witness_set", "semantic_freeze", "implementation_mapping",
    "verification_plan", "readiness", "owner_projection",
)
DEEP = (
    "source_bundle", "source_coverage", "source_authority_ledger", "blind_path_a",
    "blind_path_b", "blind_paths_freeze", "deep_synthesis", "goal_obstacle",
    "pre_mortem", "contract_candidate", "adversarial_audit", "revisions",
    "witness_set", "mutation_analysis", "final_audit", "semantic_freeze",
    "implementation_mapping", "verification_plan", "readiness", "owner_projection",
)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(raw: bytes, schema_id: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvanError("SESSION12R_CANONICAL_JSON_INVALID", schema_id) from exc
    if not isinstance(value, dict) or value.get("schema_id") != schema_id or raw != _canonical(value):
        raise ProvanError("SESSION12R_CANONICAL_JSON_INVALID", schema_id)
    return value


def validate_model_egress_allowlist_serialized(raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session12r_model_egress_allowlist.v1")
    expected = [
        {"case_id": case_id, "source_digests": list(digests)}
        for case_id, digests in sorted(FROZEN_PUBLIC_MODEL_EGRESS.items())
    ]
    if (value.get("sensitivity") != "PUBLIC_SAFE" or
            value.get("classification") != "PUBLIC_SAFE" or
            value.get("operator_authorization_required") is not True or
            value.get("derived_public_artifacts_require_separate_authorization") is not True or
            value.get("raw_private_inputs_public") is not False or
            value.get("cases") != expected):
        raise ProvanError("SESSION12R_MODEL_EGRESS_ALLOWLIST_INVALID", "cases")
    return value


def _ref(ref: Any, expected_id: str, raw: bytes, code: str) -> None:
    if not isinstance(ref, dict) or ref.get("id") != expected_id or ref.get("sha256") != _digest(raw):
        raise ProvanError(code, expected_id)


def _pointer(path: tuple[str | int, ...]) -> str:
    return "" if not path else "/" + "/".join(str(item).replace("~", "~0").replace("/", "~1") for item in path)


def _leaves(value: Any, path: tuple[str | int, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items(): yield from _leaves(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value): yield from _leaves(child, (*path, index))
    else: yield _pointer(path), value


def validate_source_bundle_serialized(raw: bytes, frozen_blobs: dict[str, bytes]) -> dict[str, Any]:
    value = _load(raw, "provan.internal.source_bundle.v1")
    if value.get("sensitivity") != "PRIVATE_LOCAL" or value.get("raw_bytes_public") is not False or value.get("raw_bytes_telemetry") is not False or value.get("cleanup_state") != "RETAINED_UNTIL_TERMINAL":
        raise ProvanError("SESSION12R_SOURCE_BUNDLE_SENSITIVITY_INVALID", value.get("bundle_id", ""))
    inventory = []
    ids: set[str] = set()
    for row in value.get("sources", []):
        source_id = row.get("source_id"); blob = frozen_blobs.get(source_id)
        if source_id in ids or blob is None or row.get("sha256") != _digest(blob) or row.get("bytes") != len(blob) or row.get("blob_ref", {}).get("sha256") != row.get("sha256") or row.get("sensitivity") != "PRIVATE_LOCAL":
            raise ProvanError("SESSION12R_SOURCE_BUNDLE_BINDING_INVALID", str(source_id))
        ids.add(source_id); inventory.append({key: row[key] for key in ("source_id", "role", "media_type", "bytes", "sha256")})
    if not ids or value.get("semantic_input_digest") != _digest(_canonical(inventory)) or not DIGEST.fullmatch(str(value.get("candidate_digest", ""))):
        raise ProvanError("SESSION12R_SOURCE_BUNDLE_BINDING_INVALID", value.get("bundle_id", ""))
    return value


def validate_source_coverage_serialized(raw: bytes, bundle_raw: bytes, frozen_blobs: dict[str, bytes], *, adjudicated_material: dict[str, str] | None = None) -> dict[str, Any]:
    value = _load(raw, "provan.internal.source_coverage.v1")
    bundle = validate_source_bundle_serialized(bundle_raw, frozen_blobs)
    _ref(value.get("bundle_ref"), bundle["bundle_id"], bundle_raw, "SESSION12R_COVERAGE_BUNDLE_MISMATCH")
    rows = value.get("items", []); by_source: dict[str, list[dict[str, Any]]] = {}
    ids: set[str] = set()
    for row in rows:
        if row.get("coverage_id") in ids or row.get("classification") not in SEMANTIC | {"non_semantic", "ignored"} or not isinstance(row.get("semantic_text"), str):
            raise ProvanError("SESSION12R_COVERAGE_ITEM_INVALID", str(row.get("coverage_id")))
        ids.add(row["coverage_id"]); by_source.setdefault(row.get("source_id"), []).append(row)
    entries = {row["source_id"]: row for row in bundle["sources"]}
    if set(by_source) != set(entries): raise ProvanError("SESSION12R_COVERAGE_SOURCE_SET_MISMATCH", "sources")
    for source_id, entry in entries.items():
        blob = frozen_blobs[source_id]
        spans = sorted((row for row in by_source[source_id] if row.get("coordinate_type") == "byte_span"), key=lambda row: row.get("start", -1))
        cursor = 0
        for row in spans:
            start = row.get("start"); end = row.get("end")
            if start != cursor or not isinstance(end, int) or end < start or end > len(blob) or row.get("excerpt_digest") != _digest(blob[start:end]) or row.get("semantic_text") != blob[start:end].decode("utf-8").strip():
                raise ProvanError("SESSION12R_COVERAGE_SPAN_INVALID", source_id)
            cursor = end
        if cursor != len(blob): raise ProvanError("SESSION12R_COVERAGE_GAP", source_id)
        if entry["media_type"] in {"json", "yaml", "yml"}:
            text = blob.decode("utf-8"); parsed = json.loads(text) if entry["media_type"] == "json" else yaml.safe_load(text)
            expected = {_pointer_path: _value for _pointer_path, _value in _leaves(parsed)}
            structured = {row.get("pointer"): row for row in by_source[source_id] if row.get("coordinate_type") == "structured_node"}
            if set(structured) != set(expected): raise ProvanError("SESSION12R_COVERAGE_STRUCTURED_SET_MISMATCH", source_id)
            for pointer, item in expected.items():
                row = structured[pointer]
                if row.get("value_digest") != _digest(_canonical(item)) or row.get("semantic_text") != str(item): raise ProvanError("SESSION12R_COVERAGE_STRUCTURED_VALUE_MISMATCH", pointer)
    counts = {"classified_semantic": 0, "explicit_non_semantic": 0, "explicit_ignored": 0, "unresolved": 0}
    for row in rows:
        if row["classification"] == "non_semantic": counts["explicit_non_semantic"] += 1
        elif row["classification"] == "ignored": counts["explicit_ignored"] += 1
        elif row["classification"] == "unresolved": counts["unresolved"] += 1
        else: counts["classified_semantic"] += 1
    if value.get("counts") != counts or value.get("unaccounted") != 0 or value.get("yaml_comment_policy") != "CONTEXTUAL_UNTRUSTED_COVERAGE_SPAN":
        raise ProvanError("SESSION12R_COVERAGE_AGGREGATE_INVALID", value["coverage_id"])
    if adjudicated_material:
        actual = {row["coverage_id"]: row["classification"] for row in rows}
        for coverage_id, expected_class in adjudicated_material.items():
            if actual.get(coverage_id) != expected_class:
                raise ProvanError("SESSION12R_MATERIAL_COVERAGE_MISCLASSIFIED", coverage_id)
    return value


def validate_source_ledger_serialized(raw: bytes, bundle_raw: bytes, coverage_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.source_authority_ledger.v2")
    bundle = _load(bundle_raw, "provan.internal.source_bundle.v1"); coverage = _load(coverage_raw, "provan.internal.source_coverage.v1")
    _ref(value.get("source_bundle_ref"), bundle["bundle_id"], bundle_raw, "SESSION12R_LEDGER_BUNDLE_MISMATCH")
    _ref(value.get("coverage_ref"), coverage["coverage_id"], coverage_raw, "SESSION12R_LEDGER_COVERAGE_MISMATCH")
    coverage_by_id = {row["coverage_id"]: row for row in coverage["items"] if row["classification"] not in {"non_semantic", "ignored"}}
    source_by_id = {row["source_id"]: row for row in bundle["sources"]}
    statements = value.get("statements", [])
    if len(statements) != len(coverage_by_id): raise ProvanError("SESSION12R_LEDGER_COVERAGE_INCOMPLETE", value["ledger_id"])
    seen: set[str] = set()
    for statement in statements:
        expected_coverage = next((row for row in coverage_by_id.values() if _digest(_canonical([row["coverage_id"], row["classification"]])) == statement.get("statement_id")), None)
        if expected_coverage is None or statement["statement_id"] in seen: raise ProvanError("SESSION12R_STATEMENT_ID_INVALID", str(statement.get("statement_id")))
        seen.add(statement["statement_id"]); source = source_by_id[expected_coverage["source_id"]]
        expected_ref = {"id": source["source_id"], "sha256": source["sha256"]}
        expected_coordinate = {key: expected_coverage[key] for key in ("coordinate_type", "start", "end", "pointer") if key in expected_coverage}
        if statement.get("source_ref") != expected_ref or statement.get("coordinate") != expected_coordinate or statement.get("content_digest") != expected_coverage.get("excerpt_digest", expected_coverage.get("value_digest")) or statement.get("semantic_text") != expected_coverage["semantic_text"] or statement.get("classification") != expected_coverage["classification"] or statement.get("material") != expected_coverage["material"]:
            raise ProvanError("SESSION12R_STATEMENT_RECOMPUTATION_MISMATCH", statement["statement_id"])
        if statement.get("authority") not in {"source_attributed", "untrusted_context", "unresolved"} or statement.get("sensitivity") != "PRIVATE_LOCAL": raise ProvanError("SESSION12R_STATEMENT_AUTHORITY_INVALID", statement["statement_id"])
    if value.get("authority_ceiling") != "SOURCE_ATTRIBUTED_PROPOSAL" or value.get("candidate_digest") != bundle.get("candidate_digest"):
        raise ProvanError("SESSION12R_LEDGER_AUTHORITY_INVALID", value["ledger_id"])
    return value


def validate_intent_serialized(raw: bytes, ledger_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.intent_model.v2"); ledger = _load(ledger_raw, "provan.source_authority_ledger.v2")
    _ref(value.get("source_ledger_ref"), ledger["ledger_id"], ledger_raw, "SESSION12R_INTENT_LEDGER_MISMATCH")
    statement_by_id = {row["statement_id"]: row for row in ledger["statements"]}
    buckets = {"outcome": "outcomes", "invariant": "invariants", "recovery_requirement": "recovery_expectations", "non_goal": "non_goals", "unresolved_conflict": "conflicts", "implementation_description": "implementation_descriptions", "implementation_constraint": "implementation_descriptions", "exact_content": "exact_content", "technical_contract": "states_transitions", "example": "ambiguities", "suggestion": "ambiguities", "untrusted_instruction": "ambiguities", "historical_context": "ambiguities", "unresolved": "ambiguities"}
    actual: dict[str, str] = {}
    for bucket in ("actors", "users", "outcomes", "invariants", "states_transitions", "recovery_expectations", "non_goals", "ambiguities", "conflicts", "implementation_descriptions", "exact_content"):
        for item in value.get(bucket, []):
            ref = item.get("statement_ref")
            if ref is not None:
                if ref in actual or ref not in statement_by_id or item.get("semantic_value") != statement_by_id[ref]["semantic_text"] or item.get("material") != statement_by_id[ref]["material"]: raise ProvanError("SESSION12R_INTENT_ITEM_BINDING_INVALID", str(ref))
                actual[ref] = bucket
    expected = {sid: buckets.get(row["classification"], "ambiguities") for sid, row in statement_by_id.items()}
    if actual != expected: raise ProvanError("SESSION12R_INTENT_COVERAGE_INVALID", value["intent_id"])
    return value


def validate_candidate_serialized(raw: bytes, intent_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.contract_candidate.v2"); intent = _load(intent_raw, "provan.intent_model.v2")
    _ref(value.get("intent_ref"), intent["intent_id"], intent_raw, "SESSION12R_CANDIDATE_INTENT_MISMATCH")
    obligation_items = {row["item_id"]: row for bucket in ("outcomes", "invariants", "recovery_expectations", "states_transitions", "exact_content") for row in intent[bucket]}
    non_goals = {row["item_id"] for row in intent["non_goals"]}
    covered: set[str] = set()
    for criterion in value.get("criteria", []):
        refs = criterion.get("statement_refs", [])
        if not refs or any(ref in non_goals or ref not in obligation_items for ref in refs) or any(ref in covered for ref in refs): raise ProvanError("SESSION12R_CANDIDATE_CRITERION_AUTHORITY_INVALID", criterion.get("criterion_id", ""))
        covered.update(refs)
        expected_material = any(obligation_items[ref]["material"] for ref in refs)
        if criterion.get("material") != expected_material or criterion.get("authority") not in {obligation_items[ref]["authority"] for ref in refs}: raise ProvanError("SESSION12R_CANDIDATE_CRITERION_BINDING_INVALID", criterion["criterion_id"])
    if covered != set(obligation_items): raise ProvanError("SESSION12R_CANDIDATE_OBLIGATION_COVERAGE_INVALID", value["candidate_id"])
    return value


def validate_mapping(value: dict[str, Any], candidate: dict[str, Any], brief: dict[str, Any], semantic_freeze_digest: str) -> None:
    evidence_rows = brief.get("analysis_evidence", [])
    surface_inventory = sorted(({"path": row.get("path"), "digest": row.get("blob_sha256", row.get("content_digest")), "surface_classes": sorted(str(item) for item in row.get("surface_classes", []))} for row in evidence_rows), key=lambda row: str(row["path"]))
    if value.get("schema_id") != "provan.internal.implementation_source_map.v1" or value.get("candidate") != brief.get("candidate") or value.get("candidate_bytes_digest") != brief.get("candidate", {}).get("candidate_digest") or value.get("candidate_surface_digest") != _digest(_canonical(surface_inventory)) or value.get("semantic_freeze_digest") != semantic_freeze_digest or value.get("analysis_evidence_digest") != _digest(_canonical(evidence_rows)):
        raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_CANDIDATE_MISMATCH", str(value.get("map_id")))
    criteria = {row["criterion_id"]: row for row in candidate["criteria"]}; mappings = value.get("criterion_mappings", [])
    if len(mappings) != len(criteria) or {row.get("criterion_id") for row in mappings} != set(criteria): raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_COVERAGE_INVALID", value["map_id"])
    evidence = {row.get("path"): row for row in brief.get("analysis_evidence", [])}
    for row in mappings:
        if row.get("status") not in {"supported", "unresolved", "not_discoverable"}: raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_STATUS_INVALID", row["criterion_id"])
        if row["status"] == "supported" and (not row.get("surface_refs") or any(ref.get("path") not in evidence or ref.get("surface_classes") != sorted(evidence[ref["path"]].get("surface_classes", [])) for ref in row["surface_refs"])): raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_UNSUPPORTED", row["criterion_id"])
        if row["status"] != "supported" and row.get("surface_refs"): raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_UNSUPPORTED", row["criterion_id"])
    if value.get("unsupported_claimed_supported") != 0 or value.get("mutable_explanatory_only") != (brief["candidate"].get("mode") != "immutable") or value.get("source_only") is not True or value.get("read_only") is not True or value.get("creates_authority") is not False:
        raise ProvanError("SESSION12R_IMPLEMENTATION_MAP_AUTHORITY_INVALID", value["map_id"])


def validate_pattern_selection_serialized(raw: bytes, candidate_raw: bytes, library: dict[str, Any]) -> dict[str, Any]:
    value = _load(raw, "provan.verification_pattern_selection.v2"); candidate = _load(candidate_raw, "provan.contract_candidate.v2")
    _ref(value.get("contract_candidate_ref"), candidate["candidate_id"], candidate_raw, "SESSION12R_PATTERN_CANDIDATE_MISMATCH")
    patterns = {row["pattern_id"]: row for row in library.get("patterns", [])}; criteria = {row["criterion_id"] for row in candidate["criteria"]}
    pairs: set[tuple[str, str]] = set(); selected: set[str] = set()
    for row in value.get("items", []):
        pattern_id = row.get("pattern_ref", {}).get("id"); criterion = row.get("criterion_ref"); dimension = row.get("distinct_verification_contribution")
        if pattern_id not in patterns or row["pattern_ref"].get("version") != patterns[pattern_id].get("version") or criterion not in criteria or not row.get("applicability_basis") or not row.get("oracle_need") or row.get("capability_requirement") != patterns[pattern_id].get("capability_requirements") or not dimension:
            raise ProvanError("SESSION12R_PATTERN_BASIS_INVALID", str(pattern_id))
        if (criterion, dimension) in pairs: raise ProvanError("SESSION12R_PATTERN_DUPLICATE_DIMENSION", criterion)
        pairs.add((criterion, dimension)); selected.add(pattern_id)
    if selected == set(patterns): raise ProvanError("SESSION12R_PATTERN_SELECT_ALL_FORBIDDEN", value["selection_id"])
    if len(selected) * 4 >= len(patterns) * 3: raise ProvanError("SESSION12R_PATTERN_HIGH_COVERAGE_REVIEW_REQUIRED", value["selection_id"])
    if value.get("materially_irrelevant_selected") != 0 or value.get("execution_implied") is not False or value.get("challenge_implied") is not False:
        raise ProvanError("SESSION12R_PATTERN_AUTHORITY_INVALID", value["selection_id"])
    return value


def validate_projection_serialized(raw: bytes, candidate_raw: bytes, audit_digest: str, witness_digest: str, selection_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.foundry_acceptance_projection.v2"); candidate = _load(candidate_raw, "provan.contract_candidate.v2"); selection = _load(selection_raw, "provan.verification_pattern_selection.v2")
    if value.get("creates_authority") is not False or value.get("owner_confirmation_required") is not True or value.get("execution_available") is not False or value.get("challenge_available") is not False:
        raise ProvanError("SESSION12R_PROJECTION_AUTHORITY_INVALID", value["projection_id"])
    criteria = value.get("proposed_contract_terms", {}).get("criteria", []); candidate_ids = {row["criterion_id"] for row in candidate["criteria"]}
    if {row.get("criterion_id") for row in criteria} != candidate_ids or {row.get("criterion_id") for row in value.get("term_provenance", [])} != candidate_ids:
        raise ProvanError("SESSION12R_PROJECTION_TERM_COVERAGE_INVALID", value["projection_id"])
    selected = {row["criterion_ref"]: [] for row in selection["items"]}
    for row in selection["items"]: selected.setdefault(row["criterion_ref"], []).append(row["pattern_ref"])
    for row in value["term_provenance"]:
        if row.get("audit_ref") is None or row.get("witness_ref") is None or sorted(row.get("pattern_refs", []), key=_canonical) != sorted(selected.get(row["criterion_id"], []), key=_canonical): raise ProvanError("SESSION12R_PROJECTION_PROVENANCE_INVALID", row["criterion_id"])
    if not DIGEST.fullmatch(str(value.get("semantic_freeze_digest", ""))) or not DIGEST.fullmatch(str(value.get("implementation_map_digest", ""))): raise ProvanError("SESSION12R_PROJECTION_BINDING_INVALID", value["projection_id"])
    return value


def validate_run_serialized(raw: bytes, artifacts: dict[str, bytes], brief_raw: bytes, library: dict[str, Any]) -> dict[str, Any]:
    value = _load(raw, "provan.internal.contract_foundry_run.v2"); brief = _load(brief_raw, "provan.change_brief.v1")
    if value.get("package_version") != "0.5.1" or value.get("policy_version") != "community.contract-foundry.semantic-successor.v1" or value.get("scorer_version") != "community.contract-foundry.semantic-scorer.v1": raise ProvanError("SESSION12R_RUN_VERSION_INVALID", value["run_id"])
    expected_order = DEEP if value.get("depth") == "deep" else STANDARD
    if tuple(value.get("stage_order", [])) != expected_order or [row.get("stage") for row in value.get("stage_execution", [])] != list(expected_order): raise ProvanError("SESSION12R_STAGE_ORDER_INVALID", value["run_id"])
    trace = {row["stage"]: row for row in value["stage_execution"]}; previous: list[str] = []
    ledger_digest = value["source_ledger_ref"]["sha256"]; paths = [row["output_digest"] for row in value.get("deep_paths", [])]
    for stage in expected_order:
        row = trace[stage]
        if stage == "source_bundle": expected_inputs = []
        elif stage in {"blind_path_a", "blind_path_b"}: expected_inputs = [ledger_digest]
        elif stage == "blind_paths_freeze": expected_inputs = paths
        else: expected_inputs = previous
        if row.get("input_digests") != expected_inputs or row.get("status") != ("EXECUTED" if row.get("output_digests") else "NOT_APPLICABLE"): raise ProvanError("SESSION12R_STAGE_DATAFLOW_INVALID", stage)
        if row.get("output_digests"): previous = row["output_digests"]
    bundle_raw = artifacts["source_bundle"]; coverage_raw = artifacts["source_coverage"]; ledger_raw = artifacts["source_ledger"]; intent_raw = artifacts["intent"]; candidate_raw = artifacts["candidate"]; selection_raw = artifacts["selection"]; projection_raw = artifacts["projection"]
    bundle = validate_source_bundle_serialized(bundle_raw, artifacts["blobs"]); coverage = validate_source_coverage_serialized(coverage_raw, bundle_raw, artifacts["blobs"]); ledger = validate_source_ledger_serialized(ledger_raw, bundle_raw, coverage_raw); intent = validate_intent_serialized(intent_raw, ledger_raw); candidate = validate_candidate_serialized(candidate_raw, intent_raw); selection = validate_pattern_selection_serialized(selection_raw, candidate_raw, library)
    _ref(value.get("source_bundle_ref"), bundle["bundle_id"], bundle_raw, "SESSION12R_RUN_BUNDLE_MISMATCH"); _ref(value.get("source_coverage_ref"), coverage["coverage_id"], coverage_raw, "SESSION12R_RUN_COVERAGE_MISMATCH"); _ref(value.get("source_ledger_ref"), ledger["ledger_id"], ledger_raw, "SESSION12R_RUN_LEDGER_MISMATCH")
    semantic_freeze_digest = _digest(_canonical(value.get("semantic_artifacts")))
    validate_mapping(value.get("implementation_map", {}), candidate, brief, semantic_freeze_digest)
    validate_projection_serialized(projection_raw, candidate_raw, value["semantic_artifacts"]["audit"], value["semantic_artifacts"]["witnesses"], selection_raw)
    if value.get("information_boundary") == "implementation-informed" and value.get("contract_readiness") != "NOT_READY": raise ProvanError("SESSION12R_NONBLIND_READINESS_INVALID", value["run_id"])
    if value.get("implementation_map", {}).get("mutable_explanatory_only") and value.get("contract_readiness") != "NOT_READY": raise ProvanError("SESSION12R_MUTABLE_READINESS_INVALID", value["run_id"])
    if value.get("execution_available") is not False or value.get("challenge_available") is not False or value.get("mode_qualification") != "IMPLEMENTED_UNQUALIFIED": raise ProvanError("SESSION12R_RUN_CAPABILITY_INVALID", value["run_id"])
    measurements = value.get("measurements", {})
    required = {"wall_time_ms", "http_model_calls", "input_tokens", "output_tokens", "reasoning_tokens", "cost_status", "cost_usd"}
    if set(measurements) != required or any(key.lower().startswith("p50") or "percentile" in key.lower() for key in measurements): raise ProvanError("SESSION12R_MEASUREMENTS_INVALID", value["run_id"])
    budget = value.get("budget_policy", {})
    expected_budget = {"session_hard_cap_usd":75,"classification_calls_max":16,"classification_input_tokens_max":512000,"classification_output_tokens_max":64000,"classification_reserved_cost_usd":2,"total_calls_max":28 if value["depth"]=="deep" else 24,"run_reserved_cost_usd":7 if value["depth"]=="deep" else 5}
    if budget != expected_budget or measurements["http_model_calls"] > budget["total_calls_max"]: raise ProvanError("SESSION12R_BUDGET_BINDING_INVALID", value["run_id"])
    return value


def semantic_stability(runs: list[dict[str, Any]]) -> dict[str, Any]:
    if len(runs) < 3: raise ProvanError("SESSION12R_STABILITY_RUN_COUNT_INVALID", str(len(runs)))
    dimensions = ("material_obligations", "non_goals", "exact_content_rules", "material_ambiguities", "core_verification_dimensions")
    baseline = {key: set(runs[0].get(key, [])) for key in dimensions}
    disagreements = []
    for index, run in enumerate(runs[1:], 2):
        for key in dimensions:
            if set(run.get(key, [])) != baseline[key]: disagreements.append({"run": index, "dimension": key})
    return {"schema_id": "provan.internal.semantic_stability.v1", "runs": len(runs), "dimensions": list(dimensions), "semantic_stable": not disagreements, "disagreements": disagreements, "byte_identity_required": False}


def hard_qualification(metrics: dict[str, Any]) -> str:
    ones = {"material_explicit_obligation_recall", "valid_acceptance", "near_valid_acceptance", "adversarial_rejection", "material_ambiguity_owner_routing", "material_oracle_disposition_completeness", "material_finding_disposition_coverage", "material_obligation_map_disposition", "material_verification_dimension_disposition", "material_mutation_plan_sensitivity", "non_material_mutation_stability"}
    zeros = {"unsupported_material_mandatory_criteria", "material_non_goal_errors", "exact_content_authority_errors", "implementation_authority_errors", "unaccounted_material_source", "wrongly_non_semantic_material_source", "wrongly_ignored_material_source", "unsupported_material_mappings_claimed_supported", "materially_irrelevant_patterns"}
    if set(metrics) != ones | zeros | {"six_run_semantic_stability"}: raise ProvanError("SESSION12R_HARD_GATE_SET_INVALID", "metrics")
    if any(metrics[key] != 1 for key in ones) or any(metrics[key] != 0 for key in zeros) or metrics["six_run_semantic_stability"] is not True: return "FAIL"
    return "PASS"


def validate_public_semantic_evidence_serialized(raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session12r_public_semantic_evidence.v1")
    if value.get("sensitivity") != "PUBLIC_SAFE" or value.get("package_version") != "0.5.1" or value.get("batch_policy_id") != "session12r-public-semantic-v2-strict-output":
        raise ProvanError("SESSION12R_PUBLIC_EVIDENCE_POLICY_INVALID", "public semantic evidence")
    if value.get("raw_source_bytes_published") is not False or value.get("private_source_bundle_published") is not False or value.get("percentiles_reported") is not False or value.get("execution_available") is not False or value.get("challenge_available") is not False:
        raise ProvanError("SESSION12R_PUBLIC_EVIDENCE_AUTHORITY_INVALID", "public semantic evidence")
    runs = value.get("runs")
    if not isinstance(runs, list) or len(runs) != 8:
        raise ProvanError("SESSION12R_PUBLIC_RUN_SET_INVALID", str(len(runs) if isinstance(runs, list) else -1))
    expected_counts = {("httpx-pr-3699-control", "standard"): 1, ("click-pr-3721-control", "standard"): 3, ("httpcore-pr-880-consequential", "standard"): 3, ("httpcore-pr-880-consequential", "deep"): 1}
    actual_counts: dict[tuple[str, str], int] = {}
    for run in runs:
        key = (run.get("case_id"), run.get("depth")); actual_counts[key] = actual_counts.get(key, 0) + 1
        expected_sources = FROZEN_PUBLIC_MODEL_EGRESS.get(run.get("case_id"))
        if tuple(run.get("source_digests", [])) != expected_sources or run.get("run_eligibility") != "ELIGIBLE" or run.get("contract_readiness") not in {"READY_FOR_OWNER_CONFIRMATION", "READY_WITH_MATERIAL_QUESTIONS"} or run.get("execution_available") is not False or run.get("challenge_available") is not False:
            raise ProvanError("SESSION12R_PUBLIC_RUN_BINDING_INVALID", str(run.get("case_id")))
        receipts = run.get("role_receipts"); expected_roles = 7 if run.get("depth") == "deep" else 5
        if not isinstance(receipts, list) or len(receipts) != expected_roles: raise ProvanError("SESSION12R_PUBLIC_ROLE_SET_INVALID", str(run.get("run_id")))
        total_input = total_output = total_calls = 0; total_cost = 0.0
        for receipt in receipts:
            input_tokens = receipt.get("input_tokens"); output_tokens = receipt.get("output_tokens"); cached = receipt.get("cached_input_tokens")
            if receipt.get("provider") != "openai-responses-primary" or receipt.get("model") != "gpt-5.6-sol" or receipt.get("calls") != 1 or receipt.get("previous_response_id") is not None or receipt.get("background") is not False or receipt.get("pricing_policy") != "openai-gpt-5.6-sol-public-rates-2026-08-20" or receipt.get("cost_status") != "computed_from_provider_usage_at_pinned_rates" or not all(isinstance(item, int) for item in (input_tokens, output_tokens, cached)) or not 0 <= cached <= input_tokens:
                raise ProvanError("SESSION12R_PUBLIC_ROLE_RECEIPT_INVALID", str(receipt.get("role")))
            long_input = 2.0 if input_tokens > 272_000 else 1.0; long_output = 1.5 if input_tokens > 272_000 else 1.0
            expected_cost = round(((input_tokens - cached) * 5.0 * long_input + cached * 0.5 * long_input + output_tokens * 30.0 * long_output) / 1_000_000, 8)
            if receipt.get("cost_usd") != expected_cost: raise ProvanError("SESSION12R_PUBLIC_ROLE_COST_MISMATCH", str(receipt.get("role")))
            total_input += input_tokens; total_output += output_tokens; total_calls += 1; total_cost += expected_cost
        measurements = run.get("measurements", {})
        if measurements.get("http_model_calls") != total_calls or measurements.get("input_tokens") != total_input or measurements.get("output_tokens") != total_output or measurements.get("cost_status") != "computed_from_provider_usage_at_pinned_rates" or measurements.get("cost_usd") != round(total_cost, 8):
            raise ProvanError("SESSION12R_PUBLIC_MEASUREMENT_MISMATCH", str(run.get("run_id")))
    if actual_counts != expected_counts: raise ProvanError("SESSION12R_PUBLIC_RUN_SET_INVALID", str(actual_counts))
    expected_dimensions = sorted(["material_obligations", "non_goals", "exact_content_rules", "material_ambiguities", "core_verification_dimensions"])
    stability = value.get("stability")
    if not isinstance(stability, list) or {row.get("case_id") for row in stability} != {"click-pr-3721-control", "httpcore-pr-880-consequential"} or any(row.get("run_count") != 3 or row.get("semantic_dimensions") != expected_dimensions or row.get("semantic_stable") is not True or row.get("disagreements") != [] or row.get("byte_identity_required") is not False for row in stability):
        raise ProvanError("SESSION12R_PUBLIC_STABILITY_INVALID", "stability")
    budget = value.get("batch_budget", {})
    if budget.get("hard_cap_usd") != 75 or budget.get("prior_reserved_cost_usd", 76) < 0 or budget.get("completed_run_reserved_cost_usd") != 42 or budget.get("cumulative_reserved_cost_usd") != budget.get("prior_reserved_cost_usd") + 42 or budget.get("cumulative_reserved_cost_usd") > 75:
        raise ProvanError("SESSION12R_PUBLIC_BATCH_BUDGET_INVALID", "batch budget")
    return value
