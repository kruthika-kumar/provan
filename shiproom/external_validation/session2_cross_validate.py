"""Independent Session 2 artifact checks.

This module intentionally does not import :mod:`session2`: it shares only the
canonical encoder and stable error vocabulary with the producer.  Keep this
boundary testable because a producer bug must not validate its own output.
"""
from __future__ import annotations

import re
from typing import Any

from .identity import canonical_json


_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT = re.compile(r"^[0-9a-f]{40}$")


class CrossArtifactError(ValueError):
    pass


def _fail(code: str) -> None:
    raise CrossArtifactError(code)


def _digest(value: Any, code: str) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value) or value[7:] == "0" * 64 or len(set(value[7:])) == 1:
        _fail(code)


def validate_budget_policy(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "programme_budget_usd", "warning_threshold_usd", "projection_gate_usd", "hard_stop_usd", "normal_input_ceiling", "absolute_input_ceiling", "normal_call_reservation_usd", "absolute_per_call_cap_usd", "stage_caps", "hosted_tools", "retry_policy", "long_context_policy", "projection_formula"}
    expected_caps = {"session2_probes": 2, "session3_beta": 40, "beta_rerun_reserve": 25, "session4_controlled": 120, "session5_remediation": 25, "session6_natural": 20, "single_sol_sensitivity": 3, "retry_contingency": 15}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_budget_policy.v1" or value.get("schema_version") != "1": _fail("session2_budget_policy_invalid")
    if {key: value[key] for key in ("programme_budget_usd", "warning_threshold_usd", "projection_gate_usd", "hard_stop_usd", "normal_input_ceiling", "absolute_input_ceiling", "normal_call_reservation_usd", "absolute_per_call_cap_usd")} != {"programme_budget_usd": 250, "warning_threshold_usd": 175, "projection_gate_usd": 210, "hard_stop_usd": 250, "normal_input_ceiling": 220000, "absolute_input_ceiling": 260000, "normal_call_reservation_usd": 1, "absolute_per_call_cap_usd": 2}: _fail("session2_budget_policy_values_invalid")
    if value["stage_caps"] != expected_caps or value["hosted_tools"] != {"web_search": False, "shell": False, "code_interpreter": False} or value["retry_policy"] != "new_attempt_new_reservation" or value["long_context_policy"] != "reject_at_absolute_ceiling": _fail("session2_budget_policy_values_invalid")
    return value


def validate_model_prompt_policy_freeze(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "terra", "artifacts", "arm_equivalence"}
    terra = {"provider": "OpenAI", "api": "Responses API", "model": "gpt-5.6-terra", "knowledge_cutoff": "2026-02-16", "reasoning_effort": "high", "max_output_tokens": 16384, "store": False, "temperature": None, "service_tier": "standard", "hosted_web_search": False, "hosted_shell": False, "hosted_code_interpreter": False}
    arms = {"SHIPROOM_FULL", "SOTA_AGENT", "SHIPROOM_NO_DETERMINISTIC_CORE"}
    properties = {"patient_snapshot_hash", "release_packet_hash", "model_settings_hash", "output_contract_hash", "tool_classes_hash", "network_policy_hash", "wall_time_policy_hash", "cost_policy_hash", "retry_policy_hash"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_model_prompt_policy_freeze.v1" or value.get("schema_version") != "1" or value.get("terra") != terra: _fail("session2_policy_freeze_invalid")
    if not isinstance(value["artifacts"], list) or not value["artifacts"]: _fail("session2_policy_artifacts_invalid")
    seen = set()
    for row in value["artifacts"]:
        if not isinstance(row, dict) or set(row) != {"artifact_id", "path", "git_blob", "sha256", "semantic_version", "used_by_arms"} or not isinstance(row["artifact_id"], str) or not row["artifact_id"] or row["artifact_id"] in seen or not isinstance(row["path"], str) or row["path"].startswith("/") or ".." in row["path"].split("/") or not _GIT.fullmatch(row["git_blob"]): _fail("session2_policy_artifacts_invalid")
        _digest(row["sha256"], "session2_policy_artifacts_invalid")
        if not isinstance(row["semantic_version"], str) or not row["semantic_version"] or not isinstance(row["used_by_arms"], list) or not row["used_by_arms"] or not set(row["used_by_arms"]).issubset(arms): _fail("session2_policy_artifacts_invalid")
        seen.add(row["artifact_id"])
    table = value["arm_equivalence"]
    if not isinstance(table, dict) or set(table) != arms: _fail("session2_arm_equivalence_invalid")
    rows = []
    for arm in sorted(arms):
        row = table[arm]
        if not isinstance(row, dict) or set(row) != properties: _fail("session2_arm_equivalence_invalid")
        for item in row.values(): _digest(item, "session2_arm_equivalence_invalid")
        rows.append(row)
    if rows[1:] != [rows[0], rows[0]]: _fail("session2_arm_equivalence_mismatch")
    return value


def validate_controlled_population(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "controlled_pairs", "additional_harness_only_pairs", "unique_pair_count", "beta_pair_count", "beta_pairs_overlapping_controlled", "controlled_pair_ids", "harness_pair_ids", "beta_pair_ids"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_controlled_population.v1" or value.get("schema_version") != "1": _fail("session2_population_invalid")
    if {key: value[key] for key in ("controlled_pairs", "additional_harness_only_pairs", "unique_pair_count", "beta_pair_count", "beta_pairs_overlapping_controlled")} != {"controlled_pairs":18, "additional_harness_only_pairs":2, "unique_pair_count":20, "beta_pair_count":6, "beta_pairs_overlapping_controlled":4}: _fail("session2_population_counts_invalid")
    controlled, harness, beta = value["controlled_pair_ids"], value["harness_pair_ids"], value["beta_pair_ids"]
    if any(not isinstance(rows, list) or len(rows) != count or len(set(rows)) != count or any(not isinstance(item, str) or not item for item in rows) for rows, count in ((controlled,18),(harness,2),(beta,6))): _fail("session2_population_ids_invalid")
    if set(controlled) & set(harness) or len(set(beta) & set(controlled)) != 4 or len(set(beta) & set(harness)) != 2: _fail("session2_population_overlap_invalid")
    return value


def validate_owner_context_case(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "beta_context_case_id", "repository", "base_sha", "target_sha", "pr_number_or_release_id", "merge_sha", "release_surface", "context_packet_hash", "selection_method", "selection_timestamp", "execution_environment_hash", "assessability_status"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_owner_context_case.v1" or value.get("schema_version") != "1": _fail("session2_owner_context_invalid")
    if value.get("repository") not in {"healthchecks/healthchecks", "pretalx/pretalx", "dlt-hub/dlt", "pypa/hatch"} or any(not _GIT.fullmatch(value[key]) for key in ("base_sha", "target_sha", "merge_sha")) or value.get("assessability_status") not in {"ASSESSABLE", "NOT_ASSESSABLE"}: _fail("session2_owner_context_invalid")
    _digest(value.get("context_packet_hash"), "session2_owner_context_invalid"); _digest(value.get("execution_environment_hash"), "session2_owner_context_invalid")
    return value


def canonical_export_hash(value: Any) -> str:
    """Exposed only to construct independent logical-ledger checkpoints."""
    import hashlib
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()
