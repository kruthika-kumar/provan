"""Session 2 immutable-input authority.

This module deliberately contains no candidate discovery, model invocation, or
patient execution.  It establishes the durable identities and fail-closed
control-plane rules required before those activities can begin.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .identity import canonical_json


SHA = "sha256:"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"(?:todo|tbd|placeholder|example|dummy|fake)", re.I)
LEDGER_STATES = {"RESERVED", "SUBMITTED", "SETTLED", "CANCELLED_BEFORE_SEND", "FAILED_MAX_CHARGED", "BLOCKED"}
TERMINAL_LEDGER_STATES = {"SETTLED", "CANCELLED_BEFORE_SEND", "FAILED_MAX_CHARGED", "BLOCKED"}
STAGES = {"session2_probes", "session3_beta", "beta_rerun_reserve", "session4_controlled", "session5_remediation", "session6_natural", "single_sol_sensitivity", "retry_contingency"}
CONTAMINATION_BANDS = {"FRESH_A", "FRESH_B", "FALLBACK_RECENT"}
PRIMARY_MODEL_ARMS = {"SHIPROOM_FULL", "SOTA_AGENT", "SHIPROOM_NO_DETERMINISTIC_CORE"}
REPOSITORY_SLOTS = (
    "ordinary_workflow_1", "ordinary_workflow_2", "ordinary_workflow_3",
    "engineering_developer", "data_contract_pipeline", "product_measurement_privacy",
)
PRIMARY_POOL = (
    "healthchecks/healthchecks", "pretix/pretix", "pretalx/pretalx",
    "inventree/InvenTree", "pypa/hatch", "dlt-hub/dlt", "formbricks/formbricks",
)
MATURE_POOL = ("streamlit/streamlit", "pytest-dev/pytest", "dbt-labs/dbt-core")
BACKUP_POOL = ("documenso/documenso", "paperless-ngx/paperless-ngx", "sqlfluff/sqlfluff", "evidentlyai/evidently")
PRIVATE_MUTATION_CATALOGUE = {
    "engineering.absent_claimed_artifact", "engineering.public_response_schema_drift", "engineering.swallowed_failure_false_success",
    "journey.returned_share_or_result_url_broken", "journey.required_state_lost_after_navigation", "journey.backend_failure_false_success",
    "measurement.success_failure_indistinguishable", "measurement.required_success_event_missing_or_premature",
    "data.grain_changing_join_duplicates", "data.required_key_null_or_referential_failure",
    "ai_eval.random_cases_instead_of_frozen_ids", "ai_eval.unsupported_output_lacks_fallback_or_false_success",
}
OWNER_CONTEXT_REPOSITORIES = ("healthchecks/healthchecks", "pretalx/pretalx", "dlt-hub/dlt")


class Session2ValidationError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def fail(code: str) -> None:
    raise Session2ValidationError(code)


def canonical_hash(value: Any) -> str:
    return SHA + sha256(canonical_json(value)).hexdigest()


def require_sha(value: Any, code: str = "session2_hash_invalid") -> str:
    if not isinstance(value, str) or not value.startswith(SHA) or not HEX_64.fullmatch(value[7:]):
        fail(code)
    if value[7:] == "0" * 64 or len(set(value[7:])) == 1:
        fail("session2_placeholder_hash")
    return value


def require_git_sha(value: Any, code: str = "session2_git_sha_invalid") -> str:
    if not isinstance(value, str) or not GIT_SHA.fullmatch(value) or value == "0" * 40 or len(set(value)) == 1:
        fail(code)
    return value


def seed_order(seed: str, *parts: str) -> str:
    if not isinstance(seed, str) or not HEX_64.fullmatch(seed):
        fail("session2_seed_invalid")
    if not all(isinstance(part, str) and part for part in parts):
        fail("session2_order_input_invalid")
    return sha256("".join((seed, *parts)).encode("utf-8")).hexdigest()


def contamination_band(issue_created_at: str, fix_created_at: str, cutoff: str = "2026-03-01T00:00:00Z") -> str:
    try:
        issue = datetime.fromisoformat(issue_created_at.replace("Z", "+00:00"))
        fixed = datetime.fromisoformat(fix_created_at.replace("Z", "+00:00"))
        limit = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        fail("session2_fresh_timestamp_invalid")
    if issue.tzinfo is None or fixed.tzinfo is None or issue > fixed:
        fail("session2_fresh_timestamp_invalid")
    if issue >= limit and fixed >= limit:
        return "FRESH_A"
    if fixed >= limit:
        return "FRESH_B"
    return "FALLBACK_RECENT"


def validate_fresh_qualification(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict): fail("session2_fresh_receipt_invalid")
    required = {"case_id", "repository", "buggy_sha", "fixed_sha", "issue_created_at", "fix_created_at", "contamination_band", "cutoff_compliant", "fallback_reason", "public_repository", "usable_license", "authoritative_issue_or_requirement", "buggy_target_oracle", "fixed_target_oracle", "buggy_protected_checks", "fixed_protected_checks", "target_runtime_minutes", "paid_credentials_required", "gpu_required", "proprietary_service_required", "uncontrolled_patient_network_required", "qualified_linux_container_path", "dependency_authority_frozen", "production_supervisor_receipt_present", "independent_replay_present"}
    if set(value) != required: fail("session2_fresh_receipt_fields_invalid")
    require_git_sha(value["buggy_sha"]); require_git_sha(value["fixed_sha"])
    if value["buggy_sha"] == value["fixed_sha"]: fail("session2_fresh_pair_identical")
    band = contamination_band(value["issue_created_at"], value["fix_created_at"])
    if value["contamination_band"] != band or value["cutoff_compliant"] != (band == "FRESH_A"):
        fail("session2_fresh_band_invalid")
    if band == "FRESH_A" and value["fallback_reason"] is not None: fail("session2_fresh_fallback_invalid")
    if band != "FRESH_A" and (not isinstance(value["fallback_reason"], str) or not value["fallback_reason"]): fail("session2_fresh_fallback_missing")
    truthy = {"public_repository", "usable_license", "authoritative_issue_or_requirement", "qualified_linux_container_path", "dependency_authority_frozen", "production_supervisor_receipt_present", "independent_replay_present"}
    if any(value[key] is not True for key in truthy): fail("session2_fresh_gate_failed")
    if (value["buggy_target_oracle"], value["fixed_target_oracle"], value["buggy_protected_checks"], value["fixed_protected_checks"]) != ("EXPECTED_FAILURE", "PASSED", "PASSED", "PASSED"):
        fail("session2_fresh_oracle_transition_invalid")
    if not isinstance(value["target_runtime_minutes"], (int, float)) or value["target_runtime_minutes"] <= 0 or value["target_runtime_minutes"] > 15:
        fail("session2_fresh_runtime_invalid")
    if any(value[key] is not False for key in {"paid_credentials_required", "gpu_required", "proprietary_service_required", "uncontrolled_patient_network_required"}):
        fail("session2_fresh_execution_gate_failed")
    return value


def validate_model_prompt_policy_freeze(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict): fail("session2_policy_freeze_invalid")
    required = {"schema_id", "schema_version", "terra", "artifacts", "arm_equivalence"}
    if set(value) != required or value.get("schema_id") != "external_validation.session2_model_prompt_policy_freeze.v1" or value.get("schema_version") != "1":
        fail("session2_policy_freeze_header_invalid")
    terra = value["terra"]
    expected_terra = {"provider": "OpenAI", "api": "Responses API", "model": "gpt-5.6-terra", "knowledge_cutoff": "2026-02-16", "reasoning_effort": "high", "max_output_tokens": 16384, "store": False, "temperature": None, "service_tier": "standard", "hosted_web_search": False, "hosted_shell": False, "hosted_code_interpreter": False}
    if terra != expected_terra: fail("session2_terra_policy_invalid")
    if not isinstance(value["artifacts"], list) or not value["artifacts"]: fail("session2_policy_artifacts_missing")
    ids = set()
    for item in value["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"artifact_id", "path", "git_blob", "sha256", "semantic_version", "used_by_arms"}: fail("session2_policy_artifact_invalid")
        if not isinstance(item["artifact_id"], str) or not item["artifact_id"] or item["artifact_id"] in ids or not isinstance(item["path"], str) or not item["path"] or item["path"].startswith("/") or PLACEHOLDER.search(item["path"]): fail("session2_policy_artifact_invalid")
        ids.add(item["artifact_id"]); require_git_sha(item["git_blob"]); require_sha(item["sha256"])
        if not isinstance(item["semantic_version"], str) or not item["semantic_version"] or not isinstance(item["used_by_arms"], list) or not set(item["used_by_arms"]).issubset(PRIMARY_MODEL_ARMS) or not item["used_by_arms"]: fail("session2_policy_artifact_invalid")
    table = value["arm_equivalence"]
    if not isinstance(table, dict) or set(table) != PRIMARY_MODEL_ARMS: fail("session2_arm_equivalence_invalid")
    properties = {"patient_snapshot_hash", "release_packet_hash", "model_settings_hash", "output_contract_hash", "tool_classes_hash", "network_policy_hash", "wall_time_policy_hash", "cost_policy_hash", "retry_policy_hash"}
    rows = []
    for arm in sorted(PRIMARY_MODEL_ARMS):
        row = table[arm]
        if not isinstance(row, dict) or set(row) != properties: fail("session2_arm_equivalence_invalid")
        for prop in properties: require_sha(row[prop], "session2_arm_equivalence_hash_invalid")
        rows.append(row)
    if any(row != rows[0] for row in rows[1:]): fail("session2_arm_equivalence_mismatch")
    return value


def validate_qualifying_artifact(value: Any) -> dict[str, Any]:
    """Reject authored success claims and placeholder-bearing qualifying evidence."""
    if not isinstance(value, dict) or value.get("classification") not in {"QUALIFYING_PUBLIC_ARTIFACT", "QUALIFYING_PRIVATE_ARTIFACT"}: fail("session2_qualifying_artifact_classification_invalid")
    required = {"classification", "artifact_id", "source_record_hash", "command", "started_at", "completed_at", "exit_code", "stdout", "stderr", "container_digest", "supervisor_run_id", "result_contract_id"}
    if set(value) != required: fail("session2_qualifying_artifact_fields_invalid")
    if any(not isinstance(value[key], str) or not value[key] or PLACEHOLDER.search(value[key]) for key in {"artifact_id", "source_record_hash", "command", "container_digest", "supervisor_run_id", "result_contract_id"}): fail("session2_qualifying_artifact_placeholder")
    require_sha(value["source_record_hash"])
    if "@sha256:" not in value["container_digest"]: fail("session2_qualifying_artifact_container_mutable")
    total_transcript_bytes = 0
    for stream in ("stdout", "stderr"):
        item = value[stream]
        if not isinstance(item, dict) or set(item) != {"opaque_id", "bytes", "sha256"} or not isinstance(item["opaque_id"], str) or not item["opaque_id"] or not isinstance(item["bytes"], int) or item["bytes"] < 0: fail("session2_qualifying_artifact_stream_invalid")
        require_sha(item["sha256"])
        total_transcript_bytes += item["bytes"]
    if total_transcript_bytes == 0: fail("session2_qualifying_artifact_empty_transcript")
    if not isinstance(value["exit_code"], int): fail("session2_qualifying_artifact_exit_invalid")
    try:
        started = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00")); completed = datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))
        if started.tzinfo is None or completed.tzinfo is None or completed < started: raise ValueError
    except (AttributeError, ValueError): fail("session2_qualifying_artifact_time_invalid")
    return value


def validate_controlled_population(value: Any) -> dict[str, Any]:
    """Freeze the two beta populations without allowing count drift."""
    required = {"controlled_pairs", "additional_harness_only_pairs", "unique_pair_count", "beta_pair_count", "beta_pairs_overlapping_controlled", "controlled_pair_ids", "harness_pair_ids", "beta_pair_ids"}
    if not isinstance(value, dict) or set(value) != required:
        fail("session2_population_invalid")
    counts = {key: value[key] for key in required - {"controlled_pair_ids", "harness_pair_ids", "beta_pair_ids"}}
    expected = {"controlled_pairs": 18, "additional_harness_only_pairs": 2, "unique_pair_count": 20, "beta_pair_count": 6, "beta_pairs_overlapping_controlled": 4}
    if counts != expected:
        fail("session2_population_counts_invalid")
    controlled, harness, beta = value["controlled_pair_ids"], value["harness_pair_ids"], value["beta_pair_ids"]
    if any(not isinstance(items, list) or len(items) != expected_count or len(set(items)) != expected_count or any(not isinstance(item, str) or not item for item in items)
           for items, expected_count in ((controlled, 18), (harness, 2), (beta, 6))):
        fail("session2_population_ids_invalid")
    if set(controlled) & set(harness) or len(set(beta) & set(controlled)) != 4 or len(set(beta) & set(harness)) != 2:
        fail("session2_population_overlap_invalid")
    return value


def validate_owner_context_case(value: Any) -> dict[str, Any]:
    required = {"beta_context_case_id", "repository", "base_sha", "target_sha", "pr_number_or_release_id", "merge_sha", "release_surface", "context_packet_hash", "selection_method", "selection_timestamp", "execution_environment_hash", "assessability_status"}
    if not isinstance(value, dict) or set(value) != required:
        fail("session2_owner_context_fields_invalid")
    if value["repository"] not in set(OWNER_CONTEXT_REPOSITORIES) | {"pypa/hatch"}:
        fail("session2_owner_context_repository_invalid")
    for key in ("base_sha", "target_sha", "merge_sha"):
        require_git_sha(value[key], "session2_owner_context_sha_invalid")
    for key in ("context_packet_hash", "execution_environment_hash"):
        require_sha(value[key], "session2_owner_context_hash_invalid")
    if (not isinstance(value["beta_context_case_id"], str) or not value["beta_context_case_id"]
            or not isinstance(value["pr_number_or_release_id"], (str, int)) or not str(value["pr_number_or_release_id"])
            or not isinstance(value["release_surface"], str) or not value["release_surface"]
            or not isinstance(value["selection_method"], str) or not value["selection_method"]
            or value["assessability_status"] not in {"ASSESSABLE", "NOT_ASSESSABLE"}):
        fail("session2_owner_context_value_invalid")
    try:
        timestamp = datetime.fromisoformat(value["selection_timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None: raise ValueError
    except (AttributeError, ValueError):
        fail("session2_owner_context_time_invalid")
    return value


def _repository_gate(candidate: dict[str, Any]) -> bool:
    gates = {"usable_license", "active_development", "immutable_checkout", "qualified_execution_path", "no_mandatory_secret", "no_gpu", "no_paid_service"}
    signals = candidate.get("consequence_signals")
    return (all(candidate.get(gate) is True for gate in gates)
            and isinstance(signals, list) and len(signals) >= 2
            and len({item.get("category") for item in signals if isinstance(item, dict) and item.get("category") not in {None, "stars"}}) >= 2)


def select_repository_slots(seed: str, candidates: list[dict[str, Any]], *, measurement_qualified: bool) -> dict[str, Any]:
    """Apply the frozen six-slot algorithm and preserve every exclusion."""
    if not isinstance(candidates, list): fail("session2_repository_frame_invalid")
    known = set(PRIMARY_POOL) | set(MATURE_POOL) | set(BACKUP_POOL)
    by_slug: dict[str, dict[str, Any]] = {}
    exclusions: list[dict[str, str]] = []
    for item in candidates:
        if not isinstance(item, dict) or set(item) != {"repository", "eligible_slots", "usable_license", "active_development", "immutable_checkout", "qualified_execution_path", "no_mandatory_secret", "no_gpu", "no_paid_service", "consequence_signals", "review_saturation"}:
            fail("session2_repository_frame_invalid")
        slug = item["repository"]
        if not isinstance(slug, str) or slug not in known or slug in by_slug or not isinstance(item["eligible_slots"], list) or not set(item["eligible_slots"]).issubset(REPOSITORY_SLOTS):
            fail("session2_repository_frame_invalid")
        by_slug[slug] = item
    selected: dict[str, str] = {}
    used: set[str] = set()
    for slot in REPOSITORY_SLOTS:
        required_slot = slot if measurement_qualified or slot != "product_measurement_privacy" else "ordinary_workflow_fallback"
        eligible = []
        for slug, item in by_slug.items():
            slot_ok = slot in item["eligible_slots"] if required_slot != "ordinary_workflow_fallback" else any(candidate_slot.startswith("ordinary_workflow") for candidate_slot in item["eligible_slots"])
            if slug in used or not slot_ok:
                continue
            if _repository_gate(item):
                eligible.append(slug)
            else:
                exclusions.append({"repository": slug, "slot": slot, "reason": "repository_hard_gate_failed"})
        if not eligible:
            fail("session2_repository_slot_exhausted")
        winner = min(eligible, key=lambda slug: seed_order(seed, slug, slot))
        selected[slot] = winner; used.add(winner)
    return {"selected": selected, "exclusions": sorted(exclusions, key=lambda item: (item["slot"], item["repository"])), "coverage_unavailable": [] if measurement_qualified else ["product_measurement_privacy"]}


def validate_review_saturation(value: Any) -> dict[str, Any]:
    required = {"recent_pr_volume", "typical_reviewer_count", "review_comment_density", "ci_check_breadth", "codeowners_present", "merge_latency_hours", "active_contributor_count", "release_process_maturity", "classification"}
    if not isinstance(value, dict) or set(value) != required or value.get("classification") not in {"LOW", "MEDIUM", "HIGH"}:
        fail("session2_review_saturation_invalid")
    numeric = required - {"codeowners_present", "release_process_maturity", "classification"}
    if any(not isinstance(value[key], (int, float)) or isinstance(value[key], bool) or value[key] < 0 for key in numeric):
        fail("session2_review_saturation_invalid")
    if value["codeowners_present"] not in {True, False} or not isinstance(value["release_process_maturity"], str) or not value["release_process_maturity"]:
        fail("session2_review_saturation_invalid")
    return value


def select_subset(seed: str, subset_id: str, family_id: str, cases: list[dict[str, Any]], *, count: int) -> list[dict[str, Any]]:
    if not isinstance(subset_id, str) or not isinstance(family_id, str) or count < 1 or len(cases) < count:
        fail("session2_subset_input_invalid")
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str) or not case["case_id"] or case["case_id"] in ids:
            fail("session2_subset_case_invalid")
        ids.add(case["case_id"])
    return sorted(cases, key=lambda case: seed_order(seed, subset_id, family_id, case["case_id"]))[:count]


def select_sol_sensitivity_case(seed: str, cases: list[dict[str, Any]]) -> str:
    """Select exactly one beta-controlled case under the published priority."""
    eligible = [case for case in cases if case.get("beta_controlled") is True]
    if len(eligible) != 4:
        fail("session2_sol_population_invalid")
    ranks = {"Product Journey": 0, "Product Measurement": 1, "Data Contract/Pipeline": 1, "Engineering": 2}
    if any(case.get("family") not in ranks or not isinstance(case.get("case_id"), str) for case in eligible):
        fail("session2_sol_population_invalid")
    best = min(ranks[case["family"]] for case in eligible)
    candidates = [case for case in eligible if ranks[case["family"]] == best]
    if best == 2:
        maximum = max(case.get("release_surface_count", -1) for case in candidates)
        if not isinstance(maximum, int) or maximum < 0: fail("session2_sol_population_invalid")
        candidates = [case for case in candidates if case["release_surface_count"] == maximum]
    return min(candidates, key=lambda case: seed_order(seed, "sol-sensitivity", case["case_id"]))["case_id"]


def validate_private_mutation(value: Any) -> dict[str, Any]:
    required = {"mutation_id", "family", "source_packet_hash", "source_packet_created_at", "worktree_created_at", "contract", "real_incident_pattern_ref"}
    if not isinstance(value, dict) or set(value) != required or value.get("mutation_id") not in PRIVATE_MUTATION_CATALOGUE:
        fail("session2_private_mutation_invalid")
    require_sha(value["source_packet_hash"], "session2_private_mutation_source_invalid")
    if not isinstance(value["real_incident_pattern_ref"], str) or not value["real_incident_pattern_ref"]:
        fail("session2_private_mutation_incident_invalid")
    try:
        source_time = datetime.fromisoformat(value["source_packet_created_at"].replace("Z", "+00:00")); worktree_time = datetime.fromisoformat(value["worktree_created_at"].replace("Z", "+00:00"))
        if source_time.tzinfo is None or worktree_time.tzinfo is None or source_time >= worktree_time: raise ValueError
    except (AttributeError, ValueError):
        fail("session2_private_mutation_contract_predates_worktree")
    contract = value["contract"]
    required_by_family = {
        "journey": {"actor", "preconditions", "action", "expected_durable_outcome", "failure_behavior", "source_refs"},
        "measurement": {"event_name", "durable_outcome_represented", "success_failure_distinction", "emission_timing", "required_properties", "privacy_constraints", "non_goals", "source_refs"},
        "data": {"entity", "grain", "primary_key", "nullability", "relationship_cardinality", "transformation", "integrity_invariants", "source_refs"},
        "ai_eval": {"case_set_id", "case_set_version", "frozen_case_ids", "oracle_or_rubric_ref", "accepted_output_contract", "unsupported_output_behavior", "fallback_behavior", "malformed_output_behavior", "unavailable_model_behavior", "release_gate_rule", "source_refs"},
    }
    family = value["family"]
    if family in required_by_family and (not isinstance(contract, dict) or set(contract) != required_by_family[family] or any(not contract[key] for key in contract)):
        fail("session2_private_mutation_contract_invalid")
    return value


@dataclass(frozen=True)
class BudgetPolicy:
    programme_budget_usd: float = 250.0
    warning_threshold_usd: float = 175.0
    projection_gate_usd: float = 210.0
    hard_stop_usd: float = 250.0
    normal_input_ceiling: int = 220000
    absolute_input_ceiling: int = 260000
    normal_call_reservation_usd: float = 1.0
    absolute_per_call_cap_usd: float = 2.0
    stage_caps: tuple[tuple[str, float], ...] = (("session2_probes", 2.0), ("session3_beta", 40.0), ("beta_rerun_reserve", 25.0), ("session4_controlled", 120.0), ("session5_remediation", 25.0), ("session6_natural", 20.0), ("single_sol_sensitivity", 3.0), ("retry_contingency", 15.0))

    def document(self) -> dict[str, Any]:
        return {"schema_id": "external_validation.session2_budget_policy.v1", "schema_version": "1", "programme_budget_usd": self.programme_budget_usd, "warning_threshold_usd": self.warning_threshold_usd, "projection_gate_usd": self.projection_gate_usd, "hard_stop_usd": self.hard_stop_usd, "normal_input_ceiling": self.normal_input_ceiling, "absolute_input_ceiling": self.absolute_input_ceiling, "normal_call_reservation_usd": self.normal_call_reservation_usd, "absolute_per_call_cap_usd": self.absolute_per_call_cap_usd, "stage_caps": dict(self.stage_caps), "hosted_tools": {"web_search": False, "shell": False, "code_interpreter": False}, "retry_policy": "new_attempt_new_reservation", "long_context_policy": "reject_at_absolute_ceiling", "projection_formula": "settled+submitted_max+reserved+mandatory_remaining+retry_reserve+sol_reserve"}

    @property
    def hash(self) -> str: return canonical_hash(self.document())


class BudgetLedger:
    """Transactional logical-ledger authority; SQLite bytes are never attested."""
    def __init__(self, path: Path, policy: BudgetPolicy):
        self.path, self.policy = path, policy
        self.db = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.db.execute("PRAGMA foreign_keys=ON"); self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS entries (sequence INTEGER PRIMARY KEY, attempt_id TEXT NOT NULL, idempotency_key TEXT UNIQUE, stage TEXT NOT NULL, state TEXT NOT NULL, reserved REAL NOT NULL, settled REAL, provider_request_id TEXT, predecessor_hash TEXT NOT NULL, entry_hash TEXT UNIQUE NOT NULL)")
        if not self.db.execute("SELECT 1 FROM meta WHERE key='policy_hash'").fetchone():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("INSERT INTO meta(key,value) VALUES('policy_hash',?)", (policy.hash,)); self.db.execute("INSERT INTO meta(key,value) VALUES('genesis_previous_hash','')")
                self.db.execute("COMMIT")
            except Exception: self.db.execute("ROLLBACK"); raise
        elif self.db.execute("SELECT value FROM meta WHERE key='policy_hash'").fetchone()[0] != policy.hash: fail("session2_budget_policy_mismatch")

    def _rows(self) -> list[dict[str, Any]]:
        result = []
        for row in self.db.execute("SELECT sequence,attempt_id,idempotency_key,stage,state,reserved,settled,provider_request_id,predecessor_hash,entry_hash FROM entries ORDER BY sequence"):
            result.append(dict(zip(("sequence","attempt_id","idempotency_key","stage","state","reserved","settled","provider_request_id","predecessor_hash","entry_hash"), row)))
        return result

    def _current(self, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        current: dict[str, dict[str, Any]] = {}
        for row in rows: current[row["attempt_id"]] = row
        return current

    def _append(self, body: dict[str, Any]) -> None:
        self.db.execute("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?)", (*body.values(), canonical_hash(body)))

    def reserve(self, attempt_id: str, idempotency_key: str, stage: str, amount: float, *, input_tokens: int = 0) -> int:
        if (stage not in STAGES or not isinstance(attempt_id, str) or not attempt_id
                or not isinstance(idempotency_key, str) or not idempotency_key
                or not isinstance(amount, (int, float)) or amount <= 0
                or amount > self.policy.absolute_per_call_cap_usd
                or not isinstance(input_tokens, int) or input_tokens < 0
                or input_tokens > self.policy.absolute_input_ceiling):
            fail("session2_budget_reservation_invalid")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self._rows(); current = self._current(rows)
            if attempt_id in current or self.db.execute("SELECT 1 FROM entries WHERE idempotency_key=?", (idempotency_key,)).fetchone():
                fail("session2_budget_duplicate_attempt")
            active = sum(row["reserved"] for row in current.values() if row["state"] in {"RESERVED", "SUBMITTED"}); settled = sum(row["settled"] or 0 for row in current.values() if row["state"] in {"SETTLED", "FAILED_MAX_CHARGED"})
            stage_spend = sum((row["settled"] if row["state"] in {"SETTLED", "FAILED_MAX_CHARGED"} else row["reserved"]) or 0 for row in current.values() if row["stage"] == stage and row["state"] != "CANCELLED_BEFORE_SEND")
            if settled + active + amount > self.policy.hard_stop_usd: fail("session2_budget_programme_cap_exceeded")
            if stage_spend + amount > dict(self.policy.stage_caps)[stage]: fail("session2_budget_stage_cap_exceeded")
            prior = rows[-1]["entry_hash"] if rows else ""
            sequence = len(rows) + 1; body = {"sequence": sequence, "attempt_id": attempt_id, "idempotency_key": idempotency_key, "stage": stage, "state": "RESERVED", "reserved": float(amount), "settled": None, "provider_request_id": None, "predecessor_hash": prior}
            self._append(body); self.db.execute("COMMIT"); return sequence
        except Exception: self.db.execute("ROLLBACK"); raise

    def transition(self, attempt_id: str, state: str, *, provider_request_id: str | None = None, settled: float | None = None, provably_not_sent: bool = False) -> None:
        """Apply a legal append-only state transition without releasing history."""
        if state not in LEDGER_STATES: fail("session2_budget_state_invalid")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT sequence,stage,state,reserved,settled,provider_request_id,entry_hash FROM entries WHERE attempt_id=? ORDER BY sequence DESC LIMIT 1", (attempt_id,)).fetchone()
            if row is None: fail("session2_budget_attempt_missing")
            _, stage, prior_state, reserved, _, prior_request, predecessor = row
            if prior_state in TERMINAL_LEDGER_STATES: fail("session2_budget_terminal_transition_forbidden")
            if state == "SUBMITTED":
                if prior_state != "RESERVED" or not isinstance(provider_request_id, str) or not provider_request_id or PLACEHOLDER.search(provider_request_id): fail("session2_budget_submit_invalid")
                if self.db.execute("SELECT 1 FROM entries WHERE provider_request_id=? AND attempt_id<>?", (provider_request_id, attempt_id)).fetchone(): fail("session2_budget_provider_request_duplicate")
                pass
            elif state == "CANCELLED_BEFORE_SEND":
                if prior_state != "RESERVED" or not provably_not_sent: fail("session2_budget_cancel_invalid")
                settled = 0.0
            elif state in {"SETTLED", "FAILED_MAX_CHARGED"}:
                if prior_state not in {"RESERVED", "SUBMITTED"}: fail("session2_budget_settlement_invalid")
                charge = reserved if state == "FAILED_MAX_CHARGED" else settled
                if not isinstance(charge, (int, float)) or charge < 0 or charge > reserved: fail("session2_budget_settlement_invalid")
                settled = float(charge)
            else:
                fail("session2_budget_transition_invalid")
            if state != "SUBMITTED": provider_request_id = prior_request
            rows = self._rows(); body = {"sequence": len(rows) + 1, "attempt_id": attempt_id, "idempotency_key": None, "stage": stage, "state": state, "reserved": reserved, "settled": settled, "provider_request_id": provider_request_id, "predecessor_hash": predecessor}
            self._append(body); self.db.execute("COMMIT")
        except Exception: self.db.execute("ROLLBACK"); raise

    def max_charge_unresolved_submissions(self) -> int:
        """Crash recovery: unresolved submitted requests consume their reservation."""
        attempts = [item["attempt_id"] for item in self._current(self._rows()).values() if item["state"] == "SUBMITTED"]
        for attempt in attempts: self.transition(attempt, "FAILED_MAX_CHARGED")
        return len(attempts)

    def checkpoint(self) -> dict[str, Any]:
        rows = self._rows(); prior = ""; 
        for expected, row in enumerate(rows, 1):
            body = {key: row[key] for key in ("sequence","attempt_id","idempotency_key","stage","state","reserved","settled","provider_request_id","predecessor_hash")}
            if row["sequence"] != expected or row["predecessor_hash"] != prior or row["entry_hash"] != canonical_hash(body): fail("session2_budget_history_invalid")
            prior = row["entry_hash"]
        current = self._current(rows); committed = sum(row["settled"] or 0 for row in current.values() if row["state"] in {"SETTLED", "FAILED_MAX_CHARGED"}); reserved = sum(row["reserved"] for row in current.values() if row["state"] in {"RESERVED", "SUBMITTED"})
        stages = {stage: dict(self.policy.stage_caps)[stage] - sum((row["settled"] if row["state"] in {"SETTLED", "FAILED_MAX_CHARGED"} else row["reserved"]) or 0 for row in current.values() if row["stage"] == stage and row["state"] != "CANCELLED_BEFORE_SEND") for stage in STAGES}
        return {"schema_id": "external_validation.session2_budget_checkpoint.v1", "schema_version": "1", "first_sequence": 1 if rows else 0, "last_sequence": len(rows), "entry_count": len(rows), "previous_checkpoint_hash": "", "entries_root_hash": canonical_hash(rows), "committed_spend": committed, "reserved_spend": reserved, "remaining_budget": self.policy.hard_stop_usd - committed - reserved, "stage_balances": stages, "policy_hash": self.policy.hash, "latest_entry_hash": prior}

    def genesis_checkpoint(self) -> dict[str, Any]:
        """Canonical Session-2 anchor; never hash SQLite/WAL bytes."""
        checkpoint = self.checkpoint()
        return {"schema_id": "external_validation.session2_budget_genesis.v1", "schema_version": "1", "programme_id": "external_validation.session2", "policy_hash": self.policy.hash, "opening_balance": self.policy.hard_stop_usd, "stage_balances": checkpoint["stage_balances"], "latest_canonical_sequence": checkpoint["last_sequence"], "prior_entry_hash": checkpoint["latest_entry_hash"], "ledger_checkpoint": checkpoint}

    def projected_total(self, *, mandatory_remaining_run_reservations: float, frozen_retry_reserve: float, sol_sensitivity_reserve: float) -> float:
        if any(not isinstance(item, (int, float)) or item < 0 for item in (mandatory_remaining_run_reservations, frozen_retry_reserve, sol_sensitivity_reserve)):
            fail("session2_budget_projection_invalid")
        checkpoint = self.checkpoint()
        unresolved_submitted_max_charge = sum(row["reserved"] for row in self._current(self._rows()).values() if row["state"] == "SUBMITTED")
        return checkpoint["committed_spend"] + unresolved_submitted_max_charge + checkpoint["reserved_spend"] + float(mandatory_remaining_run_reservations) + float(frozen_retry_reserve) + float(sol_sensitivity_reserve)
