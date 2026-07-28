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
    for stream in ("stdout", "stderr"):
        item = value[stream]
        if not isinstance(item, dict) or set(item) != {"opaque_id", "bytes", "sha256"} or not isinstance(item["opaque_id"], str) or not item["opaque_id"] or not isinstance(item["bytes"], int) or item["bytes"] < 0: fail("session2_qualifying_artifact_stream_invalid")
        require_sha(item["sha256"])
        if item["bytes"] == 0: fail("session2_qualifying_artifact_empty_transcript")
    if not isinstance(value["exit_code"], int): fail("session2_qualifying_artifact_exit_invalid")
    try:
        started = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00")); completed = datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))
        if started.tzinfo is None or completed.tzinfo is None or completed < started: raise ValueError
    except (AttributeError, ValueError): fail("session2_qualifying_artifact_time_invalid")
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

    def reserve(self, attempt_id: str, idempotency_key: str, stage: str, amount: float) -> int:
        if stage not in STAGES or not isinstance(amount, (int, float)) or amount <= 0 or amount > self.policy.absolute_per_call_cap_usd: fail("session2_budget_reservation_invalid")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self._rows(); current = self._current(rows); active = sum(row["reserved"] for row in current.values() if row["state"] in {"RESERVED", "SUBMITTED"}); settled = sum(row["settled"] or 0 for row in current.values() if row["state"] in {"SETTLED", "FAILED_MAX_CHARGED"})
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
