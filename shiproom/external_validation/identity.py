from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Stable bytes for identity inputs; reject non-finite numbers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _identity(prefix: str, value: dict[str, Any]) -> str:
    return f"{prefix}_{hashlib.sha256(canonical_json(value)).hexdigest()}"


def case_id(case_authority: dict[str, Any]) -> str:
    """Stable authority for a declared case and immutable snapshot only."""
    required = {"dataset", "snapshot", "repository", "commit_sha", "manifest_version"}
    if not required.issubset(case_authority):
        raise ValueError("case_authority_fields_invalid")
    return _identity("case", case_authority)


def observation_key(inputs: dict[str, Any]) -> str:
    """Scientific observation identity, intentionally independent of scheduling and repricing."""
    required = {"case_id", "snapshot_hash", "arm", "system_version", "prompt_version", "policy_version", "model", "model_settings", "model_sampling_seed", "tool_policy_version", "execution_policy_version", "cache_mode"}
    if set(inputs) != required:
        raise ValueError("observation_key_fields_invalid")
    forbidden = {"price_version", "schedule_seed", "schedule_order", "timestamp", "attempt", "retry"}
    if forbidden.intersection(inputs):
        raise ValueError("observation_key_contains_nonexperimental_input")
    return _identity("obs", inputs)


def schedule_id(frozen_run_set_hash: str, algorithm_version: str, public_seed: str) -> str:
    return _identity("schedule", {"frozen_run_set_hash": frozen_run_set_hash, "algorithm_version": algorithm_version, "public_seed": public_seed})


def attempt_id(observation: str, infrastructure_lineage: int) -> str:
    if infrastructure_lineage < 1:
        raise ValueError("attempt_lineage_invalid")
    return _identity("attempt", {"observation_key": observation, "infrastructure_lineage": infrastructure_lineage})


def receipt_id(receipt_bytes: bytes) -> str:
    return "receipt_" + hashlib.sha256(receipt_bytes).hexdigest()


def cost_view_id(receipt: str, price_version: str) -> str:
    return _identity("cost", {"receipt_id": receipt, "price_version": price_version})
