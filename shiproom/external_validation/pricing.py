from __future__ import annotations

from datetime import date
import math
from typing import Any

from .identity import canonical_json


RATE_DIMENSIONS = {"input", "cached_input", "output", "reasoning", "tool"}


def validate_price_table(value: dict[str, Any]) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "provider", "model", "effective_date", "currency", "source", "rates"}
    if set(value) != required or value.get("schema_id") != "external_validation.price_table" or value.get("schema_version") != "1":
        raise ValueError("price_table_shape_invalid")
    try: date.fromisoformat(value["effective_date"])
    except (TypeError, ValueError) as exc: raise ValueError("price_effective_date_invalid") from exc
    if value["currency"] != "USD" or not all(isinstance(value[field], str) and value[field] for field in ("provider", "model", "source")):
        raise ValueError("price_table_metadata_invalid")
    rates = value["rates"]
    if not isinstance(rates, dict) or not rates or set(rates).difference(RATE_DIMENSIONS): raise ValueError("price_rate_dimension_invalid")
    for rate in rates.values():
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not math.isfinite(rate) or rate < 0: raise ValueError("price_rate_invalid")
    return value


def price_table_hash(value: dict[str, Any]) -> str:
    import hashlib
    validate_price_table(value)
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def normalize_cost(usage: dict[str, Any], table: dict[str, Any] | None) -> dict[str, Any]:
    """Retain native values; absent table never fabricates a normalized value."""
    state = usage.get("state")
    if state == "not_applicable": return {"state": "not_applicable"}
    if state != "available": return {"state": "cost_unavailable", "reason": "provider_usage_unavailable"}
    if table is None: return {"state": "cost_unavailable", "reason": "price_table_unavailable"}
    validate_price_table(table)
    dimensions = {"input": "input_tokens", "cached_input": "cached_input_tokens", "output": "output_tokens", "reasoning": "reasoning_tokens", "tool": "tool_calls"}
    total = 0.0
    for dimension, usage_field in dimensions.items():
        count = usage.get(usage_field, 0)
        if not isinstance(count, (int, float)) or isinstance(count, bool) or not math.isfinite(count) or count < 0: raise ValueError("provider_usage_invalid")
        total += count * table["rates"].get(dimension, 0.0)
    return {"state": "available", "normalized_billed_cost": total, "price_version": price_table_hash(table), "provider_reported_cost": usage.get("provider_reported_cost")}
