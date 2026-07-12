from __future__ import annotations

from datetime import datetime


def validate_manager_decision(value: dict, available_ids: set[str]) -> dict:
    required = {"selected_modules", "skipped_modules", "selection_reasons", "delegation_plan"}
    if set(value) != required:
        raise ValueError("manager decision must use the exact selection contract")
    selected = value["selected_modules"]
    skipped = value["skipped_modules"]
    if not isinstance(selected, list) or not isinstance(skipped, list) or set(selected) | set(skipped) != available_ids or set(selected) & set(skipped):
        raise ValueError("manager decision must partition the available modules")
    if set(value["selection_reasons"]) != available_ids:
        raise ValueError("every module requires an explicit selection reason")
    plan = value["delegation_plan"]
    if not isinstance(plan, list) or not {"product_ux", "engineering_qa"}.issubset({p.get("role") for p in plan if isinstance(p, dict)}):
        raise ValueError("delegation plan requires Product/UX and Engineering/QA")
    return value


def apply_manager_decision(release: dict, decision: dict, available_ids: set[str]) -> dict:
    decision = validate_manager_decision(decision, available_ids)
    release["panel"] = {"selected_modules": decision["selected_modules"], "skipped_modules": [{"module_id": module, "reason": decision["selection_reasons"][module]} for module in decision["skipped_modules"]], "selection_reasons": decision["selection_reasons"], "delegation_plan": decision["delegation_plan"]}
    return release


def validate_receipt(receipt: dict, release_id: str) -> dict:
    required = {"release_id", "session_id", "session_name", "started_at", "ended_at", "public_inputs_only"}
    if set(receipt) != required or receipt.get("release_id") != release_id or receipt.get("public_inputs_only") is not True:
        raise ValueError("invalid Hermes receipt")
    if not all(isinstance(receipt.get(k), str) and receipt[k].strip() for k in ("session_id", "session_name", "started_at", "ended_at")):
        raise ValueError("Hermes receipt requires native identifiers and timestamps")
    datetime.fromisoformat(receipt["started_at"].replace("Z", "+00:00")); datetime.fromisoformat(receipt["ended_at"].replace("Z", "+00:00"))
    return receipt
