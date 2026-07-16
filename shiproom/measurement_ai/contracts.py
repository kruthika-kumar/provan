from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

from shiproom.project import canonical_json, content_hash
from .registries import (
    AI_MATURITY_RUNGS, DECISION_USE_CASES, DEFINITION_STATES, DENOMINATOR_STATES,
    INFERENCE_INTENTS, METRIC_ROLES, ROLE_RESULT_SCHEMAS,
)


PREPARATION_COMPILER_VERSION = "measurement-ai-preparation.v3"
COMPILER_VERSION = "portable-measurement-ai.v3"
ROLE_SCHEMA = "shiproom.measurement-ai-role.v3"
WORK_ORDER_SCHEMA = "shiproom.work-order.v6"
CAPABILITIES_SCHEMA = "measurement-ai-capabilities.v3"
APPLICABILITY_SCHEMA = "measurement-ai-applicability.v3"
REVIEW_CAPABILITIES_SCHEMA = "measurement-review-capabilities.v3"
PERMISSION_SCHEMA = "measurement-review-permission.v3"
SOURCE_PACKET_SCHEMA = "measurement-ai-source-packet.v3"
ROLE_CONTEXT_SCHEMA = "measurement-ai-role-context.v3"
WORK_ORDERS_SCHEMA = "measurement-ai-work-orders.v3"
OVERLAY_SCHEMA = "measurement-ai-overlay.v3"
MANIFEST_SCHEMA = "portable-measurement-ai-manifest.v3"
PREPARATION_POINTER_SCHEMA = "active-measurement-ai-preparation.v3"
GENERATION_POINTER_SCHEMA = "current-portable-measurement-ai.v3"
RECEIPT_SCHEMA = "measurement-ai-completion-receipt.v3"

ROLES = ("measurement", "ai_evaluation")
ROLE_VERSIONS = {role: "3.0.0" for role in ROLES}
RESULT_SCHEMAS = ROLE_RESULT_SCHEMAS

CHECK_IDS = (
    "DATA_OUTCOME_EVENT_DEFINED",
    "DATA_SUCCESS_AND_FAILURE_DISTINGUISHABLE",
    "DATA_CRITICAL_EVENT_PROPERTIES_PRESENT",
    "DATA_PRIMARY_METRIC_DECISION_USEFUL",
    "AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS",
    "AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF",
)
FIELD_STATES = {
    "owner_confirmed", "source_declared", "model_proposed", "unresolved",
    "not_applicable", "not_inspected",
}
BASIS_EVIDENCE_CLASSES = {
    "source_verified", "deterministically_established", "model_mapped_candidate",
    "model_reviewed", "not_inspected",
}
SEMANTIC_REVIEW_AUTHORITIES = {
    "not_performed", "model_reviewed", "model_reviewed_with_curated_guidance",
    "dual_reviewed_with_curated_guidance",
}
CHECK_STATUSES = {"ready", "gap", "owner_confirmation_required", "not_inspected", "not_applicable"}
READINESS_SCOPES = {"contract_definition", "source_mapping", "test_mapping", "upstream_runtime", "semantic_review"}
SURFACE_STATES = {"established", "candidate", "owner_confirmation_required", "absent"}
SCOPE_STATES = {"applicable", "owner_confirmation_required", "not_applicable", "not_inspected"}
DISPOSITIONS = {"assessed", "not_inspected", "not_applicable", "blocked_by_input_ambiguity"}
UNCERTAINTIES = {"none", "bounded", "material", "not_assessed"}
REVIEW_MODES = {"contract_only", "guided_review", "expert_escalated_review"}
RECOMMENDATION_CLASSES = {
    "deterministic_contract_gap", "research_backed_warning", "contextual_hypothesis",
    "owner_confirmation_question", "contextual_metric_proposal",
}
RECOMMENDATION_EFFECTS = {
    "none", "owner_confirmation", "non_blocking_warning", "proposal_only",
    "condition_candidate", "blocker_candidate",
}
DIMENSION_STATES = {"adequate", "contextual_concern", "material_concern", "insufficient_context", "not_applicable", "not_inspected"}
NODE_TYPES = {
    "measurement_contract", "metric_definition", "required_signal", "event_candidate",
    "signal_property", "instrumentation_test", "runtime_evidence_binding", "reviewer_conclusion",
    "guidance_rule_reference", "measurement_warning", "ai_eval_case", "ai_eval_execution",
    "observability_candidate", "owner_confirmation_proposal", "project_source_reference",
}
RELATIONSHIPS = {
    "measures_journey", "governs_criterion", "uses_metric_definition", "requires_signal",
    "has_event_candidate", "requires_property", "mapped_to_project_source", "mapped_to_base_reference",
    "covered_by_test", "has_runtime_binding", "binds_base_runtime_evidence", "assesses_contract",
    "assesses_criterion", "applies_guidance_rule", "identifies_warning", "proposes_owner_confirmation",
    "evaluates_ai_criterion", "has_execution_result", "has_observability_candidate",
}

CHECK_GAP_REGISTRY = {
    "outcome_event_definition_gap": "DATA_OUTCOME_EVENT_DEFINED",
    "success_failure_distinction_gap": "DATA_SUCCESS_AND_FAILURE_DISTINGUISHABLE",
    "critical_property_gap": "DATA_CRITICAL_EVENT_PROPERTIES_PRESENT",
    "metric_decision_gap": "DATA_PRIMARY_METRIC_DECISION_USEFUL",
    "fixed_eval_gap": "AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS",
    "claim_authority_gap": "AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF",
    "instrumentation_mapping_gap": None,
    "failure_case_gap": None,
    "version_traceability_gap": None,
    "observability_gap": None,
}



def is_material_recommendation(value: dict) -> bool:
    return value.get("derived_effect") in {"condition_candidate", "blocker_candidate"}

SOURCE_LIMIT = 256 * 1024
ROLE_FILE_LIMIT = 64
ROLE_TEXT_LIMIT = 2 * 1024 * 1024
STRUCTURAL_RECORD_LIMIT = 2048
STRUCTURAL_BYTES_LIMIT = 2 * 1024 * 1024
RESULT_BYTES_LIMIT = 1024 * 1024


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def render_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(f"non-finite JSON value: {item}")),
        )
    except UnicodeDecodeError as exc:
        raise ValueError("JSON must be UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def require_exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"invalid {label} fields")
    return value


def require_text(value: object, label: str, maximum: int = 4096, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value or (not empty and not value.strip()):
        raise ValueError(f"{label} must be bounded text")
    return value if empty else value.strip()


def require_string_list(value: object, label: str, *, maximum: int = 500) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, str) or not item for item in value) or len(value) != len(set(value)):
        raise ValueError(f"{label} must be a unique bounded string list")
    return value


def validate_relative_path(value: object, label: str) -> str:
    path = require_text(value, label, 500)
    if "\\" in path or ":" in path or path.startswith("/") or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts):
        raise ValueError(f"invalid {label}")
    return path


def stable_id(prefix: str, value: object) -> str:
    return prefix + "_" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:24]


def work_order_hash(value: dict) -> str:
    return content_hash({key: item for key, item in value.items() if key != "work_order_hash"})


def semantic_without_local_ids(value: object) -> object:
    if isinstance(value, list):
        return [semantic_without_local_ids(item) for item in value]
    if isinstance(value, dict):
        return {
            key: semantic_without_local_ids(item)
            for key, item in value.items()
            if key not in {
                "local_id", "provider_id", "model_id", "candidate_id", "run_id",
                "reviewer_label", "preparation_id", "work_order_id",
                "verifier_preparation_id", "verifier_work_order_id",
                "result_snapshot_hash", "receipt_snapshot_hash",
                "completion_receipt_snapshot_hash", "started_at", "completed_at",
            }
        }
    return value


def validate_source_ref(value: object, sources: list[dict]) -> dict:
    full = {"path", "returned_git_path", "git_blob_hash", "normalized_text_hash"}
    quoted = full | {"start_line", "end_line", "quote", "quote_hash"}
    if not isinstance(value, dict) or set(value) not in {frozenset(full), frozenset(quoted)}:
        raise ValueError("invalid packet source reference")
    matches = [item for item in sources if all(value[key] == item[key] for key in full)]
    if len(matches) != 1:
        raise ValueError("source reference is outside the role packet")
    if set(value) == quoted:
        quote = require_text(value["quote"], "quote", 16384)
        if not isinstance(value["start_line"], int) or not isinstance(value["end_line"], int) or value["start_line"] < 1 or value["end_line"] < value["start_line"]:
            raise ValueError("invalid quote range")
        lines = matches[0]["text"].splitlines()
        if value["end_line"] > len(lines):
            raise ValueError("quote range is outside source")
        bounded = "\n".join(lines[value["start_line"] - 1:value["end_line"]])
        if bounded.count(quote) != 1 or value["quote_hash"] != sha256_bytes(quote.encode("utf-8")):
            raise ValueError("quote binding is invalid")
    return value


def canonical_refs(values: object, sources: list[dict]) -> list[dict]:
    if not isinstance(values, list):
        raise ValueError("basis_source_refs must be a list")
    validated = [validate_source_ref(item, sources) for item in values]
    keys = [canonical_json(item) for item in validated]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate source reference")
    return [dict(json.loads(key)) for key in sorted(keys)]


def effective_basis_class(classes: list[str]) -> str:
    if not classes:
        return "not_inspected"
    if any(item not in BASIS_EVIDENCE_CLASSES for item in classes):
        raise ValueError("invalid basis evidence class")
    if "not_inspected" in classes:
        return "not_inspected"
    if "model_mapped_candidate" in classes:
        return "model_mapped_candidate"
    factual = [item for item in classes if item != "model_reviewed"]
    if not factual:
        return "not_inspected"
    if set(factual) == {"deterministically_established"}:
        return "deterministically_established"
    if set(factual).issubset({"source_verified", "deterministically_established"}):
        return "source_verified"
    raise ValueError("invalid criterion-scoped factual authority mixture")
