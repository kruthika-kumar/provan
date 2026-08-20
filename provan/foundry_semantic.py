from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable

import jsonschema
import yaml

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .state import secure_read, secure_write, state_root


PACKAGE_VERSION = "0.5.1"
POLICY_VERSION = "community.contract-foundry.semantic-successor.v1"
SCORER_VERSION = "community.contract-foundry.semantic-scorer.v1"
STANDARD_STAGES = (
    "source_bundle", "source_coverage", "source_authority_ledger", "blind_intent",
    "goal_obstacle", "pre_mortem", "contract_candidate", "adversarial_audit",
    "revision", "witness_set", "semantic_freeze", "implementation_mapping",
    "verification_plan", "readiness", "owner_projection",
)
DEEP_STAGES = (
    "source_bundle", "source_coverage", "source_authority_ledger", "blind_path_a",
    "blind_path_b", "blind_paths_freeze", "deep_synthesis", "goal_obstacle",
    "pre_mortem", "contract_candidate", "adversarial_audit", "revisions",
    "witness_set", "mutation_analysis", "final_audit", "semantic_freeze",
    "implementation_mapping", "verification_plan", "readiness", "owner_projection",
)
SEMANTIC_CLASSIFICATIONS = {
    "outcome", "invariant", "recovery_requirement", "technical_contract",
    "implementation_constraint", "exact_content", "example", "suggestion",
    "implementation_description", "historical_context", "non_goal",
    "untrusted_instruction", "unresolved_conflict",
}
DISPOSITIONS = {
    "accepted_and_revised", "rejected_with_source_evidence", "converted_to_suggestion",
    "marked_as_owner_question", "marked_unresolved",
}
OWNER_SECTIONS = (
    "Sources require", "Provan inferred", "Audit changed", "Intentionally non-mandatory",
    "Ambiguities", "Patterns & evidence", "Owner decisions",
)


def _schema(filename: str, value: dict[str, Any]) -> None:
    schema = json.loads((Path(__file__).with_name("schemas") / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(value)


def _ref(value: dict[str, Any], raw: bytes, id_key: str, path: str | None = None) -> dict[str, Any]:
    result = {"id": value[id_key], "sha256": sha256_bytes(raw)}
    if path is not None:
        result["path"] = path
    return result


def _store(root: Path, name: str, value: dict[str, Any], schema_file: str, id_key: str) -> tuple[dict[str, Any], bytes]:
    _schema(schema_file, value)
    raw = canonical_bytes(value)
    path = root / f"{name}.json"
    secure_write(path, raw)
    return _ref(value, raw, id_key, f"{name}.json"), raw


def _source_stable_id(case_id: str, role: str, index: int, digest: str) -> str:
    return sha256_bytes(canonical_bytes([case_id, role, index, digest]))


def freeze_source_bundle(
    *, run_id: str, case_id: str, candidate: dict[str, Any], manifest: dict[str, Any], sources: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    """Freeze each source exactly once before any semantic extraction."""
    entries: list[dict[str, Any]] = []
    frozen: dict[str, bytes] = {}
    for index, row in enumerate(sources):
        raw = row["content"].encode("utf-8")
        if sha256_bytes(raw) != row["sha256"]:
            raise ProvanError("FOUNDRY_SOURCE_CHANGED_BEFORE_FREEZE", row["source_id"])
        source_id = _source_stable_id(case_id, row["role"], index, row["sha256"])
        relative = Path("outputs/contract-foundry") / run_id / "source-bundle" / "blobs" / f"{source_id.removeprefix('sha256:')}.blob"
        secure_write(relative, raw, allowed_suffixes=frozenset({".blob"}))
        reread = secure_read(relative, limit=max(len(raw), 1), allowed_suffixes=frozenset({".blob"}))
        if reread != raw:
            raise ProvanError("FOUNDRY_SOURCE_BUNDLE_IDENTITY_MISMATCH", source_id)
        frozen[source_id] = reread
        entries.append({
            "source_id": source_id, "manifest_source_id": row["source_id"], "role": row["role"],
            "media_type": row["media_type"], "bytes": len(raw), "sha256": row["sha256"],
            "blob_ref": {"path": str(relative).replace("\\", "/"), "sha256": row["sha256"]},
            "sensitivity": "PRIVATE_LOCAL",
        })
    inventory = [{key: entry[key] for key in ("source_id", "role", "media_type", "bytes", "sha256")} for entry in entries]
    bundle = {
        "schema_id": "provan.internal.source_bundle.v1", "bundle_id": str(uuid.uuid4()),
        "sensitivity": "PRIVATE_LOCAL", "case_id": case_id,
        "candidate_digest": candidate["candidate_digest"],
        "manifest_digest": sha256_bytes(canonical_bytes(manifest)), "sources": entries,
        "semantic_input_digest": sha256_bytes(canonical_bytes(inventory)),
        "raw_bytes_public": False, "raw_bytes_telemetry": False, "cleanup_state": "RETAINED_UNTIL_TERMINAL",
        "limitations": ["RAW_BYTES_PRIVATE_LOCAL", "LIVE_REREAD_DIGEST_CONTINUITY_ONLY"],
    }
    raw = canonical_bytes(bundle)
    secure_write(Path("outputs/contract-foundry") / run_id / "source-bundle.json", raw)
    return bundle, frozen, raw


def verify_live_source_continuity(sources: list[dict[str, Any]], bundle: dict[str, Any]) -> None:
    by_manifest = {entry["manifest_source_id"]: entry for entry in bundle["sources"]}
    for row in sources:
        entry = by_manifest.get(row["source_id"])
        if entry is None or entry["sha256"] != row["sha256"]:
            raise ProvanError("FOUNDRY_LIVE_SOURCE_DIGEST_CHANGED", row["source_id"])


def cleanup_source_bundle(run_id: str) -> dict[str, Any]:
    base_relative = Path("outputs/contract-foundry") / run_id
    raw = secure_read(base_relative / "source-bundle.json")
    bundle = json.loads(raw)
    deleted: list[dict[str, str]] = []
    root = state_root().resolve(strict=True)
    for entry in bundle["sources"]:
        relative = Path(entry["blob_ref"]["path"])
        secure_read(relative, limit=max(int(entry["bytes"]), 1), allowed_suffixes=frozenset({".blob"}))
        target = state_root() / relative
        if target.resolve(strict=True).parent.resolve(strict=True) != (state_root() / relative.parent).resolve(strict=True) or root not in target.resolve(strict=True).parents:
            raise ProvanError("FOUNDRY_SOURCE_BUNDLE_CLEANUP_UNSAFE", entry["source_id"])
        target.unlink()
        deleted.append({"source_id": entry["source_id"], "sha256": entry["sha256"]})
    tombstone = {
        "schema_id": "provan.internal.source_bundle_tombstone.v1", "tombstone_id": str(uuid.uuid4()),
        "bundle_id": bundle["bundle_id"], "bundle_sha256": sha256_bytes(raw), "deleted": deleted,
        "raw_bytes_retained": False, "sensitivity": "PRIVATE_LOCAL",
    }
    secure_write(base_relative / "source-bundle-tombstone.json", canonical_bytes(tombstone))
    return tombstone


def _json_pointer(path: tuple[str | int, ...]) -> str:
    if not path:
        return ""
    return "/" + "/".join(str(item).replace("~", "~0").replace("/", "~1") for item in path)


def _leaf_nodes(value: Any, path: tuple[str | int, ...] = ()) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _leaf_nodes(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaf_nodes(child, (*path, index))
    else:
        yield _json_pointer(path), value


def _classify_text(text: str, *, role: str, media_type: str) -> tuple[str, str | None, str, bool]:
    stripped = text.strip()
    lower = stripped.lower()
    if not stripped:
        return "non_semantic", "WHITESPACE_OR_MARKUP_ONLY", "none", False
    if media_type in {"yaml", "yml"} and (stripped.startswith("#") or re.search(r"\s#", stripped)):
        return "untrusted_instruction", "YAML_COMMENT_CONTEXTUAL_UNTRUSTED", "untrusted_context", False
    if any(token in lower for token in ("out of scope", "non-goal", "must not", "not required")):
        return "non_goal", None, "source_attributed", True
    if any(token in lower for token in ("conflict", "contradict", "supersed")):
        return "unresolved_conflict", None, "source_attributed", True
    if any(token in lower for token in ("for example", "e.g.", "example:")):
        return "example", None, "source_attributed", False
    if any(token in lower for token in ("exactly", "literal", "verbatim", "byte-for-byte")):
        return "exact_content", None, "source_attributed", True
    if any(token in lower for token in ("recover", "rollback", "retry", "resume", "restore")):
        return "recovery_requirement", None, "source_attributed", role == "formal_contract"
    if any(token in lower for token in ("schema", "api", "header", "field", "format", "protocol")):
        return "technical_contract", None, "source_attributed", role == "formal_contract"
    if any(token in lower for token in ("implementation", "function", "class ", "module", "database")):
        return "implementation_description", None, "source_attributed", False
    if any(token in lower for token in ("always", "never", "invariant")):
        return "invariant", None, "source_attributed", role == "formal_contract"
    if any(token in lower for token in ("should", "could", "recommend", "suggest")):
        return "suggestion", None, "source_attributed", False
    return "outcome", None, "source_attributed", role == "formal_contract" or any(token in lower for token in ("must", "shall", "required"))


def build_source_coverage(bundle: dict[str, Any], frozen: dict[str, bytes]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for entry in bundle["sources"]:
        raw = frozen[entry["source_id"]]
        text = raw.decode("utf-8", errors="strict")
        offset = 0
        for line in text.splitlines(keepends=True) or [""]:
            encoded = line.encode("utf-8")
            classification, reason, authority, material = _classify_text(line, role=entry["role"], media_type=entry["media_type"])
            item = {
                "coverage_id": sha256_bytes(canonical_bytes([entry["source_id"], "byte_span", offset, offset + len(encoded)])),
                "source_id": entry["source_id"], "coordinate_type": "byte_span", "start": offset,
                "end": offset + len(encoded), "excerpt_digest": sha256_bytes(encoded), "classification": classification,
                "reason_code": reason, "authority": authority, "material": material, "semantic_text": line.strip(),
            }
            rows.append(item)
            offset += len(encoded)
        if offset != len(raw):
            raise ProvanError("FOUNDRY_SOURCE_COVERAGE_GAP", entry["source_id"])
        if entry["media_type"] in {"json", "yaml", "yml"}:
            parsed = json.loads(text) if entry["media_type"] == "json" else yaml.safe_load(text)
            for pointer, value in _leaf_nodes(parsed):
                value_raw = canonical_bytes(value)
                classification, reason, authority, material = _classify_text(str(value), role=entry["role"], media_type=entry["media_type"])
                rows.append({
                    "coverage_id": sha256_bytes(canonical_bytes([entry["source_id"], "structured_node", pointer])),
                    "source_id": entry["source_id"], "coordinate_type": "structured_node", "pointer": pointer,
                    "value_digest": sha256_bytes(value_raw), "classification": classification,
                    "reason_code": reason, "authority": authority, "material": material, "semantic_text": str(value),
                })
    counts = {"classified_semantic": 0, "explicit_non_semantic": 0, "explicit_ignored": 0, "unresolved": 0}
    for row in rows:
        if row["classification"] == "non_semantic": counts["explicit_non_semantic"] += 1
        elif row["classification"] == "ignored": counts["explicit_ignored"] += 1
        elif row["classification"] == "unresolved": counts["unresolved"] += 1
        else: counts["classified_semantic"] += 1
    return {
        "schema_id": "provan.internal.source_coverage.v1", "coverage_id": str(uuid.uuid4()),
        "bundle_ref": {"id": bundle["bundle_id"], "sha256": sha256_bytes(canonical_bytes(bundle))},
        "items": rows, "counts": counts, "unaccounted": 0,
        "yaml_comment_policy": "CONTEXTUAL_UNTRUSTED_COVERAGE_SPAN",
        "limitations": ["DETERMINISTIC_INITIAL_CLASSIFICATION", "MODEL_MAY_ONLY_REFER_TO_EXISTING_COVERAGE_IDS"],
    }


def _statement_from_coverage(row: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    coordinate = {key: row[key] for key in ("coordinate_type", "start", "end", "pointer") if key in row}
    return {
        "statement_id": sha256_bytes(canonical_bytes([row["coverage_id"], row["classification"]])),
        "source_ref": {"id": entry["source_id"], "sha256": entry["sha256"]},
        "coordinate": coordinate, "content_digest": row.get("excerpt_digest", row.get("value_digest")),
        "semantic_text": row["semantic_text"],
        "source_type": entry["role"], "classification": row["classification"],
        "scope": "case", "effective_time": "current_or_unresolved", "authority": row["authority"],
        "conflict_state": "active_unresolved" if row["classification"] == "unresolved_conflict" else "none",
        "supersession_state": "active", "material": row["material"],
        "limitations": [row["reason_code"]] if row.get("reason_code") else [], "sensitivity": "PRIVATE_LOCAL",
    }


def build_statement_ledger(bundle: dict[str, Any], coverage: dict[str, Any], candidate_digest: str) -> dict[str, Any]:
    entries = {entry["source_id"]: entry for entry in bundle["sources"]}
    statements = [_statement_from_coverage(row, entries[row["source_id"]]) for row in coverage["items"] if row["classification"] not in {"non_semantic", "ignored"}]
    return {
        "schema_id": "provan.source_authority_ledger.v2", "ledger_id": str(uuid.uuid4()),
        "case_id": bundle["case_id"], "candidate_digest": candidate_digest,
        "source_bundle_ref": {"id": bundle["bundle_id"], "sha256": sha256_bytes(canonical_bytes(bundle))},
        "coverage_ref": {"id": coverage["coverage_id"], "sha256": sha256_bytes(canonical_bytes(coverage))},
        "statements": statements, "amendment_refs": [],
        "authority_ceiling": "SOURCE_ATTRIBUTED_PROPOSAL", "limitations": ["NO_OWNER_AUTHORITY_CREATED"],
    }


def create_source_authority_amendment(run_id: str, ledger: dict[str, Any], changes: list[dict[str, Any]], actor: dict[str, Any]) -> dict[str, Any]:
    statement_ids = {row["statement_id"] for row in ledger["statements"]}
    if not changes or any(row.get("statement_id") not in statement_ids or row.get("action") not in {"reclassify", "mark_superseded", "resolve_conflict"} or not row.get("reason") for row in changes):
        raise ProvanError("FOUNDRY_SOURCE_AMENDMENT_INVALID", run_id)
    if actor.get("authority_scope") != "case_source_interpretation" or not actor.get("actor_label"):
        raise ProvanError("FOUNDRY_SOURCE_AMENDMENT_ACTOR_INVALID", run_id)
    value = {"schema_id": "provan.internal.source_authority_amendment.v1", "amendment_id": str(uuid.uuid4()), "ledger_ref": {"id": ledger["ledger_id"], "sha256": sha256_bytes(canonical_bytes(ledger))}, "changes": changes, "actor": actor, "append_only": True, "creates_owner_authority": False}
    secure_write(Path("outputs/contract-foundry") / run_id / "source-authority-amendments" / f"{value['amendment_id']}.json", canonical_bytes(value))
    return value


def _semantic_text(statement: dict[str, Any]) -> str:
    return statement["semantic_text"]


def build_intent(ledger: dict[str, Any], path_id: str = "standard") -> dict[str, Any]:
    fields: dict[str, list[dict[str, Any]]] = {name: [] for name in ("actors", "users", "outcomes", "invariants", "states_transitions", "recovery_expectations", "non_goals", "ambiguities", "conflicts", "implementation_descriptions", "exact_content")}
    mapping = {
        "outcome": "outcomes", "invariant": "invariants", "recovery_requirement": "recovery_expectations",
        "non_goal": "non_goals", "unresolved_conflict": "conflicts", "implementation_description": "implementation_descriptions",
        "exact_content": "exact_content", "example": "ambiguities", "suggestion": "ambiguities", "untrusted_instruction": "ambiguities",
        "technical_contract": "states_transitions", "implementation_constraint": "implementation_descriptions",
    }
    for statement in ledger["statements"]:
        target = mapping.get(statement["classification"], "ambiguities")
        fields[target].append({"item_id": statement["statement_id"], "statement_ref": statement["statement_id"], "semantic_value": _semantic_text(statement), "authority": statement["authority"], "material": statement["material"]})
    if not fields["outcomes"]:
        fields["ambiguities"].append({"item_id": sha256_bytes(canonical_bytes([ledger["ledger_id"], "outcome-missing"])), "statement_ref": None, "semantic_value": "INTENDED_OUTCOME_UNRESOLVED", "authority": "unresolved", "material": True})
    return {
        "schema_id": "provan.intent_model.v2", "intent_id": str(uuid.uuid4()), "path_id": path_id,
        "source_ledger_ref": {"id": ledger["ledger_id"], "sha256": sha256_bytes(canonical_bytes(ledger))},
        **fields, "authority": "proposal_only", "limitations": ["BLIND_TO_IMPLEMENTATION", "OWNER_CONFIRMATION_REQUIRED"],
    }


def _apply_intent_role_result(intent: dict[str, Any], result: dict[str, Any], role: str) -> None:
    """Incorporate model interpretation without promoting it to source authority."""
    for kind, material in (("model_reviewed_implications", False), ("unresolved", True)):
        for index, text in enumerate(result.get(kind, [])):
            intent["ambiguities"].append({
                "item_id": sha256_bytes(canonical_bytes([intent["intent_id"], role, kind, index, text])),
                "statement_ref": None, "semantic_value": text,
                "authority": "model_reviewed_proposal" if kind == "model_reviewed_implications" else "unresolved",
                "material": material,
            })


def _apply_goal_role_result(goals: dict[str, Any], premortem: dict[str, Any], result: dict[str, Any]) -> None:
    for index, text in enumerate(result.get("model_reviewed_implications", [])):
        goals["obstacles"].append({
            "obstacle_id": sha256_bytes(canonical_bytes([goals["model_id"], "model", index, text])),
            "intent_item_ref": None, "cause": text,
            "stopping_basis": "MODEL_PROPOSAL_REQUIRES_SOURCE_OR_OWNER_DISPOSITION",
        })
    for index, text in enumerate(result.get("unresolved", [])):
        premortem["failure_narratives"].append({
            "failure_id": sha256_bytes(canonical_bytes([premortem["analysis_id"], "unresolved", index, text])),
            "violated_outcome_ref": None, "failure_dimension": "unresolved_model_question",
            "causal_chain": [text], "symptoms": ["unresolved"],
            "visible_check_gap": "requires owner or oracle disposition",
            "distinguishing_evidence": "not yet established", "authority": "model_proposed",
        })


def _apply_candidate_role_result(candidate: dict[str, Any], result: dict[str, Any], role: str) -> None:
    for kind in ("model_reviewed_implications", "unresolved"):
        for index, text in enumerate(result.get(kind, [])):
            candidate["suggestions"].append({
                "suggestion_id": sha256_bytes(canonical_bytes([candidate["candidate_id"], role, kind, index, text])),
                "basis_ref": None, "kind": "owner_question" if kind == "unresolved" else "non_authoritative_enhancement",
                "statement": text, "authority": "model_proposed_non_authoritative",
            })


def _apply_audit_role_result(audit: dict[str, Any], result: dict[str, Any]) -> None:
    for kind in ("model_reviewed_implications", "unresolved"):
        for index, text in enumerate(result.get(kind, [])):
            audit["findings"].append({
                "finding_id": sha256_bytes(canonical_bytes([audit["audit_id"], "model", kind, index, text])),
                "class": "model_adversarial_finding" if kind == "model_reviewed_implications" else "material_ambiguity",
                "candidate_field": "/", "evidence_refs": [], "rationale": text,
                "witness_expectation": "adversarial_invalid" if kind == "model_reviewed_implications" else "ambiguity",
                "disposition": "converted_to_suggestion" if kind == "model_reviewed_implications" else "marked_as_owner_question",
            })
    audit["disposition_coverage"] = {"total": len(audit["findings"]), "disposed": len(audit["findings"])}


def _criteria(intent: dict[str, Any], interpretation: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    criteria: list[dict[str, Any]] = []
    suggestions: list[dict[str, Any]] = []
    mandatory_sources = [*intent["outcomes"], *intent["invariants"], *intent["recovery_expectations"], *intent["states_transitions"], *intent["exact_content"]]
    for index, item in enumerate(mandatory_sources):
        criterion_id = sha256_bytes(canonical_bytes(["criterion", item["item_id"], index]))
        criteria.append({
            "criterion_id": criterion_id, "statement_refs": [item["statement_ref"]] if item["statement_ref"] else [],
            "semantic_obligation": item["semantic_value"], "material": bool(item["material"]),
            "authority": item["authority"], "settlement_class": "proposed_mandatory" if item["material"] else "proposed",
            "failure_examples": ["superficial behavior without the declared outcome"],
            "evidence_plan": {"required_class": "source_verified_or_owner_confirmed", "runtime_established": False},
            "oracle_plan": {"status": "owner_confirmation_required", "oracle": "typed criterion-specific future oracle"},
            "ambiguity_refs": [], "non_goal_refs": [row["item_id"] for row in intent["non_goals"]],
        })
    if interpretation in {"clarifying", "enhanced"}:
        for ambiguity in intent["ambiguities"]:
            suggestions.append({"suggestion_id": sha256_bytes(canonical_bytes([interpretation, ambiguity["item_id"]])), "basis_ref": ambiguity["item_id"], "kind": "owner_question" if interpretation == "clarifying" else "non_authoritative_enhancement", "authority": "model_proposed_non_authoritative"})
    return criteria, suggestions


def _goal_obstacle(intent: dict[str, Any]) -> dict[str, Any]:
    goals = [{"goal_id": sha256_bytes(canonical_bytes(["goal", item["item_id"]])), "intent_item_ref": item["item_id"], "singular": True, "material": item["material"], "oracle_path": "criterion_specific"} for item in intent["outcomes"]]
    obstacles = []
    for item in [*intent["ambiguities"], *intent["conflicts"]]:
        obstacles.append({"obstacle_id": sha256_bytes(canonical_bytes(["obstacle", item["item_id"]])), "intent_item_ref": item["item_id"], "cause": item["semantic_value"], "stopping_basis": "MATERIAL_OWNER_DECISION_OR_ORACLE_REQUIRED"})
    return {"schema_id": "provan.internal.goal_obstacle.v2", "model_id": str(uuid.uuid4()), "intent_digest": sha256_bytes(canonical_bytes(intent)), "goals": goals, "obstacles": obstacles, "limitations": []}


def _premortem(intent: dict[str, Any], goals: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for goal in goals["goals"] or [{"goal_id": "UNRESOLVED", "intent_item_ref": None}]:
        rows.append({"failure_id": sha256_bytes(canonical_bytes(["failure", goal["goal_id"]])), "violated_outcome_ref": goal["intent_item_ref"], "failure_dimension": "false_success", "causal_chain": ["visible artifact passes", "declared outcome remains unmet"], "symptoms": ["superficial success"], "visible_check_gap": "oracle does not discriminate durable outcome", "distinguishing_evidence": "criterion-specific oracle", "authority": "model_proposed"})
    return {"schema_id": "provan.internal.premortem.v2", "analysis_id": str(uuid.uuid4()), "intent_digest": sha256_bytes(canonical_bytes(intent)), "goal_digest": sha256_bytes(canonical_bytes(goals)), "failure_narratives": rows, "creates_authority": False, "implementation_fixes": []}


def _candidate(case_id: str, intent: dict[str, Any], goals: dict[str, Any], premortem: dict[str, Any], interpretation: str, path_id: str) -> dict[str, Any]:
    criteria, suggestions = _criteria(intent, interpretation)
    return {
        "schema_id": "provan.contract_candidate.v2", "candidate_id": str(uuid.uuid4()), "path_id": path_id,
        "case_id": case_id, "intent_ref": {"id": intent["intent_id"], "sha256": sha256_bytes(canonical_bytes(intent))},
        "goal_obstacle_digest": sha256_bytes(canonical_bytes(goals)), "premortem_digest": sha256_bytes(canonical_bytes(premortem)),
        "criteria": criteria, "non_requirements": intent["non_goals"], "ambiguities": [*intent["ambiguities"], *intent["conflicts"]],
        "suggestions": suggestions, "interpretation": interpretation, "authority": "proposal_only",
        "limitations": ["OWNER_DISPOSITION_REQUIRED", "RUNTIME_EVIDENCE_NOT_ESTABLISHED"],
    }


def _audit(candidate: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for ambiguity in candidate["ambiguities"]:
        findings.append({"finding_id": sha256_bytes(canonical_bytes(["ambiguity", ambiguity["item_id"]])), "class": "material_ambiguity", "candidate_field": "/ambiguities", "evidence_refs": [ambiguity["item_id"]], "rationale": "source ambiguity requires owner routing", "witness_expectation": "ambiguity", "disposition": "marked_as_owner_question" if ambiguity["material"] else "converted_to_suggestion"})
    for criterion in candidate["criteria"]:
        if criterion["oracle_plan"]["status"] != "complete":
            findings.append({"finding_id": sha256_bytes(canonical_bytes(["oracle", criterion["criterion_id"]])), "class": "weak_oracle", "candidate_field": f"/criteria/{criterion['criterion_id']}/oracle_plan", "evidence_refs": criterion["statement_refs"], "rationale": "oracle requires explicit owner disposition", "witness_expectation": "near_valid", "disposition": "marked_unresolved"})
    for item in intent["implementation_descriptions"]:
        findings.append({"finding_id": sha256_bytes(canonical_bytes(["implementation", item["item_id"]])), "class": "implementation_authority_risk", "candidate_field": "/criteria", "evidence_refs": [item["item_id"]], "rationale": "implementation description cannot create outcome authority", "witness_expectation": "adversarial_invalid", "disposition": "rejected_with_source_evidence"})
    if any(row["disposition"] not in DISPOSITIONS for row in findings):
        raise ProvanError("FOUNDRY_AUDIT_DISPOSITION_INVALID", "finding")
    return {"schema_id": "provan.internal.contract_audit.v2", "audit_id": str(uuid.uuid4()), "candidate_digest": sha256_bytes(canonical_bytes(candidate)), "findings": findings, "material_findings": sum(bool(next((x for x in candidate["ambiguities"] if x["item_id"] in row["evidence_refs"]), {"material": True})["material"]) for row in findings), "disposition_coverage": {"total": len(findings), "disposed": len(findings)}, "authority": "advisory"}


def _revision(candidate: dict[str, Any], audit: dict[str, Any], cap: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deltas: list[dict[str, Any]] = []
    revised = json.loads(json.dumps(candidate))
    for finding in audit["findings"]:
        if finding["class"] == "material_ambiguity":
            deltas.append({"op": "add", "path": "/limitations/-", "value": f"OWNER_QUESTION:{finding['finding_id']}", "finding_ref": finding["finding_id"]})
            revised["limitations"].append(f"OWNER_QUESTION:{finding['finding_id']}")
    records = []
    if deltas:
        records.append({"schema_id": "provan.internal.revision_record.v2", "revision_id": str(uuid.uuid4()), "number": 1, "candidate_before": candidate["candidate_id"], "candidate_before_digest": sha256_bytes(canonical_bytes(candidate)), "audit_ref": audit["audit_id"], "field_deltas": deltas, "candidate_after_digest": sha256_bytes(canonical_bytes(revised))})
    if len(records) > cap:
        raise ProvanError("FOUNDRY_REVISION_CAP_EXCEEDED", str(cap))
    return revised, records


def _witnesses(candidate: dict[str, Any]) -> dict[str, Any]:
    rows = []
    kinds = ("valid", "near_valid", "adversarial_invalid", "ambiguity", "over_specification")
    for criterion in candidate["criteria"]:
        for kind in kinds:
            rows.append({"witness_id": sha256_bytes(canonical_bytes([criterion["criterion_id"], kind])), "kind": kind, "criterion_refs": [criterion["criterion_id"]], "source_refs": criterion["statement_refs"], "oracle_ref": criterion["oracle_plan"]["oracle"], "expected_disposition": {"valid": "accept", "near_valid": "accept_if_declared_alternative", "adversarial_invalid": "reject", "ambiguity": "owner_decision", "over_specification": "reject_or_demote"}[kind], "reason_code": kind.upper()})
    return {"schema_id": "provan.internal.witness_set.v2", "witness_set_id": str(uuid.uuid4()), "candidate_digest": sha256_bytes(canonical_bytes(candidate)), "witnesses": rows}


def _surface_classes(row: dict[str, Any]) -> set[str]:
    return {str(item) for item in row.get("surface_classes", [])}


def implementation_map(brief: dict[str, Any], candidate: dict[str, Any], semantic_freeze_digest: str) -> dict[str, Any]:
    candidate_binding = brief["candidate"]
    evidence = list(brief.get("analysis_evidence", []))
    mappings = []
    for criterion in candidate["criteria"]:
        obligation = criterion["semantic_obligation"].lower()
        matched = []
        for row in evidence:
            classes = _surface_classes(row)
            if any(token in obligation for token in ("schema", "api", "format")) and classes & {"schema", "api", "public_api", "configuration"}:
                matched.append(row)
            elif any(token in obligation for token in ("test", "ci", "verify")) and classes & {"test", "ci", "workflow"}:
                matched.append(row)
        status = "supported" if matched else "not_discoverable"
        mappings.append({"criterion_id": criterion["criterion_id"], "status": status, "surface_refs": [{"path": row.get("path"), "digest": row.get("blob_sha256", row.get("content_digest")), "surface_classes": sorted(_surface_classes(row))} for row in matched], "reason_code": "EXACT_SOURCE_SURFACE_MATCH" if matched else "NO_SUPPORTED_SURFACE_DISCOVERED"})
    unauthorised = [{"path": row.get("path"), "reason": "CANDIDATE_CHANGE_WITHOUT_MATCHED_INTENT"} for row in evidence if not any(row.get("path") == surface.get("path") for mapping in mappings for surface in mapping["surface_refs"])]
    mutable = candidate_binding.get("mode") != "immutable"
    surface_inventory = sorted(({"path": row.get("path"), "digest": row.get("blob_sha256", row.get("content_digest")), "surface_classes": sorted(_surface_classes(row))} for row in evidence), key=lambda row: str(row["path"]))
    return {
        "schema_id": "provan.internal.implementation_source_map.v1", "map_id": str(uuid.uuid4()),
        "semantic_freeze_digest": semantic_freeze_digest, "candidate": candidate_binding,
        "candidate_bytes_digest": candidate_binding["candidate_digest"], "candidate_surface_digest": sha256_bytes(canonical_bytes(surface_inventory)), "analysis_evidence_digest": sha256_bytes(canonical_bytes(evidence)),
        "criterion_mappings": mappings, "candidate_without_authorised_intent": unauthorised,
        "unsupported_claimed_supported": 0, "mutable_explanatory_only": mutable,
        "source_only": True, "read_only": True, "creates_authority": False,
    }


def _pattern_for(criterion: dict[str, Any]) -> list[str]:
    text = criterion["semantic_obligation"].lower()
    selected = ["false_success_durable_state"]
    rules = [
        (("schema", "api", "format"), "api_schema_backward_compatibility"),
        (("permission", "identity", "authoriz"), "permission_privilege_boundary"),
        (("retry", "concurr", "idempot"), "retry_idempotency_concurrency"),
        (("recover", "rollback", "restart"), "timeout_restart_persistence"),
        (("ai", "model", "tool"), "ai_identity_tool_authority"),
        (("state", "transition"), "state_transition"),
    ]
    for needles, pattern in rules:
        if any(needle in text for needle in needles): selected.append(pattern)
    return list(dict.fromkeys(selected))


def pattern_selection(candidate: dict[str, Any], library: dict[str, Any]) -> dict[str, Any]:
    by_family = {row["family"]: row for row in library["patterns"]}
    items = []
    for criterion in candidate["criteria"]:
        for family in _pattern_for(criterion):
            pattern = by_family[family]
            items.append({"pattern_ref": {"id": pattern["pattern_id"], "version": pattern["version"]}, "criterion_ref": criterion["criterion_id"], "failure_dimension": "false_success" if family == "false_success_durable_state" else family, "applicability_basis": criterion["statement_refs"], "oracle_need": criterion["oracle_plan"], "capability_requirement": pattern["capability_requirements"], "distinct_verification_contribution": family, "limitations": pattern["limitations"], "status": "owner_confirmation_required"})
    unique_pairs = {(row["criterion_ref"], row["distinct_verification_contribution"]) for row in items}
    if len(unique_pairs) != len(items):
        raise ProvanError("FOUNDRY_PATTERN_DUPLICATE_DIMENSION", "selection")
    selected_ids = {row["pattern_ref"]["id"] for row in items}
    if selected_ids == {row["pattern_id"] for row in library["patterns"]}:
        raise ProvanError("FOUNDRY_PATTERN_SELECT_ALL_FORBIDDEN", "selection")
    if len(selected_ids) * 4 >= len(library["patterns"]) * 3:
        raise ProvanError("FOUNDRY_PATTERN_HIGH_COVERAGE_REVIEW_REQUIRED", "selection")
    return {"schema_id": "provan.verification_pattern_selection.v2", "selection_id": str(uuid.uuid4()), "contract_candidate_ref": {"id": candidate["candidate_id"], "sha256": sha256_bytes(canonical_bytes(candidate))}, "items": items, "material_dimensions_complete": all(bool(row["criterion_ref"]) for row in items), "materially_irrelevant_selected": 0, "execution_implied": False, "challenge_implied": False, "limitations": ["SESSION12_PLANNING_ONLY"]}


def mutation_analysis(candidate: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    material = []
    wording = []
    for criterion in candidate["criteria"]:
        current = [row for row in selection["items"] if row["criterion_ref"] == criterion["criterion_id"]]
        material.append({"criterion_id": criterion["criterion_id"], "mutation": "remove_or_invert", "material_plan_change": bool(current), "changed_dimensions": sorted({row["distinct_verification_contribution"] for row in current})})
        wording.append({"criterion_id": criterion["criterion_id"], "mutation": "wording_only", "material_plan_change": False, "pattern_id_churn_required": False})
    return {"schema_id": "provan.internal.contract_mutation_analysis.v1", "analysis_id": str(uuid.uuid4()), "candidate_digest": sha256_bytes(canonical_bytes(candidate)), "selection_digest": sha256_bytes(canonical_bytes(selection)), "material_mutations": material, "non_material_mutations": wording}


def _readiness(candidate: dict[str, Any], audit: dict[str, Any], mapping: dict[str, Any], selection: dict[str, Any], eligibility: str) -> tuple[str, dict[str, Any]]:
    reasons = []
    if eligibility == "NOT_ELIGIBLE": reasons.append("RUN_NOT_ELIGIBLE")
    if mapping["mutable_explanatory_only"]: reasons.append("MUTABLE_CANDIDATE_NOT_OWNER_CONFIRMATION_READY")
    if any(row["disposition"] in {"marked_unresolved", "marked_as_owner_question"} for row in audit["findings"]): reasons.append("MATERIAL_OWNER_QUESTIONS")
    if mapping["unsupported_claimed_supported"]: reasons.append("UNSUPPORTED_SURFACE_MAPPING")
    if selection["materially_irrelevant_selected"]: reasons.append("MATERIALLY_IRRELEVANT_PATTERN")
    if eligibility == "NOT_ELIGIBLE" or mapping["mutable_explanatory_only"] or mapping["unsupported_claimed_supported"]:
        state = "NOT_READY"
    elif reasons:
        state = "READY_WITH_MATERIAL_QUESTIONS"
    else:
        state = "READY_FOR_OWNER_CONFIRMATION"
    basis = {"schema_id": "provan.internal.readiness_basis.v1", "basis_id": str(uuid.uuid4()), "candidate_digest": sha256_bytes(canonical_bytes(candidate)), "audit_digest": sha256_bytes(canonical_bytes(audit)), "mapping_digest": sha256_bytes(canonical_bytes(mapping)), "selection_digest": sha256_bytes(canonical_bytes(selection)), "reason_codes": reasons, "runtime_evidence_established": False}
    return state, basis


def owner_review(projection: dict[str, Any], candidate: dict[str, Any], audit: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    sections = {
        "Sources require": [{"criterion_ref": row["criterion_id"], "authority": row["authority"]} for row in candidate["criteria"] if row["settlement_class"] == "proposed_mandatory"],
        "Provan inferred": candidate["suggestions"],
        "Audit changed": [{"finding_ref": row["finding_id"], "disposition": row["disposition"]} for row in audit["findings"] if row["disposition"] == "accepted_and_revised"],
        "Intentionally non-mandatory": [*candidate["non_requirements"], *candidate["suggestions"]],
        "Ambiguities": candidate["ambiguities"],
        "Patterns & evidence": [{"criterion_ref": row["criterion_ref"], "pattern_ref": row["pattern_ref"], "oracle_need": row["oracle_need"], "capability_requirement": row["capability_requirement"]} for row in selection["items"]],
        "Owner decisions": [{"criterion_ref": row["criterion_id"], "required_action": "confirm_reject_edit_or_unresolved"} for row in candidate["criteria"]],
    }
    sensitivity = "PUBLIC_SAFE" if projection["sensitivity"] == "PUBLIC_SAFE" else ("CLIENT_SAFE" if projection["sensitivity"] == "CLIENT_SAFE" else "LOCAL_NON_PUBLIC")
    return {"schema_id": "provan.foundry_owner_review.v1", "owner_review_id": str(uuid.uuid4()), "sensitivity": sensitivity, "projection_ref": {"id": projection["projection_id"], "sha256": sha256_bytes(canonical_bytes(projection))}, "section_order": list(OWNER_SECTIONS), "sections": sections, "creates_authority": False, "execution_available": False, "challenge_available": False}


def _render(run: dict[str, Any], review: dict[str, Any], format_name: str, view: str) -> str:
    value = review if view == "owner-review" else run
    if format_name == "json": return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
    if view == "owner-review":
        lines = [f"# Foundry owner review {review['owner_review_id']}"]
        for name in OWNER_SECTIONS:
            lines.extend(["", f"## {name}", json.dumps(review["sections"][name], sort_keys=True, ensure_ascii=False)])
    else:
        lines = [f"# Contract Foundry {run['run_id']}", f"Eligibility: `{run['run_eligibility']}`", f"Readiness: `{run['contract_readiness']}`", f"Information boundary: `{run['information_boundary']}`", f"Projection: `{run['owner_projection_ref']['id']}`"]
    body = "\n".join(lines) + "\n"
    if format_name in {"terminal", "markdown"}: return body
    import html
    return "<!doctype html><html><body><pre>" + html.escape(body) + "</pre></body></html>"


def _stage_trace(stages: tuple[str, ...], outputs: dict[str, list[str]], ledger_digest: str, deep_path_digests: list[str]) -> list[dict[str, Any]]:
    trace = []
    previous: list[str] = []
    for stage in stages:
        if stage == "source_bundle": inputs = []
        elif stage in {"blind_path_a", "blind_path_b"}: inputs = [ledger_digest]
        elif stage == "blind_paths_freeze": inputs = deep_path_digests
        else: inputs = previous
        current = outputs.get(stage, [])
        trace.append({"stage": stage, "input_digests": inputs, "output_digests": current, "status": "EXECUTED" if current else "NOT_APPLICABLE"})
        if current: previous = current
    return trace


def foundry_v2(
    *, brief: dict[str, Any], brief_raw: bytes, manifest: dict[str, Any], initial_sources: list[dict[str, Any]],
    interpretation: str, depth: str, provider_id: str | None, no_model: bool,
    information_boundary: str, view: str, format_name: str, library: dict[str, Any],
    semantic_role: Callable[[str, dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]] | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    started = time.perf_counter()
    run_id = run_id or str(uuid.uuid4()); case_id = brief["case_id"]
    root = Path("outputs/contract-foundry") / run_id
    bundle, frozen, bundle_raw = freeze_source_bundle(run_id=run_id, case_id=case_id, candidate=brief["candidate"], manifest=manifest, sources=initial_sources)
    verify_live_source_continuity(initial_sources, bundle)
    coverage = build_source_coverage(bundle, frozen)
    coverage_ref, coverage_raw = _store(root, "source-coverage", coverage, "source-coverage.v1.json", "coverage_id")
    ledger = build_statement_ledger(bundle, coverage, brief["candidate"]["candidate_digest"])
    ledger_ref, ledger_raw = _store(root, "source-authority-ledger", ledger, "source-authority-ledger.v2.json", "ledger_id")

    required_model = depth in {"standard", "deep"}
    semantic_available = semantic_role is not None and not no_model
    eligibility = "ELIGIBLE"
    limitations = ["SOURCE_ONLY", "TARGET_READ_ONLY", "EXECUTION_UNAVAILABLE", "CHALLENGE_UNAVAILABLE"]
    if required_model and not semantic_available:
        eligibility = "NOT_ELIGIBLE"; limitations.append("REQUIRED_SEMANTIC_ROLE_UNAVAILABLE")
    if information_boundary == "implementation-informed":
        limitations.append("IMPLEMENTATION_INFORMED_NON_BLIND_DEGRADED")

    role_receipts: list[dict[str, Any]] = []
    path_artifacts: list[dict[str, Any]] = []
    if depth == "deep":
        for path_id in ("A", "B"):
            intent = build_intent(ledger, path_id)
            goals = _goal_obstacle(intent); pre = _premortem(intent, goals)
            candidate = _candidate(case_id, intent, goals, pre, interpretation, f"blind-{path_id.lower()}")
            if semantic_available:
                result, receipt = semantic_role(f"deep_path_{path_id.lower()}", {"ledger": ledger, "intent": intent, "candidate": candidate})
                role_receipts.append(receipt)
                _apply_intent_role_result(intent, result, f"deep_path_{path_id.lower()}")
                _apply_candidate_role_result(candidate, result, f"deep_path_{path_id.lower()}")
            path_artifacts.append({"path": path_id, "input_digest": ledger_ref["sha256"], "conversation_state": None, "previous_response_id": None, "background": False, "intent": intent, "candidate_or_critique": candidate})
        path_digests = [sha256_bytes(canonical_bytes(row)) for row in path_artifacts]
        synthesis = {"schema_id": "provan.internal.deep_synthesis.v1", "synthesis_id": str(uuid.uuid4()), "path_digests": path_digests, "preserved_disagreements": [], "source_ledger_digest": ledger_ref["sha256"], "authority": "proposal_only"}
        if semantic_available:
            result, receipt = semantic_role("deep_synthesis", {"path_digests": path_digests, "synthesis": synthesis})
            role_receipts.append(receipt); synthesis["model_role_result"] = result
        intent = build_intent(ledger, "synthesis")
        intent["synthesis_ref"] = {"id": synthesis["synthesis_id"], "sha256": sha256_bytes(canonical_bytes(synthesis))}
        if semantic_available:
            _apply_intent_role_result(intent, result, "deep_synthesis")
    else:
        path_digests = []
        intent = build_intent(ledger, "standard" if depth == "standard" else "fast")
        if semantic_available:
            result, receipt = semantic_role("blind_intent", {"ledger": ledger, "intent": intent})
            role_receipts.append(receipt); _apply_intent_role_result(intent, result, "blind_intent")
        synthesis = None

    if any(receipt.get("semantic_qualification") is False for receipt in role_receipts):
        eligibility = "NOT_ELIGIBLE"
        limitations.append("SCRIPTED_PROVIDER_SEMANTICALLY_UNQUALIFIED")

    intent_ref, intent_raw = _store(root, "intent-model", intent, "intent-model.v2.json", "intent_id")
    goals = _goal_obstacle(intent)
    premortem = _premortem(intent, goals)
    if semantic_available:
        result, receipt = semantic_role("goal_premortem", {"intent": intent, "goals": goals, "premortem": premortem})
        role_receipts.append(receipt); _apply_goal_role_result(goals, premortem, result)
    candidate = _candidate(case_id, intent, goals, premortem, interpretation, "synthesized" if depth == "deep" else depth)
    if semantic_available:
        result, receipt = semantic_role("contract_proposer", {"intent": intent, "goals": goals, "premortem": premortem, "candidate": candidate})
        role_receipts.append(receipt); _apply_candidate_role_result(candidate, result, "contract_proposer")
    audit = _audit(candidate, intent)
    if semantic_available:
        result, receipt = semantic_role("adversarial_auditor", {"candidate": candidate, "audit": audit})
        role_receipts.append(receipt); _apply_audit_role_result(audit, result)
        result, receipt = semantic_role("revision", {"candidate": candidate, "audit": audit})
        role_receipts.append(receipt); _apply_candidate_role_result(candidate, result, "revision")
    revised, revisions = _revision(candidate, audit, 2 if depth == "deep" else 1)
    candidate_ref, candidate_raw = _store(root, "contract-candidate", revised, "contract-candidate.v2.json", "candidate_id")
    witnesses = _witnesses(revised)
    semantic_freeze = {"intent": sha256_bytes(intent_raw), "goal_obstacle": sha256_bytes(canonical_bytes(goals)), "premortem": sha256_bytes(canonical_bytes(premortem)), "candidate": sha256_bytes(canonical_bytes(revised)), "audit": sha256_bytes(canonical_bytes(audit)), "revisions": sha256_bytes(canonical_bytes(revisions)), "witnesses": sha256_bytes(canonical_bytes(witnesses))}
    semantic_freeze_digest = sha256_bytes(canonical_bytes(semantic_freeze))
    mapping = implementation_map(brief, revised, semantic_freeze_digest)
    selection = pattern_selection(revised, library)
    mutation = mutation_analysis(revised, selection)
    readiness, readiness_basis = _readiness(revised, audit, mapping, selection, eligibility)
    if information_boundary == "implementation-informed": readiness = "NOT_READY"

    projected_criteria = [{
        "criterion_id": row["criterion_id"], "statement": row["semantic_obligation"], "class": "mandatory",
        "material": row["material"], "required_evidence_classes": ["owner_confirmed"],
        "challenge_requirement": "not_required", "activation_rule": None,
        "closure_requirement": {"check_mode": "human_confirmation", "required_evidence_class": "owner_confirmed", "check": {"type": "canonical_case_operator_action"}, "subject_refs": row["statement_refs"], "limitations": ["OWNER_CONFIRMATION_REQUIRED", "RUNTIME_BEHAVIOR_NOT_ESTABLISHED"]},
    } for row in revised["criteria"]]
    projection_policy = manifest.get("projection_policy", {}) if isinstance(manifest.get("projection_policy"), dict) else {}
    projection_sensitivity = projection_policy.get("sensitivity") if projection_policy.get("operator_confirmed") is True and projection_policy.get("sensitivity") in {"CLIENT_SAFE", "PUBLIC_SAFE"} else "LOCAL_NON_PUBLIC"
    projection = {
        "schema_id": "provan.foundry_acceptance_projection.v2", "projection_id": str(uuid.uuid4()),
        "sensitivity": projection_sensitivity, "run_id": run_id,
        "brief_ref": {"id": brief["brief_id"], "sha256": sha256_bytes(brief_raw)}, "case_id": case_id,
        "candidate_digest": brief["candidate"]["candidate_digest"], "proposed_contract_terms": {
            "intended_outcome": revised["criteria"][0]["semantic_obligation"] if revised["criteria"] else "INTENDED_OUTCOME_UNRESOLVED",
            "target_user": None, "journeys": [], "criteria": projected_criteria, "protected_invariants": [],
            "allowed_evidence_classes": ["source_verified", "owner_confirmed", "trusted_imported_receipt"],
            "future_verifier_requirements": sorted({cap for row in selection["items"] for cap in row["capability_requirement"]}),
            "network_policy": "none", "challenge_budget": {"class": "not_required", "max_instances": 0, "max_wall_seconds": 0, "max_network_requests": 0},
            "risk": {"tier": {"value": "unresolved", "authority": "unresolved", "provenance_refs": []}, "reversibility": {"value": "unresolved", "authority": "unresolved", "provenance_refs": []}},
            "conditions": [], "reinspection_triggers": ["candidate_changed", "expiry_reached"], "interpretation": interpretation,
        },
        "term_provenance": [{"criterion_id": row["criterion_id"], "source_refs": row["statement_refs"], "candidate_ref": candidate_ref, "audit_ref": audit["audit_id"], "witness_ref": witnesses["witness_set_id"], "pattern_refs": [x["pattern_ref"] for x in selection["items"] if x["criterion_ref"] == row["criterion_id"]], "authority": row["authority"]} for row in revised["criteria"]],
        "semantic_freeze_digest": semantic_freeze_digest, "implementation_map_digest": sha256_bytes(canonical_bytes(mapping)),
        "contract_readiness": readiness, "run_eligibility": eligibility, "owner_confirmation_required": True,
        "creates_authority": False, "execution_available": False, "challenge_available": False, "limitations": limitations,
    }
    _schema("foundry-acceptance-projection.v2.json", projection)
    projection_raw = canonical_bytes(projection)
    review = owner_review(projection, revised, audit, selection)
    _schema("foundry-owner-review.v1.json", review)
    review_raw = canonical_bytes(review)
    secure_write(root / "foundry-acceptance-projection.json", projection_raw)
    secure_write(root / "foundry-owner-review.json", review_raw)

    artifacts = {
        "source_bundle": [sha256_bytes(bundle_raw)], "source_coverage": [coverage_ref["sha256"]],
        "source_authority_ledger": [ledger_ref["sha256"]], "blind_intent": [intent_ref["sha256"]],
        "blind_path_a": path_digests[:1], "blind_path_b": path_digests[1:2],
        "blind_paths_freeze": [sha256_bytes(canonical_bytes(path_digests))] if path_digests else [],
        "deep_synthesis": [sha256_bytes(canonical_bytes(synthesis))] if synthesis else [],
        "goal_obstacle": [semantic_freeze["goal_obstacle"]], "pre_mortem": [semantic_freeze["premortem"]],
        "contract_candidate": [candidate_ref["sha256"]], "adversarial_audit": [semantic_freeze["audit"]],
        "revision": [sha256_bytes(canonical_bytes(revisions))] if revisions else [], "revisions": [sha256_bytes(canonical_bytes(revisions))] if revisions else [],
        "witness_set": [semantic_freeze["witnesses"]], "mutation_analysis": [sha256_bytes(canonical_bytes(mutation))],
        "final_audit": [semantic_freeze["audit"]], "semantic_freeze": [semantic_freeze_digest],
        "implementation_mapping": [sha256_bytes(canonical_bytes(mapping))], "verification_plan": [sha256_bytes(canonical_bytes(selection))],
        "readiness": [sha256_bytes(canonical_bytes(readiness_basis))], "owner_projection": [sha256_bytes(projection_raw)],
    }
    stages = DEEP_STAGES if depth == "deep" else STANDARD_STAGES
    trace = _stage_trace(stages, artifacts, ledger_ref["sha256"], path_digests)
    elapsed = round((time.perf_counter() - started) * 1000, 4)
    computed_costs = [float(row["cost_usd"]) for row in role_receipts if row.get("cost_status") == "computed_from_provider_usage_at_pinned_rates" and row.get("cost_usd") is not None]
    all_costs_computed = bool(role_receipts) and len(computed_costs) == len(role_receipts)
    measurements = {"wall_time_ms": elapsed, "http_model_calls": sum(int(row.get("calls") or 0) for row in role_receipts), "input_tokens": sum(int(row.get("input_tokens") or 0) for row in role_receipts), "output_tokens": sum(int(row.get("output_tokens") or 0) for row in role_receipts), "reasoning_tokens": sum(int(row.get("reasoning_tokens") or 0) for row in role_receipts), "cost_status": "computed_from_provider_usage_at_pinned_rates" if all_costs_computed else "unavailable", "cost_usd": round(sum(computed_costs), 8) if all_costs_computed else None}
    run = {
        "schema_id": "provan.internal.contract_foundry_run.v2", "run_id": run_id, "sensitivity": "LOCAL_NON_PUBLIC",
        "package_version": PACKAGE_VERSION, "policy_version": POLICY_VERSION, "scorer_version": SCORER_VERSION,
        "case_id": case_id, "candidate": brief["candidate"], "brief_ref": projection["brief_ref"],
        "source_bundle_ref": {"id": bundle["bundle_id"], "sha256": sha256_bytes(bundle_raw)}, "source_coverage_ref": coverage_ref,
        "source_ledger_ref": ledger_ref, "information_boundary": information_boundary,
        "semantic_artifacts": semantic_freeze, "deep_paths": [{"path": row["path"], "input_digest": row["input_digest"], "output_digest": sha256_bytes(canonical_bytes(row))} for row in path_artifacts],
        "stage_order": list(stages), "stage_execution": trace, "implementation_map": mapping,
        "pattern_selection": selection, "mutation_analysis": mutation, "readiness_basis": readiness_basis,
        "role_receipts": role_receipts, "interpretation": interpretation, "depth": depth,
        "run_eligibility": eligibility, "contract_readiness": readiness, "mode_qualification": "IMPLEMENTED_UNQUALIFIED",
        "owner_projection_ref": {"id": projection["projection_id"], "sha256": sha256_bytes(projection_raw)},
        "owner_review_ref": {"id": review["owner_review_id"], "sha256": sha256_bytes(review_raw)},
        "measurements": measurements, "budget_policy": {"session_hard_cap_usd": 75, "classification_calls_max": 16, "classification_input_tokens_max": 512000, "classification_output_tokens_max": 64000, "classification_reserved_cost_usd": 2, "total_calls_max": 28 if depth == "deep" else 24, "run_reserved_cost_usd": 7 if depth == "deep" else 5},
        "execution_available": False, "challenge_available": False, "limitations": limitations,
    }
    secure_write(root / "contract-foundry-run.json", canonical_bytes(run))
    return run, _render(run, review, format_name, view)
