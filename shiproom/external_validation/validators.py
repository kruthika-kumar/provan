from __future__ import annotations

import math
import re
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Any

from .registry import registration
from .identity import case_id as derive_case_id, observation_key as derive_observation_key, attempt_id as derive_attempt_id


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
SURFACES = {"ENGINEERING_EXECUTION", "PRODUCT_JOURNEY", "PRODUCT_MEASUREMENT", "DATA_CONTRACT_PIPELINE", "AI_EVAL"}
APPLICABILITY = {"applicable", "not_applicable", "missing_context", "accepted_constraint"}
EVIDENCE = {"deterministically_verified", "browser_observed", "source_verified", "model_reviewed", "owner_confirmed", "agent_reported", "missing_evidence", "not_applicable"}
ORIGINS = {"native_checks", "shiproom_deterministic", "shiproom_semantic", "sota_agent", "human"}
SEVERITIES = {"info", "low", "medium", "high", "blocker"}
REPRODUCTION = {"reproduced", "not_reproduced", "not_attempted", "not_applicable"}
ADJUDICATION = {"unadjudicated", "verified", "rejected", "blocker_closed", "target_detected", "target_not_detected"}
TERMINAL = {"completed", "timeout", "error", "budget_exceeded", "malformed_output", "unsafe_execution", "indeterminate_in_flight"}
ARMS = {"NATIVE_CHECKS_ONLY", "SOTA_AGENT", "SHIPROOM_DETERMINISTIC_ONLY", "SHIPROOM_FULL", "SHIPROOM_NO_DETERMINISTIC_CORE"}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str


class ValidationError(ValueError):
    def __init__(self, issue: ValidationIssue):
        self.issue = issue
        super().__init__(f"{issue.code}:{issue.path}:{issue.message}")


def _error(code: str, path: str, message: str) -> None:
    raise ValidationError(ValidationIssue(code, path, message))


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict): _error("type_invalid", path, "must be object")
    return value


def _required(value: dict[str, Any], keys: set[str], path: str) -> None:
    missing = keys.difference(value)
    unknown = set(value).difference(keys)
    if missing: _error("required_field_missing", path, ",".join(sorted(missing)))
    if unknown: _error("unknown_field", path, ",".join(sorted(unknown)))


def _sha(value: Any, path: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value): _error("sha256_invalid", path, "requires sha256:<64 lowercase hex>")


def _git_sha(value: Any, path: str) -> None:
    if not isinstance(value, str) or not GIT_SHA.fullmatch(value): _error("immutable_commit_required", path, "requires immutable Git SHA")


def _finite_nonnegative(value: Any, path: str) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0: _error("nonnegative_finite_required", path, "must be finite and non-negative")


def _header(value: dict[str, Any], schema_id: str, *, readable: bool = False) -> None:
    _required(value, set(value) | {"schema_id", "schema_version"}, "")
    if value.get("schema_id") != schema_id: _error("schema_id_invalid", "/schema_id", schema_id)
    if not isinstance(value.get("schema_version"), str): _error("schema_version_invalid", "/schema_version", "must be string")
    try: registration(schema_id, value["schema_version"], readable=readable)
    except ValueError: _error("unsupported_schema_version", "/schema_version", "not registered current version")


def _validate_case(value: dict[str, Any], schema_id: str) -> dict[str, Any]:
    _header(value, schema_id)
    base = {"schema_id", "schema_version", "case_id", "case_authority", "repository", "commit_sha", "snapshot_hash", "release_surfaces", "applicability", "visible_patient_root"}
    if schema_id == "external_validation.controlled_pair_case": base |= {"buggy_sha", "fixed_sha", "target_id", "oracle_ref", "oracle_commitment", "release_packet_hash", "target_clearance"}
    if schema_id == "external_validation.natural_pr_case": base |= {"pr_number", "context_refs"}
    _required(value, base, "")
    _git_sha(value["commit_sha"], "/commit_sha"); _sha(value["snapshot_hash"], "/snapshot_hash")
    authority = _mapping(value["case_authority"], "/case_authority")
    expected_dataset = {"external_validation.beta_case":"beta", "external_validation.controlled_pair_case":"controlled", "external_validation.natural_pr_case":"natural"}[schema_id]
    expected_authority = {"dataset": expected_dataset, "snapshot": value["snapshot_hash"], "repository": value["repository"], "commit_sha": value["commit_sha"], "manifest_version": value["schema_version"], "release_surfaces": sorted(value["release_surfaces"]), "applicability": value["applicability"]}
    if schema_id == "external_validation.controlled_pair_case":
        expected_authority |= {"buggy_sha": value["buggy_sha"], "fixed_sha": value["fixed_sha"], "target_id": value["target_id"], "oracle_commitment": value["oracle_commitment"], "release_packet_hash": value["release_packet_hash"]}
    if schema_id == "external_validation.natural_pr_case": expected_authority |= {"pr_number": value["pr_number"], "context_refs": value["context_refs"]}
    if authority != expected_authority or value["case_id"] != derive_case_id(authority): _error("case_identity_mismatch", "/case_id", "must derive from declared immutable authority")
    surfaces = value["release_surfaces"]
    if not isinstance(surfaces, list) or not surfaces or any(item not in SURFACES for item in surfaces): _error("release_surface_invalid", "/release_surfaces", "requires typed surfaces")
    if "DATA" in surfaces: _error("generic_data_forbidden", "/release_surfaces", "DATA is not a surface")
    applicability = _mapping(value["applicability"], "/applicability")
    if set(applicability) != SURFACES: _error("applicability_incomplete", "/applicability", "all typed surfaces required")
    if any(item not in APPLICABILITY for item in applicability.values()): _error("applicability_state_invalid", "/applicability", "invalid state")
    if any(applicability[surface] == "not_applicable" for surface in surfaces):
        _error("declared_surface_not_applicable", "/applicability", "declared active surface cannot be not_applicable")
    if schema_id == "external_validation.controlled_pair_case":
        _git_sha(value["buggy_sha"], "/buggy_sha"); _git_sha(value["fixed_sha"], "/fixed_sha")
        _sha(value["oracle_commitment"], "/oracle_commitment"); _sha(value["release_packet_hash"], "/release_packet_hash")
        if value["buggy_sha"] == value["fixed_sha"]: _error("paired_snapshot_identical", "/fixed_sha", "buggy and fixed twins must differ")
        if not isinstance(value["oracle_ref"], str): _error("oracle_ref_invalid", "/oracle_ref", "must be absolute external path")
        patient = Path(value["visible_patient_root"]).resolve(strict=False)
        oracle = Path(value["oracle_ref"]).resolve(strict=False)
        try:
            oracle.relative_to(patient)
        except ValueError:
            pass
        else:
            _error("oracle_visible_to_patient", "/oracle_ref", "oracle cannot be patient-visible")
        if value["target_clearance"] not in {"named_target_only", "not_run"}: _error("target_clearance_scope_invalid", "/target_clearance", "cannot claim global cleanliness")
    if schema_id == "external_validation.natural_pr_case":
        forbidden = {"recall", "true_negative", "known_clean", "complete_ground_truth", "overall_cleanliness"}
        if forbidden.intersection(value): _error("natural_claim_forbidden", "/", "natural cases have incomplete ground truth")
    return value


def _validate_receipt(value: dict[str, Any]) -> dict[str, Any]:
    _header(value, "external_validation.run_receipt", readable=True)
    keys = {"schema_id", "schema_version", "receipt_id", "observation_key", "observation_inputs", "attempt_id", "attempt_lineage", "case_id", "dataset", "snapshot_type", "arm", "repository", "pr_number", "maturity_band", "base_sha", "target_sha", "commit_sha", "release_surfaces", "applicability", "hashes", "versions", "started_at", "completed_at", "terminal_state", "termination", "checks", "model_usage", "cost", "totals", "findings", "logs", "supervisor"}
    _required(value, keys, "")
    if value["arm"] not in ARMS: _error("arm_invalid", "/arm", "unknown arm")
    _git_sha(value["commit_sha"], "/commit_sha"); _git_sha(value["base_sha"], "/base_sha"); _git_sha(value["target_sha"], "/target_sha")
    if value["dataset"] not in {"beta", "controlled", "natural"}: _error("dataset_invalid", "/dataset", "unknown dataset")
    if (value["dataset"] == "natural") != (value["snapshot_type"] == "natural_pr"): _error("dataset_snapshot_inconsistent", "/snapshot_type", "natural snapshots only belong to natural dataset")
    if value["dataset"] != "natural" and value["snapshot_type"] not in {"buggy", "fixed"}: _error("dataset_snapshot_inconsistent", "/snapshot_type", "paired datasets require buggy/fixed snapshot")
    if value["dataset"] == "natural" and (not isinstance(value["pr_number"], int) or value["pr_number"] < 1): _error("pr_number_required", "/pr_number", "natural receipt needs PR number")
    if value["dataset"] != "natural" and value["pr_number"] is not None: _error("pr_number_forbidden", "/pr_number", "only natural receipts carry PR number")
    if value["maturity_band"] not in {"beta", "primary", "mature_control", "not_applicable"}: _error("maturity_band_invalid", "/maturity_band", "explicit band required")
    if not isinstance(value["release_surfaces"], list) or any(surface not in SURFACES for surface in value["release_surfaces"]): _error("release_surface_invalid", "/release_surfaces", "typed surfaces required")
    applicability = _mapping(value["applicability"], "/applicability")
    if set(applicability) != SURFACES or any(state not in APPLICABILITY for state in applicability.values()): _error("applicability_incomplete", "/applicability", "typed decision for every surface required")
    if any(applicability[surface] == "not_applicable" for surface in value["release_surfaces"]): _error("declared_surface_not_applicable", "/applicability", "declared active surface cannot be not_applicable")
    try:
        started, completed = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00")), datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))
        if completed < started: raise ValueError
    except (AttributeError, ValueError): _error("timestamp_invalid", "/completed_at", "ordered ISO timestamps required")
    obs_inputs = _mapping(value["observation_inputs"], "/observation_inputs")
    if obs_inputs.get("case_id") != value["case_id"] or obs_inputs.get("arm") != value["arm"] or value["observation_key"] != derive_observation_key(obs_inputs): _error("observation_identity_mismatch", "/observation_key", "must derive from experimental inputs")
    if not isinstance(value["attempt_lineage"], int) or value["attempt_id"] != derive_attempt_id(value["observation_key"], value["attempt_lineage"]): _error("attempt_identity_mismatch", "/attempt_id", "must derive from observation and infrastructure lineage")
    if value["terminal_state"] not in TERMINAL: _error("terminal_state_invalid", "/terminal_state", "receipt must preserve terminal outcome")
    if value["termination"] not in TERMINAL: _error("termination_invalid", "/termination", "explicit termination required")
    hashes = _mapping(value["hashes"], "/hashes")
    for field in {"source", "release_packet", "output", "receipt"}:
        if field not in hashes: _error("hash_missing", f"/hashes/{field}", "required")
        _sha(hashes[field], f"/hashes/{field}")
    payload = dict(value); payload.pop("receipt_id"); payload_hashes = dict(payload["hashes"]); payload_hashes.pop("receipt"); payload["hashes"] = payload_hashes
    canonical = __import__("json").dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    actual_receipt_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if hashes["receipt"] != actual_receipt_hash or value["receipt_id"] != "receipt_" + actual_receipt_hash.removeprefix("sha256:"):
        _error("receipt_identity_mismatch", "/receipt_id", "receipt ID and receipt hash must be supervisor-recomputed")
    usage = _mapping(value["model_usage"], "/model_usage")
    state = usage.get("state")
    if state not in {"not_applicable", "available", "unavailable"}: _error("model_usage_state_invalid", "/model_usage/state", "explicit state required")
    token_fields = {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "tool_calls"}
    if state == "available":
        for field in token_fields | {"calls", "billed_cost_usd"}:
            if field not in usage: _error("provider_usage_missing", f"/model_usage/{field}", "available usage must be retained")
            _finite_nonnegative(usage[field], f"/model_usage/{field}")
    elif any(field in usage for field in token_fields): _error("model_usage_state_conflict", "/model_usage", "unavailable/not_applicable usage cannot silently carry numbers")
    cost = _mapping(value["cost"], "/cost")
    if cost.get("state") not in {"available", "cost_unavailable", "not_applicable"}: _error("cost_state_invalid", "/cost/state", "explicit state required")
    if cost["state"] == "available":
        _finite_nonnegative(cost.get("normalized_billed_cost"), "/cost/normalized_billed_cost")
        if not isinstance(cost.get("price_version"), str): _error("price_version_missing", "/cost/price_version", "required for priced receipt")
    if state == "available" and cost["state"] == "not_applicable": _error("model_cost_missing", "/cost", "model use requires cost or explicit unavailable state")
    versions = _mapping(value["versions"], "/versions")
    required_versions = {"shiproom_commit", "container_image", "model", "model_version", "prompt_version", "policy_version", "execution_policy_version", "tool_policy_version", "price_version"}
    if set(versions) != required_versions or any(not isinstance(versions[field], str) or not versions[field] for field in required_versions): _error("receipt_versions_incomplete", "/versions", "full immutable provenance required")
    checks = _mapping(value["checks"], "/checks")
    if set(checks) != {"attempted", "passed", "failed", "skipped", "skip_reasons", "duration_seconds"}: _error("checks_incomplete", "/checks", "complete native check outcomes required")
    _finite_nonnegative(checks["duration_seconds"], "/checks/duration_seconds")
    totals = _mapping(value["totals"], "/totals")
    if set(totals) != {"wall_time_seconds", "local_compute_seconds", "model_cost_usd", "external_tool_cost_usd"}: _error("totals_incomplete", "/totals", "all execution totals required")
    for key in totals: _finite_nonnegative(totals[key], "/totals/" + key)
    for finding in value["findings"]:
        item = _mapping(finding, "/findings")
        required_finding = {"finding_id", "target_id", "origin", "severity", "evidence_state", "evidence_refs", "reproduction_status", "adjudication"}
        if set(item) != required_finding: _error("finding_shape_invalid", "/findings", "typed finding contract required")
        if not isinstance(item["finding_id"], str) or not isinstance(item["evidence_refs"], list): _error("finding_field_invalid", "/findings", "finding fields invalid")
        if item["origin"] not in ORIGINS or item["severity"] not in SEVERITIES or item["reproduction_status"] not in REPRODUCTION or item["adjudication"] not in ADJUDICATION: _error("finding_state_invalid", "/findings", "unknown finding state")
        if item.get("evidence_state") not in EVIDENCE: _error("evidence_state_invalid", "/findings/evidence_state", "unknown evidence state")
        if item.get("evidence_state") in {"model_reviewed", "agent_reported", "missing_evidence"} and item.get("adjudication") in {"blocker_closed", "verified", "target_detected"}: _error("insufficient_evidence_for_closure", "/findings/adjudication", "model/agent/missing evidence cannot establish closure or target proof")
    if value["supervisor"] != "host_supervisor": _error("receipt_supervisor_invalid", "/supervisor", "patient code cannot finalize receipt")
    return value


def _validate_applicability(value: dict[str, Any]) -> dict[str, Any]:
    _header(value, "external_validation.applicability")
    _required(value, {"schema_id", "schema_version", "decisions"}, "")
    decisions = _mapping(value["decisions"], "/decisions")
    if set(decisions) != SURFACES: _error("applicability_incomplete", "/decisions", "all surfaces required")
    if any(item not in APPLICABILITY for item in decisions.values()): _error("applicability_state_invalid", "/decisions", "invalid state")
    return value


def _validate_run_index(value: dict[str, Any]) -> dict[str, Any]:
    _header(value, "external_validation.run_index")
    _required(value, {"schema_id", "schema_version", "schedule_id", "records"}, "")
    if not isinstance(value["schedule_id"], str) or not isinstance(value["records"], list): _error("run_index_shape_invalid", "/", "schedule ID and records required")
    seen = set()
    for index, record in enumerate(value["records"]):
        entry = _mapping(record, f"/records/{index}")
        key = entry.get("observation_key")
        if not isinstance(key, str): _error("observation_key_missing", f"/records/{index}/observation_key", "required")
        if key in seen: _error("duplicate_observation", f"/records/{index}/observation_key", "duplicate run observation")
        seen.add(key)
    return value


def _validate_synthetic_proof_receipt(value: dict[str, Any]) -> dict[str, Any]:
    _header(value, "external_validation.synthetic_proof_receipt")
    required = {"schema_id", "schema_version", "proof", "executed_at", "implementation_base_commit", "implementation_state", "command", "image", "qualification", "corpus", "arm_receipts", "private_artifact_hashes", "redaction"}
    _required(value, required, "")
    if value["proof"] != "docker_five_arm_lifecycle" or not isinstance(value["command"], str) or not value["command"]:
        _error("synthetic_proof_identity_invalid", "/proof", "requires canonical Docker lifecycle proof")
    _git_sha(value["implementation_base_commit"], "/implementation_base_commit")
    if not isinstance(value["image"], str) or "@sha256:" not in value["image"]:
        _error("synthetic_proof_image_invalid", "/image", "immutable image digest required")
    qualification = _mapping(value["qualification"], "/qualification")
    if qualification != {"qualification_status": "QUALIFIED", "canaries": {"read_only": "enforced", "network": "enforced", "secret_socket": "isolated"}}:
        _error("synthetic_proof_qualification_invalid", "/qualification", "qualified doctor canaries required")
    arm_receipts = _mapping(value["arm_receipts"], "/arm_receipts")
    if set(arm_receipts) != ARMS or any(not isinstance(item, str) or not re.fullmatch(r"receipt_[0-9a-f]{64}", item) for item in arm_receipts.values()) or len(set(arm_receipts.values())) != len(ARMS):
        _error("synthetic_proof_arm_receipts_invalid", "/arm_receipts", "one distinct finalized receipt per arm required")
    corpus = _mapping(value["corpus"], "/corpus")
    if corpus != {"receipt_count": 5, "all_states": ["TERMINAL"]}:
        _error("synthetic_proof_corpus_invalid", "/corpus", "five terminal receipts required")
    hashes = _mapping(value["private_artifact_hashes"], "/private_artifact_hashes")
    if set(hashes) != {"scheduler.sqlite", "source-snapshot.json", "release-packet.json"}:
        _error("synthetic_proof_hashes_invalid", "/private_artifact_hashes", "fixed redacted artifact set required")
    for name, digest in hashes.items(): _sha(digest, "/private_artifact_hashes/" + name)
    if not isinstance(value["redaction"], str) or not value["redaction"]:
        _error("synthetic_proof_redaction_missing", "/redaction", "redaction declaration required")
    return value


def validate_artifact(value: Any) -> dict[str, Any]:
    item = _mapping(value, "")
    schema_id = item.get("schema_id")
    if schema_id == "external_validation.beta_case": return _validate_case(item, schema_id)
    if schema_id == "external_validation.controlled_pair_case": return _validate_case(item, schema_id)
    if schema_id == "external_validation.natural_pr_case": return _validate_case(item, schema_id)
    if schema_id == "external_validation.run_receipt": return _validate_receipt(item)
    if schema_id == "external_validation.run_receipt.v2":
        from .v2 import validate_receipt_v2
        return validate_receipt_v2(item)
    if schema_id == "external_validation.artifact_manifest.v1":
        from .v2 import validate_artifact_manifest
        return validate_artifact_manifest(item)
    if schema_id == "external_validation.containment_incident.v1":
        from .v2 import validate_incident
        return validate_incident(item)
    if schema_id == "external_validation.status_supersession.v1":
        from .v2 import validate_status_record
        return validate_status_record(item)
    if schema_id == "external_validation.finalization_journal.v1":
        from .v2 import validate_finalization_journal_record
        return validate_finalization_journal_record(item)
    if schema_id == "external_validation.applicability": return _validate_applicability(item)
    if schema_id == "external_validation.run_index": return _validate_run_index(item)
    if schema_id == "external_validation.synthetic_proof_receipt": return _validate_synthetic_proof_receipt(item)
    if schema_id == "external_validation.price_table":
        from .pricing import validate_price_table
        return validate_price_table(item)
    if schema_id == "remediation_release_authorization.v1":
        from .remediation_backend.contracts import validate_release_authorization
        try: return validate_release_authorization(item)
        except ValueError as exc: _error(str(exc), "/", "remediation release authorization invalid")
    if schema_id == "remediation_package_contract.v1":
        from .remediation_backend.package_contract import validate
        try: return validate(item)
        except ValueError as exc: _error(str(exc), "/", "remediation package contract invalid")
    if schema_id == "external_validation.status_authority.v1":
        from .status import validate_status_authority_document
        return validate_status_authority_document(item)
    if schema_id == "external_validation.profile_status_chain.v2":
        from .status import validate_profile_status_chain
        return validate_profile_status_chain(item)
    if schema_id == "external_validation.session1_closeout_manifest.v1":
        from .status import validate_closeout_manifest_document
        return validate_closeout_manifest_document(item)
    if schema_id == "external_validation.status_attestation.v2":
        from .status import validate_status_attestation_document
        return validate_status_attestation_document(item)
    _error("schema_id_invalid", "/schema_id", "unsupported artifact")


def validate_receipt_against_case(receipt: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Cross-artifact authority check performed by the host supervisor."""
    validate_artifact(case); validate_artifact(receipt)
    bindings = {"case_id": case["case_id"], "repository": case["repository"], "commit_sha": case["commit_sha"], "release_surfaces": case["release_surfaces"], "applicability": case["applicability"]}
    for field, expected in bindings.items():
        if receipt.get(field) != expected: _error("receipt_case_binding_mismatch", "/" + field, "receipt differs from immutable case authority")
    expected_dataset = {"external_validation.beta_case":"beta", "external_validation.controlled_pair_case":"controlled", "external_validation.natural_pr_case":"natural"}[case["schema_id"]]
    if receipt["dataset"] != expected_dataset: _error("receipt_case_binding_mismatch", "/dataset", "dataset differs from case")
    return receipt
