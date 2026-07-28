"""Typed Session 2 freeze and trusted-attestation authority."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from .identity import canonical_json
from .trusted_attestation import TRUSTED_ROOT, TrustedAttestationError, load_trusted_attestation


SESSION2_TRUSTED_ROOT = TRUSTED_ROOT.parent / "session2"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT = re.compile(r"^[0-9a-f]{40}$")
FREEZE_ATTESTATION_FIELDS = {
    "schema_id", "schema_version", "implementation_commit", "implementation_tree", "freeze_commit", "freeze_tree",
    "public_freeze_manifest_path", "public_freeze_manifest_hash", "private_inventory_root_hash", "budget_policy_hash", "budget_ledger_genesis_hash", "seed_artifact_hash", "model_prompt_policy_manifest_hash", "price_table_hash", "container_freeze_manifest_hash", "candidate_frame_index_hash", "claim_audit_hash", "leakage_validation_hash", "review_gate_1_hash", "review_gate_2_hash", "review_gate_3_hash", "baseline_record_hash", "clean_replay_receipt_hash", "model_probe_count", "evaluated_model_call_count", "shiproom_evaluated_output_count", "comparator_evaluated_output_count", "remediation_comparison_executed", "session3_work_performed",
}
NO_EVALUATED_OUTPUT_FIELDS = {"evaluated_model_call_count", "shiproom_evaluated_output_count", "comparator_evaluated_output_count"}
SESSION2_UNTESTED_CLAIMS = {"shiproom_target_recall", "terra_target_recall", "relative_model_performance", "cost_advantage", "fixed_twin_persistence_during_evaluated_runs", "remediation_success", "natural_defect_prevalence", "matched_budget_performance", "release_decision_quality"}


class Session2FreezeError(ValueError):
    pass


def _fail(code: str) -> None:
    raise Session2FreezeError(code)


def canonical_hash(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value)).hexdigest()


def _sha(value: Any, code: str) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None or value[7:] == "0" * 64 or len(set(value[7:])) == 1:
        _fail(code)


def _git(value: Any, code: str) -> None:
    if not isinstance(value, str) or _GIT.fullmatch(value) is None or value == "0" * 40 or len(set(value)) == 1:
        _fail(code)


def validate_claim_audit(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "claims"}
    allowed = {"ESTABLISHED", "PROVISIONALLY_SUPPORTED", "NOT_YET_TESTED", "FAILED", "OUT_OF_SCOPE"}
    row_fields = {"claim_id", "status", "implementation_refs", "positive_proof_refs", "negative_proof_refs", "artifact_refs", "replay_refs"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_claim_audit.v1" or value.get("schema_version") != "1" or not isinstance(value.get("claims"), list):
        _fail("session2_claim_audit_invalid")
    seen: set[str] = set()
    for row in value["claims"]:
        if not isinstance(row, dict) or set(row) != row_fields or not isinstance(row.get("claim_id"), str) or not row["claim_id"] or row["claim_id"] in seen or row.get("status") not in allowed:
            _fail("session2_claim_audit_invalid")
        if row["claim_id"] in SESSION2_UNTESTED_CLAIMS and row["status"] != "NOT_YET_TESTED":
            _fail("session2_claim_audit_overstatement")
        for field in row_fields - {"claim_id", "status"}:
            if not isinstance(row[field], list) or not row[field] or any(not isinstance(item, str) or not item for item in row[field]):
                _fail("session2_claim_audit_invalid")
        seen.add(row["claim_id"])
    if not SESSION2_UNTESTED_CLAIMS.issubset(seen):
        _fail("session2_claim_audit_missing_required_claim")
    return value


def validate_freeze_manifest(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "public_seed", "model_prompt_policy_manifest_hash", "budget_policy_hash", "budget_ledger_genesis_hash", "controlled_pair_count", "harness_pair_count", "unique_pair_count", "natural_pr_count", "beta_executed", "controlled_executed", "natural_executed", "prohibited_work", "artifacts"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_freeze_manifest.v1" or value.get("schema_version") != "1":
        _fail("session2_freeze_manifest_invalid")
    _git(value["implementation_commit"], "session2_freeze_manifest_invalid"); _git(value["implementation_tree"], "session2_freeze_manifest_invalid")
    if not isinstance(value["public_seed"], str) or re.fullmatch(r"[0-9a-f]{64}", value["public_seed"]) is None:
        _fail("session2_freeze_manifest_seed_invalid")
    for key in ("model_prompt_policy_manifest_hash", "budget_policy_hash", "budget_ledger_genesis_hash"):
        _sha(value[key], "session2_freeze_manifest_hash_invalid")
    if {key: value[key] for key in ("controlled_pair_count", "harness_pair_count", "unique_pair_count", "natural_pr_count")} != {"controlled_pair_count": 18, "harness_pair_count": 2, "unique_pair_count": 20, "natural_pr_count": 15}:
        _fail("session2_freeze_manifest_counts_invalid")
    if any(value[key] is not False for key in ("beta_executed", "controlled_executed", "natural_executed")):
        _fail("session2_freeze_manifest_execution_invalid")
    if not isinstance(value["prohibited_work"], dict) or any(item is not False for item in value["prohibited_work"].values()):
        _fail("session2_freeze_manifest_prohibited_work_invalid")
    if not isinstance(value["artifacts"], dict) or not value["artifacts"]:
        _fail("session2_freeze_manifest_artifacts_invalid")
    for name, ref in value["artifacts"].items():
        if not isinstance(name, str) or not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not isinstance(ref["path"], str) or not ref["path"] or ref["path"].startswith("/") or ".." in Path(ref["path"]).parts:
            _fail("session2_freeze_manifest_artifacts_invalid")
        _sha(ref["sha256"], "session2_freeze_manifest_artifacts_invalid")
    return value


def validate_freeze_attestation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FREEZE_ATTESTATION_FIELDS or value.get("schema_id") != "external_validation.session2_freeze_attestation.v1" or value.get("schema_version") != "1":
        _fail("session2_freeze_attestation_invalid")
    for key in ("implementation_commit", "implementation_tree", "freeze_commit", "freeze_tree"):
        _git(value[key], "session2_freeze_attestation_invalid")
    if value["public_freeze_manifest_path"] != "external_validation/proofs/session2/session2_freeze_manifest.v1.json":
        _fail("session2_freeze_attestation_path_invalid")
    omitted = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "freeze_commit", "freeze_tree", "public_freeze_manifest_path", "model_probe_count", "evaluated_model_call_count", "shiproom_evaluated_output_count", "comparator_evaluated_output_count", "remediation_comparison_executed", "session3_work_performed"}
    for key in FREEZE_ATTESTATION_FIELDS - omitted:
        _sha(value[key], "session2_freeze_attestation_hash_invalid")
    if value["model_probe_count"] != 1 or any(value[key] != 0 for key in NO_EVALUATED_OUTPUT_FIELDS) or value["remediation_comparison_executed"] is not False or value["session3_work_performed"] is not False:
        _fail("session2_freeze_attestation_execution_invalid")
    return value


def load_trusted_session2_attestation(attestation_id: str) -> dict[str, Any]:
    try:
        result = load_trusted_attestation(attestation_id, trusted_root=SESSION2_TRUSTED_ROOT)
    except TrustedAttestationError as exc:
        _fail(str(exc))
    return validate_freeze_attestation(result.document)
