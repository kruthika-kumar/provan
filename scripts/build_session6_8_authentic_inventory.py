"""Build the frozen 106-row authentic Sessions 6--8 requirement inventory."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shiproom.session6_8_requirement_catalogue import BEHAVIORS
from shiproom.session6_8_semantics import REQUIREMENT_FIELDS, requirement_semantic_hash


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "validation" / "session6-8-requirement-inventory.json"


GROUPS = {
    "6": [key for key in BEHAVIORS if key.startswith("S6_")],
    "7": [key for key in BEHAVIORS if key.startswith("S7_")],
    "8_contestability": [key for key in BEHAVIORS if key.startswith("S8_")][:17],
    "8_management": [key for key in BEHAVIORS if key.startswith("S8_")][17:],
    "shared": [key for key in BEHAVIORS if key.startswith("SHARED_")],
}
EXPECTED = {"6": 22, "7": 30, "8_contestability": 17, "8_management": 22, "shared": 15}


def _sha(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _metadata(requirement_id: str, group: str) -> tuple[list[str], str, str]:
    if group == "6":
        entrypoint = "shiproom.remediation_roadmaps.closure_verify" if "CLOSURE" in requirement_id else "shiproom.remediation_roadmaps.compile"
        if requirement_id == "S6_REMEDIATION_CARDINALITY":
            return ["remediation-plan.json", "remediation-overlay.json", "closure-contracts/"], "real three-issue generation with exact one-to-one records", entrypoint
        if "CLOSURE" in requirement_id:
            return ["closure-verification.json", "closure-evidence.json", "closure-contract.json"], "real closure inbox produces a bounded non-satisfied status", entrypoint
        if requirement_id in {"S6_PACKET_CONTRACT_LINKS", "S6_PACKET_FILE_INTEGRITY", "S6_CLOSURE_CONTRACT_COMPLETENESS"}:
            return ["remediation-plan.json", "remediation-overlay.json", "generation-manifest.json", "closure-contracts/"], "valid minimal packet remains source-definition scoped", entrypoint
        return ["remediation-plan.json", "generation-manifest.json"], "real compiler-only packet preserves an explicit limitation", entrypoint
    if group == "7":
        if "ADAPTATION" in requirement_id or requirement_id in {"S7_SUPERSEDED_WORK_ORDER_PRESERVATION", "S7_POINTER_LAST_PUBLICATION"}:
            return ["review-plan.json", "plan-events.json", "execution-summary.json", "generation-manifest.json"], "real accepted evidence yields a bounded successor or precise unavailability", "shiproom.review_organisation.adapt"
        if requirement_id in {"S7_REVISION_REQUEST", "S7_CORRECTED_RESULT_ACCEPTANCE", "S7_SECOND_INVALID_FAILURE", "S7_FAILED_RESULT_NO_ADAPTATION", "S7_SUBMISSION_BYTE_PERSISTENCE"}:
            return ["revision-ledger.json", "submission-attempts/", "accepted-results.json", "generation-manifest.json"], "first invalid native submission remains revision_required and unaccepted", "shiproom.review_organisation.submit_result"
        if requirement_id in {"S7_CODEX_PACKAGE_COMPLETENESS", "S7_MANUAL_CODEX_PARITY", "S7_HARNESS_DECLARATION_HONESTY"}:
            return ["codex-execution-package.json", "accepted-results.json"], "valid manual transport remains explicitly limited by declared independence", "shiproom.review_organisation.render_package"
        return ["review-plan.json", "specialist-work-orders/", "generation-manifest.json"], "candidate or unavailable native surface remains explicitly bounded", "shiproom.review_organisation.prepare"
    if group == "8_contestability":
        if "OWNER_DECISION" in requirement_id or "NAMED_RISK" in requirement_id:
            return ["contestation-ledger.json", "contestation-effects.json"], "two or fewer eligible decisions produce an empty overflow without changing facts", "shiproom.contestability.append_action"
        return ["contestation-ledger.json", "contestation-effects.json", "generation-manifest.json"], "a valid non-owner action records agreement or a request without changing its target", "shiproom.contestability.append_action"
    if group == "8_management":
        if requirement_id == "S8_MEASUREMENT_AI_PASSTHROUGH":
            return ["measurement-ai-readiness.json", "release-packet-index.json", "measurement-ai-readiness.html"], "not_used Measurement/AI emits only its registered typed empty section", "shiproom.management_artifacts.compile"
        if requirement_id in {"S8_SAFE_HTML", "S8_SAFE_MARKDOWN"}:
            return ["executive-release-brief.json", "executive-release-brief.html", "github-summary.md"], "escaped hostile text remains inert presentation content", "shiproom.management_artifacts.compile"
        return ["release-packet-index.json", "generation-manifest.json", "github-summary-payload.json"], "an unconsumed optional dependency emits only its registered typed empty state", "shiproom.management_artifacts.compile"
    shared = {
        "SHARED_CONTRACT_INVENTORY": ["session6-8-contract-inventory.json", "session6-8-contract-registry.json"],
        "SHARED_EXECUTED_CONTRACT_PARITY": ["session6-8-contract-parity-report.json", "parity-fixtures/"],
        "SHARED_BEHAVIORAL_EVAL_INTEGRITY": ["behavioral-eval-receipt.json"],
        "SHARED_WORKFLOW_EVAL_INTEGRITY": ["session6-8-workflow-eval-receipt.json", "workflow-artifacts/"],
        "SHARED_INSTALLED_WHEEL_LIFECYCLE": ["session6-8-installed-wheel-receipt.json", "wheel-logs/", "wheel/"],
        "SHARED_ZERO_PROHIBITED_OPERATIONS": ["session6-8-security-receipt.json", "security-evidence/"],
        "SHARED_PROOF_EXECUTION": ["session6-8-proof-execution-receipt.json", "proof-artifacts/"],
        "SHARED_CLOSEOUT_GENERATION": ["session6-8-final-closeout-report.json", "session6-8-final-closeout-receipt.json"],
        "SHARED_INDEPENDENT_VALIDATION": ["session6-8-evidence-bundle-manifest.json", "copied-bundle-validation.json"],
    }
    artifacts = shared.get(requirement_id, ["trusted-storage-receipt.json", "state-before.json", "state-after.json"])
    entrypoint = {
        "SHARED_INSTALLED_WHEEL_LIFECYCLE": "scripts.validate_session6_8_wheel_receipt.validate",
        "SHARED_EXECUTED_CONTRACT_PARITY": "scripts.validate_session6_8_contract_parity.validate",
        "SHARED_ZERO_PROHIBITED_OPERATIONS": "scripts.validate_session6_8_security_receipt.validate",
        "SHARED_INDEPENDENT_VALIDATION": "scripts.validate_session6_8_closeout_independently.validate_bundle",
    }.get(requirement_id, "scripts.validate_session6_8_closeout_independently.validate_bundle")
    return artifacts, "the real boundary records a constrained accepted state without claiming full closure", entrypoint


def _forbidden(requirement_id: str) -> list[str]:
    values = [
        "registry_or_requirement_row_presence_as_proof",
        "synthetic_measurement_or_configured_expected_value_as_actual",
        "runner_pass_flag_or_truthiness_wrapper_as_evidence",
    ]
    if any(token in requirement_id for token in ("AUTHORITY", "EVIDENCE", "PASSTHROUGH")):
        values.append("weaker_unlinked_or_recomputed_authority_substitution")
    if any(token in requirement_id for token in ("CARDINALITY", "COMPLETENESS", "INDEX", "OVERFLOW", "BUDGET")):
        values.append("key_presence_empty_collection_or_configured_minimum_as_count")
    if "ADAPTATION" in requirement_id or "POINTER_LAST" in requirement_id:
        values.append("event_only_successor_or_recorded_status_without_material_plan_delta")
    if "PARITY" in requirement_id:
        values.append("recorded_rejection_without_valid_baseline_and_real_boundary_replay")
    return values


def main() -> int:
    if {key: len(value) for key, value in GROUPS.items()} != EXPECTED:
        raise SystemExit("session6_8_requirement_distribution_invalid")
    rows = []
    for group, identifiers in GROUPS.items():
        for requirement_id in identifiers:
            artifacts, near_valid, entrypoint = _metadata(requirement_id, group)
            minimums = {artifact: 1 for artifact in artifacts}
            if requirement_id == "S6_REMEDIATION_CARDINALITY":
                minimums = {artifact: 3 for artifact in artifacts}
            row = {
                "requirement_id": requirement_id,
                "session": group,
                "source_section": "approved Sessions 6-8 Authentic Evidence Closeout",
                "source_requirement": requirement_id,
                "source_text_hash": _sha(BEHAVIORS[requirement_id]),
                "normative_behavior": BEHAVIORS[requirement_id],
                "forbidden_substitutions": _forbidden(requirement_id),
                "required_artifacts": artifacts,
                "minimum_cardinalities": minimums,
                "near_valid_behavior": near_valid,
                "adversarial_behavior": "Mutate only the owning input or canonical artifact for " + requirement_id + " and require the owning production validator or loader to reject while preserving authoritative state.",
                "adversarial_error_code": requirement_id.lower() + "_rejected",
                "owning_production_entrypoint": entrypoint,
                "status": "pending_authentic_execution",
            }
            row["approved_semantic_hash"] = requirement_semantic_hash(row)
            rows.append(row)
    if len(rows) != 106 or any(set(REQUIREMENT_FIELDS) - set(row) for row in rows):
        raise SystemExit("session6_8_requirement_inventory_invalid")
    TARGET.write_text(
        json.dumps({"schema_version": "session6-8-requirement-inventory.v3", "expected_requirement_count": 106, "requirements": rows}, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"requirements": len(rows), "status": "pending_authentic_execution"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
