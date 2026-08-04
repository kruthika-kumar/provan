"""Fail-closed validation for the proof-only Session 2 partial closeout."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .identity import canonical_json


_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
CLASSIFICATIONS = {
    "PUBLIC_SAFE_CONTROL_PLANE", "PUBLIC_SAFE_EXAMPLE", "PRIVATE_EVAL_CASE",
    "PRIVATE_INCIDENT_REGRESSION", "HISTORICAL_ONLY", "INCOMPLETE_NOT_FOR_CLAIMS",
}
PROOF_ROOT = Path("external_validation/proofs/session2")
HANDOFF_PATH = Path("external_validation/handoffs/session9/session2_asset_handoff.v1.json")
REVIEW_PATH = Path("external_validation/reviews/session2_closeout_review.v1.json")
BASELINE_PATH = PROOF_ROOT / "session2_validation_baseline.v1.json"
TRANSITION_PATH = Path("external_validation/status/session2-blueprint-transition.md")
FORBIDDEN_PUBLIC_FRAGMENTS = ("/var/lib/", "/mnt/shiproom", "C:\\Users\\", "recovery-hold/")
QUEUE_LOGICAL_HASH = "sha256:cab9988899cae8b15e55e831411901f56a0f76038f66dfbbae9a1a1078deb5d6"
QUEUE_DATABASE_SHA256 = "sha256:1fab536ba42ce244919443d6d3d4ef477dcf929caf9dd27aa86dcff0b0f0de15"
ALLOCATOR_LOGICAL_HASH = "sha256:abb0d3a4cfedc5609d0d9af5916d46e6f9aa6b6977628b0e9e483403d3bccb74"
BUDGET_LOGICAL_HASH = "sha256:087522bfed555e52daab94bd0b32512d1eafeaaff76aa3c7b894d489aab240ae"
EXPECTED_STATE_SOURCE_HASHES = {
    "projects_registry": "sha256:d3cfce00b99962fcc3281a562b60d1663d7d4a54e5dddeb1a00e6512fb54a914",
    "backend_state": "sha256:d015033b8a570b88e93cd909dc104991a5ac86e8b9de3c9b296d8bdc17773700",
    "capacity_record": "sha256:a592f907c3f1139436208df7dd8a31daa3003dd0ebdd8d4d265071e3f868841f",
    "recovery_incident": "sha256:555979060f1d9f4aadcbb62803d10e82a5de8c12a88aeb16995853d83c02f18e",
    "quarantine_receipt": "sha256:6c63be82482b95c5c4607bd2aa156aa61731114dedfd2fd43385dd959f4aad4d",
    "full_tree_manifest": "sha256:1334392541a3fa42abd0404cc36d40c2f88da247ebc9c175fa59e3b38201e5ed",
}
REVIEWED_ARTIFACT_PATHS = {
    "external_validation/handoffs/session9/session2_asset_handoff.v1.json",
    "external_validation/proofs/session2/session2_claim_audit.v1.json",
    "external_validation/proofs/session2/session2_closeout_state_inspection.v1.json",
    "external_validation/proofs/session2/session2_leakage_validation.v1.json",
    "external_validation/proofs/session2/session2_partial_closeout.md",
    "external_validation/proofs/session2/session2_partial_closeout.v1.json",
    "external_validation/status/session2-blueprint-transition.md",
    "scripts/validate_session2_closeout.py",
    "shiproom/external_validation/schemas/schema-registry.v1.json",
    "shiproom/external_validation/schemas/session2-partial-closeout.v1.json",
    "shiproom/external_validation/session2_closeout.py",
    "tests/test_session2_closeout.py",
}
REQUIRED_MANIFEST_PATHS = REVIEWED_ARTIFACT_PATHS | {
    "external_validation/proofs/session2/session2_validation_baseline.v1.json",
    "external_validation/reviews/session2_closeout_review.v1.json",
}
REQUIRED_VALIDATIONS = {
    "focused_session2_closeout_tests", "public_leakage_validation", "private_inventory_validation",
    "run_evals", "run_workflow_integration_evals", "full_pytest", "git_diff_check",
}


class Session2CloseoutError(ValueError):
    pass


def _fail(code: str) -> None:
    raise Session2CloseoutError(code)


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _exact(value: Any, expected: Any, code: str) -> None:
    if value != expected:
        _fail(code)


def _ref(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"authority", "sha256"} or not isinstance(value["authority"], str) or not value["authority"]:
        _fail("session2_closeout_evidence_ref_invalid")
    _sha(value["sha256"], "session2_closeout_evidence_ref_invalid")


def _asset(value: Any) -> None:
    required = {"asset_id", "classification", "claim_authorized", "evidence_refs", "limitations"}
    if not isinstance(value, dict) or set(value) != required or not isinstance(value["asset_id"], str) or not value["asset_id"]:
        _fail("session2_closeout_asset_invalid")
    if value["classification"] not in CLASSIFICATIONS or not isinstance(value["claim_authorized"], bool):
        _fail("session2_closeout_asset_invalid")
    if not isinstance(value["evidence_refs"], list) or not isinstance(value["limitations"], list) or not all(isinstance(x, str) and x for x in value["limitations"]):
        _fail("session2_closeout_asset_invalid")
    for item in value["evidence_refs"]:
        _ref(item)
    if value["classification"] == "INCOMPLETE_NOT_FOR_CLAIMS" and value["claim_authorized"]:
        _fail("session2_closeout_incomplete_claim_authorized")
    if value["classification"] == "PUBLIC_SAFE_EXAMPLE" and (not value["claim_authorized"] or not value["evidence_refs"]):
        _fail("session2_closeout_public_example_unsupported")
    if value["claim_authorized"] and (not value["evidence_refs"] or not value["limitations"]):
        _fail("session2_closeout_claim_evidence_missing")


def validate_partial_closeout(value: Any) -> dict[str, Any]:
    required = {
        "schema_id", "schema_version", "status", "closure_reason", "methodology_completed",
        "headline_comparative_study_completed", "headline_comparative_claims_authorized",
        "session1_authority_retained", "session1_runtime_unchanged", "implementation_commit",
        "implementation_tree", "model_usage", "portfolio", "active_claim", "execution_counts",
        "allocator_state", "runtime_disposition", "authority_sources", "validated_assets",
        "incomplete_assets", "not_tested_claims", "public_claim_limitations", "private_eval_candidates",
    }
    if not isinstance(value, dict) or set(value) != required:
        _fail("session2_closeout_shape_invalid")
    nested_shapes = {
        "model_usage": {"terra_content_free_probe_count", "evaluated_model_call_count", "openai_spend_usd", "budget_logical_hash"},
        "active_claim": {"claim_id", "candidate", "queue_state", "programme_closeout_disposition", "candidate_outcome", "qualified", "excluded", "terminal_candidate_receipt_present", "queue_logical_hash"},
        "allocator_state": {"real_recovery_successor_created", "real_recovery_allocation_created", "real_recovery_quota_project_created", "real_recovery_worktree_created", "historical_project_count", "terminal_historical_project_count", "allocator_logical_hash"},
    }
    if any(not isinstance(value[name], dict) or set(value[name]) != fields for name, fields in nested_shapes.items()):
        _fail("session2_closeout_schema_invalid")
    fixed = {
        "schema_id": "external_validation.session2_partial_closeout.v1", "schema_version": "1",
        "status": "CLOSED_PARTIAL", "closure_reason": "SUPERSEDED_BY_COMMUNITY_FIRST_PRODUCT_BLUEPRINT",
        "methodology_completed": False, "headline_comparative_study_completed": False,
        "headline_comparative_claims_authorized": False, "session1_authority_retained": True,
        "session1_runtime_unchanged": True,
    }
    for key, expected in fixed.items():
        _exact(value[key], expected, "session2_closeout_status_invalid")
    if not all(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{40}", value[key]) for key in ("implementation_commit", "implementation_tree")):
        _fail("session2_closeout_git_identity_invalid")
    _exact(value["model_usage"].get("terra_content_free_probe_count"), 3, "session2_closeout_model_usage_invalid")
    _exact(value["model_usage"].get("evaluated_model_call_count"), 0, "session2_closeout_model_usage_invalid")
    _exact(value["model_usage"].get("openai_spend_usd"), 2.0, "session2_closeout_model_usage_invalid")
    _sha(value["model_usage"].get("budget_logical_hash"), "session2_closeout_model_usage_invalid")
    _exact(value["model_usage"]["budget_logical_hash"], BUDGET_LOGICAL_HASH, "session2_closeout_budget_authority_changed")
    expected_portfolio = {
        "fresh_a_candidates_attempted": 134, "fresh_a_candidates_qualified": 0,
        "fresh_b_fallback_invoked": True, "fresh_b_candidates_attempted": 9, "fresh_b_candidates_qualified": 0,
        "controlled_pair_target": 18, "controlled_pairs_completed": 0, "harness_pair_target": 2,
        "harness_pairs_completed": 0, "natural_pr_target": 15, "natural_prs_completed": 0,
    }
    _exact(value["portfolio"], expected_portfolio, "session2_closeout_portfolio_invalid")
    claim = value["active_claim"]
    expected_claim = {
        "claim_id": "fresh_b_claim_0fc88cf308df34ba7e6e565f",
        "candidate": "inventree/InvenTree#10947->inventree/InvenTree#12472", "queue_state": "IN_PROGRESS",
        "programme_closeout_disposition": "UNEXECUTED_AT_STRATEGIC_TERMINATION", "candidate_outcome": None,
        "qualified": False, "excluded": False, "terminal_candidate_receipt_present": False,
    }
    if not isinstance(claim, dict) or {k: claim.get(k) for k in expected_claim} != expected_claim:
        _fail("session2_closeout_active_claim_invalid")
    _sha(claim.get("queue_logical_hash"), "session2_closeout_active_claim_invalid")
    _exact(claim["queue_logical_hash"], QUEUE_LOGICAL_HASH, "session2_closeout_queue_authority_changed")
    zero_counts = {key: 0 for key in (
        "patient_execution_count", "target_execution_count", "protected_check_execution_count",
        "shiproom_execution_count", "comparator_execution_count", "evaluated_model_execution_count",
    )}
    _exact(value["execution_counts"], zero_counts, "session2_closeout_evaluated_work_present")
    allocator = value["allocator_state"]
    if not isinstance(allocator, dict) or any(allocator.get(key) is not False for key in (
        "real_recovery_successor_created", "real_recovery_allocation_created",
        "real_recovery_quota_project_created", "real_recovery_worktree_created",
    )) or allocator.get("historical_project_count") != 23 or allocator.get("terminal_historical_project_count") != 23:
        _fail("session2_closeout_recovery_allocation_present")
    _sha(allocator.get("allocator_logical_hash"), "session2_closeout_allocator_invalid")
    _exact(allocator["allocator_logical_hash"], ALLOCATOR_LOGICAL_HASH, "session2_closeout_allocator_authority_changed")
    runtime = value["runtime_disposition"]
    expected_runtime = {"runtime_left_running": True, "default_docker_untouched": True, "custom_daemon_healthy": True,
                        "default_socket_absent": True, "filesystem": "xfs", "quota_mode": "prjquota",
                        "data_project_id": 10000, "data_bytes": 8589934592, "data_inodes": 200000}
    _exact(runtime, expected_runtime, "session2_closeout_runtime_disposition_invalid")
    for item in value["authority_sources"]:
        _ref(item)
    for group in ("validated_assets", "incomplete_assets", "private_eval_candidates"):
        if not isinstance(value[group], list):
            _fail("session2_closeout_asset_invalid")
        for item in value[group]:
            _asset(item)
    if not value["validated_assets"] or not value["incomplete_assets"]:
        _fail("session2_closeout_asset_invalid")
    for group in ("not_tested_claims", "public_claim_limitations"):
        if not isinstance(value[group], list) or not value[group] or not all(isinstance(x, str) and x for x in value[group]):
            _fail("session2_closeout_limitations_invalid")
    public_text = json.dumps(value["public_claim_limitations"], sort_keys=True)
    if any(fragment in public_text for fragment in FORBIDDEN_PUBLIC_FRAGMENTS):
        _fail("session2_closeout_private_path_leak")
    return value


def validate_claim_audit(value: Any, closeout: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_id": "external_validation.session2_claim_audit.v1", "schema_version": "1",
        "claim_id": closeout["active_claim"]["claim_id"], "candidate": closeout["active_claim"]["candidate"],
        "queue_state": "IN_PROGRESS", "queue_record_mutated_for_closeout": False,
        "programme_closeout_disposition": "UNEXECUTED_AT_STRATEGIC_TERMINATION", "candidate_outcome": None,
        "qualified": False, "excluded": False, "terminal_candidate_receipt_present": False,
        "further_queue_actions_authorized": False, "queue_logical_hash": closeout["active_claim"]["queue_logical_hash"],
    }
    _exact(value, expected, "session2_closeout_claim_audit_invalid")
    return value


def validate_state_inspection(value: Any, closeout: dict[str, Any]) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "inspected_at", "queue_database_sha256", "queue_logical_hash", "queue_counts",
                "budget_logical_hash", "allocator_logical_hash", "historical_project_count", "terminal_historical_project_count",
                "recovery_successor_count", "recovery_allocation_count", "recovery_quota_project_count", "recovery_worktree_count",
                "runtime", "source_hashes"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema_id") != "external_validation.session2_closeout_state_inspection.v1" or value.get("schema_version") != "1"
            or not isinstance(value.get("inspected_at"), str) or not value["inspected_at"]):
        _fail("session2_closeout_state_inspection_invalid")
    expected = {"recovery_successor_count": 0, "recovery_allocation_count": 0, "recovery_quota_project_count": 0,
                "recovery_worktree_count": 0, "historical_project_count": 23, "terminal_historical_project_count": 23}
    if {key: value.get(key) for key in expected} != expected:
        _fail("session2_closeout_recovery_allocation_present")
    if value.get("queue_logical_hash") != closeout["active_claim"]["queue_logical_hash"] or value.get("allocator_logical_hash") != closeout["allocator_state"]["allocator_logical_hash"]:
        _fail("session2_closeout_state_hash_mismatch")
    if value.get("queue_database_sha256") != QUEUE_DATABASE_SHA256 or value.get("queue_logical_hash") != QUEUE_LOGICAL_HASH:
        _fail("session2_closeout_queue_authority_changed")
    if value.get("budget_logical_hash") != BUDGET_LOGICAL_HASH or value.get("allocator_logical_hash") != ALLOCATOR_LOGICAL_HASH:
        _fail("session2_closeout_state_hash_mismatch")
    if value.get("queue_counts") != {"EXCLUDED": 8, "IN_PROGRESS": 1, "PENDING": 23}:
        _fail("session2_closeout_queue_counts_changed")
    if value.get("runtime") != closeout["runtime_disposition"] or not isinstance(value.get("source_hashes"), list):
        _fail("session2_closeout_state_inspection_invalid")
    for item in value["source_hashes"]:
        _ref(item)
    if {item["authority"]: item["sha256"] for item in value["source_hashes"]} != EXPECTED_STATE_SOURCE_HASHES:
        _fail("session2_closeout_state_source_changed")
    return value


def validate_handoff(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_id", "schema_version", "session2_status", "headline_claims_authorized", "assets", "handoff_limitations"}:
        _fail("session2_handoff_shape_invalid")
    if value["schema_id"] != "external_validation.session9_handoff_manifest.v1" or value["schema_version"] != "1" or value["session2_status"] != "CLOSED_PARTIAL" or value["headline_claims_authorized"] is not False:
        _fail("session2_handoff_status_invalid")
    if not isinstance(value["assets"], list) or not value["assets"]:
        _fail("session2_handoff_assets_invalid")
    for item in value["assets"]:
        _asset(item)
    if any(item["classification"] == "PUBLIC_SAFE_EXAMPLE" for item in value["assets"]):
        _fail("session2_closeout_public_example_unsupported")
    if not isinstance(value["handoff_limitations"], list) or not value["handoff_limitations"]:
        _fail("session2_handoff_limitations_invalid")
    return value


def validate_leakage(value: Any) -> dict[str, Any]:
    expected = {
        "schema_id": "external_validation.session2_leakage_validation.v1", "schema_version": "1", "verdict": "PASS",
        "forbidden_path_match_count": 0, "private_eval_payload_exported": False, "private_material_leaked": False,
        "public_example_authorized": False,
        "reviewed_public_surfaces": ["external_validation/proofs/session2/session2_partial_closeout.md",
                                     "external_validation/status/session2-blueprint-transition.md"],
        "limitations": ["This validates the closeout public surfaces only; private regression artifacts remain outside the public projection."],
    }
    _exact(value, expected, "session2_closeout_leakage_invalid")
    return value


def _artifact_rows(repository_root: Path, paths: set[str]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _hash((repository_root / path).read_bytes())} for path in sorted(paths)]


def validate_review(value: Any, repository_root: Path, closeout: dict[str, Any]) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "review_verdict", "open_p0_count", "open_p1_count", "findings",
                "reviewed_commit", "reviewed_tree", "reviewed_proof_set_root", "reviewer_mode",
                "no_outcome_invented", "no_comparative_claim_invented", "qualification_evaluation_separated",
                "queue_authority_bound"}
    if not isinstance(value, dict) or set(value) != required:
        _fail("session2_closeout_review_invalid")
    expected_root = _hash(canonical_json(_artifact_rows(repository_root, REVIEWED_ARTIFACT_PATHS)))
    expected = {
        "schema_id": "external_validation.session2_closeout_review.v1", "schema_version": "1",
        "review_verdict": "GO", "open_p0_count": 0, "open_p1_count": 0, "findings": [],
        "reviewed_commit": closeout["implementation_commit"], "reviewed_tree": closeout["implementation_tree"],
        "reviewed_proof_set_root": expected_root, "reviewer_mode": "FRESH_READ_ONLY",
        "no_outcome_invented": True, "no_comparative_claim_invented": True,
        "qualification_evaluation_separated": True, "queue_authority_bound": True,
    }
    _exact(value, expected, "session2_closeout_review_invalid")
    return value


def validate_baseline(value: Any, closeout: dict[str, Any]) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "generated_at",
                "all_required_commands_passed", "authoritative_counts_reconfirmed", "queue_database_sha256",
                "queue_logical_hash", "commands"}
    if not isinstance(value, dict) or set(value) != required:
        _fail("session2_closeout_baseline_invalid")
    if (value["schema_id"] != "external_validation.session2_validation_baseline.v1" or value["schema_version"] != "1"
            or value["implementation_commit"] != closeout["implementation_commit"] or value["implementation_tree"] != closeout["implementation_tree"]
            or value["all_required_commands_passed"] is not True or value["authoritative_counts_reconfirmed"] is not True
            or value["queue_database_sha256"] != QUEUE_DATABASE_SHA256 or value["queue_logical_hash"] != QUEUE_LOGICAL_HASH
            or not isinstance(value["generated_at"], str) or not value["generated_at"]):
        _fail("session2_closeout_baseline_invalid")
    commands = value["commands"]
    if not isinstance(commands, list) or {item.get("validation_id") for item in commands if isinstance(item, dict)} != REQUIRED_VALIDATIONS:
        _fail("session2_closeout_baseline_invalid")
    for item in commands:
        if (not isinstance(item, dict) or set(item) != {"validation_id", "command", "started_at", "finished_at", "exit_code", "transcript_sha256", "result_count"}
                or not all(isinstance(item[key], str) and item[key] for key in ("validation_id", "command", "started_at", "finished_at"))
                or item["exit_code"] != 0 or not isinstance(item["result_count"], int) or item["result_count"] < 0):
            _fail("session2_closeout_baseline_invalid")
        _sha(item["transcript_sha256"], "session2_closeout_baseline_invalid")
    return value


def load_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Session2CloseoutError("session2_closeout_json_invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail("session2_closeout_json_noncanonical")
    return value, raw


def validate_manifest(value: Any, repository_root: Path, closeout: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_id", "schema_version", "implementation_commit", "implementation_tree", "status", "proof_set_root", "artifacts"}:
        _fail("session2_closeout_manifest_invalid")
    if value["schema_id"] != "external_validation.session2_closeout_manifest.v1" or value["schema_version"] != "1" or value["status"] != "CLOSED_PARTIAL":
        _fail("session2_closeout_manifest_invalid")
    if value["implementation_commit"] != closeout["implementation_commit"] or value["implementation_tree"] != closeout["implementation_tree"]:
        _fail("session2_closeout_manifest_identity_invalid")
    if not isinstance(value["artifacts"], list) or not value["artifacts"]:
        _fail("session2_closeout_manifest_invalid")
    seen: set[str] = set()
    rows = []
    for item in value["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} or item["path"] in seen or Path(item["path"]).is_absolute() or ".." in Path(item["path"]).parts:
            _fail("session2_closeout_manifest_invalid")
        target = repository_root / item["path"]
        if not target.is_file() or _hash(target.read_bytes()) != _sha(item["sha256"], "session2_closeout_manifest_hash_invalid"):
            _fail("session2_closeout_manifest_hash_invalid")
        seen.add(item["path"]); rows.append(item)
    if rows != sorted(rows, key=lambda row: row["path"]):
        _fail("session2_closeout_manifest_order_invalid")
    if seen != REQUIRED_MANIFEST_PATHS:
        _fail("session2_closeout_manifest_inventory_invalid")
    if value["proof_set_root"] != _hash(canonical_json(rows)):
        _fail("session2_closeout_manifest_root_invalid")
    return value


def validate_repository_bundle(repository_root: Path) -> dict[str, Any]:
    closeout, _ = load_canonical(repository_root / PROOF_ROOT / "session2_partial_closeout.v1.json")
    validate_partial_closeout(closeout)
    claim, _ = load_canonical(repository_root / PROOF_ROOT / "session2_claim_audit.v1.json")
    validate_claim_audit(claim, closeout)
    state, _ = load_canonical(repository_root / PROOF_ROOT / "session2_closeout_state_inspection.v1.json")
    validate_state_inspection(state, closeout)
    handoff, _ = load_canonical(repository_root / HANDOFF_PATH)
    validate_handoff(handoff)
    leakage, _ = load_canonical(repository_root / PROOF_ROOT / "session2_leakage_validation.v1.json")
    validate_leakage(leakage)
    review, _ = load_canonical(repository_root / REVIEW_PATH)
    validate_review(review, repository_root, closeout)
    baseline, _ = load_canonical(repository_root / BASELINE_PATH)
    validate_baseline(baseline, closeout)
    manifest, _ = load_canonical(repository_root / PROOF_ROOT / "session2_closeout_manifest.v1.json")
    validate_manifest(manifest, repository_root, closeout)
    return {"status": "CLOSED_PARTIAL", "proof_set_root": manifest["proof_set_root"], "artifact_count": len(manifest["artifacts"])}
