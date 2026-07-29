"""Deterministic Session 2 selection compiler.

It consumes retained primary retrieval records rather than accepting a hand
entered list of attractive cases.  Networking remains outside this module so
the receipt is the durable source authority and is independently replayable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from .session2 import CONTAMINATION_BANDS, Session2ValidationError, contamination_band, require_sha, seed_order, validate_fresh_qualification


class SelectionError(ValueError):
    pass


def _fail(code: str) -> None:
    raise SelectionError(code)


def _time(value: Any, code: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None: raise ValueError
        return result.astimezone(timezone.utc)
    except (AttributeError, ValueError):
        _fail(code)


def validate_retrieval_receipt(value: Any) -> dict[str, Any]:
    """Prove every candidate came from complete primary pagination."""
    required = {"schema_id", "schema_version", "source", "query", "filters", "retrieved_at", "parser_id", "pages", "candidate_ids"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_retrieval_receipt.v1" or value.get("schema_version") != "1":
        _fail("session2_retrieval_receipt_invalid")
    if not all(isinstance(value[key], str) and value[key] for key in ("source", "query", "parser_id")) or not isinstance(value["filters"], dict):
        _fail("session2_retrieval_receipt_invalid")
    _time(value["retrieved_at"], "session2_retrieval_receipt_invalid")
    pages = value["pages"]
    if not isinstance(pages, list) or not pages:
        _fail("session2_retrieval_pagination_missing")
    ids: list[str] = []
    for expected, page in enumerate(pages, 1):
        if not isinstance(page, dict) or set(page) != {"page", "raw_response_hash", "candidate_ids", "next_page"} or page["page"] != expected or not isinstance(page["candidate_ids"], list):
            _fail("session2_retrieval_pagination_invalid")
        try:
            require_sha(page["raw_response_hash"], "session2_retrieval_response_hash_invalid")
        except Session2ValidationError as exc:
            _fail(exc.code)
        ids.extend(page["candidate_ids"])
        if any(not isinstance(item, str) or not item for item in page["candidate_ids"]):
            _fail("session2_retrieval_pagination_invalid")
        if expected < len(pages) and page["next_page"] != expected + 1:
            _fail("session2_retrieval_pagination_gap")
        if expected == len(pages) and page["next_page"] is not None:
            _fail("session2_retrieval_pagination_gap")
    if len(ids) != len(set(ids)) or value["candidate_ids"] != ids:
        _fail("session2_retrieval_candidate_authority_invalid")
    return value


def validate_pr_classifier_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Validate all committed classifier registries before PR enumeration."""
    expected = {
        "source_file_registry": "external_validation.session2_source_file_registry.v1",
        "generated_path_registry": "external_validation.session2_generated_path_registry.v1",
        "vendor_path_registry": "external_validation.session2_vendor_path_registry.v1",
        "lockfile_registry": "external_validation.session2_lockfile_registry.v1",
        "snapshot_registry": "external_validation.session2_snapshot_registry.v1",
        "formatting_only_policy": "external_validation.session2_formatting_only_policy.v1",
        "component_mapping_policy": "external_validation.session2_component_mapping_policy.v1",
        "reviewable_churn_policy": "external_validation.session2_reviewable_churn_policy.v1",
    }
    if not isinstance(bundle, dict) or set(bundle) != set(expected):
        _fail("session2_pr_classifier_bundle_invalid")
    for key, schema_id in expected.items():
        row = bundle[key]
        if not isinstance(row, dict) or row.get("schema_id") != schema_id or row.get("schema_version") != "1":
            _fail("session2_pr_classifier_bundle_invalid")
    source = bundle["source_file_registry"]
    churn = bundle["reviewable_churn_policy"]
    if not isinstance(source.get("allowed_extensions"), list) or not source["allowed_extensions"] or source.get("test_file_treatment") != "included_for_churn_but_not_human_source_file_threshold" or churn.get("p95_method") != "nearest_rank_p95_over_basic_mechanical_exclusion_passing_prs" or churn.get("large_minimum") != 1000 or churn.get("large_p95_minimum") != 500:
        _fail("session2_pr_classifier_policy_invalid")
    return bundle


def select_fresh_pairs(seed: str, receipt: dict[str, Any], candidates: list[dict[str, Any]], *, reviewer_approved_fallbacks: set[str]) -> dict[str, Any]:
    """Select exactly six in the public source/time order with no repo >2."""
    validate_retrieval_receipt(receipt)
    candidate_ids = receipt["candidate_ids"]
    by_id: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("candidate_id"), str) or candidate["candidate_id"] in by_id:
            _fail("session2_candidate_frame_invalid")
        by_id[candidate["candidate_id"]] = candidate
    if set(by_id) != set(candidate_ids):
        _fail("session2_manual_candidate_rejected")
    ordered = sorted(candidate_ids, key=lambda identifier: (int(by_id[identifier].get("source_priority", 99)), _time(by_id[identifier].get("issue_created_at"), "session2_candidate_frame_invalid"), identifier))
    buckets = {band: [] for band in CONTAMINATION_BANDS}
    exclusions: list[dict[str, str]] = []
    per_repository: dict[str, int] = {}
    selected: list[dict[str, Any]] = []
    for band in ("FRESH_A", "FRESH_B", "FALLBACK_RECENT"):
        for identifier in ordered:
            candidate = by_id[identifier]
            try:
                record = validate_fresh_qualification({key: value for key, value in candidate.items() if key != "candidate_id" and key != "source_priority"})
            except Session2ValidationError as exc:
                exclusions.append({"candidate_id": identifier, "reason": exc.code}); continue
            if record["contamination_band"] != band:
                continue
            buckets[band].append(identifier)
            if len(selected) >= 6 or per_repository.get(record["repository"], 0) >= 2:
                exclusions.append({"candidate_id": identifier, "reason": "repository_cap_or_portfolio_full"}); continue
            if band != "FRESH_A" and identifier not in reviewer_approved_fallbacks:
                exclusions.append({"candidate_id": identifier, "reason": "fallback_not_reviewer_approved"}); continue
            selected.append({"candidate_id": identifier, **record}); per_repository[record["repository"]] = per_repository.get(record["repository"], 0) + 1
        if len(selected) >= 6:
            break
    if len(selected) != 6:
        _fail("session2_fresh_portfolio_insufficient")
    # The seed does not replace source/timestamp ordering; it binds the frozen
    # selection itself so later drift is detectable.
    return {"selection_id": "fresh_" + sha256((seed + "".join(item["case_id"] for item in selected)).encode()).hexdigest(), "selected": selected, "exclusions": exclusions, "exhaustion": {band: buckets[band] for band in ("FRESH_A", "FRESH_B", "FALLBACK_RECENT")}}


def pr_hash(seed: str, repository: str, kind: str, pr_number: int, merge_sha: str, *, large_pr_number: int | None = None) -> str:
    if not isinstance(pr_number, int) or pr_number < 1 or not isinstance(merge_sha, str) or len(merge_sha) != 40:
        _fail("session2_pr_identity_invalid")
    values = [seed, repository]
    if kind == "large": values += ["large", str(pr_number), merge_sha]
    elif kind == "moderate" and isinstance(large_pr_number, int) and large_pr_number > 0: values += [str(large_pr_number), "moderate", str(pr_number), merge_sha]
    else: _fail("session2_pr_hash_kind_invalid")
    return sha256("".join(values).encode()).hexdigest()


def qualify_pr(value: Any, *, window_start: str, window_end: str, p95_churn: int | None = None) -> str:
    """Return LARGE, MODERATE or raise a stable mechanical exclusion."""
    required = {"pr_number", "merged_at", "merge_sha", "reviewable_churn", "human_source_file_count", "components", "release_surface", "excluded_classifications"}
    if not isinstance(value, dict) or set(value) != required:
        _fail("session2_pr_frame_invalid")
    merged = _time(value["merged_at"], "session2_pr_frame_invalid")
    if not (_time(window_start, "session2_window_invalid") <= merged <= _time(window_end, "session2_window_invalid")):
        _fail("session2_pr_window_excluded")
    churn = value["reviewable_churn"]
    if not isinstance(churn, int) or churn < 0 or not isinstance(value["human_source_file_count"], int) or not isinstance(value["components"], list) or len(set(value["components"])) < 2 or not isinstance(value["release_surface"], str) or not value["release_surface"] or value["excluded_classifications"]:
        _fail("session2_pr_mechanical_excluded")
    if churn >= 1000 or (isinstance(p95_churn, int) and churn >= 500 and churn >= p95_churn):
        if value["human_source_file_count"] < 10: _fail("session2_pr_large_source_file_threshold")
        return "LARGE"
    if 100 <= churn <= 500:
        return "MODERATE"
    _fail("session2_pr_churn_threshold")
