"""Compile Session 2 issue/fix candidates from sealed primary retrieval bytes.

The compiler deliberately stops before checkout or qualification.  Its only
authority is a deterministic, replayable mapping from public issues to merged
pull requests whose *public PR body* explicitly closes the issue.  That makes
candidate exclusions durable and prevents manually inserted attractive pairs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import platform
import re
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2 import contamination_band
from .session2_selection import validate_retrieval_receipt


class CandidateCompilationError(RuntimeError):
    pass


_CLOSES = re.compile(r"(?im)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+(?:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+))?#(?P<number>[1-9][0-9]*)\b")
_HEX = re.compile(r"^[0-9a-f]{64}$")


def _fail(code: str) -> None:
    raise CandidateCompilationError(code)


def _time(value: Any) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise CandidateCompilationError("session2_candidate_timestamp_invalid") from exc
    if result.tzinfo is None:
        _fail("session2_candidate_timestamp_invalid")
    return result.astimezone(timezone.utc)


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux":
        _fail("session2_candidate_compile_requires_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise CandidateCompilationError("session2_candidate_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_candidate_external_root_invalid")
    base = root / "session2"
    if not (base / "retrieval" / "raw").is_dir() or not (base / "cases").is_dir():
        _fail("session2_candidate_namespace_missing")
    return base


def _read_hash(path: Path, expected: str) -> Any:
    if not expected.startswith("sha256:") or not _HEX.fullmatch(expected[7:]) or _is_reparse(path):
        _fail("session2_candidate_raw_authority_invalid")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != expected[7:]:
        _fail("session2_candidate_raw_hash_mismatch")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateCompilationError("session2_candidate_raw_invalid") from exc


def _document_honors_filters(document: dict[str, Any], filters: dict[str, Any]) -> bool:
    """Independent consumer check: a sealed receipt is not blindly trusted."""
    for item in document.get("items", []):
        if not isinstance(item, dict):
            return False
        is_pull = "pull_request" in item
        if filters.get("kind") == "issue" and is_pull:
            return False
        if filters.get("kind") == "pull_request" and not is_pull:
            return False
        try:
            created = _time(item.get("created_at"))
            if "created_from" in filters and created < _time(filters["created_from"]): return False
            if "created_to" in filters and created > _time(filters["created_to"]): return False
            if "merged_from" in filters or "merged_to" in filters:
                # Search Issues does not expose authoritative ``merged_at``.
                # The sealed query asserts the provider-side merged window;
                # exact object receipts revalidate merged_at before a pair can
                # enter qualification.  Here we only require that the search
                # result is a well-formed closed PR observation.
                _time(item.get("closed_at"))
        except CandidateCompilationError:
            return False
    return True


def _frame_receipt_hashes(base: Path, receipt_hash: str) -> dict[str, dict[str, Any]]:
    """Load the sole complete retrieval-frame authority for compilation.

    A search receipt proves one query happened.  It does not prove that every
    query in the precommitted frame completed.  Selection must therefore be
    rooted in the content-addressed frame receipt emitted by the supervisor,
    never in a convenient subset of retained receipt files.
    """
    if not isinstance(receipt_hash, str) or not _HEX.fullmatch(receipt_hash.removeprefix("sha256:")) or not receipt_hash.startswith("sha256:"):
        _fail("session2_candidate_retrieval_frame_hash_invalid")
    path = base / "retrieval" / "frames" / (receipt_hash[7:] + ".retrieval-frame-receipts.json")
    if not path.is_file() or _is_reparse(path):
        _fail("session2_candidate_retrieval_frame_missing")
    raw = path.read_bytes()
    if "sha256:" + sha256(raw).hexdigest() != receipt_hash:
        _fail("session2_candidate_retrieval_frame_hash_mismatch")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateCompilationError("session2_candidate_retrieval_frame_invalid") from exc
    if canonical_json(value) != raw:
        _fail("session2_candidate_retrieval_frame_noncanonical")
    required = {"schema_id", "schema_version", "frame_relative_path", "frame_hash", "frame_git_blob", "repository", "predecessor_candidate_index_hash", "receipts"}
    entries = value.get("receipts") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema_id") != "external_validation.session2_retrieval_frame_receipts.v1"
            or value.get("schema_version") != "1" or not isinstance(entries, list) or not entries):
        _fail("session2_candidate_retrieval_frame_invalid")
    hashes: dict[str, dict[str, Any]] = {}
    identities: set[tuple[str, str, str]] = set()
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"kind", "start", "end", "receipt_hash", "candidate_count"}
                or entry.get("kind") not in {"issue", "pull_request"}
                or not isinstance(entry.get("start"), str) or not isinstance(entry.get("end"), str)
                or not isinstance(entry.get("candidate_count"), int) or entry["candidate_count"] < 0
                or not isinstance(entry.get("receipt_hash"), str) or not _HEX.fullmatch(entry["receipt_hash"].removeprefix("sha256:"))
                or not entry["receipt_hash"].startswith("sha256:")):
            _fail("session2_candidate_retrieval_frame_invalid")
        identity = (entry["kind"], entry["start"], entry["end"])
        if identity in identities or entry["receipt_hash"] in hashes:
            _fail("session2_candidate_retrieval_frame_duplicate")
        identities.add(identity); hashes[entry["receipt_hash"]] = entry
    return hashes


def _receipt_documents(base: Path, allowed_hashes: dict[str, dict[str, Any]]) -> tuple[list[tuple[dict[str, Any], list[dict[str, Any]]]], list[dict[str, str]]]:
    result: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in sorted((base / "retrieval").glob("*.retrieval-receipt.json")):
        if _is_reparse(path):
            _fail("session2_candidate_receipt_reparse")
        raw = path.read_bytes()
        digest = "sha256:" + sha256(raw).hexdigest()
        if digest not in allowed_hashes:
            continue
        seen.add(digest)
        receipt = json.loads(raw.decode("utf-8"))
        validate_retrieval_receipt(receipt)
        declared = allowed_hashes[digest]
        filter_kind = receipt["filters"].get("kind")
        if (filter_kind != declared["kind"] or len(receipt["candidate_ids"]) != declared["candidate_count"]
                or (filter_kind == "issue" and (receipt["filters"].get("created_from") != declared["start"] or receipt["filters"].get("created_to") != declared["end"]))
                or (filter_kind == "pull_request" and (receipt["filters"].get("merged_from") != declared["start"] or receipt["filters"].get("merged_to") != declared["end"]))):
            _fail("session2_candidate_retrieval_frame_receipt_mismatch")
        documents = [_read_hash(base / "retrieval" / "raw" / (page["raw_response_hash"][7:] + ".json"), page["raw_response_hash"]) for page in receipt["pages"]]
        if not all(_document_honors_filters(document, receipt["filters"]) for document in documents):
            rejected.append({"receipt_hash": digest, "reason": "raw_response_does_not_honor_declared_filters"})
            continue
        result.append((receipt, documents))
    if seen != set(allowed_hashes):
        _fail("session2_candidate_retrieval_frame_receipt_missing")
    if not result:
        _fail("session2_candidate_retrieval_missing")
    return result, rejected


def _slug(item: dict[str, Any]) -> str:
    source = item.get("repository_url")
    prefix = "https://api.github.com/repos/"
    if not isinstance(source, str) or not source.startswith(prefix):
        _fail("session2_candidate_raw_invalid")
    return source.removeprefix(prefix)


def _screened_candidates(base: Path) -> dict[str, dict[str, str]]:
    """Load only canonical supervisor-owned prequalification exclusions."""
    directory = base / "cases" / "screens"
    if not directory.exists():
        return {}
    if not directory.is_dir() or _is_reparse(directory):
        _fail("session2_candidate_screen_store_invalid")
    screens_by_hash: dict[str, dict[str, str]] = {}
    screens_by_candidate: dict[str, list[dict[str, str]]] = {}
    unbound_runtime_v1: set[str] = set()
    legacy_source_v2: set[str] = set()
    provenance_by_candidate: dict[str, dict[str, str]] = {}
    resolved_provenance: set[str] = set()
    for path in sorted(directory.glob("*.safe-export-screen.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if digest != "sha256:" + path.name.removesuffix(".safe-export-screen.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_candidate_screen_invalid") from exc
        required = {"schema_id", "schema_version", "candidate_id", "candidate_index_hash", "materialization_failure_hash", "stage", "decision", "reason", "created_at"}
        if (not isinstance(value, dict) or set(value) != required
                or value.get("schema_id") != "external_validation.session2_safe_export_screen.v1"
                or value.get("schema_version") != "1" or not isinstance(value.get("candidate_id"), str)
                or not isinstance(value.get("candidate_index_hash"), str) or not isinstance(value.get("materialization_failure_hash"), str)
                or value.get("stage") != "SAFE_SOURCE_EXPORT" or value.get("decision") != "EXCLUDED_PREQUALIFICATION"
                or value.get("reason") != "UNSAFE_PATIENT_TREE_ENTRY"
                or not (value["candidate_index_hash"].startswith("sha256:") and _HEX.fullmatch(value["candidate_index_hash"][7:]))
                or not (value["materialization_failure_hash"].startswith("sha256:") and _HEX.fullmatch(value["materialization_failure_hash"][7:]))):
            _fail("session2_candidate_screen_invalid")
        entry = {"reason":value["reason"], "screen_hash":digest}
        screens_by_hash[digest] = {"candidate_id":value["candidate_id"], **entry}
        screens_by_candidate.setdefault(value["candidate_id"], []).append(entry)
    for path in sorted(directory.glob("*.mirror-acquisition-screen.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if digest != "sha256:" + path.name.removesuffix(".mirror-acquisition-screen.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_candidate_screen_invalid") from exc
        required = {"schema_id", "schema_version", "candidate_id", "candidate_index_hash", "mirror_attempt_hash", "stage", "decision", "reason", "created_at"}
        if (not isinstance(value, dict) or set(value) != required
                or value.get("schema_id") != "external_validation.session2_mirror_acquisition_screen.v1"
                or value.get("schema_version") != "1" or not isinstance(value.get("candidate_id"), str)
                or not isinstance(value.get("candidate_index_hash"), str) or not isinstance(value.get("mirror_attempt_hash"), str)
                or value.get("stage") != "SOURCE_MIRROR_ACQUISITION"
                or value.get("decision") != "EXCLUDED_PREQUALIFICATION"
                or value.get("reason") != "MIRROR_ACQUISITION_TIMED_OUT"
                or not (value["candidate_index_hash"].startswith("sha256:") and _HEX.fullmatch(value["candidate_index_hash"][7:]))
                or not (value["mirror_attempt_hash"].startswith("sha256:") and _HEX.fullmatch(value["mirror_attempt_hash"][7:]))):
            _fail("session2_candidate_screen_invalid")
        entry = {"reason": value["reason"], "screen_hash": digest}
        screens_by_hash[digest] = {"candidate_id": value["candidate_id"], **entry}
        screens_by_candidate.setdefault(value["candidate_id"], []).append(entry)
    for path in sorted(directory.glob("*.provenance-screen.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if digest != "sha256:" + path.name.removesuffix(".provenance-screen.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_candidate_screen_invalid") from exc
        required = {"schema_id", "schema_version", "candidate_id", "candidate_index_hash", "stage", "decision", "reason", "expected_source_object_receipt_hashes", "missing_source_object_receipt_hashes", "created_at"}
        expected = value.get("expected_source_object_receipt_hashes") if isinstance(value, dict) else None
        missing = value.get("missing_source_object_receipt_hashes") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_candidate_provenance_screen.v1"
                or value.get("schema_version") != "1" or not isinstance(value.get("candidate_id"), str)
                or value.get("stage") != "PRIMARY_RETRIEVAL_AUTHORITY" or value.get("decision") != "EXCLUDED_PREQUALIFICATION"
                or value.get("reason") != "PRIMARY_RETRIEVAL_RECEIPT_UNAVAILABLE"
                or not isinstance(expected, list) or len(expected) != 2 or expected != sorted(expected)
                or not isinstance(missing, list) or not missing or missing != sorted(missing)
                or any(not isinstance(item, str) or not item.startswith("sha256:") for item in expected + missing)
                or not set(missing).issubset(expected) or value["candidate_id"] in provenance_by_candidate):
            _fail("session2_candidate_screen_invalid")
        provenance_by_candidate[value["candidate_id"]] = {"reason": value["reason"], "screen_hash": digest}
    for path in sorted(directory.glob("*.provenance-resolution.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if digest != "sha256:" + path.name.removesuffix(".provenance-resolution.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_candidate_screen_resolution_invalid") from exc
        required = {"schema_id", "schema_version", "candidate_id", "supersedes_screen_hash", "reason", "resolution", "created_at"}
        target = value.get("supersedes_screen_hash") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_candidate_provenance_resolution.v1"
                or value.get("schema_version") != "1" or value.get("reason") != "PRIMARY_RETRIEVAL_REFERENCE_TYPE_CORRECTED"
                or value.get("resolution") != "REOPEN_FOR_REQUALIFICATION" or target in resolved_provenance
                or not isinstance(target, str)):
            _fail("session2_candidate_screen_resolution_invalid")
        candidate = value.get("candidate_id")
        entry = provenance_by_candidate.get(candidate)
        if entry is None or entry["screen_hash"] != target:
            _fail("session2_candidate_screen_resolution_invalid")
        resolved_provenance.add(target)
    for path in sorted(directory.glob("*.screen.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes()
        if "sha256:" + sha256(raw).hexdigest() != "sha256:" + path.name.removesuffix(".screen.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateCompilationError("session2_candidate_screen_invalid") from exc
        required_v1 = {"schema_id", "schema_version", "candidate_id", "candidate_index_hash", "buggy_sha", "fixed_sha", "stage", "decision", "reason", "source_object_receipt_hashes", "supervisor_command", "created_at"}
        required_v2 = required_v1 | {"materialization_hash", "execution_evidence_hash"}
        version = value.get("schema_id") if isinstance(value, dict) else None
        # One historical producer revision labelled source-only screens v2
        # without the required runtime-evidence fields.  Retain it only as
        # resolvable history; it cannot remain active authority.
        runtime_reasons = {"UNQUALIFIED_LINUX_CONTAINER_PATH", "DEPENDENCY_AUTHORITY_NOT_FROZEN"}
        is_legacy_source_v2 = (version == "external_validation.session2_prequalification_screen.v2"
                               and isinstance(value, dict)
                               and value.get("reason") not in runtime_reasons
                               and set(value) == required_v1)
        required = required_v1 if is_legacy_source_v2 else (required_v2 if version == "external_validation.session2_prequalification_screen.v2" else required_v1)
        if (not isinstance(value, dict) or set(value) != required or version not in {"external_validation.session2_prequalification_screen.v1", "external_validation.session2_prequalification_screen.v2"}
                or value.get("schema_version") != "1" or value.get("stage") != "SOURCE_CONTRACT_SCREEN"
                or value.get("decision") != "EXCLUDED_PREQUALIFICATION" or not isinstance(value.get("candidate_id"), str)
                or not isinstance(value.get("reason"), str)
                or (version == "external_validation.session2_prequalification_screen.v2" and not is_legacy_source_v2 and (value.get("reason") not in runtime_reasons or not all(isinstance(value.get(key), str) and value[key].startswith("sha256:") for key in ("materialization_hash", "execution_evidence_hash"))))):
            _fail("session2_candidate_screen_invalid")
        entry = {"reason": value["reason"], "screen_hash": "sha256:" + path.name.removesuffix(".screen.json")}
        if version == "external_validation.session2_prequalification_screen.v1" and value.get("reason") == "UNQUALIFIED_LINUX_CONTAINER_PATH":
            # A v1 record is only historical diagnostic material.  It is
            # acceptable to retain when a canonical successor explicitly
            # reopens it, but an active v1 runtime exclusion is never final
            # qualification authority.
            unbound_runtime_v1.add(entry["screen_hash"])
        if is_legacy_source_v2:
            legacy_source_v2.add(entry["screen_hash"])
        screens_by_hash[entry["screen_hash"]] = {"candidate_id": value["candidate_id"], **entry}
        screens_by_candidate.setdefault(value["candidate_id"], []).append(entry)
    resolved_screens: set[str] = set()
    for path in sorted(directory.glob("*.resolution.json")):
        if _is_reparse(path): _fail("session2_candidate_screen_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if digest != "sha256:" + path.name.removesuffix(".resolution.json"):
            _fail("session2_candidate_screen_hash_mismatch")
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_candidate_screen_resolution_invalid") from exc
        required = {"schema_id", "schema_version", "candidate_id", "supersedes_screen_hash", "prior_candidate_index_hash", "reason", "resolution", "implementation_commit", "created_at"}
        candidate = value.get("candidate_id") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or set(value) != required or value.get("schema_id") != "external_validation.session2_prequalification_resolution.v1"
                or value.get("schema_version") != "1" or value.get("reason") not in {"MATERIALIZATION_POLICY_NARROWING_CORRECTED", "FIXED_TWIN_COMMIT_AUTHORITY_CORRECTED", "QUALIFIED_RUNNER_COMPATIBILITY_SUPERSEDED", "HASH_PINNED_REQUIREMENTS_AUTHORITY_SUPERSEDED"}
                or value.get("resolution") != "REOPEN_FOR_REQUALIFICATION" or candidate not in screens_by_candidate
                or value.get("supersedes_screen_hash") not in screens_by_hash
                or screens_by_hash[value.get("supersedes_screen_hash")].get("candidate_id") != candidate
                or value.get("supersedes_screen_hash") in resolved_screens):
            _fail("session2_candidate_screen_resolution_invalid")
        resolved_screens.add(value["supersedes_screen_hash"])
    if any(screen_hash not in resolved_screens for screen_hash in unbound_runtime_v1):
        _fail("session2_candidate_runtime_screen_unbound")
    if any(screen_hash not in resolved_screens for screen_hash in legacy_source_v2):
        _fail("session2_candidate_screen_invalid")
    result: dict[str, dict[str, str]] = {}
    for candidate, entries in screens_by_candidate.items():
        active = [entry for entry in entries if entry["screen_hash"] not in resolved_screens]
        if len(active) > 1:
            _fail("session2_candidate_screen_duplicate")
        if active:
            result[candidate] = active[0]
    for candidate, entry in provenance_by_candidate.items():
        if entry["screen_hash"] in resolved_provenance:
            continue
        if candidate in result:
            _fail("session2_candidate_screen_duplicate")
        result[candidate] = entry
    return result


def compile_github_issue_fix_candidates(repository_root: Path, *, retrieval_frame_receipt_hashes: list[str]) -> dict[str, Any]:
    """Seal one candidate index from complete sealed primary-retrieval frames.

    Every source repository is independently frame-complete.  Combining those
    complete frames is allowed; accepting arbitrary retained receipts is not.
    """
    base = _root(repository_root)
    issues: dict[tuple[str, int], tuple[dict[str, Any], str]] = {}
    pulls: list[tuple[dict[str, Any], str]] = []
    source_receipts: list[str] = []
    # A screen is bound to the candidate-index hash that existed when the
    # screen was produced.  Applying every historical screen while compiling
    # a new source frame would let an old, unrelated index silently suppress
    # new observations (and make a retained malformed historical record a
    # denial of service for future collection).  Screens are enforced later,
    # at qualification, against their exact cited index.  This compilation is
    # intentionally a pure complete-retrieval projection.
    if (not isinstance(retrieval_frame_receipt_hashes, list) or not retrieval_frame_receipt_hashes
            or retrieval_frame_receipt_hashes != sorted(set(retrieval_frame_receipt_hashes))):
        _fail("session2_candidate_retrieval_frame_set_invalid")
    allowed_receipts: dict[str, dict[str, Any]] = {}
    frame_repositories: set[str] = set()
    for frame_hash in retrieval_frame_receipt_hashes:
        frame_receipts = _frame_receipt_hashes(base, frame_hash)
        # Frame receipt records are independently validated on load.  A
        # receipt hash may occur in exactly one frame; reusing it would give
        # that observation duplicate source weight.
        if set(allowed_receipts).intersection(frame_receipts):
            _fail("session2_candidate_retrieval_frame_overlap")
        for entry in frame_receipts.values():
            receipt_path = base / "retrieval" / "frames" / (frame_hash[7:] + ".retrieval-frame-receipts.json")
            value = json.loads(receipt_path.read_text(encoding="utf-8"))
            repository = value["repository"]
            break
        else:  # The semantic frame loader already rejects an empty frame.
            _fail("session2_candidate_retrieval_frame_invalid")
        if repository in frame_repositories:
            _fail("session2_candidate_retrieval_frame_repository_duplicate")
        frame_repositories.add(repository)
        allowed_receipts.update(frame_receipts)
    receipts, receipt_exclusions = _receipt_documents(base, allowed_receipts)
    for receipt, documents in receipts:
        digest = "sha256:" + sha256(canonical_json(receipt)).hexdigest()
        source_receipts.append(digest)
        kind = receipt["filters"].get("kind")
        if kind not in {"issue", "pull_request"}:
            _fail("session2_candidate_retrieval_kind_invalid")
        for document in documents:
            for item in document["items"]:
                if not isinstance(item, dict):
                    _fail("session2_candidate_raw_invalid")
                slug, number = _slug(item), item.get("number")
                if not isinstance(number, int) or number < 1:
                    _fail("session2_candidate_raw_invalid")
                if kind == "issue":
                    key = (slug, number)
                    if key in issues and issues[key][0] != item:
                        _fail("session2_candidate_duplicate_issue_conflict")
                    issues[key] = (item, digest)
                else:
                    pulls.append((item, digest))
    # A search receipt is append-only evidence, so the same public issue/PR
    # can legitimately appear in more than one retained query frame.  The
    # candidate population, however, is a set of observations: duplicating a
    # pair would silently change its selection weight.  Retain every receipt at
    # index level while deriving one deterministic representative provenance
    # pair for each semantically identical candidate.
    candidates_by_id: dict[str, dict[str, Any]] = {}
    linked_issues: set[tuple[str, int]] = set()
    for pull, pull_receipt in pulls:
        slug = _slug(pull)
        body = pull.get("body")
        if not isinstance(body, str):
            continue
        fixed_at = pull.get("closed_at")
        _time(fixed_at)
        for match in _CLOSES.finditer(body):
            target_slug = ((match.group("owner") + "/" + match.group("repo")) if match.group("owner") else slug)
            key = (target_slug, int(match.group("number")))
            issue_tuple = issues.get(key)
            if issue_tuple is None:
                continue
            issue, issue_receipt = issue_tuple
            issue_at = str(issue.get("created_at")); _time(issue_at)
            band = contamination_band(issue_at, str(fixed_at))
            candidate_id = target_slug + "#" + str(key[1]) + "->" + slug + "#" + str(pull["number"])
            candidate = {
                "candidate_id": candidate_id,
                "source_priority": 2,
                "repository": target_slug,
                "issue_number": key[1],
                "fix_pr_number": pull["number"],
                "issue_created_at": issue_at,
                "fix_created_at": fixed_at,
                "contamination_band": band,
                "issue_retrieval_receipt_hash": issue_receipt,
                "fix_retrieval_receipt_hash": pull_receipt,
            }
            existing = candidates_by_id.get(candidate_id)
            if existing is None:
                candidates_by_id[candidate_id] = candidate
            else:
                semantic_fields = set(candidate) - {"issue_retrieval_receipt_hash", "fix_retrieval_receipt_hash"}
                if any(existing[field] != candidate[field] for field in semantic_fields):
                    _fail("session2_candidate_duplicate_pair_conflict")
                existing["issue_retrieval_receipt_hash"] = min(existing["issue_retrieval_receipt_hash"], issue_receipt)
                existing["fix_retrieval_receipt_hash"] = min(existing["fix_retrieval_receipt_hash"], pull_receipt)
            linked_issues.add(key)
    candidates = sorted(candidates_by_id.values(), key=lambda item: (_time(item["issue_created_at"]), item["candidate_id"]))
    exclusions = receipt_exclusions + [{"repository": slug, "issue_number": number, "reason": "no_public_closing_merged_pr_in_retrieved_frame"} for slug, number in sorted(set(issues) - linked_issues)]
    result = {
        "schema_id": "external_validation.session2_github_issue_fix_candidate_index.v3",
        "schema_version": "1",
        "retrieval_frame_receipt_hashes": retrieval_frame_receipt_hashes,
        "source_receipt_hashes": sorted(set(source_receipts)),
        "candidates": candidates,
        "exclusions": exclusions,
    }
    payload = canonical_json(result)
    digest = sha256(payload).hexdigest()
    target = base / "cases" / (digest + ".candidate-index.json")
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        if target.read_bytes() != payload:
            _fail("session2_candidate_index_collision")
    else:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
    return {"candidate_index_hash": "sha256:" + digest, "candidate_count": len(candidates), "exclusion_count": len(exclusions)}


def _fresh_b_v2_frame(base: Path, receipt_hash: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load one complete recovery frame without treating search data as fixes.

    GitHub's Search Issues API returns ``closed_at`` for a merged pull request,
    not the authoritative ``merged_at``.  A v2 recovery frame can therefore
    establish only source references.  The final Fresh B index is derived by
    :func:`finalize_fresh_b_object_candidates` from immutable issue and PR
    object receipts.
    """
    if not isinstance(receipt_hash, str) or not receipt_hash.startswith("sha256:") or not _HEX.fullmatch(receipt_hash[7:]):
        _fail("session2_fresh_b_reference_frame_hash_invalid")
    path = base / "retrieval" / "frames" / (receipt_hash[7:] + ".retrieval-frame-receipts.json")
    if not path.is_file() or _is_reparse(path):
        _fail("session2_fresh_b_reference_frame_missing")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != receipt_hash[7:]:
        _fail("session2_fresh_b_reference_frame_hash_mismatch")
    try:
        frame = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateCompilationError("session2_fresh_b_reference_frame_invalid") from exc
    required = {"schema_id", "schema_version", "frame_relative_path", "frame_hash", "frame_git_blob", "repository", "predecessor_candidate_index_hash", "receipts", "fresh_b_authority_hash", "fresh_a_exhaustion_hash", "fix_windows_authority_hash", "retrieval_not_before"}
    if (canonical_json(frame) != raw or not isinstance(frame, dict) or set(frame) != required
            or frame.get("schema_id") != "external_validation.session2_fresh_b_retrieval_frame_receipts.v2"
            or frame.get("schema_version") != "1" or not isinstance(frame.get("repository"), str)
            or not isinstance(frame.get("receipts"), list) or len(frame["receipts"]) != 8):
        _fail("session2_fresh_b_reference_frame_invalid")
    expected: set[tuple[str, str, str]] = {
        ("issue:B1", "2026-02-17T00:00:00Z", "2026-02-28T23:59:59Z"),
        ("issue:B2", "2025-12-01T00:00:00Z", "2026-02-16T23:59:59Z"),
        ("issue:B3", "2025-09-01T00:00:00Z", "2025-11-30T23:59:59Z"),
        ("pull_request", "2026-03-01T00:00:00Z", "2026-03-31T23:59:59Z"),
        ("pull_request", "2026-04-01T00:00:00Z", "2026-04-30T23:59:59Z"),
        ("pull_request", "2026-05-01T00:00:00Z", "2026-05-31T23:59:59Z"),
        ("pull_request", "2026-06-01T00:00:00Z", "2026-06-30T23:59:59Z"),
        ("pull_request", "2026-07-01T00:00:00Z", "2026-07-30T10:32:18.825171Z"),
    }
    entries: dict[str, dict[str, Any]] = {}
    identities: set[tuple[str, str, str]] = set()
    for entry in frame["receipts"]:
        if (not isinstance(entry, dict) or set(entry) != {"kind", "start", "end", "receipt_hash", "candidate_count"}
                or not isinstance(entry.get("kind"), str) or not isinstance(entry.get("start"), str)
                or not isinstance(entry.get("end"), str) or not isinstance(entry.get("candidate_count"), int)
                or entry["candidate_count"] < 0 or not isinstance(entry.get("receipt_hash"), str)
                or not entry["receipt_hash"].startswith("sha256:") or not _HEX.fullmatch(entry["receipt_hash"][7:])):
            _fail("session2_fresh_b_reference_frame_invalid")
        identity = (entry["kind"], entry["start"], entry["end"])
        if identity not in expected or identity in identities or entry["receipt_hash"] in entries:
            _fail("session2_fresh_b_reference_frame_invalid")
        identities.add(identity); entries[entry["receipt_hash"]] = entry
    if identities != expected:
        _fail("session2_fresh_b_reference_frame_invalid")
    return frame, entries


def _fresh_b_documents(base: Path, entries: dict[str, dict[str, Any]]) -> list[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], str]]:
    result: list[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], str]] = []
    for receipt_hash, entry in sorted(entries.items()):
        path = base / "retrieval" / (receipt_hash[7:] + ".retrieval-receipt.json")
        if not path.is_file() or _is_reparse(path):
            _fail("session2_fresh_b_reference_receipt_missing")
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != receipt_hash[7:]:
            _fail("session2_fresh_b_reference_receipt_hash_mismatch")
        try:
            receipt = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateCompilationError("session2_fresh_b_reference_receipt_invalid") from exc
        if canonical_json(receipt) != raw:
            _fail("session2_fresh_b_reference_receipt_invalid")
        validate_retrieval_receipt(receipt)
        expected_kind = "issue" if entry["kind"].startswith("issue:") else "pull_request"
        if (receipt["filters"].get("kind") != expected_kind or len(receipt["candidate_ids"]) != entry["candidate_count"]
                or (expected_kind == "issue" and (receipt["filters"].get("created_from") != entry["start"] or receipt["filters"].get("created_to") != entry["end"]))
                or (expected_kind == "pull_request" and (receipt["filters"].get("merged_from") != entry["start"] or receipt["filters"].get("merged_to") != entry["end"]))):
            _fail("session2_fresh_b_reference_receipt_mismatch")
        documents = [_read_hash(base / "retrieval" / "raw" / (page["raw_response_hash"][7:] + ".json"), page["raw_response_hash"]) for page in receipt["pages"]]
        if not all(_document_honors_filters(document, receipt["filters"]) for document in documents):
            _fail("session2_fresh_b_reference_raw_filter_invalid")
        result.append((receipt, documents, entry, receipt_hash))
    return result


def compile_fresh_b_reference_candidates(repository_root: Path, *, retrieval_frame_receipt_hashes: list[str]) -> dict[str, Any]:
    """Create a non-selecting Fresh B reference index from complete v2 frames."""
    base = _root(repository_root)
    if (not isinstance(retrieval_frame_receipt_hashes, list) or len(retrieval_frame_receipt_hashes) != 7
            or retrieval_frame_receipt_hashes != sorted(set(retrieval_frame_receipt_hashes))):
        _fail("session2_fresh_b_reference_frame_set_invalid")
    issues: dict[tuple[str, int], tuple[dict[str, Any], str, str]] = {}
    pulls: list[tuple[dict[str, Any], str]] = []
    frame_repositories: set[str] = set()
    source_receipts: set[str] = set()
    retrieval_not_before: set[str] = set()
    for frame_hash in retrieval_frame_receipt_hashes:
        frame, entries = _fresh_b_v2_frame(base, frame_hash)
        if frame["repository"] in frame_repositories:
            _fail("session2_fresh_b_reference_repository_duplicate")
        frame_repositories.add(frame["repository"])
        retrieval_not_before.add(frame["retrieval_not_before"])
        for receipt, documents, entry, receipt_hash in _fresh_b_documents(base, entries):
            source_receipts.add(receipt_hash)
            kind = "issue" if entry["kind"].startswith("issue:") else "pull_request"
            for document in documents:
                for item in document["items"]:
                    if not isinstance(item, dict): _fail("session2_fresh_b_reference_raw_invalid")
                    slug, number = _slug(item), item.get("number")
                    if not isinstance(number, int) or number < 1 or slug != frame["repository"]:
                        _fail("session2_fresh_b_reference_raw_invalid")
                    if kind == "issue":
                        key = (slug, number)
                        previous = issues.get(key)
                        candidate = (item, receipt_hash, entry["kind"].split(":", 1)[1])
                        if previous is not None and previous != candidate:
                            _fail("session2_fresh_b_reference_issue_duplicate_conflict")
                        issues[key] = candidate
                    else:
                        pulls.append((item, receipt_hash))
    candidates: dict[str, dict[str, Any]] = {}
    linked: set[tuple[str, int]] = set()
    for pull, pull_receipt in pulls:
        slug = _slug(pull); body = pull.get("body")
        if not isinstance(body, str): continue
        search_closed_at = str(pull.get("closed_at")); _time(search_closed_at)
        for match in _CLOSES.finditer(body):
            target_slug = (match.group("owner") + "/" + match.group("repo")) if match.group("owner") else slug
            key = (target_slug, int(match.group("number")))
            issue_tuple = issues.get(key)
            if issue_tuple is None: continue
            issue, issue_receipt, band = issue_tuple
            issue_at = str(issue.get("created_at")); _time(issue_at)
            candidate_id = target_slug + "#" + str(key[1]) + "->" + slug + "#" + str(pull["number"])
            candidate = {"candidate_id": candidate_id, "source_priority": 2, "repository": target_slug,
                         "issue_number": key[1], "fix_repository": slug, "fix_pr_number": pull["number"],
                         "issue_created_at": issue_at, "search_fix_closed_at": search_closed_at,
                         "fresh_b_band": band, "contamination_tier": "FRESH_B",
                         "issue_retrieval_receipt_hash": issue_receipt, "fix_retrieval_receipt_hash": pull_receipt,
                         "selection_status": "REFERENCE_ONLY_REQUIRES_OBJECT_RECEIPTS"}
            existing = candidates.get(candidate_id)
            if existing is not None and existing != candidate:
                _fail("session2_fresh_b_reference_pair_conflict")
            candidates[candidate_id] = candidate; linked.add(key)
    exclusions = [{"repository": slug, "issue_number": number, "reason": "no_public_closing_merged_pr_in_retrieved_frame"}
                  for slug, number in sorted(set(issues) - linked)]
    if len(retrieval_not_before) != 1: _fail("session2_fresh_b_reference_timestamp_authority_invalid")
    result = {"schema_id": "external_validation.session2_fresh_b_candidate_reference_index.v1", "schema_version": "1",
              "retrieval_frame_receipt_hashes": retrieval_frame_receipt_hashes, "source_receipt_hashes": sorted(source_receipts),
              "object_receipt_not_before": next(iter(retrieval_not_before)), "selection_effect": "reference_collection_only", "candidates": [candidates[key] for key in sorted(candidates)], "exclusions": exclusions}
    payload = canonical_json(result); digest = sha256(payload).hexdigest(); target = base / "cases" / (digest + ".fresh-b-reference-index.json")
    try: descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        if _is_reparse(target) or target.read_bytes() != payload: _fail("session2_fresh_b_reference_index_collision")
    else:
        with os.fdopen(descriptor, "wb") as handle: handle.write(payload); handle.flush(); os.fsync(handle.fileno())
    return {"reference_index_hash": "sha256:" + digest, "reference_candidate_count": len(candidates), "exclusion_count": len(exclusions)}


def _read_fresh_b_reference_index(base: Path, reference_index_hash: str) -> dict[str, Any]:
    if not isinstance(reference_index_hash, str) or not reference_index_hash.startswith("sha256:") or not _HEX.fullmatch(reference_index_hash[7:]):
        _fail("session2_fresh_b_reference_index_hash_invalid")
    path = base / "cases" / (reference_index_hash[7:] + ".fresh-b-reference-index.json")
    if not path.is_file() or _is_reparse(path): _fail("session2_fresh_b_reference_index_missing")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != reference_index_hash[7:]: _fail("session2_fresh_b_reference_index_hash_mismatch")
    try: value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_fresh_b_reference_index_invalid") from exc
    required = {"schema_id", "schema_version", "retrieval_frame_receipt_hashes", "source_receipt_hashes", "object_receipt_not_before", "selection_effect", "candidates", "exclusions"}
    candidate_fields = {"candidate_id", "source_priority", "repository", "issue_number", "fix_repository", "fix_pr_number", "issue_created_at", "search_fix_closed_at", "fresh_b_band", "contamination_tier", "issue_retrieval_receipt_hash", "fix_retrieval_receipt_hash", "selection_status"}
    if (canonical_json(value) != raw or not isinstance(value, dict) or set(value) != required
            or value.get("schema_id") != "external_validation.session2_fresh_b_candidate_reference_index.v1" or value.get("schema_version") != "1"
            or value.get("selection_effect") != "reference_collection_only" or not isinstance(value.get("candidates"), list)
            or not isinstance(value.get("exclusions"), list) or not value["candidates"]):
        _fail("session2_fresh_b_reference_index_invalid")
    _time(value["object_receipt_not_before"])
    identifiers: set[str] = set()
    for candidate in value["candidates"]:
        if (not isinstance(candidate, dict) or set(candidate) != candidate_fields or not isinstance(candidate.get("candidate_id"), str)
                or candidate["candidate_id"] in identifiers or candidate.get("source_priority") != 2
                or not isinstance(candidate.get("repository"), str) or not isinstance(candidate.get("fix_repository"), str)
                or not isinstance(candidate.get("issue_number"), int) or candidate["issue_number"] < 1
                or not isinstance(candidate.get("fix_pr_number"), int) or candidate["fix_pr_number"] < 1
                or candidate.get("fresh_b_band") not in {"B1", "B2", "B3"} or candidate.get("contamination_tier") != "FRESH_B"
                or candidate.get("selection_status") != "REFERENCE_ONLY_REQUIRES_OBJECT_RECEIPTS"):
            _fail("session2_fresh_b_reference_index_invalid")
        _time(candidate["issue_created_at"]); _time(candidate["search_fix_closed_at"])
        for field in ("issue_retrieval_receipt_hash", "fix_retrieval_receipt_hash"):
            if not isinstance(candidate.get(field), str) or not candidate[field].startswith("sha256:") or not _HEX.fullmatch(candidate[field][7:]):
                _fail("session2_fresh_b_reference_index_invalid")
        identifiers.add(candidate["candidate_id"])
    return value


def required_fresh_b_object_requests(repository_root: Path, *, reference_index_hash: str) -> list[dict[str, Any]]:
    """Return the deterministic, non-selecting object-retrieval worklist."""
    base = _root(repository_root); index = _read_fresh_b_reference_index(base, reference_index_hash)
    requests = {(item["repository"], "issue", item["issue_number"]) for item in index["candidates"]}
    requests.update((item["fix_repository"], "pull_request", item["fix_pr_number"]) for item in index["candidates"])
    return [{"repository": repo, "object_kind": kind, "number": number} for repo, kind, number in sorted(requests)]


def _object_receipt_map(base: Path, *, not_before: datetime | None = None) -> dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any], str]]:
    records: dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any], str]] = {}
    for path in sorted((base / "retrieval").glob("*.object-receipt.json")):
        if _is_reparse(path): _fail("session2_fresh_b_object_receipt_reparse")
        raw = path.read_bytes(); digest = "sha256:" + sha256(raw).hexdigest()
        if path.name != digest[7:] + ".object-receipt.json": _fail("session2_fresh_b_object_receipt_hash_mismatch")
        try: receipt = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise CandidateCompilationError("session2_fresh_b_object_receipt_invalid") from exc
        required = {"schema_id", "schema_version", "repository", "object_kind", "number", "retrieved_at", "parser_id", "raw_response_hash"}
        if (canonical_json(receipt) != raw or not isinstance(receipt, dict) or set(receipt) != required
                or receipt.get("schema_id") != "external_validation.session2_github_object_receipt.v1" or receipt.get("schema_version") != "1"
                or receipt.get("object_kind") not in {"issue", "pull_request"} or not isinstance(receipt.get("repository"), str)
                or not isinstance(receipt.get("number"), int) or receipt["number"] < 1 or not isinstance(receipt.get("raw_response_hash"), str)
                or not receipt["raw_response_hash"].startswith("sha256:") or not _HEX.fullmatch(receipt["raw_response_hash"][7:])):
            _fail("session2_fresh_b_object_receipt_invalid")
        if not_before is not None and _time(receipt["retrieved_at"]) < not_before:
            continue
        document = _read_hash(base / "retrieval" / "raw" / (receipt["raw_response_hash"][7:] + ".json"), receipt["raw_response_hash"])
        key = (receipt["repository"], receipt["object_kind"], receipt["number"])
        if key in records: _fail("session2_fresh_b_object_receipt_duplicate")
        records[key] = (receipt, document, digest)
    return records


def _is_closing_link(body: Any, *, issue_repository: str, issue_number: int, pull_repository: str) -> bool:
    if not isinstance(body, str): return False
    for match in _CLOSES.finditer(body):
        target = (match.group("owner") + "/" + match.group("repo")) if match.group("owner") else pull_repository
        if target == issue_repository and int(match.group("number")) == issue_number: return True
    return False


def finalize_fresh_b_object_candidates(repository_root: Path, *, reference_index_hash: str) -> dict[str, Any]:
    """Seal the strict Fresh B population from authoritative GitHub objects.

    This is the first index with a real PR ``merged_at``.  It remains a source
    population, not qualification or selection evidence.
    """
    base = _root(repository_root); references = _read_fresh_b_reference_index(base, reference_index_hash)
    objects = _object_receipt_map(base, not_before=_time(references["object_receipt_not_before"]))
    upper = _time("2026-07-30T10:32:18.825171Z"); cutoff = _time("2026-03-01T00:00:00Z")
    candidates: list[dict[str, Any]] = []; exclusions: list[dict[str, Any]] = []
    for reference in sorted(references["candidates"], key=lambda item: item["candidate_id"]):
        issue_key = (reference["repository"], "issue", reference["issue_number"]); pull_key = (reference["fix_repository"], "pull_request", reference["fix_pr_number"])
        issue = objects.get(issue_key); pull = objects.get(pull_key)
        if issue is None or pull is None:
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "primary_object_receipt_missing"}); continue
        issue_receipt, issue_document, issue_hash = issue; pull_receipt, pull_document, pull_hash = pull
        try:
            issue_at = _time(issue_document.get("created_at")); merged_at = _time(pull_document.get("merged_at"))
        except CandidateCompilationError:
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "primary_object_timestamp_invalid"}); continue
        if (issue_document.get("number") != reference["issue_number"] or "pull_request" in issue_document
                or pull_document.get("number") != reference["fix_pr_number"]
                or not _is_closing_link(pull_document.get("body"), issue_repository=reference["repository"], issue_number=reference["issue_number"], pull_repository=reference["fix_repository"])):
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "authoritative_issue_fix_link_invalid"}); continue
        if not (cutoff <= merged_at <= upper):
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "fix_merged_at_outside_frozen_fresh_b_window"}); continue
        if issue_at >= merged_at:
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "issue_does_not_predate_authoritative_fix"}); continue
        expected_band = reference["fresh_b_band"]
        if contamination_band(issue_document.get("created_at"), pull_document.get("merged_at")) != "FRESH_B" or ((expected_band == "B1" and not (_time("2026-02-17T00:00:00Z") <= issue_at < _time("2026-03-01T00:00:00Z"))) or (expected_band == "B2" and not (_time("2025-12-01T00:00:00Z") <= issue_at < _time("2026-02-17T00:00:00Z"))) or (expected_band == "B3" and not (_time("2025-09-01T00:00:00Z") <= issue_at < _time("2025-12-01T00:00:00Z")))):
            exclusions.append({"candidate_id": reference["candidate_id"], "reason": "contamination_band_object_mismatch"}); continue
        candidates.append({"candidate_id": reference["candidate_id"], "source_priority": 2, "repository": reference["repository"], "issue_number": reference["issue_number"], "fix_repository": reference["fix_repository"], "fix_pr_number": reference["fix_pr_number"], "issue_created_at": issue_document["created_at"], "fix_created_at": pull_document["merged_at"], "contamination_band": "FRESH_B", "fresh_b_band": expected_band, "cutoff_compliant": False, "fallback_reason": "fresh_a_exhausted_predeclared_higher_contamination_fallback", "issue_retrieval_receipt_hash": reference["issue_retrieval_receipt_hash"], "fix_retrieval_receipt_hash": reference["fix_retrieval_receipt_hash"], "issue_object_receipt_hash": issue_hash, "fix_object_receipt_hash": pull_hash, "source_object_receipt_hashes": sorted((issue_hash, pull_hash)), "selection_status": "SOURCE_OBJECTS_SEALED_NOT_QUALIFIED"})
    band_order = {"B1": 0, "B2": 1, "B3": 2}
    candidates.sort(key=lambda item: (band_order[item["fresh_b_band"]], -_time(item["fix_created_at"]).timestamp(), -_time(item["issue_created_at"]).timestamp(), item["repository"], item["candidate_id"]))
    result = {"schema_id": "external_validation.session2_fresh_b_candidate_index.v1", "schema_version": "1", "reference_index_hash": reference_index_hash, "selection_effect": "source_population_only", "candidates": candidates, "exclusions": exclusions}
    payload = canonical_json(result); digest = sha256(payload).hexdigest(); target = base / "cases" / (digest + ".candidate-index.json")
    try: descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        if _is_reparse(target) or target.read_bytes() != payload: _fail("session2_fresh_b_candidate_index_collision")
    else:
        with os.fdopen(descriptor, "wb") as handle: handle.write(payload); handle.flush(); os.fsync(handle.fileno())
    return {"candidate_index_hash": "sha256:" + digest, "candidate_count": len(candidates), "exclusion_count": len(exclusions)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile Session 2 candidates from sealed GitHub retrieval receipts.")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--retrieval-frame-receipt-hash", action="append", required=True)
    parser.add_argument("--fresh-b-reference-only", action="store_true", help="Compile v2 Fresh B source links; does not select or qualify cases.")
    parsed = parser.parse_args(argv)
    try:
        compiler = compile_fresh_b_reference_candidates if parsed.fresh_b_reference_only else compile_github_issue_fix_candidates
        print(json.dumps(compiler(Path(parsed.repository_root), retrieval_frame_receipt_hashes=parsed.retrieval_frame_receipt_hash), sort_keys=True, separators=(",", ":")))
    except CandidateCompilationError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
