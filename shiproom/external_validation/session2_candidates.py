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


def _receipt_documents(base: Path) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    result: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for path in sorted((base / "retrieval").glob("*.retrieval-receipt.json")):
        if _is_reparse(path):
            _fail("session2_candidate_receipt_reparse")
        receipt = json.loads(path.read_text(encoding="utf-8"))
        validate_retrieval_receipt(receipt)
        documents = [_read_hash(base / "retrieval" / "raw" / (page["raw_response_hash"][7:] + ".json"), page["raw_response_hash"]) for page in receipt["pages"]]
        result.append((receipt, documents))
    if not result:
        _fail("session2_candidate_retrieval_missing")
    return result


def _slug(item: dict[str, Any]) -> str:
    source = item.get("repository_url")
    prefix = "https://api.github.com/repos/"
    if not isinstance(source, str) or not source.startswith(prefix):
        _fail("session2_candidate_raw_invalid")
    return source.removeprefix(prefix)


def compile_github_issue_fix_candidates(repository_root: Path) -> dict[str, Any]:
    """Seal one candidate index from the existing issue/PR retrieval receipts."""
    base = _root(repository_root)
    issues: dict[tuple[str, int], tuple[dict[str, Any], str]] = {}
    pulls: list[tuple[dict[str, Any], str]] = []
    source_receipts: list[str] = []
    for receipt, documents in _receipt_documents(base):
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
    candidates: list[dict[str, Any]] = []
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
            candidates.append({
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
            })
            linked_issues.add(key)
    candidates.sort(key=lambda item: (_time(item["issue_created_at"]), item["candidate_id"]))
    exclusions = [{"repository": slug, "issue_number": number, "reason": "no_public_closing_merged_pr_in_retrieved_frame"} for slug, number in sorted(set(issues) - linked_issues)]
    result = {
        "schema_id": "external_validation.session2_github_issue_fix_candidate_index.v1",
        "schema_version": "1",
        "source_receipt_hashes": sorted(source_receipts),
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile Session 2 candidates from sealed GitHub retrieval receipts.")
    parser.add_argument("--repository-root", required=True)
    parsed = parser.parse_args(argv)
    try:
        print(json.dumps(compile_github_issue_fix_candidates(Path(parsed.repository_root)), sort_keys=True, separators=(",", ":")))
    except CandidateCompilationError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
