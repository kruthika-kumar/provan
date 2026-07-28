"""Primary, receipt-backed public retrieval for Session 2.

This module is intentionally narrow: it obtains public GitHub issue metadata
and seals exactly the raw bytes returned by the API.  It does *not* decide that
an issue is a qualified case; checkout, oracle, dependency and replay gates
remain separate production steps.  Keeping those two actions apart prevents a
convenient search response from becoming an asserted qualification result.

It is a WSL/Linux-only private-evidence operation.  Public callers receive a
portable receipt with opaque raw-artifact IDs and content hashes, never an
external-root path.
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
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2_selection import validate_retrieval_receipt


class RetrievalError(RuntimeError):
    """Stable error raised when a primary retrieval receipt cannot be sealed."""


_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')
_SHA = re.compile(r"^[0-9a-f]{64}$")
_API = "https://api.github.com/search/issues"
_PARSER_ID = "session2_github_issue_retrieval.v1"


def _fail(code: str) -> None:
    raise RetrievalError(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _assert_linux_private_operation(repository_root: Path) -> Path:
    """Resolve the one declared root; never accept a caller-provided path."""
    if os.name != "posix" or platform.system() != "Linux":
        _fail("session2_retrieval_requires_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise RetrievalError("session2_retrieval_external_root_invalid") from exc
    expected = Path("/var/lib/shiproom-external-validation")
    if root != expected or str(root).startswith("/mnt/") or _is_reparse(root):
        _fail("session2_retrieval_external_root_invalid")
    session2 = root / "session2" / "retrieval"
    if not session2.is_dir() or _is_reparse(session2):
        _fail("session2_retrieval_namespace_missing")
    raw = session2 / "raw"
    raw.mkdir(mode=0o700, exist_ok=True)
    if _is_reparse(raw):
        _fail("session2_retrieval_raw_store_invalid")
    return raw


def _write_once(path: Path, raw: bytes) -> None:
    """Content-addressed immutable write; a collision must have equal bytes."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        if not path.is_file() or _is_reparse(path) or path.read_bytes() != raw:
            _fail("session2_retrieval_hash_collision")
        return
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _next_page(headers: Any) -> int | None:
    link = headers.get("Link") if headers else None
    if not link:
        return None
    match = _NEXT_RE.search(link)
    if not match:
        return None
    values = parse_qs(urlparse(match.group(1)).query).get("page")
    if not values or len(values) != 1 or not values[0].isdigit() or int(values[0]) < 2:
        _fail("session2_retrieval_next_link_invalid")
    return int(values[0])


def _candidate_ids(document: dict[str, Any]) -> list[str]:
    items = document.get("items")
    if not isinstance(items, list):
        _fail("session2_retrieval_response_invalid")
    result: list[str] = []
    for item in items:
        repository = item.get("repository_url") if isinstance(item, dict) else None
        number = item.get("number") if isinstance(item, dict) else None
        if not isinstance(repository, str) or not repository.startswith("https://api.github.com/repos/") or not isinstance(number, int) or number < 1:
            _fail("session2_retrieval_response_invalid")
        result.append(repository.removeprefix("https://api.github.com/repos/") + "#" + str(number))
    if len(result) != len(set(result)):
        _fail("session2_retrieval_duplicate_candidate")
    return result


def retrieve_github_issues(
    repository_root: Path,
    *,
    query: str,
    filters: dict[str, str],
    max_pages: int = 10,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Retrieve complete paginated GitHub search pages and seal their bytes."""
    if not isinstance(query, str) or not query or not isinstance(filters, dict) or not filters:
        _fail("session2_retrieval_query_invalid")
    if not isinstance(max_pages, int) or not 1 <= max_pages <= 10 or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        _fail("session2_retrieval_bounds_invalid")
    raw_store = _assert_linux_private_operation(repository_root)
    page = 1
    pages: list[dict[str, Any]] = []
    all_ids: list[str] = []
    while page is not None:
        if len(pages) >= max_pages:
            _fail("session2_retrieval_pagination_limit_reached")
        request_url = _API + "?" + "&".join((
            "q=" + quote(query, safe=""),
            "per_page=100",
            "page=" + str(page),
        ))
        request = Request(request_url, headers={"Accept": "application/vnd.github+json", "User-Agent": "shiproom-session2-retrieval/1"})
        try:
            with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310: fixed HTTPS GitHub API
                raw = response.read()
                headers = response.headers
        except HTTPError as exc:
            raise RetrievalError("session2_retrieval_http_" + str(exc.code)) from exc
        except URLError as exc:
            raise RetrievalError("session2_retrieval_network_failure") from exc
        digest = _sha(raw)
        hex_digest = digest[7:]
        if not _SHA.fullmatch(hex_digest):
            _fail("session2_retrieval_hash_invalid")
        _write_once(raw_store / (hex_digest + ".json"), raw)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RetrievalError("session2_retrieval_response_invalid") from exc
        candidate_ids = _candidate_ids(document)
        next_page = _next_page(headers)
        # GitHub must make forward progress; a loop is an incomplete frame.
        if next_page is not None and next_page != page + 1:
            _fail("session2_retrieval_pagination_gap")
        pages.append({"page": page, "raw_response_hash": digest, "candidate_ids": candidate_ids, "next_page": next_page})
        all_ids.extend(candidate_ids)
        page = next_page
    receipt = {
        "schema_id": "external_validation.session2_retrieval_receipt.v1",
        "schema_version": "1",
        "source": "github_search_issues_api",
        "query": query,
        "filters": filters,
        "retrieved_at": _utc(),
        "parser_id": _PARSER_ID,
        "pages": pages,
        "candidate_ids": all_ids,
    }
    validate_retrieval_receipt(receipt)
    payload = canonical_json(receipt)
    receipt_hash = sha256(payload).hexdigest()
    _write_once(raw_store.parent / (receipt_hash + ".retrieval-receipt.json"), payload)
    return {**receipt, "receipt_hash": "sha256:" + receipt_hash}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal primary GitHub issue retrieval for Session 2.")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--filters-json", required=True)
    parser.add_argument("--max-pages", type=int, default=10)
    parsed = parser.parse_args(argv)
    try:
        filters = json.loads(parsed.filters_json)
        result = retrieve_github_issues(Path(parsed.repository_root), query=parsed.query, filters=filters, max_pages=parsed.max_pages)
    except (json.JSONDecodeError, RetrievalError) as exc:
        print(str(exc))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
