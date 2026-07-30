"""Supervisor-owned authority for a completed fresh-contamination tier.

An exhausted tier is evidence, not permission to select a fallback.  The
separate reviewer gate remains mandatory before any lower-contamination tier
is collected or selected.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import stat
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASONS = {
    "DEPENDENCY_AUTHORITY_NOT_FROZEN", "FIXED_TWIN_NON_MINIMAL",
    "UNSAFE_PATIENT_TREE_ENTRY", "UNQUALIFIED_LINUX_CONTAINER_PATH",
    "NO_AUTHORITATIVE_EXECUTABLE_TARGET_CONTRACT",
    "REQUIRES_FORBIDDEN_SERVICE_OR_CREDENTIAL",
    "MIRROR_ACQUISITION_TIMED_OUT", "PRIMARY_RETRIEVAL_RECEIPT_UNAVAILABLE",
}


class FreshExhaustionError(ValueError):
    pass


def _fail(code: str) -> None:
    raise FreshExhaustionError(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def validate_fresh_a_exhaustion(value: Any) -> dict[str, Any]:
    required = {
        "schema_id", "schema_version", "candidate_index_hash", "band",
        "candidate_count", "qualified_count", "status",
        "review_approval_required", "candidate_terminal_evidence", "reason_counts",
    }
    if not isinstance(value, dict) or set(value) != required:
        _fail("session2_fresh_exhaustion_structure_invalid")
    if (value.get("schema_id") != "external_validation.session2_fresh_a_exhaustion.v1"
            or value.get("schema_version") != "1" or value.get("band") != "FRESH_A"
            or value.get("status") != "EXHAUSTED_PENDING_REVIEW"
            or value.get("qualified_count") != 0
            or value.get("review_approval_required") is not True
            or not _HASH.fullmatch(value.get("candidate_index_hash", ""))):
        _fail("session2_fresh_exhaustion_authority_invalid")
    rows = value.get("candidate_terminal_evidence")
    if not isinstance(rows, list) or not rows or value.get("candidate_count") != len(rows):
        _fail("session2_fresh_exhaustion_count_invalid")
    previous = ""
    reasons: Counter[str] = Counter()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"candidate_id", "final_terminal_screen_hash", "terminal_screen_hashes", "reason"}:
            _fail("session2_fresh_exhaustion_row_invalid")
        candidate_id, final, all_hashes, reason = (row["candidate_id"], row["final_terminal_screen_hash"], row["terminal_screen_hashes"], row["reason"])
        if (not isinstance(candidate_id, str) or not candidate_id or candidate_id <= previous
                or not _HASH.fullmatch(final) or not isinstance(all_hashes, list)
                or all_hashes != sorted(set(all_hashes)) or final not in all_hashes
                or any(not _HASH.fullmatch(item) for item in all_hashes)
                or reason not in _REASONS):
            _fail("session2_fresh_exhaustion_row_invalid")
        previous = candidate_id
        reasons[reason] += 1
    if value.get("reason_counts") != dict(sorted(reasons.items())):
        _fail("session2_fresh_exhaustion_reason_counts_invalid")
    return value


def _canonical_record(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or _is_reparse(path):
        _fail("session2_fresh_exhaustion_evidence_missing")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshExhaustionError("session2_fresh_exhaustion_evidence_invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail("session2_fresh_exhaustion_evidence_invalid")
    return value, _sha(raw)


def seal_fresh_a_exhaustion(repository_root: Path, *, candidate_index_hash: str) -> dict[str, str]:
    """Recompute and seal an exhaustion record from immutable terminal evidence."""
    if (os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0
            or not _HASH.fullmatch(candidate_index_hash)):
        _fail("session2_fresh_exhaustion_runtime_invalid")
    root = external_root(None, repository_root)
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_fresh_exhaustion_root_invalid")
    cases = root / "session2" / "cases"
    index, actual_index_hash = _canonical_record(cases / (candidate_index_hash[7:] + ".candidate-index.json"))
    if actual_index_hash != candidate_index_hash or not isinstance(index.get("candidates"), list):
        _fail("session2_fresh_exhaustion_index_invalid")
    candidates = index["candidates"]
    ids = [item.get("candidate_id") for item in candidates if isinstance(item, dict)]
    if (len(ids) != len(candidates) or len(set(ids)) != len(ids)
            or any(item.get("contamination_band") != "FRESH_A" for item in candidates if isinstance(item, dict))):
        _fail("session2_fresh_exhaustion_band_invalid")
    terminal: dict[str, list[tuple[str, str, str]]] = {item: [] for item in ids}
    for path in (cases / "screens").glob("*.json"):
        record, digest = _canonical_record(path)
        candidate_id = record.get("candidate_id")
        if candidate_id not in terminal or record.get("decision") != "EXCLUDED_PREQUALIFICATION":
            continue
        created, reason = record.get("created_at"), record.get("reason")
        if not isinstance(created, str) or reason not in _REASONS:
            _fail("session2_fresh_exhaustion_terminal_invalid")
        terminal[candidate_id].append((created, digest, reason))
    rows = []
    for candidate_id in sorted(terminal):
        evidence = terminal[candidate_id]
        if not evidence:
            _fail("session2_fresh_exhaustion_nonterminal_candidate")
        final = max(evidence)
        rows.append({"candidate_id": candidate_id, "final_terminal_screen_hash": final[1],
                     "terminal_screen_hashes": sorted({item[1] for item in evidence}), "reason": final[2]})
    reasons = Counter(item["reason"] for item in rows)
    record = {"schema_id": "external_validation.session2_fresh_a_exhaustion.v1", "schema_version": "1",
              "candidate_index_hash": candidate_index_hash, "band": "FRESH_A", "candidate_count": len(rows),
              "qualified_count": 0, "status": "EXHAUSTED_PENDING_REVIEW", "review_approval_required": True,
              "candidate_terminal_evidence": rows, "reason_counts": dict(sorted(reasons.items()))}
    validate_fresh_a_exhaustion(record)
    raw = canonical_json(record); digest = _sha(raw)
    out = cases / "exhaustion"; out.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = out / (digest[7:] + ".fresh-a-exhaustion.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw:
            _fail("session2_fresh_exhaustion_collision")
    else:
        try:
            os.write(fd, raw); os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
    return {"exhaustion_hash": digest, "exhaustion_opaque_id": path.name}
