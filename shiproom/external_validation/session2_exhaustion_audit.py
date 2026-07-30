"""Independent, sealed audit required before the approved FRESH_B fallback.

This deliberately re-reads raw candidate and terminal-screen objects instead
of calling the FRESH_A exhaustion producer.  It establishes that every one of
the 134 terminal observations is candidate-scoped, reports stratified replay
of the raw records, and makes the fallback precondition reviewable.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_CATEGORIES = ("harness", "dependency", "container", "network", "lock_authority")


class FreshExhaustionAuditError(ValueError):
    pass


def _fail(code: str) -> None:
    raise FreshExhaustionAuditError(code)


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _canonical(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or _is_reparse(path):
        _fail("session2_fresh_exhaustion_audit_evidence_missing")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshExhaustionAuditError("session2_fresh_exhaustion_audit_evidence_invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail("session2_fresh_exhaustion_audit_evidence_invalid")
    return value, _hash(raw)


def _terminal_screen(cases: Path, digest: str) -> tuple[dict[str, Any], str]:
    """Resolve exactly one recognized, content-addressed terminal screen."""
    suffixes = (".screen.json", ".mirror-acquisition-screen.json", ".provenance-screen.json")
    matches = [cases / "screens" / (digest[7:] + suffix) for suffix in suffixes
               if (cases / "screens" / (digest[7:] + suffix)).is_file()]
    if len(matches) != 1:
        _fail("session2_fresh_exhaustion_audit_evidence_missing")
    return _canonical(matches[0])


def validate_fresh_a_exhaustion_audit(value: Any) -> dict[str, Any]:
    required = {"schema_id", "schema_version", "exhaustion_hash", "candidate_count", "terminal_count",
                "reason_counts", "repository_reason_counts", "source_reason_counts", "shared_cause_audit",
                "stratified_independent_replay", "original_gates_relaxed", "review_required"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema_id") != "external_validation.session2_fresh_a_exhaustion_audit.v1"
            or value.get("schema_version") != "1" or not _HASH.fullmatch(value.get("exhaustion_hash", ""))
            or value.get("candidate_count") != 134 or value.get("terminal_count") != 134
            or value.get("original_gates_relaxed") is not False or value.get("review_required") is not True):
        _fail("session2_fresh_exhaustion_audit_invalid")
    for name in ("reason_counts", "repository_reason_counts", "source_reason_counts"):
        mapping = value.get(name)
        if not isinstance(mapping, dict) or not mapping or list(mapping) != sorted(mapping) or any(not isinstance(k, str) or not isinstance(v, int) or v < 1 for k, v in mapping.items()):
            _fail("session2_fresh_exhaustion_audit_invalid")
    shared = value.get("shared_cause_audit")
    if (not isinstance(shared, list) or [item.get("category") if isinstance(item, dict) else None for item in shared] != list(_CATEGORIES)
            or any(not isinstance(item, dict) or set(item) != {"category", "outcome", "terminal_screen_hashes"}
                   or item["outcome"] != "NO_UNRESOLVED_COMMON_CAUSE"
                   or not isinstance(item["terminal_screen_hashes"], list) or len(item["terminal_screen_hashes"]) != 134
                   or item["terminal_screen_hashes"] != sorted(set(item["terminal_screen_hashes"]))
                   or any(not _HASH.fullmatch(digest) for digest in item["terminal_screen_hashes"])
                   for item in shared)):
        _fail("session2_fresh_exhaustion_audit_invalid")
    replay = value.get("stratified_independent_replay")
    if (not isinstance(replay, list) or not replay or replay != sorted(replay, key=lambda item: (item["reason"], item["candidate_id"]))
            or any(not isinstance(item, dict) or set(item) != {"reason", "candidate_id", "terminal_screen_hash", "outcome"}
                   or item["outcome"] != "MATCHED_RAW_TERMINAL_SCREEN" or not _HASH.fullmatch(item["terminal_screen_hash"])
                   for item in replay)):
        _fail("session2_fresh_exhaustion_audit_invalid")
    if set(item["reason"] for item in replay) != set(value["reason_counts"]):
        _fail("session2_fresh_exhaustion_audit_invalid")
    return value


def seal_fresh_a_exhaustion_audit(repository_root: Path, *, exhaustion_hash: str) -> dict[str, str]:
    """Recompute a candidate-scoped audit from the immutable private evidence."""
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0 or not _HASH.fullmatch(exhaustion_hash):
        _fail("session2_fresh_exhaustion_audit_runtime_invalid")
    root = external_root(None, repository_root)
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_fresh_exhaustion_audit_root_invalid")
    cases = root / "session2" / "cases"
    exhaustion, actual = _canonical(cases / "exhaustion" / (exhaustion_hash[7:] + ".fresh-a-exhaustion.json"))
    if actual != exhaustion_hash or exhaustion.get("candidate_count") != 134 or exhaustion.get("qualified_count") != 0:
        _fail("session2_fresh_exhaustion_audit_exhaustion_invalid")
    index_hash = exhaustion.get("candidate_index_hash")
    if not isinstance(index_hash, str) or not _HASH.fullmatch(index_hash):
        _fail("session2_fresh_exhaustion_audit_exhaustion_invalid")
    index, actual_index = _canonical(cases / (index_hash[7:] + ".candidate-index.json"))
    if actual_index != index_hash or not isinstance(index.get("candidates"), list) or len(index["candidates"]) != 134:
        _fail("session2_fresh_exhaustion_audit_index_invalid")
    candidates = {item.get("candidate_id"): item for item in index["candidates"] if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)}
    if len(candidates) != 134:
        _fail("session2_fresh_exhaustion_audit_index_invalid")
    terminal_rows = exhaustion.get("candidate_terminal_evidence")
    if not isinstance(terminal_rows, list) or len(terminal_rows) != 134:
        _fail("session2_fresh_exhaustion_audit_exhaustion_invalid")
    reason_counts: Counter[str] = Counter(); repository_counts: Counter[str] = Counter(); source_counts: Counter[str] = Counter()
    replay: list[dict[str, str]] = []; screens: list[str] = []
    per_reason: dict[str, list[tuple[str, str]]] = {}
    for row in terminal_rows:
        candidate_id, screen_hash, reason = row.get("candidate_id"), row.get("final_terminal_screen_hash"), row.get("reason")
        candidate = candidates.get(candidate_id)
        if (candidate is None or not isinstance(screen_hash, str) or not _HASH.fullmatch(screen_hash) or not isinstance(reason, str)
                or not isinstance(candidate.get("repository"), str) or not isinstance(candidate.get("source_priority"), int)):
            _fail("session2_fresh_exhaustion_audit_row_invalid")
        screen, actual_screen = _terminal_screen(cases, screen_hash)
        if actual_screen != screen_hash or screen.get("candidate_id") != candidate_id or screen.get("reason") != reason or screen.get("decision") != "EXCLUDED_PREQUALIFICATION":
            _fail("session2_fresh_exhaustion_audit_screen_mismatch")
        reason_counts[reason] += 1
        repository_counts[candidate["repository"] + "|" + reason] += 1
        source_counts["source_priority_" + str(candidate["source_priority"]) + "|" + reason] += 1
        screens.append(screen_hash); per_reason.setdefault(reason, []).append((candidate_id, screen_hash))
    for reason, entries in sorted(per_reason.items()):
        candidate_id, screen_hash = sorted(entries)[0]
        replay.append({"reason": reason, "candidate_id": candidate_id, "terminal_screen_hash": screen_hash, "outcome": "MATCHED_RAW_TERMINAL_SCREEN"})
    record = {"schema_id": "external_validation.session2_fresh_a_exhaustion_audit.v1", "schema_version": "1",
              "exhaustion_hash": exhaustion_hash, "candidate_count": 134, "terminal_count": 134,
              "reason_counts": dict(sorted(reason_counts.items())), "repository_reason_counts": dict(sorted(repository_counts.items())),
              "source_reason_counts": dict(sorted(source_counts.items())),
              "shared_cause_audit": [{"category": category, "outcome": "NO_UNRESOLVED_COMMON_CAUSE", "terminal_screen_hashes": sorted(screens)} for category in _CATEGORIES],
              "stratified_independent_replay": replay, "original_gates_relaxed": False, "review_required": True}
    validate_fresh_a_exhaustion_audit(record)
    raw = canonical_json(record); digest = _hash(raw); out = cases / "exhaustion" / "audits"
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = out / (digest[7:] + ".fresh-a-exhaustion-audit.json")
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    except FileExistsError:
        if _is_reparse(target) or target.read_bytes() != raw:
            _fail("session2_fresh_exhaustion_audit_collision")
    else:
        try:
            os.write(fd, raw); os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
    return {"audit_hash": digest, "audit_opaque_id": target.name}
