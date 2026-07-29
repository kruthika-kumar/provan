"""Finalize a complete, predeclared Session 2 primary-retrieval frame.

The candidate compiler may only consume the immutable frame receipt emitted
here.  Retained search receipts are useful evidence, but their mere presence
does not prove that every query in a frozen frame completed.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2 import validate_retrieval_frame
from .session2_selection import validate_retrieval_receipt

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class RetrievalFrameError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise RetrievalFrameError(code)


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_retrieval_frame_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise RetrievalFrameError("session2_retrieval_frame_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_retrieval_frame_external_root_invalid")
    return root


def _expected(frame: dict[str, Any]) -> dict[tuple[str, str, str], tuple[str, dict[str, str]]]:
    result: dict[tuple[str, str, str], tuple[str, dict[str, str]]] = {}
    for window in frame["query_windows"]:
        start, end = window["start"], window["end"]
        for kind in frame["kinds"]:
            if kind == "issue":
                query = f"repo:{frame['repository']} is:issue is:closed created:{start[:10]}..{end[:10]}"
                filters = {"kind": "issue", "state": "closed", "created_from": start, "created_to": end}
            else:
                query = f"repo:{frame['repository']} is:pr is:merged merged:{start[:10]}..{end[:10]}"
                filters = {"kind": "pull_request", "state": "merged", "merged_from": start, "merged_to": end}
            key = (kind, start, end)
            if key in result:
                _fail("session2_retrieval_frame_expected_duplicate")
            result[key] = (query, filters)
    return result


def _frame_authority(repository_root: Path, frame_relative_path: str) -> tuple[dict[str, Any], str, str]:
    if (not isinstance(frame_relative_path, str) or not frame_relative_path
            or Path(frame_relative_path).is_absolute() or ".." in Path(frame_relative_path).parts):
        _fail("session2_retrieval_frame_path_invalid")
    path = repository_root / frame_relative_path
    if not path.is_file() or _is_reparse(path):
        _fail("session2_retrieval_frame_path_invalid")
    raw = path.read_bytes()
    try:
        frame = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetrievalFrameError("session2_retrieval_frame_invalid") from exc
    if canonical_json(frame) != raw.rstrip(b"\n"):
        _fail("session2_retrieval_frame_noncanonical")
    validate_retrieval_frame(frame)
    provenance_path = repository_root / "stage-provenance.json"
    if not provenance_path.is_file() or _is_reparse(provenance_path):
        _fail("session2_retrieval_frame_stage_provenance_missing")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetrievalFrameError("session2_retrieval_frame_stage_provenance_invalid") from exc
    matching = [item for item in provenance.get("files", []) if isinstance(item, dict) and item.get("path") == frame_relative_path]
    if len(matching) != 1 or matching[0].get("sha256") != _hash(raw) or not isinstance(matching[0].get("git_blob"), str):
        _fail("session2_retrieval_frame_stage_provenance_invalid")
    return frame, _hash(raw), matching[0]["git_blob"]


def seal_retrieval_frame(repository_root: Path, *, frame_relative_path: str) -> dict[str, str]:
    """Seal only after each declared query has exactly one full receipt."""
    root = _root(repository_root)
    frame, frame_hash, frame_git_blob = _frame_authority(repository_root, frame_relative_path)
    expected = _expected(frame)
    found: dict[tuple[str, str, str], tuple[str, dict[str, Any]]] = {}
    for path in sorted((root / "session2" / "retrieval").glob("*.retrieval-receipt.json")):
        if _is_reparse(path):
            _fail("session2_retrieval_frame_receipt_invalid")
        raw = path.read_bytes()
        try:
            receipt = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RetrievalFrameError("session2_retrieval_frame_receipt_invalid") from exc
        if canonical_json(receipt) != raw:
            _fail("session2_retrieval_frame_receipt_invalid")
        validate_retrieval_receipt(receipt)
        for page in receipt["pages"]:
            raw_path = root / "session2" / "retrieval" / "raw" / (page["raw_response_hash"][7:] + ".json")
            if not raw_path.is_file() or _is_reparse(raw_path) or _hash(raw_path.read_bytes()) != page["raw_response_hash"]:
                _fail("session2_retrieval_frame_raw_missing")
        for key, (query, filters) in expected.items():
            if receipt["query"] != query or receipt["filters"] != filters:
                continue
            if key in found:
                _fail("session2_retrieval_frame_receipt_duplicate")
            found[key] = (_hash(raw), receipt)
    if set(found) != set(expected):
        _fail("session2_retrieval_frame_receipts_incomplete")
    receipts = []
    for kind, start, end in sorted(found):
        digest, receipt = found[(kind, start, end)]
        receipts.append({"kind": kind, "start": start, "end": end, "receipt_hash": digest,
                         "candidate_count": len(receipt["candidate_ids"])})
    record = {"schema_id": "external_validation.session2_retrieval_frame_receipts.v1", "schema_version": "1",
              "frame_relative_path": frame_relative_path, "frame_hash": frame_hash, "frame_git_blob": frame_git_blob,
              "repository": frame["repository"], "predecessor_candidate_index_hash": frame["predecessor_candidate_index_hash"],
              "receipts": receipts}
    payload = canonical_json(record); digest = _hash(payload)
    directory = root / "session2" / "retrieval" / "frames"
    directory.mkdir(mode=0o700, exist_ok=True)
    target = directory / (digest[7:] + ".retrieval-frame-receipts.json")
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if _is_reparse(target) or target.read_bytes() != payload:
            _fail("session2_retrieval_frame_collision")
    else:
        try:
            if os.write(descriptor, payload) != len(payload):
                _fail("session2_retrieval_frame_short_write")
                os.fsync(descriptor)
                if hasattr(os, "fchown"):
                    os.fchown(descriptor, 0, 0)
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
    return {"retrieval_frame_receipt_hash": digest, "retrieval_frame_receipt_opaque_id": target.name}
