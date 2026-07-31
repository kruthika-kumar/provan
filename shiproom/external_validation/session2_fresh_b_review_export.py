"""Export a redacted, non-authoritative Fresh-B review view from private evidence.

The view exists only to give a fresh read-only reviewer inspectable evidence
without disclosing candidate identities or private-root paths.  It is never a
qualification authority: every entry carries the hash of the canonical,
root-owned source object that this root-only exporter revalidated.
"""
from __future__ import annotations

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
from .session2_exhaustion import validate_fresh_a_exhaustion
from .session2_exhaustion_audit import validate_fresh_a_exhaustion_audit
from .session2_selection import validate_retrieval_receipt

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXHAUSTION = "sha256:33b510241e6af28a89b9e956c95f210b1a0b0182f66e153bb23f3f1f520e3a95"
_AUDIT = "sha256:d070accaf053ad573721da7d72b2123f28df5f5aa0825abd4c80a98909e6dcbc"
_AUTHORITY = "sha256:63ad19e0898687a1c492c3c8323e3746985efa2b24a8a3f9e1b1bf4631387f5f"
_START = "2026-07-30T10:46:32.627787Z"
_REPOSITORIES = ("dlt-hub/dlt", "formbricks/formbricks", "healthchecks/healthchecks", "inventree/InvenTree", "pretalx/pretalx", "pretix/pretix", "pypa/hatch")


class FreshBReviewExportError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise FreshBReviewExportError(code)


def _hash(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _canonical(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or _is_reparse(path):
        _fail("session2_fresh_b_review_evidence_missing")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshBReviewExportError("session2_fresh_b_review_evidence_invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail("session2_fresh_b_review_evidence_invalid")
    return value, _hash(raw)


def _assert_private(path: Path, directory: bool) -> None:
    value = path.lstat()
    if (stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_gid != 0
            or (directory and (not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700))
            or (not directory and (not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o400 or value.st_nlink != 1))):
        _fail("session2_fresh_b_review_private_authority_invalid")


def export_fresh_b_review_view(repository_root: Path, *, output_directory: Path) -> dict[str, str]:
    """Root-only traversal of canonical evidence into a reviewer-readable view."""
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        _fail("session2_fresh_b_review_requires_root_linux_wsl")
    root = external_root(None, repository_root)
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        _fail("session2_fresh_b_review_root_invalid")
    for item in (root, root / "session2", root / "session2" / "cases", root / "session2" / "retrieval", root / "session2" / "retrieval" / "frames"):
        _assert_private(item, True)
    cases = root / "session2" / "cases"
    exhaustion, digest = _canonical(cases / "exhaustion" / (_EXHAUSTION[7:] + ".fresh-a-exhaustion.json"))
    if digest != _EXHAUSTION:
        _fail("session2_fresh_b_review_exhaustion_hash_invalid")
    validate_fresh_a_exhaustion(exhaustion)
    audit, audit_digest = _canonical(cases / "exhaustion" / "audits" / (_AUDIT[7:] + ".fresh-a-exhaustion-audit.json"))
    if audit_digest != _AUDIT or audit.get("exhaustion_hash") != _EXHAUSTION:
        _fail("session2_fresh_b_review_audit_hash_invalid")
    validate_fresh_a_exhaustion_audit(audit)
    frames: list[dict[str, Any]] = []
    for path in sorted((root / "session2" / "retrieval" / "frames").glob("*.retrieval-frame-receipts.json")):
        record, record_hash = _canonical(path)
        if record.get("schema_id") != "external_validation.session2_fresh_b_retrieval_frame_receipts.v2":
            continue
        if (record.get("fresh_b_authority_hash") != _AUTHORITY or record.get("fresh_a_exhaustion_hash") != _EXHAUSTION
                or record.get("retrieval_not_before") != _START or record.get("repository") not in _REPOSITORIES):
            _fail("session2_fresh_b_review_frame_authority_invalid")
        receipts = record.get("receipts")
        if not isinstance(receipts, list) or len(receipts) != 8:
            _fail("session2_fresh_b_review_frame_incomplete")
        entries: list[dict[str, Any]] = []
        for entry in receipts:
            if not isinstance(entry, dict) or not _HASH.fullmatch(entry.get("receipt_hash", "")):
                _fail("session2_fresh_b_review_frame_invalid")
            receipt, receipt_hash = _canonical(root / "session2" / "retrieval" / (entry["receipt_hash"][7:] + ".retrieval-receipt.json"))
            if receipt_hash != entry["receipt_hash"] or receipt.get("retrieved_at", "") < _START:
                _fail("session2_fresh_b_review_receipt_invalid")
            validate_retrieval_receipt(receipt)
            raw_hashes = []
            for page in receipt["pages"]:
                raw = root / "session2" / "retrieval" / "raw" / (page["raw_response_hash"][7:] + ".json")
                if not raw.is_file() or _is_reparse(raw) or _hash(raw.read_bytes()) != page["raw_response_hash"]:
                    _fail("session2_fresh_b_review_raw_missing")
                raw_hashes.append(page["raw_response_hash"])
            entries.append({"kind": entry["kind"], "start": entry["start"], "end": entry["end"],
                            "receipt_hash": entry["receipt_hash"], "retrieved_at": receipt["retrieved_at"],
                            "page_count": len(receipt["pages"]), "candidate_count": entry["candidate_count"],
                            "raw_response_hashes": raw_hashes})
        frames.append({"repository": record["repository"], "frame_receipt_hash": record_hash,
                       "frame_hash": record["frame_hash"], "frame_git_blob": record["frame_git_blob"], "receipts": entries})
    frames.sort(key=lambda item: item["repository"])
    if [item["repository"] for item in frames] != list(_REPOSITORIES):
        _fail("session2_fresh_b_review_frame_set_invalid")
    view = {"schema_id": "external_validation.session2_fresh_b_sanitized_review_view.v1", "schema_version": "1",
            "authority": "NON_AUTHORITATIVE_SANITIZED_REVIEW_VIEW", "private_root_verified": True,
            "fresh_a": {"exhaustion_hash": _EXHAUSTION, "candidate_count": exhaustion["candidate_count"],
                        "qualified_count": exhaustion["qualified_count"], "reason_counts": exhaustion["reason_counts"],
                        "audit_hash": _AUDIT, "audit_reason_counts": audit["reason_counts"],
                        "original_gates_relaxed": audit["original_gates_relaxed"]},
            "fresh_b": {"authority_hash": _AUTHORITY, "retrieval_not_before": _START, "frame_count": len(frames), "frames": frames},
            "prohibited_work": {"evaluated_model_calls": 0, "patient_execution": 0, "candidate_qualification": 0}}
    raw = canonical_json(view); digest = _hash(raw)
    output_directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = output_directory / (digest[7:] + ".fresh-b-sanitized-review.json")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o444)
    try:
        if os.write(fd, raw) != len(raw):
            _fail("session2_fresh_b_review_short_write")
        os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o444)
    finally:
        os.close(fd)
    return {"review_view_hash": digest, "review_view_path": str(target)}
