"""Supervisor-only v2 receipt finalization and index projection."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .identity import canonical_json
from .security import sha256_file
from .v2 import FinalizationJournal, receipt_id_v2, validate_artifact_manifest, validate_receipt_v2


def finalize_v2(*, receipt: dict[str, Any], manifest: dict[str, Any], manifest_path: Path, artifacts: dict[str, Path], journal: FinalizationJournal, destination: Path) -> tuple[str, dict[str, Any]]:
    """Seal an already-contained observation; patient code has no write path here."""
    validate_artifact_manifest(manifest)
    manifest_hash = sha256_file(manifest_path)
    if receipt.get("artifact_manifest_hash") != manifest_hash: raise ValueError("receipt_manifest_hash_mismatch")
    if not journal.can_adopt(receipt.get("finalization_journal_id", ""), receipt.get("attempt_id", ""), manifest_hash, str(destination)):
        raise PermissionError("finalization_journal_authority_missing")
    for name, path in artifacts.items():
        if not path.is_file(): raise ValueError("receipt_artifact_missing:" + name)
        expected = next((entry for entry in manifest["artifacts"] if entry["path"] == name), None)
        if expected is None or expected["sha256"] != sha256_file(path): raise ValueError("receipt_artifact_hash_mismatch:" + name)
    validate_receipt_v2(receipt)
    rid = receipt_id_v2(receipt)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if canonical_json(json.loads(destination.read_text(encoding="utf-8"))) != canonical_json(receipt): raise FileExistsError("conflicting_final_receipt")
        if journal.record(receipt["finalization_journal_id"])["phase"] == "PREPARED":
            journal.phase(receipt["finalization_journal_id"], "PREPARED", "RECEIPT_DURABLE")
        return rid, receipt
    fd, temporary = tempfile.mkstemp(prefix="receipt-v2-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(receipt)); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, destination)
        # Parent metadata is part of durability on filesystems that support it.
        try:
            directory = os.open(destination.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        except (PermissionError, OSError):
            # Windows does not expose a portable directory fsync.  The receipt
            # remains in PREPARED/RECEIPT_DURABLE journal state and recovery
            # rehashes it; doctor reports this platform capability separately.
            if os.name != "nt": raise
        journal.phase(receipt["finalization_journal_id"], "PREPARED", "RECEIPT_DURABLE")
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    return rid, receipt


def write_index(receipts: list[tuple[str, Path]], destination: Path) -> None:
    """A reproducible projection: IDs and canonical supervisor-relative paths only."""
    value = {"receipts": [path.as_posix() for _, path in sorted(receipts)]}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json(value))
