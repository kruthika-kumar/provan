from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .identity import canonical_json, receipt_id
from .validators import validate_artifact, validate_receipt_against_case
from .security import canonical_safe_path, external_root
from .security import sha256_file

def finalize_receipt(value: dict[str, Any], destination: Path, evidence_root: Path, shiproom_root: Path, patient_root: Path | None = None, *, artifact_paths: dict[str, Path], case_manifest: dict[str, Any]) -> dict[str, Any]:
    """Only the host supervisor calls this after collecting untrusted raw output."""
    if value.get("supervisor") != "host_supervisor": raise PermissionError("patient_cannot_finalize_receipt")
    trusted_root = external_root(str(evidence_root), shiproom_root, patient_root)
    destination = canonical_safe_path(trusted_root, destination)
    required = {"source", "release_packet", "output"}
    if set(artifact_paths) != required: raise ValueError("receipt_artifact_paths_incomplete")
    for name, path in artifact_paths.items():
        safe = canonical_safe_path(trusted_root, path, allow_missing_leaf=False)
        if not safe.is_file() or value.get("hashes", {}).get(name) != sha256_file(safe): raise ValueError("receipt_artifact_hash_mismatch")
    receipt = json.loads(json.dumps(value))
    receipt["receipt_id"] = ""
    receipt.setdefault("hashes", {})["receipt"] = ""
    payload = dict(receipt); payload.pop("receipt_id"); hashes = dict(payload["hashes"]); hashes.pop("receipt"); payload["hashes"] = hashes
    digest = "sha256:" + __import__("hashlib").sha256(canonical_json(payload)).hexdigest()
    receipt["hashes"]["receipt"] = digest; receipt["receipt_id"] = "receipt_" + digest.removeprefix("sha256:")
    validate_receipt_against_case(receipt, case_manifest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists(): raise FileExistsError("finalized_receipt_exists")
    fd, temp = tempfile.mkstemp(prefix="receipt-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle: handle.write(canonical_json(receipt)); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, destination)
    except Exception:
        try: os.unlink(temp)
        except FileNotFoundError: pass
        raise
    return receipt
