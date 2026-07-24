from __future__ import annotations

from pathlib import Path
import json
from .validators import validate_artifact
from .security import canonical_safe_path, external_root

def validate_corpus(root: Path, shiproom_root: Path, patient_root: Path | None = None, *, case_manifest_ledger: dict[str, dict] | None = None) -> dict:
    """Fail closed across the full evidence root, not merely one mutable index."""
    evidence_root = external_root(str(root), shiproom_root, patient_root)
    seen = {"observation_key": set(), "attempt_id": set(), "receipt_id": set()}
    receipts = []
    for path in evidence_root.rglob("*.json"):
        safe = canonical_safe_path(evidence_root, path, allow_missing_leaf=False)
        value = json.loads(safe.read_text(encoding="utf-8"))
        if value.get("schema_id") == "external_validation.run_receipt":
            validate_artifact(value)
            if case_manifest_ledger is None or value["case_id"] not in case_manifest_ledger:
                raise ValueError("case_authority_ledger_required")
            from .validators import validate_receipt_against_case
            validate_receipt_against_case(value, case_manifest_ledger[value["case_id"]])
            receipts.append(value)
            for key in seen:
                item = value.get(key)
                if not item: continue
                if item in seen[key]: raise ValueError("duplicate_" + key)
                seen[key].add(item)
    return {"receipt_count": len(receipts), "receipt_ids": sorted(seen["receipt_id"])}
