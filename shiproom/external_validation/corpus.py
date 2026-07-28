from __future__ import annotations

from pathlib import Path
import json
from .validators import validate_artifact
from .security import canonical_safe_path, external_root
from .v2 import FinalizationJournal

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


def validate_corpus_v2(root: Path, shiproom_root: Path, *, receipt_index: Path, case_manifest_ledger: dict[str, dict], journal: FinalizationJournal) -> dict:
    """Validate only a supervisor-produced index, never arbitrary patient bytes."""
    # Session-qualified proof runs live in a supervisor-owned namespace below
    # the one configured external root.  The namespace is not a second root:
    # it is descriptor/canonical-path constrained beneath that authority.
    configured_root = external_root(None, shiproom_root)
    evidence_root = canonical_safe_path(configured_root, root, allow_missing_leaf=False)
    if not evidence_root.is_dir():
        raise ValueError("supervisor_namespace_missing")
    index_path = canonical_safe_path(evidence_root, receipt_index, allow_missing_leaf=False)
    if not index_path.is_file(): raise ValueError("supervisor_index_missing")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(index, dict) or set(index) != {"receipts"} or not isinstance(index["receipts"], list): raise ValueError("supervisor_index_invalid")
    seen = set()
    for relative in index["receipts"]:
        if not isinstance(relative, str) or not relative.startswith("supervisor-owned/receipts/"): raise ValueError("receipt_index_path_invalid")
        path = canonical_safe_path(evidence_root, evidence_root / relative, allow_missing_leaf=False)
        item = json.loads(path.read_text(encoding="utf-8"))
        from .v2 import receipt_id_v2, validate_receipt_v2
        validate_receipt_v2(item)
        receipt_id = receipt_id_v2(item)
        if receipt_id in seen: raise ValueError("duplicate_receipt")
        seen.add(receipt_id)
        if item["case_id"] not in case_manifest_ledger: raise ValueError("case_authority_ledger_required")
        case = case_manifest_ledger[item["case_id"]]
        if item["repository"] != case.get("repository") or item["commit_sha"] != case.get("commit_sha"):
            raise ValueError("case_authority_snapshot_mismatch")
        if item["release_surfaces"] != case.get("release_surfaces"):
            raise ValueError("case_authority_surface_mismatch")
        if item["observation_inputs"]["snapshot_hash"] != case.get("snapshot_hash"):
            raise ValueError("case_authority_hash_mismatch")
        record = journal.record(item["finalization_journal_id"])
        if not record or record["phase"] != "TERMINAL_COMMITTED" or record["attempt_id"] != item["attempt_id"] or record["manifest_hash"] != item["artifact_manifest_hash"] or record["receipt_path"] != str(path):
            raise ValueError("receipt_finalization_journal_authority_missing")
    return {"receipt_count": len(seen), "receipt_ids": sorted(seen)}
