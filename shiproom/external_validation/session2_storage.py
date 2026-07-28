"""External-root authority for Session 2.

This deliberately resolves the configured root once through the Session 1
security contract.  It never scans for a plausible directory and never embeds
an absolute external path into a public artifact.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
from typing import Any

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2 import BudgetLedger, BudgetPolicy


class Session2StorageError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise Session2StorageError(code)


def _tree_hash(root: Path) -> str:
    """Hash a strict, sorted file-tree inventory without following links."""
    if not root.is_dir() or _is_reparse(root):
        _fail("session2_inventory_namespace_invalid")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if _is_reparse(path):
            _fail("session2_inventory_reparse_forbidden")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            rows.append({"path": relative, "type": "directory"})
        elif path.is_file():
            raw = path.read_bytes()
            rows.append({"path": relative, "type": "regular", "size": len(raw), "sha256": "sha256:" + sha256(raw).hexdigest()})
        else:
            _fail("session2_inventory_special_file")
    return "sha256:" + sha256(canonical_json(rows)).hexdigest()


def prepare_external_namespace(repository_root: Path, *, newly_authorized_for_session2: bool = False) -> dict[str, str]:
    """Create only ``<configured root>/session2`` under declared root origin.

    A newly authorized Session-2 root intentionally has no Session-1 tree.
    Fabricating one would create false historical authority, so the record is
    explicitly ``NOT_APPLICABLE`` rather than an empty inventory hash.
    """
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise Session2StorageError(str(exc)) from exc
    session1 = root / "session1"
    if newly_authorized_for_session2:
        if session1.exists():
            _fail("session2_new_root_not_empty")
        existing = root / "session2"
        expected_children = {"budget", "retrieval", "cases", "mutations", "receipts", "reviews", "freeze", "provisioning"}
        if existing.exists():
            if (not existing.is_dir() or _is_reparse(existing)
                    or {child.name for child in existing.iterdir()} != expected_children
                    or any(any(child.iterdir()) for child in existing.iterdir())):
                _fail("session2_new_root_not_empty")
            return {"external_root_origin": "NEWLY_AUTHORIZED_FOR_SESSION2", "session1_inventory_before": "NOT_APPLICABLE", "session1_inventory_after": "NOT_APPLICABLE", "session1_namespace_inventory_check": "NOT_APPLICABLE", "session2_namespace_id": "session2"}
        if any(root.iterdir()):
            _fail("session2_new_root_not_empty")
        before = after = "NOT_APPLICABLE"
    else:
        if not session1.is_dir() or _is_reparse(session1):
            _fail("session2_session1_inventory_missing")
        before = _tree_hash(session1)
    target = root / "session2"
    if target.exists() or target.is_symlink():
        _fail("session2_namespace_already_exists")
    try:
        target.mkdir(mode=0o700)
        for part in ("budget", "retrieval", "cases", "mutations", "receipts", "reviews", "freeze", "provisioning"):
            (target / part).mkdir(mode=0o700)
    except OSError as exc:
        # Do not guess at partial recovery: a supervisor must inspect the
        # configured root and create an incident before retrying.
        raise Session2StorageError("session2_namespace_creation_failed") from exc
    if not newly_authorized_for_session2:
        after = _tree_hash(session1)
    if before != after:
        _fail("session2_session1_inventory_changed")
    return {"external_root_origin": "NEWLY_AUTHORIZED_FOR_SESSION2" if newly_authorized_for_session2 else "PREEXISTING_AUTHORITY", "session1_inventory_before": before, "session1_inventory_after": after, "session1_namespace_inventory_check": "NOT_APPLICABLE" if newly_authorized_for_session2 else "VERIFIED", "session2_namespace_id": "session2"}


def open_budget_ledger(repository_root: Path, policy: BudgetPolicy) -> BudgetLedger:
    """Open the only ledger location after namespace authority is established."""
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise Session2StorageError(str(exc)) from exc
    session2 = root / "session2"
    budget = session2 / "budget"
    if not session2.is_dir() or not budget.is_dir() or _is_reparse(session2) or _is_reparse(budget):
        _fail("session2_namespace_not_initialized")
    return BudgetLedger(budget / "budget-ledger.sqlite3", policy)
