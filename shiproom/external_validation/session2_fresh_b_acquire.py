"""Acquire only the currently claimed Fresh B source pair through production code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys


_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from shiproom.external_validation.identity import canonical_json  # noqa: E402
from shiproom.external_validation.session2_fresh_b_queue import _root  # noqa: E402
from shiproom.external_validation.session2_mirror import MirrorAcquisitionError, acquire_pair  # noqa: E402


class FreshBAcquireError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise FreshBAcquireError(code)


def acquire_claimed(repository_root: Path, *, candidate_index_hash: str) -> dict[str, str]:
    directory = _root(repository_root); root = directory.parents[2]
    db = sqlite3.connect(directory / "control.sqlite3")
    try:
        rows = db.execute("SELECT candidate_id,claim_id FROM queue WHERE state='IN_PROGRESS'").fetchall()
    finally:
        db.close()
    if len(rows) != 1: _fail("session2_fresh_b_acquire_claim_missing")
    candidate_id, claim_id = rows[0]
    path = root / "session2" / "cases" / (candidate_index_hash[7:] + ".candidate-index.json")
    if not path.is_file() or path.is_symlink(): _fail("session2_fresh_b_acquire_index_missing")
    raw = path.read_bytes()
    try: index = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise FreshBAcquireError("session2_fresh_b_acquire_index_invalid") from exc
    if canonical_json(index) != raw or index.get("schema_id") != "external_validation.session2_fresh_b_candidate_index.v1":
        _fail("session2_fresh_b_acquire_index_invalid")
    matches = [item for item in index.get("candidates", []) if isinstance(item, dict) and item.get("candidate_id") == candidate_id]
    if len(matches) != 1: _fail("session2_fresh_b_acquire_candidate_missing")
    candidate = matches[0]
    required = {"repository", "fix_repository", "fix_pr_number", "source_object_receipt_hashes"}
    if not required.issubset(candidate) or candidate["repository"] != candidate["fix_repository"]:
        _fail("session2_fresh_b_acquire_candidate_invalid")
    receipts = candidate["source_object_receipt_hashes"]
    if not isinstance(receipts, list) or len(receipts) != 2: _fail("session2_fresh_b_acquire_candidate_invalid")
    pull_receipt = candidate.get("fix_object_receipt_hash")
    if pull_receipt not in receipts: _fail("session2_fresh_b_acquire_candidate_invalid")
    receipt_path = root / "session2" / "retrieval" / (pull_receipt[7:] + ".object-receipt.json")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        response = root / "session2" / "retrieval" / "raw" / (receipt["raw_response_hash"][7:] + ".json")
        pull = json.loads(response.read_text(encoding="utf-8"))
        base, head = pull["base"]["sha"], pull["head"]["sha"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise FreshBAcquireError("session2_fresh_b_acquire_pull_authority_invalid") from exc
    result = acquire_pair(repository_root, candidate_id=candidate_id, candidate_index_hash=candidate_index_hash,
                          repository=candidate["repository"], base_sha=base, head_sha=head,
                          source_receipts=sorted(receipts), attempt_id=claim_id.removeprefix("fresh_b_claim_"))
    return {"claim_id": claim_id, **result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acquire the currently claimed Fresh B source pair.")
    parser.add_argument("--repository-root", required=True, type=Path); parser.add_argument("--candidate-index-hash", required=True)
    parsed = parser.parse_args(argv)
    try: result = acquire_claimed(parsed.repository_root, candidate_index_hash=parsed.candidate_index_hash)
    except (FreshBAcquireError, MirrorAcquisitionError) as exc:
        print(str(exc)); return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
