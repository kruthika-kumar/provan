"""Materialize the currently claimed Fresh B pair using production authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from shiproom.external_validation.session2_fresh_b_queue import _root  # noqa: E402
from shiproom.external_validation.session2_materialize import MaterializationError, seal_materialization  # noqa: E402
from shiproom.external_validation.session2_mirror import MIRRORS  # noqa: E402


class FreshBMaterializationError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise FreshBMaterializationError(code)


def materialize_claimed(repository_root: Path, *, candidate_index_hash: str) -> dict[str, str]:
    directory = _root(repository_root); root = directory.parents[2]
    db = sqlite3.connect(directory / "control.sqlite3")
    try: rows = db.execute("SELECT candidate_id,claim_id FROM queue WHERE state='IN_PROGRESS'").fetchall()
    finally: db.close()
    if len(rows) != 1: _fail("session2_fresh_b_materialize_claim_missing")
    candidate_id, claim_id = rows[0]
    try:
        index = json.loads((root / "session2" / "cases" / (candidate_index_hash[7:] + ".candidate-index.json")).read_text(encoding="utf-8"))
        candidate = next(item for item in index["candidates"] if item["candidate_id"] == candidate_id)
        pull_receipt = json.loads((root / "session2" / "retrieval" / (candidate["fix_object_receipt_hash"][7:] + ".object-receipt.json")).read_text(encoding="utf-8"))
        pull = json.loads((root / "session2" / "retrieval" / "raw" / (pull_receipt["raw_response_hash"][7:] + ".json")).read_text(encoding="utf-8"))
        base_sha, head_sha = pull["base"]["sha"], pull["head"]["sha"]
    except (OSError, KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
        raise FreshBMaterializationError("session2_fresh_b_materialize_authority_invalid") from exc
    records = []
    for path in sorted((root / "session2" / "cases" / "mirrors").glob("*.mirror.json")):
        try: value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc: raise FreshBMaterializationError("session2_fresh_b_materialize_mirror_invalid") from exc
        if (value.get("candidate_id") == candidate_id
                and isinstance(value.get("staging_mirror_name"), str)
                and value["staging_mirror_name"].endswith("--attempt-" + claim_id.removeprefix("fresh_b_claim_"))):
            records.append((path, value))
    if len(records) != 1: _fail("session2_fresh_b_materialize_mirror_missing")
    path, mirror_record = records[0]
    mirror = MIRRORS / mirror_record["staging_mirror_name"]
    if not mirror.is_dir(): _fail("session2_fresh_b_materialize_mirror_missing")
    mirror_hash = "sha256:" + path.name.removesuffix(".mirror.json")
    source = sorted(candidate["source_object_receipt_hashes"])
    staging = Path("/mnt/shiproom-remediation/session2-supervisor/materializations") / claim_id
    buggy = seal_materialization(repository_root, candidate_id=candidate_id, mirror=mirror, commit_sha=base_sha,
                                 destination=staging / "buggy", source_object_receipt_hashes=source, mirror_receipt_hash=mirror_hash)
    fixed = seal_materialization(repository_root, candidate_id=candidate_id, mirror=mirror, commit_sha=head_sha,
                                 destination=staging / "fixed", source_object_receipt_hashes=source, mirror_receipt_hash=mirror_hash)
    return {"claim_id": claim_id, "buggy_materialization_hash": buggy["materialization_hash"], "fixed_materialization_hash": fixed["materialization_hash"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize the currently claimed Fresh B pair.")
    parser.add_argument("--repository-root", required=True, type=Path); parser.add_argument("--candidate-index-hash", required=True)
    parsed = parser.parse_args(argv)
    try: result = materialize_claimed(parsed.repository_root, candidate_index_hash=parsed.candidate_index_hash)
    except (FreshBMaterializationError, MaterializationError) as exc: print(str(exc)); return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
