"""Root-staged retrieval of the object receipts required by Fresh B references."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from shiproom.external_validation import session2_candidates as candidates  # noqa: E402
from shiproom.external_validation.session2_retrieval import (  # noqa: E402
    RetrievalError,
    retrieve_github_object,
)


def retrieve_required_objects(repository_root: Path, *, reference_index_hash: str) -> dict[str, int]:
    """Fetch only missing immutable object authorities, in fixed request order."""
    required = candidates.required_fresh_b_object_requests(repository_root, reference_index_hash=reference_index_hash)
    base = candidates._root(repository_root)  # Production private-root authority.
    existing = candidates._object_receipt_map(base)
    fetched = 0
    for request in required:
        key = (request["repository"], request["object_kind"], request["number"])
        if key in existing:
            continue
        retrieve_github_object(repository_root, **request)
        fetched += 1
    return {"required_object_count": len(required), "fetched_object_count": fetched}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch exact object receipts required by the Fresh B reference index.")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--reference-index-hash", required=True)
    parser.add_argument("--finalize", action="store_true")
    parsed = parser.parse_args(argv)
    try:
        root = Path(parsed.repository_root)
        fetched = retrieve_required_objects(root, reference_index_hash=parsed.reference_index_hash)
        if parsed.finalize:
            result = candidates.finalize_fresh_b_object_candidates(root, reference_index_hash=parsed.reference_index_hash)
            print(json.dumps({**fetched, **result}, sort_keys=True, separators=(",", ":")))
        else:
            print(json.dumps(fetched, sort_keys=True, separators=(",", ":")))
    except (candidates.CandidateCompilationError, RetrievalError) as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
