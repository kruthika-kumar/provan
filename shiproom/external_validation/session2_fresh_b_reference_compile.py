"""Root-staged entry point for the non-selecting Fresh B reference compiler.

The privileged invocation executes this file only from the immutable staged
bundle.  It deliberately has no checkout, container, model, or qualification
operation: it turns already-sealed search frames into source references that
still require authoritative GitHub object receipts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


# Direct execution from a root-owned Git archive does not put the package root
# on ``sys.path``.  The parent relationship is fixed by this reviewed bundle,
# not supplied by a caller.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from shiproom.external_validation.session2_candidates import (  # noqa: E402
    CandidateCompilationError,
    compile_fresh_b_reference_candidates,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile reference-only FRESH_B candidates from sealed v2 frames.")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--retrieval-frame-receipt-hash", action="append", required=True)
    parsed = parser.parse_args(argv)
    try:
        result = compile_fresh_b_reference_candidates(
            Path(parsed.repository_root), retrieval_frame_receipt_hashes=parsed.retrieval_frame_receipt_hash
        )
    except CandidateCompilationError as exc:
        print(str(exc))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
