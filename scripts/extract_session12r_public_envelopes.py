from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provan.canonical import canonical_bytes, sha256_bytes
from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS
from provan.state import secure_read


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--public-evidence", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PROVAN_HOME"] = str(args.state_root.resolve())
    evidence = json.loads(args.public_evidence.read_bytes())
    first_runs: dict[str, dict] = {}
    for run in evidence["runs"]:
        first_runs.setdefault(run["case_id"], run)
    if set(first_runs) != set(FROZEN_PUBLIC_MODEL_EGRESS) - {"session12r-final-provan-dogfood"}:
        raise SystemExit("SESSION12R_PUBLIC_ENVELOPE_CASE_SET_INVALID")
    args.output_directory.mkdir(parents=True, exist_ok=True)
    for case_id, run in sorted(first_runs.items()):
        bundle_root = Path("outputs/contract-foundry") / run["run_id"]
        bundle = json.loads(secure_read(bundle_root / "source-bundle.json"))
        blocks = []
        for row in bundle["sources"]:
            raw = secure_read(
                Path(row["blob_ref"]["path"]),
                allowed_suffixes=frozenset({".blob"}),
            )
            if row["sha256"] != sha256_bytes(raw):
                raise SystemExit("SESSION12R_PUBLIC_ENVELOPE_BLOB_MISMATCH")
            blocks.append({"content": raw.decode("utf-8", errors="strict")})
        if tuple(sha256_bytes(row["content"].encode("utf-8")) for row in blocks) != FROZEN_PUBLIC_MODEL_EGRESS[case_id]:
            raise SystemExit("SESSION12R_PUBLIC_ENVELOPE_DIGEST_MISMATCH")
        (args.output_directory / f"{case_id}.json").write_bytes(
            canonical_bytes({"case_id": case_id, "selected_blocks": blocks})
        )
    print("SESSION12R_PUBLIC_ENVELOPES_RECONSTRUCTED", len(first_runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
