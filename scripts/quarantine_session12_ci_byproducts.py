from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_session12_authoritative_gate import quarantine_local_test_outputs


def main() -> int:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise SystemExit("SESSION12_CI_QUARANTINE_ROOT_MISSING")
    transcript_root = (Path(runner_temp) / "provan-session12-ci-quarantine").resolve()
    repo = ROOT.resolve()
    if transcript_root == repo or repo in transcript_root.parents or transcript_root in repo.parents:
        raise SystemExit("SESSION12_CI_QUARANTINE_SEPARATION_INVALID")
    transcript_root.mkdir(parents=True, exist_ok=True)
    count, receipt = quarantine_local_test_outputs(repo, transcript_root)
    (transcript_root / "quarantine-receipt.txt").write_bytes(receipt)
    print(f"SESSION12_CI_LOCAL_BYPRODUCTS_QUARANTINED:{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
