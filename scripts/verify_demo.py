from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.remediation import verify_and_close
from shiproom.verdict import is_terminal_success
from shiproom.authority import LocalExecutionContext


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", default="release-state/release.json")
    args = parser.parse_args()
    path = Path(args.release).resolve()
    raw=json.loads(path.read_text(encoding="utf-8")); release = verify_and_close(raw,LocalExecutionContext.from_release(raw))
    path.write_text(json.dumps(release, indent=2), encoding="utf-8")
    print(json.dumps(release["verdict"], indent=2))
    return 0 if is_terminal_success(release["verdict"]["status"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
