from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.remediation import verify_and_close


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--release", default="release-state/release.json"); args = parser.parse_args()
    path = Path(args.release); release = verify_and_close(json.loads(path.read_text(encoding="utf-8"))); path.write_text(json.dumps(release, indent=2), encoding="utf-8")
    print(json.dumps(release["verdict"], indent=2)); return 0 if release["verdict"]["status"] != "HOLD" else 1


if __name__ == "__main__": raise SystemExit(main())

