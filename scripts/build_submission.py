from __future__ import annotations

import argparse, json
from pathlib import Path

from shiproom.console import write_submission
from shiproom.report import render

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--release", default="release-state/release.json"); parser.add_argument("--receipt", default="hermes-receipts/receipt.json"); parser.add_argument("--verified", default="submission/verified.json"); parser.add_argument("--output", default="dist"); args=parser.parse_args()
    release=json.loads(Path(args.release).read_text(encoding="utf-8")); receipt=json.loads(Path(args.receipt).read_text(encoding="utf-8")); verified=json.loads(Path(args.verified).read_text(encoding="utf-8")); output=Path(args.output)
    run=write_submission(release,receipt,verified,output); render(release,output/"release-report.html")
    print(json.dumps({"output":str(output),"release_id":run["release_id"],"assets":sorted(p.name for p in output.iterdir())},indent=2)); return 0
if __name__ == "__main__": raise SystemExit(main())
