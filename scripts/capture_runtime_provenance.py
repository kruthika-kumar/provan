from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.provenance import extract_hermes_runtime


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--database",required=True); parser.add_argument("--session-id",required=True); parser.add_argument("--output",default="runtime-provenance/controlled.json"); args=parser.parse_args()
    runtime=extract_hermes_runtime(Path(args.database),args.session_id); output=Path(args.output); output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(runtime,indent=2)+"\n",encoding="utf-8"); print(output); return 0


if __name__=="__main__": raise SystemExit(main())
