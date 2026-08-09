from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RUNNER=ROOT/"scripts/run_session10_proofs.py"


def main() -> int:
    spec=importlib.util.spec_from_file_location("session10_proof_runner",RUNNER)
    if not spec or not spec.loader:raise SystemExit("SESSION10_CLAIM_SURFACE_BUILDER_UNAVAILABLE")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    value=module.build_claim_surface_authority();output=module.CLAIM_SURFACE_AUTHORITY
    output.write_text(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n",encoding="utf-8")
    print("SESSION10_CLAIM_SURFACE_AUTHORITY_BUILT",len(value["surfaces"]));return 0


if __name__=="__main__":raise SystemExit(main())
