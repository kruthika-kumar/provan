from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from shiproom.console import EVAL_VERSION
from shiproom.policy import POLICY_VERSION


def run(command: list[str]) -> str:
    result=subprocess.run(command,text=True,capture_output=True)
    print(result.stdout,end=""); print(result.stderr,end="",file=sys.stderr)
    if result.returncode: raise SystemExit(result.returncode)
    return result.stdout


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--verified",default="submission/verified.json"); parser.add_argument("--cloudflare-version",required=True); args=parser.parse_args()
    tests_output=run([sys.executable,"-m","pytest","-q"])
    match=re.search(r"(\d+) passed",tests_output)
    if not match: raise SystemExit("could not determine passing test count")
    eval_output=run([sys.executable,"scripts/run_evals.py"]); evals=sum(line.startswith("PASS ") for line in eval_output.splitlines())
    required={"CONTEXT_HANDOFF_INTEGRITY","CONTEXT_PROJECT_ISOLATION","CONTEXT_CANNOT_OVERRIDE_VERIFIED_EVIDENCE"}
    passed_names={line.removeprefix("PASS ") for line in eval_output.splitlines() if line.startswith("PASS ")}
    if evals < 17 or not required.issubset(passed_names): raise SystemExit(f"expected prior evals plus named context cases; observed {evals}, missing={sorted(required-passed_names)}")
    run([sys.executable,"scripts/verify_external_read_only.py"])
    gates=json.loads(run([sys.executable,"scripts/verify_context_gates.py"]));
    target=Path(args.verified); verified=json.loads(target.read_text(encoding="utf-8"))
    verified.update({"tests_passed":int(match.group(1)),"evals_passed":evals,"policy_gate":"passed","policy_version":POLICY_VERSION,"eval_version":EVAL_VERSION,"rollback_baseline_version_id":args.cloudflare_version,"pr2_url":"https://github.com/kruthika-kumar/shiproom/pull/2","context_handoff":gates["context_handoff"],"context_isolation":gates["context_isolation"],"source_authority_conflict":gates["source_authority_conflict"],"context_source_types":["release_input","repository_context"]})
    target.write_text(json.dumps(verified,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"tests":verified["tests_passed"],"evals":evals,"policy_gate":"passed"},indent=2)); return 0


if __name__ == "__main__": raise SystemExit(main())
