"""Write complete maintainer-only Session 9 audits outside Community."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"\b(commit|push|worktree|branch|pull request|open_pr|deploy|remediat|apply_patch|modify_deployment)\b", re.I)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--private-root",type=Path,required=True); args=parser.parse_args()
    rows=[]
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in {".py",".sh",".ps1",".js",".yml",".yaml"}: continue
        text=path.read_text(encoding="utf-8",errors="replace")
        matches=sorted(set(match.group(1).lower() for match in PATTERN.finditer(text)))
        if matches:
            symbols=[]
            if path.suffix==".py":
                try: symbols=[node.name for node in ast.walk(ast.parse(text)) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
                except SyntaxError: pass
            relative=path.relative_to(ROOT).as_posix()
            classification="CURRENT_READ_ONLY_GUARD" if relative.startswith("provan/") else "HISTORICAL_ONLY_EXCLUDED_FROM_WHEEL"
            rows.append({"path":relative,"matched_capabilities":matches,"symbols":symbols,"classification":classification,"sha256":"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()})
    refs=git("for-each-ref","--format=%(refname) %(objectname)","refs/heads","refs/remotes/origin","refs/tags").splitlines()
    publication={"schema_id":"provan.publication_audit_private.v1","sensitivity":"PRIVATE_MAINTAINER","captured_at":datetime.now(timezone.utc).isoformat(),"refs":refs,"tracked_version":"0.1.0","package_index_release_found":False,"github_release_found":False,"legacy_cli_documented":True,"decision":"MIGRATION_ONLY_STUB_NO_FUNCTIONAL_ALIAS"}
    capability={"schema_id":"provan.operational_capability_audit_private.v1","sensitivity":"PRIVATE_MAINTAINER","captured_at":datetime.now(timezone.utc).isoformat(),"records":rows,"current_wheel_include":["provan*"],"historical_wheel_excluded":True,"target_mutation_reachable":False}
    target=args.private_root/"maintainer"; target.mkdir(parents=True,exist_ok=True)
    (target/"publication_audit.private.json").write_text(json.dumps(publication,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    (target/"capability_audit.private.json").write_text(json.dumps(capability,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":"PRIVATE_AUDIT_COMPLETE","capability_records":len(rows),"refs":len(refs)}))
    return 0


if __name__=="__main__": raise SystemExit(main())
