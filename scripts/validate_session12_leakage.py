from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from provan.errors import ProvanError
from provan.leakage import TEXT_SUFFIXES,_text_violations,validate_candidate_surfaces


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--tree-only",action="store_true");parser.add_argument("--archive",action="append",type=Path,default=[]);args=parser.parse_args()
    excluded={".git",".venv","venv","build","candidate-dist","__pycache__",".pytest_cache"};paths=[]
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES or any(part in excluded for part in path.parts):continue
        paths.append(path)
    baseline="6c1006c7fe546805aaefd0bc2b47a40317c19c88";violations=[];historical=0
    for path in paths:
        relative=path.relative_to(ROOT).as_posix();items=_text_violations(relative,path.read_text(encoding="utf-8",errors="replace"))
        if not items:continue
        prior=subprocess.run(["git","show",f"{baseline}:{relative}"],cwd=ROOT,capture_output=True,check=False).stdout
        if prior and hashlib.sha256(prior).digest()==hashlib.sha256(path.read_bytes()).digest():historical+=len(items)
        else:violations.extend(items)
    if violations:raise ProvanError("COMMUNITY_PRIVATE_LEAKAGE",str(violations[:10]))
    if not args.tree_only:
        base=os.environ.get("PROVAN_PUBLICATION_BASE","6c1006c7fe546805aaefd0bc2b47a40317c19c88");head=os.environ.get("PROVAN_PUBLICATION_HEAD","HEAD");integration=os.environ.get("PROVAN_INTEGRATION_HEAD",head)
        validate_candidate_surfaces(ROOT,args.archive,history_base=base,history_head=head,integration_head=integration)
    print(json.dumps({"status":"VALID","result":"PRIVATE_PLANNING_AUTHORITY_ABSENT","scope":"TREE_ONLY" if args.tree_only else "TREE_INDEX_HISTORY_DELTA_ARCHIVES","files_scanned":len(paths),"historical_byte_identical_findings":historical,"archive_count":len(args.archive)},sort_keys=True));return 0


if __name__=="__main__":
    try:raise SystemExit(main())
    except ProvanError as exc:
        print(json.dumps({"status":"INVALID","error":exc.code,"message":str(exc)},sort_keys=True));raise SystemExit(2)
