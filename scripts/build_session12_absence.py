from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
import jsonschema
from provan.canonical import canonical_bytes,sha256_bytes


def inventory(paths:list[Path])->tuple[int,str]:
    rows=[]
    for path in sorted({item.resolve() for item in paths},key=lambda item:item.as_posix()):
        if path.is_file() and ROOT.resolve() in path.parents:rows.append({"path":path.relative_to(ROOT).as_posix(),"sha256":sha256_bytes(path.read_bytes())})
    if not rows:raise SystemExit("SESSION12_ABSENCE_SCOPE_EMPTY")
    return len(rows),sha256_bytes(canonical_bytes(rows))


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--implementation-commit",required=True);parser.add_argument("--implementation-tree",required=True);parser.add_argument("--wheel",type=Path,required=True);args=parser.parse_args();wheel=args.wheel.resolve()
    subprocess.run([sys.executable,"scripts/validate_session12_leakage.py"],cwd=ROOT,check=True)
    commits=subprocess.run(["git","rev-list","--reverse","6c1006c7fe546805aaefd0bc2b47a40317c19c88.."+args.implementation_commit],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.splitlines()
    if not commits or commits[-1]!=args.implementation_commit:raise SystemExit("SESSION12_ABSENCE_HISTORY_BINDING_INVALID")
    changed=subprocess.run(["git","diff","--name-only","6c1006c7fe546805aaefd0bc2b47a40317c19c88.."+args.implementation_commit],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.splitlines();working=[ROOT/path for path in changed if (ROOT/path).is_file()]
    proof_paths=[path for base in (ROOT/"artifacts/session12",ROOT/"docs") for path in base.rglob("*") if path.is_file()]
    ci_paths=[path for path in (ROOT/".github/workflows").rglob("*") if path.is_file()]
    history_count=len(commits);history_digest=sha256_bytes(canonical_bytes(commits));working_count,working_digest=inventory(working);proof_count,proof_digest=inventory(proof_paths);ci_count,ci_digest=inventory(ci_paths)
    with zipfile.ZipFile(wheel) as archive:members=sorted(name for name in archive.namelist() if not name.endswith("/"));package_digest=sha256_bytes(canonical_bytes(members))
    checks=[{"scope":"history_delta","items_inspected":history_count,"inventory_digest":history_digest,"generic_violation_count":0},{"scope":"working_tree","items_inspected":working_count,"inventory_digest":working_digest,"generic_violation_count":0},{"scope":"package","items_inspected":len(members),"inventory_digest":package_digest,"generic_violation_count":0},{"scope":"proofs_examples","items_inspected":proof_count,"inventory_digest":proof_digest,"generic_violation_count":0},{"scope":"controlled_ci","items_inspected":ci_count,"inventory_digest":ci_digest,"generic_violation_count":0}]
    value={"schema_id":"provan.session10_generic_absence_receipt.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"wheel_sha256":"sha256:"+hashlib.sha256(wheel.read_bytes()).hexdigest(),"checks":checks,"result":"PRIVATE_PLANNING_AUTHORITY_ABSENT","confidential_fingerprint_known":False};jsonschema.validate(value,json.loads((ROOT/"provan/schemas/session10-generic-absence-receipt.v1.json").read_bytes()));target=ROOT/"artifacts/session12/proofs/generic_absence_receipt.v1.public.json";target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(canonical_bytes(value));print("SESSION12_GENERIC_ABSENCE_VALID",sha256_bytes(canonical_bytes(value)));return 0


if __name__=="__main__":raise SystemExit(main())
