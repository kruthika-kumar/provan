from __future__ import annotations

import argparse, hashlib, json, subprocess, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from shiproom.measurement_ai.closeout import CLAIMS, resolve_claims

def passed_tests(path:Path)->set[str]:
    root=ET.parse(path).getroot(); result=set()
    for case in root.iter("testcase"):
        if not list(case): result.add(case.attrib["name"])
    return result

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--junit",type=Path,required=True); parser.add_argument("--junit-commit",required=True); parser.add_argument("--artifact-root",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    artifacts={}
    for path in args.artifact_root.rglob("*.json"):
        if path.name in {a["artifact"] for claim in CLAIMS for a in claim["artifact_assertions"]}:
            if path.name in artifacts: raise SystemExit("duplicate closeout artifact: "+path.name)
            artifacts[path.name]=json.loads(path.read_text(encoding="utf-8"))
    rows=resolve_claims(passed_tests(args.junit),artifacts)
    commit=subprocess.run(["git","rev-parse","HEAD"],text=True,capture_output=True,check=True).stdout.strip()
    branch=subprocess.run(["git","branch","--show-current"],text=True,capture_output=True,check=True).stdout.strip()
    if args.junit_commit != commit: raise SystemExit("JUnit commit differs from current commit")
    junit_hash="sha256:"+hashlib.sha256(args.junit.read_bytes()).hexdigest()
    artifact_paths=sorted(args.artifact_root.rglob("*.json"));artifact_hashes={str(path.relative_to(args.artifact_root)).replace("\\","/"):"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest() for path in artifact_paths}
    required={"contract-parity-report.json","private-rubric-parity-report.json"}
    if not required.issubset(artifact_hashes):raise SystemExit("closeout parity reports are absent")
    resolved=sum(row["status"]=="resolved" for row in rows);unresolved=len(rows)-resolved
    report={"schema_version":"measurement-ai-closeout-report.v2","generated_at":datetime.now(timezone.utc).isoformat(),"branch":branch,"commit":commit,"junit_commit":args.junit_commit,"junit_snapshot_hash":junit_hash,"artifact_snapshot_hashes":artifact_hashes,"parity_report_snapshot_hashes":{name:artifact_hashes[name] for name in sorted(required)},"claims":rows,"resolved_claim_count":resolved,"unresolved_claim_count":unresolved,"resolved":unresolved==0,"report_self_hash":""}
    canonical=json.dumps({**report,"report_self_hash":""},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode();report["report_self_hash"]="sha256:"+hashlib.sha256(canonical).hexdigest()
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    loaded=json.loads(args.output.read_text(encoding="utf-8"));expected="sha256:"+hashlib.sha256(json.dumps({**loaded,"report_self_hash":""},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    if loaded["report_self_hash"]!=expected or not report["resolved"]: raise SystemExit("measurement AI closeout report validation failed")
    return 0

if __name__=="__main__": raise SystemExit(main())
