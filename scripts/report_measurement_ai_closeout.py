from __future__ import annotations

import argparse, hashlib, json, subprocess, xml.etree.ElementTree as ET
from pathlib import Path

from shiproom.measurement_ai.closeout import CLAIMS, resolve_claims

def passed_tests(path:Path)->set[str]:
    root=ET.parse(path).getroot(); result=set()
    for case in root.iter("testcase"):
        if not list(case): result.add(case.attrib["name"])
    return result

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--junit",type=Path,required=True); parser.add_argument("--artifact-root",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    artifacts={}
    for path in args.artifact_root.rglob("*.json"):
        if path.name in {a["artifact"] for claim in CLAIMS for a in claim["artifact_assertions"]}:
            if path.name in artifacts: raise SystemExit("duplicate closeout artifact: "+path.name)
            artifacts[path.name]=json.loads(path.read_text(encoding="utf-8"))
    rows=resolve_claims(passed_tests(args.junit),artifacts)
    commit=subprocess.run(["git","rev-parse","HEAD"],text=True,capture_output=True,check=True).stdout.strip()
    junit_hash="sha256:"+hashlib.sha256(args.junit.read_bytes()).hexdigest()
    artifact_hashes={name:"sha256:"+hashlib.sha256((args.artifact_root/name).read_bytes()).hexdigest() for name in sorted(artifacts)}
    report={"schema_version":"measurement-ai-closeout-report.v1","commit":commit,"junit_snapshot_hash":junit_hash,"artifact_snapshot_hashes":artifact_hashes,"claims":rows,"resolved":all(row["status"]=="resolved" for row in rows)}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if not report["resolved"]: raise SystemExit("measurement AI closeout claims are incomplete")
    return 0

if __name__=="__main__": raise SystemExit(main())
