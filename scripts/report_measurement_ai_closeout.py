from __future__ import annotations

import argparse, json, xml.etree.ElementTree as ET
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
    report={"schema_version":"measurement-ai-closeout-report.v1","claims":rows,"resolved":True}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if not report["resolved"]: raise SystemExit("measurement AI closeout claims are incomplete")
    return 0

if __name__=="__main__": raise SystemExit(main())
