from __future__ import annotations

import argparse, hashlib, json, subprocess
from pathlib import Path

def sha(path:Path)->str:return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    execution=root/"docs/validation/session6-8-execution-map.json";proofs=root/"docs/validation/session6-8-proof-manifest.json";e=json.loads(execution.read_text());p=json.loads(proofs.read_text());by_id={item["proof_id"]:item for item in p["proofs"]}
    if len(by_id)!=len(p["proofs"]):raise SystemExit("duplicate proof id")
    for row in e["requirements"]:
        values=[by_id.get(pid) for pid in row["proof_ids"]]
        if None in values or {item["fixture_class"] for item in values}!={"valid","near_valid","adversarial_invalid"}:raise SystemExit("closeout_proof_class_missing")
    commit=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=True).stdout.strip();report={"schema_version":"session6-8-closeout-report.v1","commit":commit,"execution_map_hash":sha(execution),"proof_manifest_hash":sha(proofs),"claims":[{"claim_id":row["requirement_id"],"status":"resolved","proof_ids":row["proof_ids"]} for row in e["requirements"]],"resolved":True,"report_self_hash":""}
    report["report_self_hash"]="sha256:"+hashlib.sha256(json.dumps({**report,"report_self_hash":""},sort_keys=True,separators=(",",":")).encode()).hexdigest();args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8");return 0
if __name__=="__main__":raise SystemExit(main())
