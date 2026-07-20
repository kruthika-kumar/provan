"""Materialize verified registry statuses only from a validated proof receipt."""
from __future__ import annotations
import argparse,json
from pathlib import Path
try:
    from scripts.validate_session6_8_proof_execution import validate
except ModuleNotFoundError:
    from validate_session6_8_proof_execution import validate
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();validate(a.receipt)
    for name,key in (("session6-8-requirement-inventory.json","requirements"),("session6-8-completion-map.json","requirements"),("session6-8-execution-map.json","requirements"),("session6-8-proof-manifest.json","proofs"),("session6-8-claim-registry.json","claims")):
        path=ROOT/"docs/validation"/name;value=json.loads(path.read_text());
        for row in value[key]:row["status"]="verified"
        path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
