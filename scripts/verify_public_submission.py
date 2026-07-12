from __future__ import annotations

import argparse
import json
import sys
from urllib.request import Request, urlopen

from shiproom.external import CAPABILITIES, validate_contract


TOP_LEVEL={"schema_version","generated_at","policy_version","eval_version","release_id","final_verdict","hermes","modules","http_evidence","owner_decision","public_references","verification","auto_merge","deployment"}


def fetch(url: str) -> tuple[int, str]:
    request=Request(url,headers={"User-Agent":"ShiproomPublicSmoke/1.0 (+https://github.com/kruthika-kumar/shiproom)"})
    with urlopen(request,timeout=20) as response: return response.status,response.read().decode("utf-8")


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--base",default="https://shiproom-demo.bookies-litany-00.workers.dev"); args=parser.parse_args(); base=args.base.rstrip("/")
    root_status,html=fetch(base+"/"); report_status,_=fetch(base+"/reports/rel_35e58f680a1a"); result_status,_=fetch(base+"/result/demo"); manifest_status,raw=fetch(base+"/public_evidence_manifest.v1.json")
    manifest=json.loads(raw); failures=[]
    if (root_status,report_status,result_status,manifest_status)!=(200,200,200,200): failures.append("required route failed")
    if set(manifest)!=TOP_LEVEL or manifest.get("schema_version")!="public_evidence_manifest.v1": failures.append("manifest allowlist/schema mismatch")
    required=("Shiproom","SHIP WITH CONDITIONS","404","200","The code passed. The product failed its promise.",manifest["release_id"],manifest["hermes"]["session_id"],manifest["hermes"]["delegation_id"],str(manifest["verification"]["tests_passed"]),str(manifest["verification"]["evals_passed"]),"Hardened external read-only policy gate: passed.")
    if any(value not in html for value in required): failures.append("HTML/manifest claims mismatch")
    if any(value not in html for value in manifest["public_references"].values() if value): failures.append("public link missing")
    forbidden=("C:\\","repository.path","rel_70e7648a0731","DrawDB","raw_prompt","model_response","None","{'", ".env=")
    if any(value.lower() in (html+raw).lower() for value in forbidden): failures.append("prohibited public content")
    example={"schema_version":"external_release_contract.v1","project_name":"public-project","repository_url":"https://github.com/example/public-project","live_url":"https://example.com","target_user":"public users","product_promise":"Inspect a public journey","critical_journey":["Open","Inspect"],"non_goals":[],"owner_constraints":["Public read-only review"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}}
    try: validate_contract(example)
    except ValueError: failures.append("generated contract example invalid")
    print(json.dumps({"status":"PASS" if not failures else "FAIL","base":base,"failures":failures},indent=2)); return 0 if not failures else 1


if __name__ == "__main__": sys.exit(main())
