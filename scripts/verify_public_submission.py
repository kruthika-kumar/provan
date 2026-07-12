from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from shiproom.external import CAPABILITIES, validate_contract

V1_FIELDS={"schema_version","generated_at","policy_version","eval_version","release_id","final_verdict","hermes","modules","http_evidence","owner_decision","public_references","verification","auto_merge","deployment"}
V2_FIELDS=V1_FIELDS|{"historical_release","hardened_capability_gates","context","runtime","evidence_counts"}
CLIENTS={"generic":"ShiproomConsistency/1.0","browser":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36","crawler":"Googlebot/2.1 (+http://www.google.com/bot.html)"}
PATHS=("/","/public_evidence_manifest.v1.json","/public_evidence_manifest.v2.json","/reports/rel_35e58f680a1a","/release-report","/result/demo")


def fetch(url: str, user_agent: str) -> dict:
    request=Request(url,headers={"User-Agent":user_agent,"Cache-Control":"no-cache"})
    with urlopen(request,timeout=20) as response:
        body=response.read().decode("utf-8")
        return {"status":response.status,"body":body,"hash":hashlib.sha256(body.encode()).hexdigest(),"cache":response.headers.get("Cache-Control"),"etag":response.headers.get("ETag")}


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--base",default="https://shiproom-demo.bookies-litany-00.workers.dev"); args=parser.parse_args(); base=args.base.rstrip("/"); failures=[]; results={}
    nonce=str(int(time.time()*1000))
    for client,agent in CLIENTS.items():
        results[client]={path:fetch(base+path+f"?consistency={nonce}",agent) for path in PATHS}
    for path in PATHS:
        values=[results[client][path] for client in CLIENTS]
        if any(item["status"]!=200 for item in values): failures.append(f"route failed: {path}")
        if len({item["hash"] for item in values})!=1: failures.append(f"client content mismatch: {path}")
        if path!="/result/demo" and any(item["cache"]!="public, max-age=0, must-revalidate" or not item["etag"] for item in values): failures.append(f"cache/etag mismatch: {path}")
    html=results["generic"]["/"]["body"]; report=results["generic"]["/release-report"]["body"]; report_alias=results["generic"]["/reports/rel_35e58f680a1a"]["body"]
    v1=json.loads(results["generic"]["/public_evidence_manifest.v1.json"]["body"]); v2=json.loads(results["generic"]["/public_evidence_manifest.v2.json"]["body"])
    if set(v1)!=V1_FIELDS or v1.get("schema_version")!="public_evidence_manifest.v1": failures.append("manifest v1 compatibility failure")
    if set(v2)!=V2_FIELDS or v2.get("schema_version")!="public_evidence_manifest.v2": failures.append("manifest v2 allowlist failure")
    required=("rel_35e58f680a1a","20260712_141653_80beb5","deleg_4ddb33af","404","200",str(v2["verification"]["tests_passed"]),str(v2["verification"]["evals_passed"]))
    if any(value not in html or value not in report for value in required) or not all(("SHIP WITH CONDITIONS" in surface or "SHIP_WITH_CONDITIONS" in surface) and ("accepted condition" in surface.lower() or "accepted_condition" in surface) for surface in (html,report)): failures.append("console/report current claims mismatch")
    if report!=report_alias: failures.append("report aliases differ")
    forbidden=("AWAITING_OWNER","null Hermes","C:\\Users\\","Canonical release object","repository.path","rel_70e7648a0731","DrawDB","raw_prompt","model_response",".env=")
    if re.search(r"\bHOLD\b",report) or any(value.lower() in (html+report+json.dumps(v2)).lower() for value in forbidden): failures.append("stale or private public content")
    for value in (value for value in v1["public_references"].values() if value):
        if value not in html and urlparse(value).path not in html: failures.append("public link missing"); break
    example={"schema_version":"external_release_contract.v1","project_name":"public-project","repository_url":"https://github.com/example/public-project","live_url":"https://example.com","target_user":"public users","product_promise":"Inspect a public journey","critical_journey":["Open","Inspect"],"non_goals":[],"owner_constraints":["Public read-only review"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}}
    try: validate_contract(example)
    except ValueError: failures.append("generated contract example invalid")
    summary={client:{path:{key:value[key] for key in ("status","hash","cache","etag")} for path,value in paths.items()} for client,paths in results.items()}
    print(json.dumps({"status":"PASS" if not failures else "FAIL","base":base,"failures":failures,"clients":summary},indent=2)); return 0 if not failures else 1


if __name__=="__main__": sys.exit(main())
