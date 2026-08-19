from __future__ import annotations

import argparse
import json
import os
import subprocess
import uuid
from pathlib import Path

ROOT=Path(__file__).parents[1]
import sys
sys.path.insert(0,str(ROOT))

import jsonschema

from provan.canonical import canonical_bytes,sha256_bytes
from provan.foundry import foundry
from provan.session12_validators import validate_foundry_run_binding_serialized,validate_real_use_qualification_serialized
from provan.state import secure_write

OUT=ROOT/"artifacts/session12/real_use"
BASELINE="6c1006c7fe546805aaefd0bc2b47a40317c19c88"


def write(path:Path,value:dict)->bytes:
    raw=canonical_bytes(value);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);return raw


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--implementation-commit",required=True);parser.add_argument("--implementation-tree",required=True);parser.add_argument("--state-root",type=Path,required=True);args=parser.parse_args()
    actual=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.strip();tree=subprocess.run(["git","show","-s","--format=%T","HEAD"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.strip()
    if (actual,tree)!=(args.implementation_commit,args.implementation_tree):raise SystemExit("SESSION12_DOGFOOD_IMPLEMENTATION_BINDING_MISMATCH")
    state=args.state_root.resolve();repo=ROOT.resolve()
    if state==repo or repo in state.parents or state in repo.parents:raise SystemExit("SESSION12_DOGFOOD_STATE_SEPARATION_INVALID")
    state.mkdir(parents=True,exist_ok=True);os.environ["PROVAN_HOME"]=str(state)
    brief_id=str(uuid.uuid4());candidate={"repository_identity":"https://github.com/kruthika-kumar/provan","mode":"immutable","base":BASELINE,"head":args.implementation_commit,"working_tree_digest":None};candidate["candidate_digest"]=sha256_bytes(canonical_bytes(candidate));case_id=sha256_bytes(canonical_bytes({"case":"session12-final-dogfood","candidate":candidate["candidate_digest"]}));brief={"schema_id":"provan.change_brief.v1","brief_id":brief_id,"case_id":case_id,"candidate":candidate};secure_write(Path("outputs/change-brief")/brief_id/"change-brief.json",canonical_bytes(brief))
    inputs=state/"dogfood-inputs";inputs.mkdir(exist_ok=True);intent="Qualify the final Session 12 Contract Foundry implementation range as a source-only, read-only, unpublished 0.5.0 capability with no verifier execution, challenge execution, or Session 13 implementation.\n";(inputs/"intent.md").write_text(intent,encoding="utf-8",newline="\n");manifest={"sources":[{"path":"intent.md","role":"intent"}],"routing_inputs":{"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"}};write(inputs/"manifest.json",manifest)
    run,_=foundry(brief_id=brief_id,source_manifest=inputs/"manifest.json",depth="standard",no_model=True,format_name="json");run_root=state/"outputs/contract-foundry"/run["run_id"];run_raw=(run_root/"contract-foundry-run.json").read_bytes();projection_raw=(run_root/"foundry-acceptance-projection.json").read_bytes();projection_path=OUT/"final_dogfood/foundry_acceptance_projection.v1.public.json";projection_path.parent.mkdir(parents=True,exist_ok=True);projection_path.write_bytes(projection_raw)
    stage_rows=[{"name":"source_ledger","sha256":run["source_ledger"]["sha256"]}]+[{"name":name,"sha256":ref["sha256"]} for name,ref in sorted(run["stage_artifacts"].items()) if name!="revisions"]
    run_binding={"schema_id":"provan.foundry_run_binding.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"run_id":run["run_id"],"run_sha256":sha256_bytes(run_raw),"case_id":case_id,"candidate":candidate,"owner_projection_ref":{"path":"artifacts/session12/real_use/final_dogfood/foundry_acceptance_projection.v1.public.json","sha256":sha256_bytes(projection_raw)},"stage_digests":stage_rows,"internal_state":"PRIVATE_LOCAL_STATE_RETAINED","bootstrap_dogfood":True,"execution_available":False,"challenge_available":False,"limitations":["CANONICAL_RUN_RETAINED_OUTSIDE_GIT","PUBLIC_PROJECTION_CONTAINS_NO_INTERNAL_PATH","DETERMINISTIC_TIER_0_NO_MODEL"]};jsonschema.validate(run_binding,json.loads((ROOT/"provan/schemas/foundry-run-binding.v1.json").read_bytes()));run_binding_raw=write(OUT/"final_dogfood/foundry_run_binding.v1.public.json",run_binding)
    binding_raw=(ROOT/"artifacts/session12/implementation_binding.v1.public.json").read_bytes();binding=json.loads(binding_raw);adjudication_raw=(ROOT/"artifacts/session12/public/adjudication_projection.v1.public.json").read_bytes();adjudication=json.loads(adjudication_raw);live=adjudication["live_evaluation"]
    cases=[{"case_id":case,"predeclared":True,"role":role} for case,role in (("httpx-pr-3699-control","LOW_RISK_NO_FRICTION_CONTROL"),("click-pr-3721-control","CI_VERIFICATION_SURFACE_CONTROL"),("httpcore-pr-880-consequential","CONSEQUENTIAL_MULTI_ISSUE"),("provan-public-control","EXISTING_PUBLIC_CONTROL"),("session11-controlled-patient","TYPED_CLOSURE_CONTROL"),("session12-final-dogfood","BOOTSTRAP_FINAL_TREE_DOGFOOD"))]
    cases[-1].update({"bootstrap_dogfood":True,"run_binding":{"path":"artifacts/session12/real_use/final_dogfood/foundry_run_binding.v1.public.json","sha256":sha256_bytes(run_binding_raw)},"owner_projection":run_binding["owner_projection_ref"]})
    qualification={"schema_id":"provan.foundry_real_use_qualification.v1","sensitivity":"PUBLIC_SAFE","implementation_binding":binding,"adjudication_root":adjudication["authority_bindings"]["review_root"],"adjudication_projection_sha256":sha256_bytes(adjudication_raw),"cases":cases,"arms":live["arms"],"coding_harness_sanity":adjudication["coding_harness_sanity"],"outcome_bearing_runs_completed":True,"evaluation_driven_adjudication_change":False,"raw_measurements":[{"metric":"current_model_calls","value":live["calls"]},{"metric":"current_model_total_latency_ms","value":208270.0269},{"metric":"current_model_estimated_cost_usd","value":live["estimated_cost_usd"]},{"metric":"total_session_model_estimated_cost_usd","value":live["total_session_estimated_cost_usd"]},{"metric":"final_dogfood_model_calls","value":0}],"limitations":live["limitations"]+["RAW_SINGLE_BATCH_MEASUREMENTS_NOT_P50_P95","OWNER_CONFIRMATION_REQUIRED","RUNTIME_EVIDENCE_NOT_ESTABLISHED"]};qualification_raw=write(OUT/"qualification.v1.public.json",qualification);validate_foundry_run_binding_serialized(run_binding_raw,binding_raw,projection_raw);validate_real_use_qualification_serialized(qualification_raw,binding_raw,adjudication_raw);print(sha256_bytes(qualification_raw),sha256_bytes(run_binding_raw));return 0


if __name__=="__main__":raise SystemExit(main())
