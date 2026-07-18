"""Deterministic, harness-neutral specialist planning."""
from __future__ import annotations

import hashlib
import json
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import ensure_directory, replace_bytes, safe_entry, write_bytes


COMPILER_VERSION="portable-review-plan.v1"
STATES={"selected","skipped","unavailable"}
AUTHORITIES={"confirmed_surface","candidate_surface","explicitly_not_applicable","not_inspected"}
TRIGGERS={"migration_discovered","ai_surface_discovered","browser_surface_disproven"}
REVISION_CODES={"MISSING_CRITERION_LINK","MISSING_EVIDENCE_LINK","AUTHORITY_UPGRADE","OUT_OF_SCOPE_RECORD","INCOMPLETE_COVERAGE","MISSING_CLOSURE_REQUIREMENT"}


def root(ctx:LocalExecutionContext)->Path:
    return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"review-organisation"


def _json(value:object)->bytes:return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _hash(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _stable(prefix:str,value:object)->str:return prefix+"_"+hashlib.sha256(canonical_json(value).encode()).hexdigest()[:24]
def _dep(state:str,generation:str|None=None,semantic_hash:str|None=None)->dict:
    if state not in {"required_present","not_applicable","not_used","unavailable"}:raise ValueError("invalid_dependency_state")
    if state=="required_present" and (not generation or not semantic_hash):raise ValueError("required_dependency_missing_binding")
    if state!="required_present" and (generation is not None or semantic_hash is not None):raise ValueError("optional_dependency_must_be_null")
    return {"state":state,"generation":generation,"semantic_hash":semantic_hash}


def registry()->dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("specialist-result-registry.v1.json").read_text(encoding="utf-8"))


def _vector(ctx:LocalExecutionContext)->dict:
    graph=load_assessment_input(ctx); nodes=graph["graph_artifacts"]["requirement-evidence-graph.json"].get("nodes",[])
    paths=sorted({node.get("path") for node in nodes if isinstance(node.get("path"),str)})
    languages={"python":any(path.endswith(".py") for path in paths),"typescript":any(path.endswith((".ts",".tsx")) for path in paths)}
    criteria=graph["intent_artifacts"]["acceptance-criteria.json"].get("criteria",[])
    browser=any("browser_or_http" in item.get("required_evidence_categories",[]) for item in criteria)
    ai=any("ai" in path.lower() or "prompt" in path.lower() for path in paths)
    migration=any("migration" in path.lower() for path in paths)
    return {"schema_version":"review-plan-input-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",graph["graph_generation"],graph["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",graph["graph_generation"],graph["graph_manifest"]["semantic_bundle_hash"]),"assessment":_dep("not_used"),"measurement_ai":_dep("not_used"),"remediation":_dep("not_used"),"browser_applicability":{"authority":"confirmed_surface" if browser else "explicitly_not_applicable","criterion_ids":[item["criterion_id"] for item in criteria if "browser_or_http" in item.get("required_evidence_categories",[])]},"language_framework_signals":languages,"migration_signal":{"authority":"confirmed_surface" if migration else "not_inspected","evidence_paths":[path for path in paths if "migration" in path.lower()]},"ai_surface_signal":{"authority":"confirmed_surface" if ai else "not_inspected","evidence_paths":[path for path in paths if "ai" in path.lower() or "prompt" in path.lower()]},"harness":{"declared_capability":"manual_external","granted_permission":"prepared_packet_only"}}


def _selection(vector:dict)->list[dict]:
    result=[]
    for entry in registry()["specialists"]:
        sid=entry["specialist_id"]; selected=False; authority="not_inspected"; reasons=[]
        if sid=="product_intent":selected=True;authority="confirmed_surface";reasons=["product_intent_required"]
        elif sid=="python_engineering" and vector["language_framework_signals"]["python"]:selected=True;authority="confirmed_surface";reasons=["python_source_present"]
        elif sid=="typescript_engineering" and vector["language_framework_signals"]["typescript"]:selected=True;authority="confirmed_surface";reasons=["typescript_source_present"]
        elif sid=="browser_journey":authority=vector["browser_applicability"]["authority"];selected=authority=="confirmed_surface";reasons=["browser_requirement"] if selected else ["browser_explicitly_not_applicable"]
        elif sid=="ai_evaluation":authority=vector["ai_surface_signal"]["authority"];selected=authority=="confirmed_surface";reasons=["ai_surface"] if selected else ["ai_not_inspected"]
        elif sid=="migration_and_rollback":authority=vector["migration_signal"]["authority"];selected=authority=="confirmed_surface";reasons=["migration_signal"] if selected else ["migration_not_inspected"]
        elif sid in {"test_adequacy","instrumentation"}: selected=vector["language_framework_signals"]["python"] or vector["language_framework_signals"]["typescript"];authority="confirmed_surface" if selected else "not_inspected";reasons=["implementation_surface"] if selected else ["no_confirmed_implementation_surface"]
        result.append({"specialist_id":sid,"state":"selected" if selected else "skipped","applicability_authority":authority,"reason_codes":reasons,"evidence_refs":[],"required_capabilities":["prepared_packet_read"],"execution_mode":"manual_external","independence_limitations":["declared capability is not proof of isolation"],"result_schema":entry["result_schema"],"role_version":entry["role_version"]})
    return result


def prepare(ctx:LocalExecutionContext)->dict:
    vector=_vector(ctx); plan_id=_stable("review_plan",vector); generation="plan_"+uuid.uuid4().hex; directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="review_plan_generation")
    selected=_selection(vector); work_orders=[]
    for item in selected:
        if item["state"]!="selected":continue
        work_orders.append({"schema_version":"specialist-work-order.v1","work_order_id":_stable("wo",{"plan":plan_id,"specialist":item["specialist_id"]}),"plan_id":plan_id,"specialist_id":item["specialist_id"],"role_version":item["role_version"],"result_schema":item["result_schema"],"input_vector_hash":content_hash(vector),"allowed_files":[],"execution_mode":item["execution_mode"]})
    plan={"schema_version":"review-plan.v1","plan_id":plan_id,"input_vector":vector,"specialists":selected,"adaptation_depth":0,"supersedes":None}
    artifacts={"review-plan.json":plan,"plan-events.json":{"schema_version":"plan-events.v1","events":[]},"revision-ledger.json":{"schema_version":"revision-ledger.v1","entries":[]},"execution-summary.json":{"schema_version":"execution-summary.v1","execution_modes":[item["execution_mode"] for item in selected if item["state"]=="selected"]}}
    for name,value in artifacts.items():write_bytes(ctx.repository_root,directory/name,_json(value),label="review_plan_artifact")
    for work in work_orders:write_bytes(ctx.repository_root,directory/"specialist-work-orders"/(work["work_order_id"]+".json"),_json(work),label="specialist_work_order")
    manifest={"schema_version":"review-plan-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"plan_id":plan_id,"input_vector":vector,"artifact_hashes":{name:_hash(_json(value)) for name,value in artifacts.items()},"semantic_bundle_hash":content_hash({"plan":plan,"work_orders":work_orders}),"bundle_hash":""};manifest["bundle_hash"]=content_hash({key:value for key,value in manifest.items() if key!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="review_plan_manifest")
    replace_bytes(ctx.repository_root,root(ctx)/"current-review-plan.json",_json({"schema_version":"current-review-plan.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="review_plan_pointer")
    return manifest


def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=json.loads((root(ctx)/"current-review-plan.json").read_text(encoding="utf-8"));directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="review_plan_generation");manifest=json.loads((directory/"manifest.json").read_text(encoding="utf-8"))
    if manifest.get("compiler_version")!=COMPILER_VERSION or manifest["input_vector"]["release_commit"]!=ctx.authority_binding["repository_commit"]:raise ValueError("stale_dependency")
    artifacts={name:json.loads((directory/name).read_text(encoding="utf-8")) for name in ("review-plan.json","plan-events.json","revision-ledger.json","execution-summary.json")}
    return manifest,artifacts


def adapt(ctx:LocalExecutionContext,trigger:str,source_specialist:str,criterion_id:str,evidence_id:str)->dict:
    if trigger not in TRIGGERS:raise ValueError("adaptation_trigger_invalid")
    manifest,artifacts=load(ctx);events=artifacts["plan-events.json"]["events"]
    identity=_stable("plan_event",{"trigger":trigger,"source":source_specialist,"criterion":criterion_id,"evidence":evidence_id})
    if any(item["event_id"]==identity for item in events):return {"status":"duplicate_trigger","event_id":identity}
    if manifest["input_vector"].get("release_commit")!=ctx.authority_binding["repository_commit"]:raise ValueError("adaptation_evidence_unlinked")
    if artifacts["review-plan.json"]["adaptation_depth"]>=3:raise ValueError("adaptation_depth_exceeded")
    event={"event_id":identity,"trigger":trigger,"source_specialist":source_specialist,"criterion_id":criterion_id,"evidence_id":evidence_id}
    return {"status":"accepted","event":event,"prior_generation":manifest["generation"]}
