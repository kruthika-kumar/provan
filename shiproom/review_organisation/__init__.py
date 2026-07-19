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
from shiproom.workflow_trust import checked_children, ensure_directory, read_json, replace_bytes, safe_entry, write_bytes


COMPILER_VERSION="portable-review-plan.v1"
STATES={"selected","skipped","unavailable"}
AUTHORITIES={"confirmed_surface","candidate_surface","explicitly_not_applicable","not_inspected"}
TRIGGERS={"migration_surface_discovered","ai_surface_discovered","browser_surface_disproven"}
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


def native_boundaries() -> dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("specialist-native-boundary-registry.v1.json").read_text(encoding="utf-8"))


def surface_policy() -> dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("review-surface-policy.v1.json").read_text(encoding="utf-8"))


def _vector(ctx:LocalExecutionContext)->dict:
    graph=load_assessment_input(ctx); nodes=graph["graph_artifacts"]["requirement-evidence-graph.json"].get("nodes",[])
    paths=sorted({node.get("path") for node in nodes if isinstance(node.get("path"),str)})
    languages={"python":any(path.endswith(".py") for path in paths),"typescript":any(path.endswith((".ts",".tsx")) for path in paths)}
    criteria=graph["intent_artifacts"]["acceptance-criteria.json"].get("criteria",[])
    browser=any("browser_or_http" in item.get("required_evidence_categories",[]) for item in criteria)
    # A filename-like hint is a candidate surface only. It cannot establish selection.
    ai_candidates=[path for path in paths if "ai" in path.lower() or "prompt" in path.lower()]
    migration_candidates=[path for path in paths if "migration" in path.lower()]
    return {"schema_version":"review-plan-input-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",graph["graph_generation"],graph["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",graph["graph_generation"],graph["graph_manifest"]["semantic_bundle_hash"]),"assessment":_dep("not_used"),"measurement_ai":_dep("not_used"),"remediation":_dep("not_used"),"browser_applicability":{"authority":"confirmed_surface" if browser else "not_inspected","criterion_ids":[item["criterion_id"] for item in criteria if "browser_or_http" in item.get("required_evidence_categories",[])]},"language_framework_signals":languages,"migration_signal":{"authority":"candidate_surface" if migration_candidates else "not_inspected","evidence_paths":migration_candidates},"ai_surface_signal":{"authority":"candidate_surface" if ai_candidates else "not_inspected","evidence_paths":ai_candidates},"harness":{"declared_capability":"manual_external","granted_permission":"prepared_packet_only","observed_execution":"not_observed","independence_limitation":"declared capability is not proof of isolation"}}


def _selection(vector:dict)->list[dict]:
    result=[]
    for entry in registry()["specialists"]:
        sid=entry["specialist_id"]; selected=False; authority="not_inspected"; reasons=[]
        if sid=="product_intent":selected=True;authority="confirmed_surface";reasons=["product_intent_required"]
        elif sid=="python_engineering" and vector["language_framework_signals"]["python"]:selected=True;authority="confirmed_surface";reasons=["python_source_present"]
        elif sid=="typescript_engineering" and vector["language_framework_signals"]["typescript"]:selected=True;authority="confirmed_surface";reasons=["typescript_source_present"]
        elif sid=="browser_journey":authority=vector["browser_applicability"]["authority"];selected=authority=="confirmed_surface";reasons=["browser_requirement"] if selected else ["browser_not_inspected"]
        elif sid=="ai_evaluation":authority=vector["ai_surface_signal"]["authority"];selected=authority in {"confirmed_surface","candidate_surface"};reasons=["ai_surface"] if selected else ["ai_not_inspected"]
        elif sid=="migration_and_rollback":authority=vector["migration_signal"]["authority"];selected=authority in {"confirmed_surface","candidate_surface"};reasons=["migration_signal"] if selected else ["migration_not_inspected"]
        elif sid in {"test_adequacy","instrumentation"}: selected=vector["language_framework_signals"]["python"] or vector["language_framework_signals"]["typescript"];authority="confirmed_surface" if selected else "not_inspected";reasons=["implementation_surface"] if selected else ["no_confirmed_implementation_surface"]
        native=next(item for item in native_boundaries()["specialists"] if item["specialist_id"]==sid)
        result.append({"specialist_id":sid,"state":"selected" if selected else "skipped","applicability_authority":authority,"reason_codes":reasons,"evidence_refs":[],"required_capabilities":["prepared_packet_read"],"execution_mode":"manual_external","independence_limitations":["declared capability is not proof of isolation"],"result_schema":entry["result_schema"],"role_version":entry["role_version"],"native_boundary":native})
    return result


def prepare(ctx:LocalExecutionContext)->dict:
    vector=_vector(ctx); plan_id=_stable("review_plan",vector); generation="plan_"+uuid.uuid4().hex; directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="review_plan_generation")
    selected=_selection(vector); work_orders=[]
    for item in selected:
        if item["state"]!="selected":continue
        work_orders.append({"schema_version":"specialist-work-order.v1","work_order_id":_stable("wo",{"plan":plan_id,"specialist":item["specialist_id"]}),"plan_id":plan_id,"specialist_id":item["specialist_id"],"role_version":item["role_version"],"result_schema":item["result_schema"],"input_vector_hash":content_hash(vector),"allowed_files":[],"execution_mode":item["execution_mode"],"revision_policy":{"maximum_invalid_submissions":2,"codes":sorted(REVISION_CODES)},"native_boundary":item["native_boundary"]})
    plan={"schema_version":"review-plan.v1","plan_id":plan_id,"input_vector":vector,"specialists":selected,"adaptation_depth":0,"supersedes":None}
    artifacts={"review-plan.json":plan,"plan-events.json":{"schema_version":"plan-events.v1","events":[]},"revision-ledger.json":{"schema_version":"revision-ledger.v1","entries":[]},"execution-summary.json":{"schema_version":"execution-summary.v1","execution_modes":[item["execution_mode"] for item in selected if item["state"]=="selected"]}}
    for name,value in artifacts.items():write_bytes(ctx.repository_root,directory/name,_json(value),label="review_plan_artifact")
    for work in work_orders:write_bytes(ctx.repository_root,directory/"specialist-work-orders"/(work["work_order_id"]+".json"),_json(work),label="specialist_work_order")
    manifest={"schema_version":"review-plan-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"plan_id":plan_id,"input_vector":vector,"artifact_hashes":{name:_hash(_json(value)) for name,value in artifacts.items()},"semantic_bundle_hash":content_hash({"plan":plan,"work_orders":work_orders}),"bundle_hash":""};manifest["bundle_hash"]=content_hash({key:value for key,value in manifest.items() if key!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="review_plan_manifest")
    replace_bytes(ctx.repository_root,root(ctx)/"current-review-plan.json",_json({"schema_version":"current-review-plan.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="review_plan_pointer")
    return manifest


def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=read_json(ctx.repository_root, root(ctx)/"current-review-plan.json",label="review_plan_pointer");directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="review_plan_generation");manifest=read_json(ctx.repository_root,directory/"manifest.json",label="review_plan_manifest")
    if manifest.get("compiler_version")!=COMPILER_VERSION or manifest["input_vector"]["release_commit"]!=ctx.authority_binding["repository_commit"]:raise ValueError("stale_dependency")
    artifacts={name:read_json(ctx.repository_root,directory/name,label="review_plan_artifact") for name in ("review-plan.json","plan-events.json","revision-ledger.json","execution-summary.json")}
    return manifest,artifacts


def adapt(ctx:LocalExecutionContext,trigger:str,source_specialist:str,criterion_id:str,evidence_id:str)->dict:
    if trigger not in TRIGGERS:raise ValueError("adaptation_trigger_invalid")
    manifest,artifacts=load(ctx);events=artifacts["plan-events.json"]["events"]
    identity=_stable("plan_event",{"trigger":trigger,"source":source_specialist,"criterion":criterion_id,"evidence":evidence_id})
    if any(item["event_id"]==identity for item in events):return {"status":"duplicate_trigger","event_id":identity}
    if manifest["input_vector"].get("release_commit")!=ctx.authority_binding["repository_commit"]:raise ValueError("adaptation_evidence_unlinked")
    if artifacts["review-plan.json"]["adaptation_depth"]>=3:raise ValueError("adaptation_depth_exceeded")
    if source_specialist not in {item["specialist_id"] for item in artifacts["review-plan.json"]["specialists"]}:
        raise ValueError("adaptation_evidence_unlinked")
    event={"event_id":identity,"trigger":trigger,"source_specialist":source_specialist,"criterion_id":criterion_id,"evidence_id":evidence_id}
    vector=manifest["input_vector"]; new_generation="plan_"+uuid.uuid4().hex
    output=ensure_directory(ctx.repository_root,root(ctx)/"generations"/new_generation,label="review_plan_adaptation")
    plan=dict(artifacts["review-plan.json"]);plan["adaptation_depth"]+=1;plan["supersedes"]=manifest["generation"]
    new_events={"schema_version":"plan-events.v1","events":events+[event]}
    new_artifacts={"review-plan.json":plan,"plan-events.json":new_events,"revision-ledger.json":artifacts["revision-ledger.json"],"execution-summary.json":artifacts["execution-summary.json"]}
    for name,value in new_artifacts.items():write_bytes(ctx.repository_root,output/name,_json(value),label="review_plan_adaptation_artifact")
    new_manifest={"schema_version":"review-plan-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":new_generation,"plan_id":plan["plan_id"],"input_vector":vector,"artifact_hashes":{name:_hash(_json(value)) for name,value in new_artifacts.items()},"semantic_bundle_hash":content_hash({"plan":plan,"events":new_events}),"bundle_hash":""};new_manifest["bundle_hash"]=content_hash({key:value for key,value in new_manifest.items() if key!="bundle_hash"})
    write_bytes(ctx.repository_root,output/"manifest.json",_json(new_manifest),label="review_plan_adaptation_manifest")
    replace_bytes(ctx.repository_root,root(ctx)/"current-review-plan.json",_json({"schema_version":"current-review-plan.v1","generation":new_generation,"manifest_hash":_hash(_json(new_manifest)),"semantic_bundle_hash":new_manifest["semantic_bundle_hash"]}),label="review_plan_pointer")
    return {"status":"accepted","event":event,"prior_generation":manifest["generation"],"generation":new_generation}


def render_package(ctx: LocalExecutionContext, specialist_id: str) -> dict:
    manifest, _ = load(ctx)
    directory = root(ctx) / "generations" / manifest["generation"] / "specialist-work-orders"
    matches = [path for path in checked_children(ctx.repository_root, directory, label="specialist_work_orders") if path.suffix == ".json" and read_json(ctx.repository_root, path, label="specialist_work_order").get("specialist_id") == specialist_id]
    if len(matches) != 1:
        raise ValueError("specialist_work_order_unavailable")
    order = read_json(ctx.repository_root, matches[0], label="specialist_work_order")
    return {"schema_version": "codex-execution-package.v1", "work_order": order, "allowed_files": order["allowed_files"], "forbidden_operations": ["model_execution", "network", "project_command", "sql"], "expected_result_path": "result.json", "expected_receipt_path": "completion-receipt.json"}


def submit_result(ctx: LocalExecutionContext, specialist_id: str, result: dict, receipt: dict) -> dict:
    manifest, artifacts = load(ctx)
    specialist = next((item for item in artifacts["review-plan.json"]["specialists"] if item["specialist_id"] == specialist_id), None)
    if specialist is None or specialist["state"] != "selected":
        raise ValueError("specialist_not_issued")
    if result.get("work_order_id") is None or receipt.get("work_order_id") != result.get("work_order_id"):
        return {"status": "revision_required", "reason": "MISSING_EVIDENCE_LINK", "json_pointers": ["/work_order_id"]}
    if result.get("authority") in {"deterministically_established", "source_verified"}:
        return {"status": "revision_required", "reason": "AUTHORITY_UPGRADE", "json_pointers": ["/authority"]}
    return {"status": "accepted", "specialist_id": specialist_id, "work_order_id": result["work_order_id"]}
