from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.project import content_hash

from .authority import domain_root
from .contracts import load_json_bytes, render_json, require_exact, sha256_bytes, stable_id
from .guidance import load_guidance_pack
from .preparation import load_preparation
from .results import normalize_result


def _atomic(path:Path,value:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(path.name+".tmp"); tmp.write_bytes(render_json(value)); tmp.replace(path)


def _primary(ctx:LocalExecutionContext,preparation_id:str,role:str)->tuple[dict,dict,bytes,bytes]:
    prep=load_preparation(ctx,preparation_id)
    if prep["semantic_basis"]["review"]["resolved"]!="expert_escalated_review": raise ValueError("verifier stage requires expert review")
    if role not in prep["work_orders"]: raise ValueError("primary role was not issued")
    work=prep["work_orders"][role]; root=domain_root(ctx)/"inbox"/preparation_id/work["work_order_id"]
    raw=(root/"result.json").read_bytes(); receipt=(root/"completion-receipt.json").read_bytes()
    result=normalize_result(raw,receipt,work,prep["contexts"][role],load_guidance_pack())
    return prep,result,raw,receipt


def prepare_verifier(ctx:LocalExecutionContext,preparation_id:str,role:str)->dict:
    prep,result,raw,receipt=_primary(ctx,preparation_id,role)
    material=[item for item in result["normalized"]["recommendations"] if item["requested_effect"] in {"condition_candidate","blocker_candidate"} or item["recommendation_class"]=="research_backed_warning"]
    if not material: raise ValueError("expert verifier requires a material recommendation")
    verifier_id="verifier_prep_"+uuid.uuid4().hex; work_id=stable_id("verifier_wo",{"primary":result["result_semantic_hash"],"role":role})
    directory=domain_root(ctx)/"verifier-preparations"/verifier_id; directory.mkdir(parents=True)
    work={"schema_version":"measurement-verifier-work-order.v2","verifier_preparation_id":verifier_id,"verifier_work_order_id":work_id,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"primary_role_id":role,"primary_work_order_id":prep["work_orders"][role]["work_order_id"],"primary_result_semantic_hash":result["result_semantic_hash"],"primary_result_snapshot_hash":result["result_snapshot_hash"],"primary_receipt_snapshot_hash":result["receipt_snapshot_hash"],"primary_snapshot_path":"primary-snapshot/normalized-result.json","material_recommendation_ids":sorted(item["recommendation_id"] for item in material),"required_qualification_capabilities":["skeptical_material_review"],"work_order_hash":""}
    work["work_order_hash"]=content_hash({k:v for k,v in work.items() if k!="work_order_hash"})
    (directory/"primary-snapshot").mkdir(); (directory/"primary-snapshot"/"result.json").write_bytes(raw); (directory/"primary-snapshot"/"completion-receipt.json").write_bytes(receipt); _atomic(directory/"primary-snapshot"/"normalized-result.json",result["normalized"]); _atomic(directory/"work-order.json",work)
    manifest={"schema_version":"measurement-verifier-preparation.v2","compiler_version":"measurement-ai-preparation.v2","verifier_preparation_id":verifier_id,"primary_preparation_id":preparation_id,"primary_role_id":role,"primary_result_semantic_hash":result["result_semantic_hash"],"primary_result_snapshot_hash":result["result_snapshot_hash"],"primary_receipt_snapshot_hash":result["receipt_snapshot_hash"],"work_order_id":work_id,"work_order_snapshot_hash":sha256_bytes(render_json(work)),"preparation_hash":""}; manifest["preparation_hash"]=content_hash({k:v for k,v in manifest.items() if k!="preparation_hash"}); _atomic(directory/"manifest.json",manifest)
    inbox=domain_root(ctx)/"verifier-inbox"/verifier_id/work_id; inbox.mkdir(parents=True)
    return {"verifier_preparation_id":verifier_id,"work_order":work,"manifest":manifest}


def _receipt(value:dict,work:dict,result_raw:bytes)->dict:
    require_exact(value,{"schema_version","executor","work_order_id","work_order_hash","result_snapshot_hash","started_at","completed_at"},"verifier completion receipt")
    if value["schema_version"]!="shiproom.assessment-completion-receipt.v2" or value["work_order_id"]!=work["verifier_work_order_id"] or value["work_order_hash"]!=work["work_order_hash"] or value["result_snapshot_hash"]!=sha256_bytes(result_raw): raise ValueError("verifier receipt binding mismatch")
    executor=value["executor"]
    if executor.get("executor_type")=="human": require_exact(executor,{"executor_type","reviewer_label"},"human verifier")
    elif executor.get("executor_type")=="agent_harness": require_exact(executor,{"executor_type","harness_id","adapter_version","run_id","model_id"},"model verifier")
    else: raise ValueError("invalid verifier executor")
    start=datetime.fromisoformat(value["started_at"].replace("Z","+00:00")); end=datetime.fromisoformat(value["completed_at"].replace("Z","+00:00"))
    if start.tzinfo is None or end.tzinfo is None or start>end: raise ValueError("invalid verifier completion interval")
    return value


def load_verifier(ctx:LocalExecutionContext,verifier_preparation_id:str)->dict:
    root=domain_root(ctx); directory=root/"verifier-preparations"/verifier_preparation_id
    manifest=load_json_bytes((directory/"manifest.json").read_bytes()); work=load_json_bytes((directory/"work-order.json").read_bytes())
    prep,result,raw,receipt=_primary(ctx,manifest["primary_preparation_id"],manifest["primary_role_id"])
    bindings=(result["result_semantic_hash"],result["result_snapshot_hash"],result["receipt_snapshot_hash"])
    if bindings!=(manifest["primary_result_semantic_hash"],manifest["primary_result_snapshot_hash"],manifest["primary_receipt_snapshot_hash"]): raise ValueError("primary result changed after verifier issuance")
    if (directory/"primary-snapshot"/"result.json").read_bytes()!=raw or (directory/"primary-snapshot"/"completion-receipt.json").read_bytes()!=receipt or (directory/"primary-snapshot"/"normalized-result.json").read_bytes()!=render_json(result["normalized"]): raise ValueError("verifier primary snapshot tamper")
    inbox=root/"verifier-inbox"/verifier_preparation_id/work["verifier_work_order_id"]; result_raw=(inbox/"result.json").read_bytes(); receipt_raw=(inbox/"completion-receipt.json").read_bytes(); value=load_json_bytes(result_raw)
    require_exact(value,{"schema_version","verifier_preparation_id","verifier_work_order_id","primary_result_semantic_hash","primary_result_snapshot_hash","primary_receipt_snapshot_hash","recommendation_reviews"},"verifier result")
    if value["schema_version"]!="measurement-verifier-result.v2" or value["verifier_preparation_id"]!=verifier_preparation_id or value["verifier_work_order_id"]!=work["verifier_work_order_id"] or (value["primary_result_semantic_hash"],value["primary_result_snapshot_hash"],value["primary_receipt_snapshot_hash"])!=bindings: raise ValueError("verifier result binding mismatch")
    reviews={}
    for item in value["recommendation_reviews"]:
        require_exact(item,{"recommendation_id","disposition","unsupported_assumption_codes","ignored_exception_ids","severity_supported","abstention_required","rationale"},"verifier recommendation review")
        if item["recommendation_id"] not in work["material_recommendation_ids"] or item["recommendation_id"] in reviews or item["disposition"] not in {"supported","downgrade","disputed","owner_confirmation_required"}: raise ValueError("invalid verifier recommendation coverage")
        reviews[item["recommendation_id"]]=item
    if set(reviews)!=set(work["material_recommendation_ids"]): raise ValueError("incomplete verifier recommendation coverage")
    completion=_receipt(load_json_bytes(receipt_raw),work,result_raw)
    return {"manifest":manifest,"work_order":work,"result":value,"receipt":completion,"result_snapshot_hash":sha256_bytes(result_raw),"receipt_snapshot_hash":sha256_bytes(receipt_raw),"semantic_hash":content_hash({"primary":bindings,"reviews":sorted(reviews.values(),key=lambda x:x["recommendation_id"])})}


def validate_embedded_verifier(directory:Path,primary_result:dict)->dict:
    prep_dir=directory/"preparation"; result_dir=directory/"result"
    manifest=load_json_bytes((prep_dir/"manifest.json").read_bytes()); work=load_json_bytes((prep_dir/"work-order.json").read_bytes())
    bindings=(primary_result["result_semantic_hash"],primary_result["result_snapshot_hash"],primary_result["receipt_snapshot_hash"])
    if (manifest["primary_result_semantic_hash"],manifest["primary_result_snapshot_hash"],manifest["primary_receipt_snapshot_hash"])!=bindings: raise ValueError("embedded verifier primary binding mismatch")
    if work["primary_result_semantic_hash"]!=bindings[0] or work["primary_result_snapshot_hash"]!=bindings[1] or work["primary_receipt_snapshot_hash"]!=bindings[2] or work["work_order_hash"]!=content_hash({k:v for k,v in work.items() if k!="work_order_hash"}): raise ValueError("embedded verifier work order binding mismatch")
    expected_manifest={**manifest,"work_order_snapshot_hash":sha256_bytes(render_json(work)),"preparation_hash":""}; expected_manifest["preparation_hash"]=content_hash({k:v for k,v in expected_manifest.items() if k!="preparation_hash"})
    if expected_manifest!=manifest: raise ValueError("embedded verifier preparation semantic tamper")
    primary_raw=(prep_dir/"primary-snapshot"/"result.json").read_bytes(); primary_receipt=(prep_dir/"primary-snapshot"/"completion-receipt.json").read_bytes()
    if sha256_bytes(primary_raw)!=bindings[1] or sha256_bytes(primary_receipt)!=bindings[2] or (prep_dir/"primary-snapshot"/"normalized-result.json").read_bytes()!=render_json(primary_result["normalized"]): raise ValueError("embedded primary snapshot mismatch")
    raw=(result_dir/"result.json").read_bytes(); receipt_raw=(result_dir/"completion-receipt.json").read_bytes(); value=load_json_bytes(raw)
    if value.get("primary_result_semantic_hash")!=bindings[0] or value.get("primary_result_snapshot_hash")!=bindings[1] or value.get("primary_receipt_snapshot_hash")!=bindings[2]: raise ValueError("embedded verifier result binding mismatch")
    expected_ids=set(work["material_recommendation_ids"]); reviews={}
    for item in value.get("recommendation_reviews",[]):
        require_exact(item,{"recommendation_id","disposition","unsupported_assumption_codes","ignored_exception_ids","severity_supported","abstention_required","rationale"},"embedded verifier review")
        if item["recommendation_id"] not in expected_ids or item["recommendation_id"] in reviews: raise ValueError("invalid embedded verifier coverage")
        reviews[item["recommendation_id"]]=item
    if set(reviews)!=expected_ids: raise ValueError("incomplete embedded verifier coverage")
    completion=_receipt(load_json_bytes(receipt_raw),work,raw)
    return {"manifest":manifest,"work_order":work,"result":value,"receipt":completion,"result_snapshot_hash":sha256_bytes(raw),"receipt_snapshot_hash":sha256_bytes(receipt_raw),"semantic_hash":content_hash({"primary":bindings,"reviews":sorted(reviews.values(),key=lambda x:x["recommendation_id"])})}
