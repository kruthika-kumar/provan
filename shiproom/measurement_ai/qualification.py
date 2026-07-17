from __future__ import annotations

from pathlib import Path
from importlib import resources

from shiproom.project import content_hash

from .contracts import load_json_bytes, render_json, require_exact, require_string_list, require_text, sha256_bytes, stable_id
from .guidance import load_guidance_pack
from .trust import ensure_directory, exact_children, replace_bytes_safe, safe_entry, validate_ancestry, write_bytes_safe


TASK_SCHEMA="measurement-reviewer-qualification-task.v3"
RESULT_SCHEMA="measurement-reviewer-qualification-result.v3"
RECEIPT_SCHEMA="measurement-reviewer-qualification-receipt.v3"
QUALIFIED_CAPABILITIES={"contract_structure","metric_decision_alignment","absolute_count_opportunity_review","ratio_denominator_review","population_review","window_delay_review","proxy_outcome_review","guardrail_review","causal_claim_review","ai_eval_structure","ai_claim_authority_review","skeptical_material_review"}


def qualification_store(repository_root:Path)->Path:
    return repository_root/".shiproom"/"local"/"measurement-reviewer-qualifications"


def _bundle_metadata(task:dict,result:dict,result_raw:bytes,receipt:dict,rubric:dict)->dict:
    task_raw=render_json(task); receipt_raw=render_json(receipt)
    values={
        "task_semantic_hash":content_hash(task),"task_snapshot_hash":sha256_bytes(task_raw),
        "result_semantic_hash":content_hash(result),"result_snapshot_hash":sha256_bytes(result_raw),
        "receipt_semantic_hash":content_hash(receipt),"receipt_snapshot_hash":sha256_bytes(receipt_raw),
        "private_rubric_semantic_hash":content_hash(rubric),
    }
    return {**values,"qualification_bundle_hash":content_hash(values)}


def write_qualification_bundle(repository_root:Path,task:dict,result:dict,result_raw:bytes,receipt:dict,rubric:dict)->dict:
    root=ensure_directory(repository_root,qualification_store(repository_root),label="qualification store")
    directory=ensure_directory(repository_root,root/receipt["qualification_id"],label="qualification bundle")
    expected={"qualification-task.json","qualification-result.json","qualification-receipt.json"}
    if any(directory.iterdir()): exact_children(directory,expected,"qualification bundle")
    replace_bytes_safe(repository_root,directory/"qualification-task.json",render_json(task),label="qualification task")
    replace_bytes_safe(repository_root,directory/"qualification-result.json",result_raw,label="qualification result")
    replace_bytes_safe(repository_root,directory/"qualification-receipt.json",render_json(receipt),label="qualification receipt")
    return {"value":receipt,"directory":directory,"bytes":render_json(receipt),**_bundle_metadata(task,result,result_raw,receipt,rubric)}


def load_qualification_bundle(path:Path,guidance:dict)->dict:
    directory=Path(path); exact_children(directory,{"qualification-task.json","qualification-result.json","qualification-receipt.json"},"qualification bundle")
    for name in ("qualification-task.json","qualification-result.json","qualification-receipt.json"):
        validate_ancestry(directory,directory/name,directory=False,label="qualification bundle file")
    task_raw=(directory/"qualification-task.json").read_bytes(); result_raw=(directory/"qualification-result.json").read_bytes(); receipt_raw=(directory/"qualification-receipt.json").read_bytes()
    task=load_json_bytes(task_raw); result=load_json_bytes(result_raw); receipt=load_json_bytes(receipt_raw)
    expected_task=build_qualification_task(guidance,task.get("result_schema_version",""))
    if task!=expected_task or task_raw!=render_json(expected_task): raise ValueError("qualification task semantic rederivation failed")
    rubric=guidance["qualification_private_rubric"]
    expected_receipt=grade_qualification_result(result,expected_task,sha256_bytes(result_raw),rubric,guidance)
    if receipt!=expected_receipt or receipt_raw!=render_json(expected_receipt): raise ValueError("qualification receipt regrading failed")
    return {"value":receipt,"directory":directory,"bytes":receipt_raw,**_bundle_metadata(task,result,result_raw,receipt,rubric)}


def build_qualification_task(guidance:dict,result_schema_version:str="measurement-result.v3")->dict:
    public=guidance["qualification_public_cases"]
    requested=sorted({cap for item in public["cases"] for cap in item["requested_capabilities"]})
    by_cap={cap:sorted(item["case_id"] for item in public["cases"] if cap in item["requested_capabilities"]) for cap in requested}
    task={"schema_version":TASK_SCHEMA,"task_id":stable_id("qualification_task",{"guidance":guidance["pack_hash"],"schema":result_schema_version}),"role_prompt_version":"measurement-ai-role.v3","guidance_pack_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v2.json"]["semantic_hash"],"result_schema_version":result_schema_version,"qualification_suite_version":public["suite_version"],"qualification_suite_hash":guidance["snapshots"]["qualification-public-cases.v1.json"]["semantic_hash"],"requested_capabilities":requested,"case_ids_by_capability":by_cap,"cases":public["cases"],"response_fields":public["response_fields"],"task_hash":""}
    task["task_hash"]=content_hash({k:v for k,v in task.items() if k!="task_hash"}); return task


def grade_qualification_result(value:dict,task:dict,result_snapshot_hash:str,rubric:dict|None=None,guidance:dict|None=None)->dict:
    if rubric is None:
        guidance=guidance or load_guidance_pack(); rubric=guidance["qualification_private_rubric"]
    require_exact(value,{"schema_version","task_id","task_hash","provider_id","model_id","requested_capabilities","case_results"},"qualification result")
    if value["schema_version"]!=RESULT_SCHEMA or value["task_id"]!=task["task_id"] or value["task_hash"]!=task["task_hash"]: raise ValueError("qualification result binding mismatch")
    require_text(value["provider_id"],"provider_id",200); require_text(value["model_id"],"model_id",200)
    if sorted(value["requested_capabilities"])!=task["requested_capabilities"]: raise ValueError("qualification capability request mismatch")
    expected={item["case_id"]:item for item in rubric["cases"]}; submitted=value["case_results"]
    if not isinstance(submitted,list) or len(submitted)!=len(expected) or {item.get("case_id") for item in submitted if isinstance(item,dict)}!=set(expected): raise ValueError("qualification case coverage is incomplete")
    passed_cases=set(); failed_cases=set()
    for item in submitted:
        require_exact(item,{"case_id","semantic_assessment","recommendation_classes","guidance_rule_ids","exception_ids","effect","abstained","claim_codes","authority_labels","automatic_replacements"},"qualification case result")
        constraint=expected[item["case_id"]]
        recommendations=set(require_string_list(item["recommendation_classes"],"recommendation classes")); rules=set(require_string_list(item["guidance_rule_ids"],"guidance rules")); exceptions=set(require_string_list(item["exception_ids"],"exception IDs")); claims=set(require_string_list(item["claim_codes"],"claim codes")); labels=set(require_string_list(item["authority_labels"],"authority labels")); replacements=set(require_string_list(item["automatic_replacements"],"automatic replacements"))
        ok=item["semantic_assessment"] in constraint["allowed_semantic_assessments"] and item["semantic_assessment"] not in constraint["forbidden_semantic_assessments"] and set(constraint["required_recommendation_classes"]).issubset(recommendations) and not recommendations&set(constraint["forbidden_recommendation_classes"]) and set(constraint["required_guidance_rules"]).issubset(rules) and set(constraint["required_exception_ids"]).issubset(exceptions) and item["effect"]==constraint["maximum_effect"] and bool(item["abstained"])==constraint["abstention_required"] and not claims&set(constraint["forbidden_claim_codes"]) and set(constraint["required_authority_labels"]).issubset(labels) and not replacements&set(constraint["automatic_replacement_prohibitions"])
        (passed_cases if ok else failed_cases).add(item["case_id"])
    by_cap=task["case_ids_by_capability"]
    passed=sorted(cap for cap,cases in by_cap.items() if set(cases).issubset(passed_cases)); failed=sorted(set(task["requested_capabilities"])-set(passed))
    rubric_hash=content_hash(rubric)
    receipt={"schema_version":RECEIPT_SCHEMA,"qualification_id":stable_id("qualification",{"task":task["task_hash"],"provider":value["provider_id"],"model":value["model_id"],"rubric":rubric_hash}),"task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":value["provider_id"],"model_id":value["model_id"],"requested_capabilities":task["requested_capabilities"],"case_ids_by_capability":by_cap,"passed_capabilities":passed,"failed_capabilities":failed,"qualified_capabilities":passed,"case_ids":sorted(expected),"private_rubric_version":rubric["rubric_version"],"private_rubric_semantic_hash":rubric_hash,"private_rubric_snapshot_hash":guidance["snapshots"]["measurement-qualification-private-rubric.v1.json"]["snapshot_hash"] if guidance else sha256_bytes(render_json(rubric)),"grading_engine_version":rubric["grading_engine_version"],"result_semantic_hash":content_hash({"task":task["task_hash"],"case_results":value["case_results"]}),"result_snapshot_hash":result_snapshot_hash}
    return receipt


def load_qualification_receipt(path:Path,task:dict)->dict:
    store=path.parent
    validate_ancestry(store,path,directory=False,label="qualification receipt")
    raw=path.read_bytes(); value=load_json_bytes(raw); require_exact(value,{"schema_version","qualification_id","task_id","task_hash","provider_id","model_id","qualified_capabilities","case_ids","result_semantic_hash","result_snapshot_hash"},"qualification receipt")
    if value["schema_version"]!=RECEIPT_SCHEMA or value["task_id"]!=task["task_id"] or value["task_hash"]!=task["task_hash"] or not set(value["qualified_capabilities"]).issubset(QUALIFIED_CAPABILITIES) or value["case_ids"]!=sorted(item["case_id"] for item in task["cases"]): raise ValueError("qualification receipt is stale or invalid")
    return {"value":value,"bytes":raw,"snapshot_hash":sha256_bytes(raw)}


def prepare_qualification(repository_root:Path)->dict:
    guidance=load_guidance_pack(); task=build_qualification_task(guidance); store=ensure_directory(repository_root,qualification_store(repository_root),label="qualification store"); public=ensure_directory(repository_root,store/"reviewer-packet",label="qualification reviewer packet"); private=ensure_directory(repository_root,store/"compiler-private",label="qualification private packet"); replace_bytes_safe(repository_root,public/"qualification-task.json",render_json(task),label="qualification task"); schema=resources.files("shiproom.measurement_ai_schemas").joinpath("measurement-reviewer-qualification-result.v3.json").read_bytes(); replace_bytes_safe(repository_root,public/"response-schema.json",schema,label="qualification response schema"); replace_bytes_safe(repository_root,private/"grading-rubric.json",guidance["snapshots"]["measurement-qualification-private-rubric.v1.json"]["bytes"],label="qualification private rubric"); return task


def compile_qualification(repository_root:Path,result_path:Path)->dict:
    guidance=load_guidance_pack(); task=build_qualification_task(guidance); raw=result_path.read_bytes(); value=load_json_bytes(raw); receipt=grade_qualification_result(value,task,sha256_bytes(raw),guidance["qualification_private_rubric"],guidance); bundle=write_qualification_bundle(repository_root,task,value,raw,receipt,guidance["qualification_private_rubric"]); return {**receipt,"qualification_bundle_hash":bundle["qualification_bundle_hash"],"qualification_bundle_path":str(bundle["directory"])}
