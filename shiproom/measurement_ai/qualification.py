from __future__ import annotations

from pathlib import Path

from shiproom.project import content_hash

from .contracts import load_json_bytes, render_json, require_exact, require_string_list, require_text, sha256_bytes, stable_id
from .guidance import load_guidance_pack
from .trust import validate_ancestry


TASK_SCHEMA="measurement-reviewer-qualification-task.v3"
RESULT_SCHEMA="measurement-reviewer-qualification-result.v3"
RECEIPT_SCHEMA="measurement-reviewer-qualification-receipt.v3"
QUALIFIED_CAPABILITIES={"contract_structure","metric_decision_alignment","absolute_count_opportunity_review","ratio_denominator_review","population_review","window_delay_review","proxy_outcome_review","guardrail_review","causal_claim_review","ai_eval_structure","ai_claim_authority_review","skeptical_material_review"}


def qualification_store(repository_root:Path)->Path:
    return repository_root/".shiproom"/"local"/"measurement-reviewer-qualifications"


def build_qualification_task(guidance:dict,result_schema_version:str="measurement-result.v3")->dict:
    task={"schema_version":TASK_SCHEMA,"task_id":stable_id("qualification_task",{"guidance":guidance["pack_hash"],"schema":result_schema_version}),"role_prompt_version":"measurement-ai-role.v3","guidance_pack_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v2.json"]["semantic_hash"],"result_schema_version":result_schema_version,"qualification_suite_version":guidance["qualification_suite"]["suite_version"],"qualification_suite_hash":guidance["snapshots"]["qualification-suite.v2.json"]["semantic_hash"],"cases":guidance["qualification_suite"]["cases"],"task_hash":""}
    task["task_hash"]=content_hash({k:v for k,v in task.items() if k!="task_hash"}); return task


def grade_qualification_result(value:dict,task:dict,result_snapshot_hash:str)->dict:
    require_exact(value,{"schema_version","task_id","task_hash","provider_id","model_id","case_results"},"qualification result")
    if value["schema_version"]!=RESULT_SCHEMA or value["task_id"]!=task["task_id"] or value["task_hash"]!=task["task_hash"]: raise ValueError("qualification result binding mismatch")
    require_text(value["provider_id"],"provider_id",200); require_text(value["model_id"],"model_id",200)
    expected={item["case_id"]:item for item in task["cases"]}; submitted=value["case_results"]
    if not isinstance(submitted,list) or len(submitted)!=len(expected) or {item.get("case_id") for item in submitted if isinstance(item,dict)}!=set(expected): raise ValueError("qualification case coverage is incomplete")
    capabilities=set()
    for item in submitted:
        require_exact(item,{"case_id","semantic_assessment","recommendation_classes","guidance_rule_ids","exception_ids","effect","abstained","claim_codes","authority_labels","automatic_replacements"},"qualification case result")
        constraint=expected[item["case_id"]]
        recommendations=set(require_string_list(item["recommendation_classes"],"recommendation classes")); rules=set(require_string_list(item["guidance_rule_ids"],"guidance rules")); exceptions=set(require_string_list(item["exception_ids"],"exception IDs")); claims=set(require_string_list(item["claim_codes"],"claim codes")); labels=set(require_string_list(item["authority_labels"],"authority labels")); replacements=set(require_string_list(item["automatic_replacements"],"automatic replacements"))
        if item["semantic_assessment"] not in constraint["allowed_semantic_assessments"] or item["semantic_assessment"] in constraint["forbidden_semantic_assessments"] or not set(constraint["required_recommendation_classes"]).issubset(recommendations) or recommendations&set(constraint["forbidden_recommendation_classes"]) or not set(constraint["required_guidance_rules"]).issubset(rules) or not set(constraint["required_exception_ids"]).issubset(exceptions) or item["effect"]!=constraint["maximum_effect"] or bool(item["abstained"])!=constraint["abstention_required"] or claims&set(constraint["forbidden_claim_codes"]) or not set(constraint["required_authority_labels"]).issubset(labels) or replacements&set(constraint["automatic_replacement_prohibitions"]): raise ValueError(f"qualification case failed: {item['case_id']}")
        capabilities.update(constraint["qualified_capabilities"])
    receipt={"schema_version":RECEIPT_SCHEMA,"qualification_id":stable_id("qualification",{"task":task["task_hash"],"provider":value["provider_id"],"model":value["model_id"]}),"task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":value["provider_id"],"model_id":value["model_id"],"qualified_capabilities":sorted(capabilities),"case_ids":sorted(expected),"result_semantic_hash":content_hash({"task":task["task_hash"],"case_results":value["case_results"]}),"result_snapshot_hash":result_snapshot_hash}
    return receipt


def load_qualification_receipt(path:Path,task:dict)->dict:
    store=path.parent
    validate_ancestry(store,path,directory=False,label="qualification receipt")
    raw=path.read_bytes(); value=load_json_bytes(raw); require_exact(value,{"schema_version","qualification_id","task_id","task_hash","provider_id","model_id","qualified_capabilities","case_ids","result_semantic_hash","result_snapshot_hash"},"qualification receipt")
    if value["schema_version"]!=RECEIPT_SCHEMA or value["task_id"]!=task["task_id"] or value["task_hash"]!=task["task_hash"] or not set(value["qualified_capabilities"]).issubset(QUALIFIED_CAPABILITIES) or value["case_ids"]!=sorted(item["case_id"] for item in task["cases"]): raise ValueError("qualification receipt is stale or invalid")
    return {"value":value,"bytes":raw,"snapshot_hash":sha256_bytes(raw)}


def prepare_qualification(repository_root:Path)->dict:
    task=build_qualification_task(load_guidance_pack()); store=qualification_store(repository_root); store.mkdir(parents=True,exist_ok=True); (store/"qualification-task.v3.json").write_bytes(render_json(task)); return task


def compile_qualification(repository_root:Path,result_path:Path)->dict:
    guidance=load_guidance_pack(); task=build_qualification_task(guidance); raw=result_path.read_bytes(); value=load_json_bytes(raw); receipt=grade_qualification_result(value,task,sha256_bytes(raw)); store=qualification_store(repository_root); store.mkdir(parents=True,exist_ok=True); (store/(receipt["qualification_id"]+".json")).write_bytes(render_json(receipt)); return receipt
