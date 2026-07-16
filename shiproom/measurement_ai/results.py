from __future__ import annotations

from datetime import datetime

from shiproom.project import content_hash

from .contracts import (
    DIMENSION_STATES, DISPOSITIONS, RECOMMENDATION_CLASSES, RECOMMENDATION_EFFECTS, RESULT_BYTES_LIMIT, SEMANTIC_REVIEW_AUTHORITIES,
    UNCERTAINTIES, effective_basis_class, load_json_bytes, require_exact,
    require_string_list, semantic_without_local_ids, sha256_bytes, stable_id,
)
from .guidance import eligible_rule_ids, rule_map


MEASUREMENT_FIELDS={"local_id","criterion_id","journey_ids","scope_state","disposition","uncertainty","basis_ids","basis_path_ids","conclusion_evidence_class","semantic_review_authority","summary","contract_updates","signal_assessments","metric_dimensions","gaps"}
AI_FIELDS={"local_id","criterion_id","scope_state","disposition","uncertainty","basis_ids","basis_path_ids","conclusion_evidence_class","semantic_review_authority","summary","ai_maturity","claims","observability_candidates","gaps"}
RECOMMENDATION_FIELDS={"local_id","criterion_id","recommendation_class","summary","basis_ids","basis_path_ids","guidance_rule_ids","exception_dispositions","requested_effect","abstained","automatic_replacements"}
GAP_FIELDS={"gap_kind","aspect_code","summary","basis_ids","basis_path_ids","requested_effect"}
GAP_KINDS={"measurement_contract_gap","instrumentation_mapping_gap","critical_property_gap","metric_decision_gap","fixed_eval_gap","failure_case_gap","version_traceability_gap","claim_authority_gap","observability_gap"}
EFFECT_RANK={"none":0,"proposal_only":0,"non_blocking_warning":1,"owner_confirmation":2,"condition_candidate":3,"blocker_candidate":4}
MATURITY_STATES={"established","candidate","not_established","not_inspected","not_applicable"}
MATURITY_KEYS={"case_candidate","fixed_input","oracle_or_rubric","pass_condition","journey_or_criterion_linkage","prompt_or_model_binding","known_failure","supplied_execution_result","deterministically_validated_result","production_trace_linkage"}
OBSERVABILITY_KINDS={"langfuse","opentelemetry","application_logging","provider_native_tracing","custom_tracing"}


def _semantic_hash(role:str,version:str,graph_hash:str,normalized:dict)->str:
    payload={key:normalized[key] for key in ("records","recommendations")}
    return content_hash({"role_id":role,"role_version":version,"base_graph_semantic_hash":graph_hash,
        "payload":semantic_without_local_ids(payload),"assumptions":normalized["assumptions"],"limitations":normalized["limitations"]})


def _validate_receipt(value:dict,work:dict,result_raw:bytes)->dict:
    require_exact(value,{"schema_version","executor","work_order_id","work_order_hash","result_snapshot_hash","started_at","completed_at"},"completion receipt")
    if value["schema_version"]!="shiproom.assessment-completion-receipt.v2" or value["work_order_id"]!=work["work_order_id"] or value["work_order_hash"]!=work["work_order_hash"] or value["result_snapshot_hash"]!=sha256_bytes(result_raw): raise ValueError("completion receipt binding mismatch")
    executor=value["executor"]
    if executor.get("executor_type")=="human": require_exact(executor,{"executor_type","reviewer_label"},"human executor")
    elif executor.get("executor_type")=="agent_harness": require_exact(executor,{"executor_type","harness_id","adapter_version","run_id","model_id"},"harness executor")
    else: raise ValueError("invalid completion executor")
    try: start=datetime.fromisoformat(value["started_at"].replace("Z","+00:00")); end=datetime.fromisoformat(value["completed_at"].replace("Z","+00:00"))
    except (TypeError,ValueError) as exc: raise ValueError("invalid completion time") from exc
    if start.tzinfo is None or end.tzinfo is None or start>end: raise ValueError("invalid completion interval")
    return value


def _authority(record:dict,context:dict,role:str)->dict:
    registry={item["basis_id"]:item for item in context["basis_registry"] if role in item["role_ids"]}
    paths={item["path_id"]:item for item in context["basis_paths"] if role in item["role_ids"]}
    basis_ids=require_string_list(record["basis_ids"],"basis IDs")
    path_ids=require_string_list(record["basis_path_ids"],"basis path IDs")
    cid=record["criterion_id"]
    if any(bid not in registry or cid not in registry[bid]["criterion_ids"] for bid in basis_ids): raise ValueError("result references an unavailable prepared basis")
    if any(pid not in paths or paths[pid]["criterion_id"]!=cid or paths[pid]["start_basis_id"] not in basis_ids for pid in path_ids): raise ValueError("result references an unavailable criterion basis path")
    direct=sorted({registry[bid]["direct_fact_authority"] for bid in basis_ids})
    effective=sorted({paths[pid]["effective_fact_authority"] for pid in path_ids})
    if not effective and direct: effective=[effective_basis_class(direct)]
    return {"direct_fact_authorities":direct,"criterion_basis_effective_authorities":effective}


def _facts(context:dict,record:dict)->dict[str,object]:
    facts={}
    cid=record["criterion_id"]
    contracts=[item for item in context.get("prepared_measurement_contracts",[]) if cid in item["criterion_ids"]]
    for contract in contracts:
        for name,field in contract["fields"].items():
            facts["contract."+name]=field
        roles=contract.get("metric_roles",[])
        facts["metric.role"]=roles[0] if len(roles)==1 else None
        denominator=contract["fields"].get("denominator",{}).get("value")
        numerator=contract["fields"].get("numerator",{}).get("value")
        facts["metric.form"]="ratio" if denominator is not None and numerator is not None else "absolute_count" if numerator is not None else None
    maturity=record.get("ai_maturity",{})
    facts.update({"ai.case_candidate":maturity.get("case_candidate"),"ai.known_failure":maturity.get("known_failure"),"ai.fallback_case":maturity.get("known_failure"),"ai.prompt_or_model_binding":maturity.get("prompt_or_model_binding")})
    return facts


def _validate_gap(gap:dict,record:dict,context:dict,role:str)->dict:
    require_exact(gap,GAP_FIELDS,"measurement AI gap")
    if gap["gap_kind"] not in GAP_KINDS or record["disposition"]!="assessed": raise ValueError("invalid assessment gap")
    proxy={"criterion_id":record["criterion_id"],"basis_ids":gap["basis_ids"],"basis_path_ids":gap["basis_path_ids"]}
    authority=_authority(proxy,context,role)
    if not gap["basis_ids"]: raise ValueError("assessment gap requires prepared project basis")
    if record["scope_state"]!="applicable" and gap["requested_effect"] in {"condition_candidate","blocker_candidate"}: raise ValueError("unresolved or candidate scope cannot create release effects")
    return {**gap,"compiled_authority":authority}


def _validate_recommendation(item:dict,record:dict,context:dict,role:str,guidance:dict,mode:str)->dict:
    require_exact(item,RECOMMENDATION_FIELDS,"measurement recommendation")
    if item["recommendation_class"] not in RECOMMENDATION_CLASSES or item["requested_effect"] not in RECOMMENDATION_EFFECTS or not isinstance(item["abstained"],bool): raise ValueError("invalid recommendation enum")
    if role=="ai_evaluation" and item["recommendation_class"]=="contextual_metric_proposal": raise ValueError("AI review cannot propose a product metric")
    if item["criterion_id"]!=record["criterion_id"]: raise ValueError("recommendation criterion mismatch")
    proxy={"criterion_id":record["criterion_id"],"basis_ids":item["basis_ids"],"basis_path_ids":item["basis_path_ids"]}
    authority=_authority(proxy,context,role)
    if not item["basis_ids"]: raise ValueError("recommendation requires prepared project basis")
    if mode=="contract_only" and item["recommendation_class"] not in {"deterministic_contract_gap","owner_confirmation_question"}: raise ValueError("contract-only review cannot issue semantic advice")
    rules=rule_map(guidance); eligible=eligible_rule_ids(guidance,_facts(context,record))
    cited=require_string_list(item["guidance_rule_ids"],"guidance rule IDs")
    formal=item["recommendation_class"] in {"research_backed_warning","contextual_metric_proposal"}
    if formal and (not cited or any(rule not in eligible for rule in cited)): raise ValueError("reviewer cited an ineligible guidance rule")
    if not cited and formal: raise ValueError("formal recommendation requires guidance basis")
    registered={exc["exception_id"]:(rule,exc) for rule_id in cited for rule in [rules.get(rule_id,{})] for exc in rule.get("exceptions",[])}
    dispositions={}
    for exc in item["exception_dispositions"]:
        require_exact(exc,{"exception_id","disposition","basis_ids"},"guidance exception disposition")
        if exc["exception_id"] not in registered or exc["exception_id"] in dispositions or exc["disposition"] not in {"applies","ruled_out","unknown","not_relevant"}: raise ValueError("invalid guidance exception disposition")
        if registered[exc["exception_id"]][1]["project_basis_required"] and exc["disposition"] in {"applies","ruled_out"} and not exc["basis_ids"]: raise ValueError("guidance exception requires project basis")
        if any(bid not in item["basis_ids"] for bid in exc["basis_ids"]): raise ValueError("exception basis is outside recommendation basis")
        dispositions[exc["exception_id"]]=exc
    if set(dispositions)!=set(registered): raise ValueError("guidance exception coverage is incomplete")
    unknown_material=any(exc["material"] and dispositions[eid]["disposition"]=="unknown" for eid,(_,exc) in registered.items())
    if unknown_material and not (item["abstained"] or item["recommendation_class"]=="owner_confirmation_question"): raise ValueError("unknown material exception requires abstention or owner confirmation")
    prohibited={value for rule_id in cited for value in rules[rule_id]["forbidden_output_classes"]}
    if set(item["automatic_replacements"]) & prohibited: raise ValueError("automatic replacement is prohibited")
    ceilings=[rules[rule_id]["maximum_effect"] for rule_id in cited]
    ceiling=min((EFFECT_RANK.get(value,0) for value in ceilings),default=0)
    if EFFECT_RANK[item["requested_effect"]]>ceiling and item["recommendation_class"] not in {"deterministic_contract_gap","owner_confirmation_question"}: raise ValueError("recommendation effect exceeds guidance ceiling")
    if record["scope_state"]!="applicable" and item["requested_effect"] in {"condition_candidate","blocker_candidate"}: raise ValueError("candidate scope cannot create a release effect")
    semantic={k:v for k,v in item.items() if k!="local_id"}
    return {**item,"recommendation_id":stable_id("recommendation",semantic),"compiled_authority":authority,"eligible_guidance_rule_ids":sorted(eligible),"maximum_effect_rank":ceiling}


def normalize_result(raw:bytes,receipt_raw:bytes,work:dict,context:dict,guidance:dict)->dict:
    if len(raw)>RESULT_BYTES_LIMIT: raise ValueError("measurement AI result exceeds byte limit")
    value=load_json_bytes(raw); required={"schema_version","role_id","role_version","preparation_id","work_order_id","base_graph_semantic_hash","resolved_review_mode","records","recommendations","assumptions","limitations"}; require_exact(value,required,"measurement AI result")
    role=work["role_id"]
    expected_schema="measurement-result.v2" if role=="measurement" else "ai-evaluation-result.v2"
    if value["schema_version"]!=expected_schema or value["role_id"]!=role or value["role_version"]!="2.0.0" or value["preparation_id"]!=work["preparation_id"] or value["work_order_id"]!=work["work_order_id"] or value["base_graph_semantic_hash"]!=work["inputs"]["graph_semantic_hash"] or value["resolved_review_mode"]!=work["resolved_review_mode"]: raise ValueError("unbound measurement AI result")
    require_string_list(value["assumptions"],"assumptions"); require_string_list(value["limitations"],"limitations")
    if not isinstance(value["records"],list) or not isinstance(value["recommendations"],list): raise ValueError("invalid result collections")
    assigned=set(context["assigned"]["criterion_ids"]); records={}
    for submitted in value["records"]:
        require_exact(submitted,MEASUREMENT_FIELDS if role=="measurement" else AI_FIELDS,"role result record")
        cid=submitted["criterion_id"]
        if cid not in assigned or cid in records or submitted["disposition"] not in DISPOSITIONS or submitted["uncertainty"] not in UNCERTAINTIES: raise ValueError("invalid assigned result coverage")
        assessed=submitted["disposition"]=="assessed"
        if assessed != (submitted["uncertainty"]!="not_assessed"): raise ValueError("disposition uncertainty mismatch")
        if submitted["conclusion_evidence_class"] not in {"model_reviewed","not_inspected"} or submitted["semantic_review_authority"] not in SEMANTIC_REVIEW_AUTHORITIES: raise ValueError("reviewer attempted authority upgrade")
        if assessed and not submitted["basis_ids"]: raise ValueError("assessed record requires prepared project basis")
        nonsemantic=[key for key in ("basis_ids","basis_path_ids","gaps") if submitted[key]]
        role_payload=(submitted["contract_updates"] or submitted["signal_assessments"] or submitted["metric_dimensions"]) if role=="measurement" else (submitted["claims"] or submitted["observability_candidates"] or any(value not in {"not_inspected","not_applicable"} for value in submitted["ai_maturity"].values()))
        if not assessed and (nonsemantic or role_payload): raise ValueError("non-assessed record must use empty sentinels")
        if value["resolved_review_mode"]=="contract_only":
            forbidden=(submitted["contract_updates"] or submitted["metric_dimensions"]) if role=="measurement" else submitted["claims"]
            if forbidden or submitted["semantic_review_authority"]!="not_performed": raise ValueError("contract-only result contains semantic review content")
        if role=="measurement" and any(item.get("state") not in DIMENSION_STATES for item in submitted["metric_dimensions"]): raise ValueError("invalid metric dimension")
        if role=="measurement":
            for update in submitted["contract_updates"]:
                require_exact(update,{"field_name","proposed_value","rationale"},"contract update")
            for signal in submitted["signal_assessments"]:
                require_exact(signal,{"signal_id","event_candidate_basis_ids","property_results","test_basis_ids","runtime_basis_ids"},"signal assessment")
                for key in ("event_candidate_basis_ids","test_basis_ids","runtime_basis_ids"): _authority({"criterion_id":cid,"basis_ids":signal[key],"basis_path_ids":[]},context,role)
                for prop in signal["property_results"]:
                    require_exact(prop,{"property_name","state","basis_ids"},"signal property result")
                    if prop["state"] not in {"present","missing","unresolved","not_inspected"}: raise ValueError("invalid signal property state")
                    _authority({"criterion_id":cid,"basis_ids":prop["basis_ids"],"basis_path_ids":[]},context,role)
            seen_dimensions=set()
            for dimension in submitted["metric_dimensions"]:
                require_exact(dimension,{"dimension","state","rationale"},"metric dimension")
                if dimension["dimension"] in seen_dimensions: raise ValueError("duplicate metric dimension")
                seen_dimensions.add(dimension["dimension"])
        else:
            if set(submitted["ai_maturity"])!=MATURITY_KEYS or any(value not in MATURITY_STATES for value in submitted["ai_maturity"].values()): raise ValueError("invalid AI maturity record")
            claim_ids=set()
            for claim in submitted["claims"]:
                require_exact(claim,{"claim_id","statement","presented_as_proof","basis_ids","basis_path_ids"},"AI claim")
                if claim["claim_id"] in claim_ids or not isinstance(claim["presented_as_proof"],bool): raise ValueError("invalid AI claim")
                claim_ids.add(claim["claim_id"]); _authority({"criterion_id":cid,"basis_ids":claim["basis_ids"],"basis_path_ids":claim["basis_path_ids"]},context,role)
            candidate_ids=set()
            for candidate in submitted["observability_candidates"]:
                require_exact(candidate,{"candidate_id","kind","basis_ids","supported_dimensions"},"observability candidate")
                if candidate["candidate_id"] in candidate_ids or candidate["kind"] not in OBSERVABILITY_KINDS: raise ValueError("invalid observability candidate")
                candidate_ids.add(candidate["candidate_id"]); require_string_list(candidate["supported_dimensions"],"observability dimensions"); _authority({"criterion_id":cid,"basis_ids":candidate["basis_ids"],"basis_path_ids":[]},context,role)
        authority=_authority(submitted,context,role)
        gaps=[_validate_gap(gap,submitted,context,role) for gap in submitted["gaps"]]
        records[cid]={**submitted,"gaps":sorted(gaps,key=lambda x:(x["gap_kind"],x["aspect_code"])),"compiled_authority":authority}
    if set(records)!=assigned: raise ValueError("incomplete assigned result coverage")
    recommendations=[]; semantic_seen=set()
    for item in value["recommendations"]:
        cid=item.get("criterion_id"); record=records.get(cid)
        if record is None or record["disposition"]!="assessed": raise ValueError("recommendation requires an assessed criterion")
        normalized=_validate_recommendation(item,record,context,role,guidance,value["resolved_review_mode"])
        identity=content_hash(semantic_without_local_ids({k:v for k,v in normalized.items() if k not in {"compiled_authority","eligible_guidance_rule_ids"}}))
        if identity in semantic_seen: raise ValueError("duplicate semantic recommendation")
        semantic_seen.add(identity); recommendations.append(normalized)
    receipt=_validate_receipt(load_json_bytes(receipt_raw),work,raw)
    normalized={**value,"records":[records[cid] for cid in sorted(records)],"recommendations":sorted(recommendations,key=lambda x:(x["criterion_id"],x["recommendation_class"],x["local_id"])),"assumptions":sorted(value["assumptions"]),"limitations":sorted(value["limitations"])}
    return {"normalized":normalized,"receipt":receipt,"result_snapshot_hash":sha256_bytes(raw),"receipt_snapshot_hash":sha256_bytes(receipt_raw),"result_semantic_hash":_semantic_hash(role,value["role_version"],value["base_graph_semantic_hash"],normalized)}
