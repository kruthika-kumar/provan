from __future__ import annotations

from datetime import datetime

from shiproom.project import content_hash

from .contracts import (
    AI_MATURITY_RUNGS, CHECK_GAP_REGISTRY, DIMENSION_STATES, DISPOSITIONS,
    RESULT_BYTES_LIMIT, SEMANTIC_REVIEW_AUTHORITIES, UNCERTAINTIES,
    effective_basis_class, load_json_bytes, require_exact, require_string_list,
    semantic_without_local_ids, sha256_bytes, stable_id,
)
from .guidance import eligible_rule_ids, rule_map
from .registries import METRIC_DIMENSIONS as REGISTERED_METRIC_DIMENSIONS, ROLE_RESULT_SCHEMAS, RUNG_BASIS_TYPES
from .authority import _typed_field_value


MEASUREMENT_FIELDS={"local_id","criterion_id","journey_ids","scope_state","disposition","uncertainty","basis_ids","basis_path_ids","conclusion_evidence_class","semantic_review_authority","summary","contract_updates","signal_assessments","metric_dimensions","gaps"}
AI_FIELDS={"local_id","criterion_id","scope_state","disposition","uncertainty","basis_ids","basis_path_ids","conclusion_evidence_class","semantic_review_authority","summary","maturity_rungs","judge_assessments","claims","observability_candidates","gaps"}
RECOMMENDATION_FIELDS={"local_id","criterion_id","recommendation_class","summary","basis_ids","basis_path_ids","guidance_rule_ids","exception_dispositions","abstained","automatic_replacements"}
GAP_FIELDS={"local_id","gap_kind","aspect_code","summary","basis_ids","basis_path_ids"}
MATURITY_STATES={"established","candidate","not_established","not_inspected","not_applicable"}
OBSERVABILITY_KINDS={"langfuse","opentelemetry","application_logging","provider_native_tracing","custom_tracing"}
CLAIM_TYPES={"configuration","eval_structure","offline_behavior","runtime_behavior","product_outcome"}
METRIC_DIMENSIONS=set(REGISTERED_METRIC_DIMENSIONS)
EFFECT_RANK={"none":0,"proposal_only":0,"non_blocking_warning":1,"owner_confirmation":2,"condition_candidate":3,"blocker_candidate":4}

BASIS_TYPES={
    "event_candidate":{"instrumentation_event_definition"},
    "property":{"instrumentation_property_definition"},
    "test":{"test_reference"},
    "runtime":{"runtime_evidence"},
    **RUNG_BASIS_TYPES,
    "observability":{"source_reference","implementation_reference","observability_candidate"},
}


def _semantic_hash(role:str,version:str,graph_hash:str,normalized:dict)->str:
    payload={"records":normalized["records"],"recommendations":normalized["recommendations"]}
    return content_hash({"role_id":role,"role_version":version,"base_graph_semantic_hash":graph_hash,
        "payload":semantic_without_local_ids(payload),"assumptions":normalized["assumptions"],"limitations":normalized["limitations"]})


def validate_executor(executor:dict,work:dict)->None:
    participants=work.get("review_participants",[]); mode=work.get("resolved_review_mode")
    if mode!="contract_only" and len(participants)!=1: raise ValueError("resolved review requires exactly one participant")
    participant=participants[0] if participants else None
    if executor.get("executor_type")=="human":
        require_exact(executor,{"executor_type","reviewer_label"},"human executor")
        if participant is not None and participant.get("type")!="human": raise ValueError("human cannot complete model participant work")
    elif executor.get("executor_type")=="agent_harness":
        require_exact(executor,{"executor_type","participant_binding","harness_id","adapter_version","run_id"},"harness executor")
        binding=executor["participant_binding"]
        if participant is None:
            if mode!="contract_only" or binding is not None: raise ValueError("unbound harness is allowed only for contract-only work")
        else:
            if participant.get("type")!="model" or not isinstance(binding,dict): raise ValueError("harness cannot complete human participant work")
            require_exact(binding,{"candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash"},"model participant binding")
            if binding!={key:participant[key] for key in binding} or not set(work.get("required_qualification_capabilities",[])).issubset(participant.get("qualified_capabilities",[])): raise ValueError("completion executor participant binding mismatch")
    else: raise ValueError("invalid completion executor")

def _validate_receipt(value:dict,work:dict,result_raw:bytes)->dict:
    require_exact(value,{"schema_version","executor","work_order_id","work_order_hash","result_snapshot_hash","started_at","completed_at"},"completion receipt")
    if value["schema_version"]!="measurement-ai-completion-receipt.v3" or value["work_order_id"]!=work["work_order_id"] or value["work_order_hash"]!=work["work_order_hash"] or value["result_snapshot_hash"]!=sha256_bytes(result_raw): raise ValueError("completion receipt binding mismatch")
    validate_executor(value["executor"],work)
    try: start=datetime.fromisoformat(value["started_at"].replace("Z","+00:00")); end=datetime.fromisoformat(value["completed_at"].replace("Z","+00:00"))
    except (TypeError,ValueError) as exc: raise ValueError("invalid completion time") from exc
    if start.tzinfo is None or end.tzinfo is None or start>end: raise ValueError("invalid completion interval")
    return value


def _authority(record:dict,context:dict,role:str)->dict:
    registry={item["basis_id"]:item for item in context["basis_registry"] if role in item["role_ids"]}
    paths={item["path_id"]:item for item in context["basis_paths"] if role in item["role_ids"]}
    basis_ids=require_string_list(record["basis_ids"],"basis IDs"); path_ids=require_string_list(record["basis_path_ids"],"basis path IDs")
    cid=record["criterion_id"]
    if any(bid not in registry or cid not in registry[bid]["criterion_ids"] for bid in basis_ids): raise ValueError("result references an unavailable prepared basis")
    if any(pid not in paths or paths[pid]["criterion_id"]!=cid or paths[pid]["start_basis_id"] not in basis_ids for pid in path_ids): raise ValueError("result references an unavailable criterion basis path")
    required={item["path_id"] for item in paths.values() if item["required"] and item["criterion_id"]==cid and item["start_basis_id"] in basis_ids}
    if not required.issubset(path_ids): raise ValueError("result omitted a required criterion basis path")
    direct=sorted({registry[bid]["direct_fact_authority"] for bid in basis_ids})
    path_by_basis={bid:[paths[pid]["effective_authority"] for pid in path_ids if paths[pid]["start_basis_id"]==bid] for bid in basis_ids}
    combined_inputs=[effective_basis_class(path_by_basis[bid]) if path_by_basis[bid] else registry[bid]["direct_fact_authority"] for bid in basis_ids]
    combined=effective_basis_class(combined_inputs)
    return {"basis_ids":sorted(basis_ids),"basis_path_ids":sorted(path_ids),"direct_fact_authorities":direct,
        "criterion_path_authorities":sorted({value for values in path_by_basis.values() for value in values}),"criterion_scoped_basis_authority":combined}


def _typed_authority(item:dict,record:dict,context:dict,role:str,kind:str)->dict:
    proxy={"criterion_id":record["criterion_id"],"basis_ids":item["basis_ids"],"basis_path_ids":item["basis_path_ids"]}
    authority=_authority(proxy,context,role); registry={entry["basis_id"]:entry for entry in context["basis_registry"]}
    allowed=BASIS_TYPES[kind]
    established=item.get("state")=="established" or kind in {"event_candidate","test","runtime"}
    if established and (not item["basis_ids"] or any(registry[bid]["basis_type"] not in allowed for bid in item["basis_ids"])): raise ValueError(f"{kind} requires compatible prepared basis")
    if established and authority["criterion_scoped_basis_authority"] in {"not_inspected","model_mapped_candidate"}: raise ValueError(f"{kind} cannot be established through weak criterion authority")
    semantic_kinds={"event_candidate","property",*RUNG_BASIS_TYPES}
    if established and kind in semantic_kinds and record["semantic_review_authority"]=="not_performed": raise ValueError(f"{kind} requires a separate semantic assessment")
    return authority


def _assert_signal_basis(item:dict,context:dict,signal_id:str,property_name:str|None=None)->None:
    registry={entry["basis_id"]:entry for entry in context["basis_registry"]}
    for basis_id in item["basis_ids"]:
        basis=registry[basis_id]
        if basis.get("signal_id")!=signal_id: raise ValueError("typed basis belongs to a different signal")
        if property_name is not None and basis.get("property_name")!=property_name: raise ValueError("typed property basis belongs to a different property")


def _claim_honesty(claim:dict,authority:dict,context:dict)->tuple[str,list[str]]:
    registry={entry["basis_id"]:entry for entry in context["basis_registry"]}; types={registry[bid]["basis_type"] for bid in claim["basis_ids"]}
    strong=authority["criterion_scoped_basis_authority"]=="deterministically_established"
    requirements={
        "configuration": lambda: bool(types & {"ai_prompt_model_binding_definition","source_reference","implementation_reference"}) and authority["criterion_scoped_basis_authority"] in {"source_verified","deterministically_established"},
        "eval_structure": lambda: {"ai_fixed_input_definition","ai_oracle_or_rubric_definition","ai_pass_condition_definition"}.issubset(types) and authority["criterion_scoped_basis_authority"] in {"source_verified","deterministically_established"},
        "offline_behavior": lambda: strong and "ai_execution" in types,
        "runtime_behavior": lambda: strong and bool(types & {"production_trace","runtime_evidence"}),
        "product_outcome": lambda: strong and any(registry[bid]["basis_type"]=="runtime_evidence" and registry[bid]["assertion_scope"]=="runtime" and registry[bid]["origin"]!="portable_assessment" for bid in claim["basis_ids"]),
    }
    honest=not claim["presented_as_proof"] or requirements[claim["claim_type"]]()
    return ("honest",[]) if honest else ("unsupported_proof",["claim_scope_exceeds_validated_basis"])


def _facts(context:dict,record:dict)->dict[str,object]:
    facts={}; cid=record["criterion_id"]
    for contract in [item for item in context.get("prepared_measurement_contracts",[]) if cid in item["criterion_ids"]]:
        for name,field in contract["fields"].items(): facts["contract."+name]=field
        roles=contract.get("metric_roles",[]); facts["metric.role"]=roles[0] if len(roles)==1 else None
        denominator=contract["fields"].get("denominator",{}).get("value"); numerator=contract["fields"].get("numerator",{}).get("value")
        facts["metric.form"]="ratio" if denominator is not None and numerator is not None else "absolute_count" if numerator is not None else None
    rungs={item["rung"]:item["state"] for item in record.get("maturity_rungs",[])}
    facts.update({"ai.case_candidate":rungs.get("case_candidate"),"ai.known_failure":rungs.get("known_failure"),"ai.fallback_case":rungs.get("fallback"),"ai.prompt_or_model_binding":rungs.get("prompt_or_model_binding")})
    return facts


def _confirmed_contradiction(authority:dict,context:dict)->bool:
    registry={entry["basis_id"]:entry for entry in context["basis_registry"]}
    return any(registry[bid]["basis_type"]=="confirmed_contradiction" and registry[bid]["direct_fact_authority"] in {"source_verified","deterministically_established"} for bid in authority["basis_ids"])


def _blocker_eligible(context:dict,cid:str)->bool:
    return any(item["criterion_id"]==cid and item.get("blocker_eligible") is True for item in context["criteria"])


def _validate_gap(gap:dict,record:dict,context:dict,role:str,mode:str)->dict:
    require_exact(gap,GAP_FIELDS,"measurement AI gap")
    if gap["gap_kind"] not in CHECK_GAP_REGISTRY or record["disposition"]!="assessed": raise ValueError("invalid assessment gap")
    if mode=="contract_only": raise ValueError("contract-only review cannot submit assessment gaps")
    authority=_authority({"criterion_id":record["criterion_id"],"basis_ids":gap["basis_ids"],"basis_path_ids":gap["basis_path_ids"]},context,role)
    if not gap["basis_ids"]: raise ValueError("assessment gap requires prepared project basis")
    contradiction=_confirmed_contradiction(authority,context)
    effect="none"
    # Semantic metric-quality effects are applied only after the staged
    # verifier.  A primary metric gap remains canonical reviewer judgment but
    # cannot independently influence readiness.
    if gap["gap_kind"] not in {"metric_decision_gap","fixed_eval_gap","claim_authority_gap"} and contradiction and record["scope_state"]=="applicable": effect="blocker_candidate" if _blocker_eligible(context,record["criterion_id"]) else "condition_candidate"
    return {**gap,"gap_id":stable_id("assessment_gap",{"role":role,"criterion":record["criterion_id"],"kind":gap["gap_kind"],"aspect":gap["aspect_code"],"summary":gap["summary"]}),"compiled_authority":authority,"permitted_check_id":CHECK_GAP_REGISTRY[gap["gap_kind"]],"confirmed_contradiction":contradiction,"readiness_effect":"gap","derived_effect":effect}


def _validate_recommendation(item:dict,record:dict,context:dict,role:str,guidance:dict,mode:str)->dict:
    require_exact(item,RECOMMENDATION_FIELDS,"measurement recommendation")
    if role=="ai_evaluation" and item["recommendation_class"]=="contextual_metric_proposal": raise ValueError("AI review cannot propose a product metric")
    if item["criterion_id"]!=record["criterion_id"]: raise ValueError("recommendation criterion mismatch")
    if mode=="contract_only" and item["recommendation_class"]!="owner_confirmation_question": raise ValueError("contract-only review cannot issue semantic advice")
    authority=_authority({"criterion_id":record["criterion_id"],"basis_ids":item["basis_ids"],"basis_path_ids":item["basis_path_ids"]},context,role)
    if not item["basis_ids"]: raise ValueError("recommendation requires prepared project basis")
    rules=rule_map(guidance); eligible=eligible_rule_ids(guidance,_facts(context,record)); cited=require_string_list(item["guidance_rule_ids"],"guidance rule IDs")
    formal=item["recommendation_class"] in {"research_backed_warning","contextual_metric_proposal"}
    if formal and (not cited or any(rule not in eligible for rule in cited)): raise ValueError("reviewer cited an ineligible guidance rule")
    if mode=="contract_only" and cited: raise ValueError("contract-only owner questions cannot cite semantic guidance")
    registered={exc["exception_id"]:(rule,exc) for rule_id in cited for rule in [rules.get(rule_id,{})] for exc in rule.get("exceptions",[])}; dispositions={}
    for exc in item["exception_dispositions"]:
        require_exact(exc,{"exception_id","disposition","basis_ids"},"guidance exception disposition")
        if exc["exception_id"] not in registered or exc["exception_id"] in dispositions or exc["disposition"] not in {"applies","ruled_out","unknown","not_relevant"}: raise ValueError("invalid guidance exception disposition")
        if registered[exc["exception_id"]][1]["project_basis_required"] and exc["disposition"] in {"applies","ruled_out"} and not exc["basis_ids"]: raise ValueError("guidance exception requires project basis")
        if any(bid not in item["basis_ids"] for bid in exc["basis_ids"]): raise ValueError("exception basis is outside recommendation basis")
        exc["exception_analysis_id"]=stable_id("exception_analysis",{"criterion":record["criterion_id"],"rule_ids":cited,**exc})
        dispositions[exc["exception_id"]]=exc
    if set(dispositions)!=set(registered): raise ValueError("guidance exception coverage is incomplete")
    unknown_material=any(exc["material"] and dispositions[eid]["disposition"]=="unknown" for eid,(_,exc) in registered.items())
    if unknown_material and not (item["abstained"] or item["recommendation_class"]=="owner_confirmation_question"): raise ValueError("unknown material exception requires abstention or owner confirmation")
    prohibited={value for rule_id in cited for value in rules[rule_id]["forbidden_output_classes"]}
    if set(item["automatic_replacements"]) & prohibited: raise ValueError("automatic replacement is prohibited")
    if item["recommendation_class"]=="owner_confirmation_question": effect="owner_confirmation"
    elif item["recommendation_class"]=="research_backed_warning":
        material_dimension=any(value.get("state")=="material_concern" for value in record.get("metric_dimensions",[]))
        condition_allowed=any(rules[rule_id]["maximum_effect"]=="condition_candidate" for rule_id in cited)
        effect="condition_candidate" if mode=="expert_escalated_review" and record["semantic_review_authority"]=="dual_reviewed_with_curated_guidance" and material_dimension and condition_allowed else "non_blocking_warning"
    elif item["recommendation_class"] in {"contextual_hypothesis","contextual_metric_proposal"}: effect="none"
    elif item["recommendation_class"]=="deterministic_contract_gap":
        if not _confirmed_contradiction(authority,context): raise ValueError("deterministic contract gap requires an exact prepared confirmed contradiction")
        effect="blocker_candidate" if _blocker_eligible(context,record["criterion_id"]) else "condition_candidate"
    else: raise ValueError("invalid recommendation class")
    if record["scope_state"]!="applicable" and effect in {"condition_candidate","blocker_candidate"}: raise ValueError("candidate scope cannot create a release effect")
    semantic={k:v for k,v in item.items() if k!="local_id"}
    return {**item,"recommendation_id":stable_id("recommendation",semantic_without_local_ids(semantic)),"compiled_authority":authority,"eligible_guidance_rule_ids":sorted(eligible),"derived_effect":effect}


def _common_record_checks(submitted:dict,role:str,assigned:set[str],records:dict,mode:str)->tuple[str,bool]:
    cid=submitted["criterion_id"]
    if cid not in assigned or cid in records or submitted["disposition"] not in DISPOSITIONS or submitted["uncertainty"] not in UNCERTAINTIES: raise ValueError("invalid assigned result coverage")
    assessed=submitted["disposition"]=="assessed"
    if assessed != (submitted["uncertainty"]!="not_assessed"): raise ValueError("disposition uncertainty mismatch")
    if submitted["conclusion_evidence_class"] not in {"model_reviewed","not_inspected"} or submitted["semantic_review_authority"] not in SEMANTIC_REVIEW_AUTHORITIES: raise ValueError("reviewer attempted authority upgrade")
    if assessed and not submitted["basis_ids"]: raise ValueError("assessed record requires prepared project basis")
    if mode=="contract_only" and submitted["semantic_review_authority"]!="not_performed": raise ValueError("contract-only result contains semantic review authority")
    return cid,assessed


def normalize_result(raw:bytes,receipt_raw:bytes,work:dict,context:dict,guidance:dict)->dict:
    if len(raw)>RESULT_BYTES_LIMIT: raise ValueError("measurement AI result exceeds byte limit")
    value=load_json_bytes(raw); required={"schema_version","role_id","role_version","preparation_id","work_order_id","base_graph_semantic_hash","resolved_review_mode","records","recommendations","assumptions","limitations"}; require_exact(value,required,"measurement AI result")
    role=work["role_id"]; expected_schema="measurement-result.v3" if role=="measurement" else "ai-evaluation-result.v3"
    if work["required_output"]["schema_version"]!=ROLE_RESULT_SCHEMAS.get(role) or value["schema_version"]!=expected_schema or value["role_id"]!=role or value["role_version"]!="3.0.0" or value["preparation_id"]!=work["preparation_id"] or value["work_order_id"]!=work["work_order_id"] or value["base_graph_semantic_hash"]!=work["inputs"]["graph_semantic_hash"] or value["resolved_review_mode"]!=work["resolved_review_mode"]: raise ValueError("unbound measurement AI result")
    require_string_list(value["assumptions"],"assumptions"); require_string_list(value["limitations"],"limitations")
    if not isinstance(value["records"],list) or not isinstance(value["recommendations"],list): raise ValueError("invalid result collections")
    assigned=set(context["assigned"]["criterion_ids"]); records={}; accepted={"common.assumptions","common.limitations","common.recommendations"}
    for submitted in value["records"]:
        require_exact(submitted,MEASUREMENT_FIELDS if role=="measurement" else AI_FIELDS,"role result record")
        cid,assessed=_common_record_checks(submitted,role,assigned,records,value["resolved_review_mode"])
        if not assessed:
            common_nonempty=any(submitted[key] for key in ("basis_ids","basis_path_ids","gaps"))
            payload_nonempty=any(submitted[key] for key in (("contract_updates","signal_assessments","metric_dimensions") if role=="measurement" else ("maturity_rungs","judge_assessments","claims","observability_candidates")))
            if common_nonempty or payload_nonempty: raise ValueError("non-assessed record must use empty sentinels")
        authority=_authority(submitted,context,role)
        if role=="measurement":
            if value["resolved_review_mode"]=="contract_only" and (submitted["contract_updates"] or submitted["metric_dimensions"] or submitted["gaps"]): raise ValueError("contract-only result contains semantic content")
            for update in submitted["contract_updates"]:
                require_exact(update,{"local_id","field_name","proposed_value","rationale"},"contract update")
                if update["field_name"] not in context["prepared_measurement_contracts"][0]["fields"] if context["prepared_measurement_contracts"] else True: raise ValueError("unknown measurement contract field")
                _typed_field_value(update["field_name"],update["proposed_value"])
                update["proposal_id"]=stable_id("contract_proposal",{"criterion":cid,"field":update["field_name"],"value":update["proposed_value"],"rationale":update["rationale"]})
            if submitted["contract_updates"]: accepted.add("measurement.contract_updates")
            for signal in submitted["signal_assessments"]:
                require_exact(signal,{"local_id","signal_id","event_candidates","property_results","tests","runtime_evidence"},"signal assessment")
                prepared_signal=next((entry for contract in context["prepared_measurement_contracts"] for entry in contract["required_signals"] if entry["signal_id"]==signal["signal_id"] and cid in entry["criterion_ids"]),None)
                if prepared_signal is None: raise ValueError("signal assessment is outside prepared scope")
                for key,kind,projection in (("event_candidates","event_candidate","measurement.signal_assessments.event_candidates"),("tests","test","measurement.signal_assessments.tests"),("runtime_evidence","runtime","measurement.signal_assessments.runtime_evidence")):
                    for item in signal[key]:
                        require_exact(item,{"local_id","basis_ids","basis_path_ids"},f"signal {kind}"); item["compiled_authority"]=_typed_authority(item,submitted,context,role,kind)
                        if kind=="event_candidate": _assert_signal_basis(item,context,signal["signal_id"])
                        item["canonical_record_id"]=stable_id(kind,{"criterion":cid,"signal":signal["signal_id"],"bases":item["basis_ids"],"paths":item["basis_path_ids"]})
                    if signal[key]: accepted.add(projection)
                for prop in signal["property_results"]:
                    require_exact(prop,{"local_id","property_name","state","basis_ids","basis_path_ids"},"signal property result")
                    if prop["state"] not in {"present","missing","unresolved","not_inspected"}: raise ValueError("invalid signal property state")
                    if prop["property_name"] not in prepared_signal["required_properties"]: raise ValueError("property assessment is outside prepared signal scope")
                    strong_state="established" if prop["state"] in {"present","missing"} else prop["state"]
                    prop["compiled_authority"]=_typed_authority({**prop,"state":strong_state},submitted,context,role,"property")
                    if prop["state"] in {"present","missing"}: _assert_signal_basis(prop,context,signal["signal_id"],prop["property_name"])
                    prop["canonical_record_id"]=stable_id("property_assertion",{"criterion":cid,"signal":signal["signal_id"],"property":prop["property_name"],"state":prop["state"],"bases":prop["basis_ids"]})
                if signal["property_results"]: accepted.add("measurement.signal_assessments.property_results")
            seen=set()
            for dimension in submitted["metric_dimensions"]:
                require_exact(dimension,{"dimension","state","rationale","basis_ids","basis_path_ids"},"metric dimension")
                if dimension["dimension"] not in METRIC_DIMENSIONS or dimension["dimension"] in seen or dimension["state"] not in DIMENSION_STATES: raise ValueError("invalid metric dimension")
                seen.add(dimension["dimension"]); dimension["compiled_authority"]=_authority({"criterion_id":cid,"basis_ids":dimension["basis_ids"],"basis_path_ids":dimension["basis_path_ids"]},context,role)
                dimension["canonical_record_id"]=stable_id("metric_dimension",{"criterion":cid,**semantic_without_local_ids(dimension)})
            if value["resolved_review_mode"]!="contract_only" and assessed and seen!=METRIC_DIMENSIONS: raise ValueError("semantic measurement review requires all eleven dimensions")
            if submitted["metric_dimensions"]: accepted.add("measurement.metric_dimensions")
        else:
            if value["resolved_review_mode"]=="contract_only" and (submitted["judge_assessments"] or submitted["claims"] or submitted["gaps"]): raise ValueError("contract-only result contains semantic AI content")
            seen=set()
            for rung in submitted["maturity_rungs"]:
                require_exact(rung,{"local_id","rung","state","basis_ids","basis_path_ids","limitations"},"AI maturity rung")
                if rung["rung"] not in AI_MATURITY_RUNGS or rung["rung"] in seen or rung["state"] not in MATURITY_STATES: raise ValueError("invalid AI maturity rung")
                seen.add(rung["rung"]); rung["compiled_authority"]=_typed_authority(rung,submitted,context,role,rung["rung"])
                rung["canonical_record_id"]=stable_id("ai_rung",{"criterion":cid,**semantic_without_local_ids(rung)})
            if assessed and seen!=set(AI_MATURITY_RUNGS): raise ValueError("AI maturity coverage is incomplete")
            if submitted["maturity_rungs"]: accepted.add("ai_evaluation.maturity_rungs")
            for judge in submitted["judge_assessments"]:
                require_exact(judge,{"local_id","judge_type","judge_model","rubric_or_prompt","version_binding","calibration_state","agreement_state","limitations","basis_ids","basis_path_ids"},"AI judge assessment")
                judge["compiled_authority"]=_authority({"criterion_id":cid,"basis_ids":judge["basis_ids"],"basis_path_ids":judge["basis_path_ids"]},context,role)
                if judge["judge_type"]=="llm_judge" and judge["calibration_state"]=="not_established": judge["limitations"]=sorted(set(judge["limitations"]+["LLM-judge calibration is not established."]))
                judge["canonical_record_id"]=stable_id("judge_assessment",{"criterion":cid,**semantic_without_local_ids(judge)})
            if submitted["judge_assessments"]: accepted.add("ai_evaluation.judge_assessments")
            claim_ids=set()
            for claim in submitted["claims"]:
                require_exact(claim,{"local_id","claim_id","claim_type","asserted_scope","claimed_evidence_class","statement","presented_as_proof","basis_ids","basis_path_ids"},"AI claim")
                if claim["claim_id"] in claim_ids or claim["claim_type"] not in CLAIM_TYPES or claim["asserted_scope"]!=claim["claim_type"] or claim["claimed_evidence_class"] not in {"source_verified","deterministically_established","model_mapped_candidate","model_reviewed","not_inspected"} or not isinstance(claim["presented_as_proof"],bool): raise ValueError("invalid AI claim")
                claim_ids.add(claim["claim_id"]); claim["compiled_authority"]=_authority({"criterion_id":cid,"basis_ids":claim["basis_ids"],"basis_path_ids":claim["basis_path_ids"]},context,role)
                claim["honesty_state"],claim["honesty_reason_codes"]=_claim_honesty(claim,claim["compiled_authority"],context)
                claim["claim_id"]=stable_id("ai_claim",{"criterion":cid,"type":claim["claim_type"],"scope":claim["asserted_scope"],"statement":claim["statement"],"proof":claim["presented_as_proof"],"bases":claim["basis_ids"],"paths":claim["basis_path_ids"]})
            if submitted["claims"]: accepted.add("ai_evaluation.claims")
            obs_ids=set()
            for candidate in submitted["observability_candidates"]:
                require_exact(candidate,{"local_id","kind","basis_ids","basis_path_ids","supported_dimensions"},"observability candidate")
                if candidate["local_id"] in obs_ids or candidate["kind"] not in OBSERVABILITY_KINDS: raise ValueError("invalid observability candidate")
                obs_ids.add(candidate["local_id"]); candidate["compiled_authority"]=_typed_authority({**candidate,"state":"candidate"},submitted,context,role,"observability")
                candidate["canonical_record_id"]=stable_id("observability",{"criterion":cid,"kind":candidate["kind"],"bases":candidate["basis_ids"],"dimensions":candidate["supported_dimensions"]})
            if submitted["observability_candidates"]: accepted.add("ai_evaluation.observability_candidates")
        gaps=[_validate_gap(gap,submitted,context,role,value["resolved_review_mode"]) for gap in submitted["gaps"]]
        if gaps: accepted.add("common.gaps")
        records[cid]={**submitted,"gaps":sorted(gaps,key=lambda item:(item["gap_kind"],item["aspect_code"])),"compiled_authority":authority}
    if set(records)!=assigned: raise ValueError("incomplete assigned result coverage")
    recommendations=[]; semantic_seen=set()
    for item in value["recommendations"]:
        record=records.get(item.get("criterion_id"))
        if record is None or record["disposition"]!="assessed": raise ValueError("recommendation requires an assessed criterion")
        normalized_item=_validate_recommendation(item,record,context,role,guidance,value["resolved_review_mode"])
        identity=content_hash(semantic_without_local_ids({key:item for key,item in normalized_item.items() if key not in {"compiled_authority","eligible_guidance_rule_ids"}}))
        if identity in semantic_seen: raise ValueError("duplicate semantic recommendation")
        semantic_seen.add(identity); recommendations.append(normalized_item)
    receipt=_validate_receipt(load_json_bytes(receipt_raw),work,raw)
    normalized={**value,"records":[records[cid] for cid in sorted(records)],"recommendations":sorted(recommendations,key=lambda item:(item["criterion_id"],item["recommendation_class"],item["recommendation_id"])),"assumptions":sorted(value["assumptions"]),"limitations":sorted(value["limitations"]),"accepted_field_ledger":sorted(accepted)}
    return {"normalized":normalized,"receipt":receipt,"result_snapshot_hash":sha256_bytes(raw),"receipt_snapshot_hash":sha256_bytes(receipt_raw),"result_semantic_hash":_semantic_hash(role,value["role_version"],value["base_graph_semantic_hash"],normalized)}
