from __future__ import annotations

from .contracts import CHECK_IDS, COMPILER_VERSION, OVERLAY_SCHEMA, stable_id
from .overlay import validate_overlay


PRECEDENCE={"gap":0,"owner_confirmation_required":1,"not_inspected":2,"ready":3,"not_applicable":4}
DIMENSIONS={"decision_use_case_alignment","metric_role","outcome_alignment","population","opportunity_exposure","denominator","window","attribution","interpretation_rule","guardrails","inference_intent_alignment"}


def _contracts_for(prepared:list[dict],cid:str)->list[dict]: return [item for item in prepared if cid in item["criterion_ids"]]


def _base_derivation(check_id:str,cid:str,scope_state:str,record:dict|None)->dict:
    authority=(record or {}).get("compiled_authority",{})
    return {"criterion_id":cid,"scope_state":scope_state,"status":"not_applicable","reason_codes":[],
        "readiness_scope":["contract_definition"],"runtime_limitations":["Session 5 does not create runtime evidence."],
        "direct_fact_authorities":authority.get("direct_fact_authorities",[]),
        "criterion_basis_effective_authorities":authority.get("criterion_basis_effective_authorities",[]),
        "reviewer_conclusion_authority":(record or {}).get("conclusion_evidence_class","not_inspected"),
        "semantic_review_authority":(record or {}).get("semantic_review_authority","not_performed"),
        "precedence_inputs":{"eligible_gaps":[],"owner_confirmation_reasons":[],"coverage_complete":bool(record and record.get("disposition")=="assessed"),"satisfied":False}}


def _derive_one(check_id:str,cid:str,scope_state:str,record:dict|None,prepared:list[dict],context:dict,verifier_reviews:dict[str,dict])->dict:
    out=_base_derivation(check_id,cid,scope_state,record)
    if scope_state not in {"applicable","owner_confirmation_required"}: return out
    if scope_state=="owner_confirmation_required":
        out["status"]="owner_confirmation_required"; out["reason_codes"]=["criterion_scope_requires_owner_confirmation"]; out["precedence_inputs"]["owner_confirmation_reasons"]=out["reason_codes"]; return out
    contracts=_contracts_for(prepared,cid)
    assessed=bool(record and record.get("disposition")=="assessed")
    gaps=[gap for gap in (record or {}).get("gaps",[]) if gap["requested_effect"] in {"condition_candidate","blocker_candidate"}]
    status="not_inspected"; reasons=[]; satisfied=False; owner=[]; eligible=[]

    if check_id=="DATA_OUTCOME_EVENT_DEFINED":
        signals=[signal for contract in contracts for signal in contract["required_signals"]]
        declared=bool(signals) and all(signal["name_state"] in {"owner_confirmed","source_declared"} for signal in signals)
        if not declared: owner=["outcome_event_identity_unresolved"]
        elif not assessed: reasons=["assigned_signal_review_not_completed"]
        else: satisfied=True
        out["readiness_scope"]=["contract_definition"]
    elif check_id=="DATA_SUCCESS_AND_FAILURE_DISTINGUISHABLE":
        fields=[(contract["fields"]["success_condition"],contract["fields"]["failure_condition"]) for contract in contracts]
        complete=bool(fields) and all(a["field_state"]!="unresolved" and b["field_state"]!="unresolved" and a["value"]!=b["value"] for a,b in fields)
        if not complete: owner=["success_or_failure_predicate_unresolved_or_indistinguishable"]
        elif not assessed: reasons=["predicate_mapping_not_inspected"]
        else: satisfied=True
        out["readiness_scope"]=["contract_definition","source_mapping"]
    elif check_id=="DATA_CRITICAL_EVENT_PROPERTIES_PRESENT":
        signals=[signal for contract in contracts for signal in contract["required_signals"]]
        if not signals or any(signal["name_state"]=="unresolved" or not signal["required_properties"] for signal in signals): owner=["required_signal_or_property_set_unresolved"]
        elif not assessed: reasons=["required_property_mapping_not_inspected"]
        else:
            submitted={item["signal_id"]:item for item in record.get("signal_assessments",[])}
            missing=[]; uninspected=[]
            for signal in signals:
                results={item["property_name"]:item["state"] for item in submitted.get(signal["signal_id"],{}).get("property_results",[])}
                for prop in signal["required_properties"]:
                    if results.get(prop)=="missing": missing.append(f"{signal['signal_id']}:{prop}")
                    elif results.get(prop)!="present": uninspected.append(f"{signal['signal_id']}:{prop}")
            if missing: eligible=["required_property_missing:"+item for item in missing]
            elif uninspected: reasons=["required_property_not_inspected:"+item for item in uninspected]
            else: satisfied=True
        out["readiness_scope"]=["source_mapping","test_mapping"]
    elif check_id=="DATA_PRIMARY_METRIC_DECISION_USEFUL":
        unresolved=sorted({name for contract in contracts for name,field in contract["fields"].items() if field["field_state"]=="unresolved"})
        if unresolved: owner=["measurement_contract_structurally_unresolved:"+name for name in unresolved]
        elif not assessed: reasons=["semantic_review_not_completed"]
        elif record["semantic_review_authority"]=="not_performed": reasons=["semantic_review_not_performed"]
        else:
            dimensions={item["dimension"]:item["state"] for item in record["metric_dimensions"]}
            if set(dimensions)!=DIMENSIONS: reasons=["metric_dimension_coverage_incomplete"]
            elif any(state=="material_concern" for state in dimensions.values()) and record["semantic_review_authority"]=="dual_reviewed_with_curated_guidance":
                material=[item for item in verifier_reviews.values() if item.get("criterion_id")==cid]
                if material and all(item["review"].get("disposition")=="supported" and item["review"].get("severity_supported") and not item["review"].get("unsupported_assumption_codes") for item in material): eligible=["dual_reviewed_material_metric_concern"]
                else: owner=["material_metric_concern_requires_supported_verifier"]
            elif any(state=="insufficient_context" for state in dimensions.values()): owner=["insufficient_context_for_metric_quality_assessment"]
            elif any(state=="not_inspected" for state in dimensions.values()): reasons=["metric_dimension_not_inspected"]
            else: satisfied=True
        out["readiness_scope"]=["contract_definition","semantic_review"]
    elif check_id=="AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS":
        if not assessed: reasons=["AI_eval_sources_not_inspected"]
        else:
            maturity=record["ai_maturity"]
            required=("fixed_input","oracle_or_rubric","pass_condition","journey_or_criterion_linkage")
            if all(maturity.get(item)=="established" for item in required): satisfied=True
            else: eligible=["qualified_fixed_eval_absent"]
        out["readiness_scope"]=["source_mapping","test_mapping"]
    elif check_id=="AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF":
        if not assessed: reasons=["AI_claims_not_inspected"]
        else:
            basis={item["basis_id"]:item for item in context["basis_registry"]}
            dishonest=[]
            for claim in record["claims"]:
                classes=[basis[bid]["direct_fact_authority"] for bid in claim["basis_ids"] if bid in basis]
                if claim["presented_as_proof"] and (not classes or any(value not in {"source_verified","deterministically_established"} for value in classes)): dishonest.append(claim["claim_id"])
            if dishonest: eligible=["model_claim_presented_as_proof:"+item for item in dishonest]
            else: satisfied=True
        out["readiness_scope"]=["contract_definition","semantic_review"]

    eligible.extend(gap["gap_kind"] for gap in gaps)
    if eligible: status="gap"; reasons=eligible
    elif owner: status="owner_confirmation_required"; reasons=owner
    elif not assessed or reasons: status="not_inspected"
    elif satisfied: status="ready"
    out["status"]=status; out["reason_codes"]=sorted(set(reasons)); out["precedence_inputs"]={"eligible_gaps":sorted(set(eligible)),"owner_confirmation_reasons":sorted(set(owner)),"coverage_complete":assessed,"satisfied":satisfied}
    return out


def _aggregate(check_id:str,derivations:list[dict])->dict:
    applicable=[item for item in derivations if item["status"]!="not_applicable"]
    status="not_applicable" if not applicable else min((item["status"] for item in applicable),key=lambda value:PRECEDENCE[value])
    semantic=sorted({item["semantic_review_authority"] for item in derivations})
    return {"check_id":check_id,"status":status,"reason_codes":sorted({reason for item in derivations if item["status"]==status for reason in item["reason_codes"]}),
        "record_derivations":derivations,"direct_basis_classifications":sorted({value for item in derivations for value in item["direct_fact_authorities"]}),
        "criterion_basis_effective_classifications":sorted({value for item in derivations for value in item["criterion_basis_effective_authorities"]}),
        "conclusion_evidence_class":"model_reviewed" if any(item["reviewer_conclusion_authority"]=="model_reviewed" for item in derivations) else "not_inspected",
        "semantic_review_authority":semantic[-1] if semantic else "not_performed",
        "check_authority":"compiler_derived_from_model_reviewed_assessment" if any(value!="not_performed" for value in semantic) else "compiler_derived_from_prepared_authority",
        "readiness_scope":sorted({value for item in derivations for value in item["readiness_scope"]}),
        "coverage_boundary":{"criterion_ids":[item["criterion_id"] for item in derivations],"runtime_verified":False}}


def build_artifacts(preparation:dict,results:dict[str,dict],verifiers:dict[str,dict]|None=None)->dict:
    source=preparation["source_packet"]; prepared=source["prepared_measurement_contracts"]; scopes=source["role_scopes"]
    records={role:{item["criterion_id"]:item for item in result["normalized"]["records"]} for role,result in results.items()}
    checks=[]; aggregate_inputs={}; verifier_reviews={}
    for verifier in (verifiers or {}).values():
        role=verifier["manifest"]["primary_role_id"]
        recommendations={item["recommendation_id"]:item for item in results[role]["normalized"]["recommendations"]}
        for review in verifier["result"]["recommendation_reviews"]:
            recommendation=recommendations.get(review["recommendation_id"])
            if recommendation: verifier_reviews[review["recommendation_id"]]={"criterion_id":recommendation["criterion_id"],"review":review}
    for check_id in CHECK_IDS:
        role="ai_evaluation" if check_id.startswith("AI_") else "measurement"; scope=scopes[role]
        ids=sorted(set(scope["applicable_criterion_ids"]+scope["candidate_criterion_ids"])); derivations=[]
        for cid in ids:
            state="applicable" if cid in scope["applicable_criterion_ids"] else "owner_confirmation_required"
            derivations.append(_derive_one(check_id,cid,state,records.get(role,{}).get(cid),prepared,preparation["contexts"].get(role,{"basis_registry":[]}),verifier_reviews))
        checks.append(_aggregate(check_id,derivations)); aggregate_inputs[check_id]=[item["precedence_inputs"] for item in derivations]
    recommendations=[item for result in results.values() for item in result["normalized"]["recommendations"]]
    all_records=[{"role_id":role,**item} for role,result in results.items() for item in result["normalized"]["records"]]
    contracts={"schema_version":"measurement-contract.v2","release_id":source["release_id"],"contracts":prepared,"downstream_definitions":[{"path":item["path"],"definition_state":"declared_external" if item["declared_external"] else "supplied_and_inspected","execution_state":"not_inspected","data_accuracy_state":"not_inspected"} for item in preparation["applicability"]["measurement"]["measurement_definition_paths"]],"review_records":[item for item in all_records if item["role_id"]=="measurement"]}
    measurement_records=[item for item in all_records if item["role_id"]=="measurement"]
    instrumentation={"schema_version":"instrumentation-coverage.v2","release_id":source["release_id"],"signals":[signal for contract in prepared for signal in contract["required_signals"]],"event_candidates":[candidate for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["event_candidate_basis_ids"]],"property_assessments":[prop for item in measurement_records for signal in item["signal_assessments"] for prop in signal["property_results"]],"test_candidates":[candidate for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["test_basis_ids"]],"runtime_bindings":[candidate for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["runtime_basis_ids"]],"observability_candidates":[candidate for item in all_records if item["role_id"]=="ai_evaluation" for candidate in item["observability_candidates"]],"coverage_boundary":"Source candidates do not prove runtime emission, populated fields, dashboards, or production monitoring."}
    readiness={"schema_version":"measurement-ai-readiness.v2","release_id":source["release_id"],"compiler_version":COMPILER_VERSION,"skip_reason":source["skip_reason"],"checks":checks,"accepted_role_validations":[{"role_id":role,"result_semantic_hash":result["result_semantic_hash"]} for role,result in sorted(results.items())],"aggregate_precedence_inputs":aggregate_inputs}
    gaps=[gap for item in all_records for gap in item["gaps"]]
    plan={"schema_version":"launch-measurement-plan.v2","release_id":source["release_id"],"warnings":recommendations,"proposals":[item for item in recommendations if item["recommendation_class"] in {"contextual_metric_proposal","contextual_hypothesis"}],"gaps":gaps,"owner_confirmation_proposals":([{"proposal_id":stable_id("owner_proposal",source["role_scopes"]),"reason":"bounded applicability requires owner confirmation","criterion_ids":sorted(set(scopes["measurement"]["candidate_criterion_ids"]+scopes["ai_evaluation"]["candidate_criterion_ids"]))}] if any(scopes[role]["candidate_criterion_ids"] or scopes[role]["unbounded_candidate_count"] for role in scopes) else []),"limitations":sorted({value for result in results.values() for value in result["normalized"]["limitations"]})}
    overlay=build_overlay(preparation,results,contracts,recommendations,plan)
    return {"measurement-contract.json":contracts,"instrumentation-coverage.json":instrumentation,"measurement-ai-readiness.json":readiness,"launch-measurement-plan.json":plan,"measurement-ai-overlay.json":overlay}


def build_overlay(preparation:dict,results:dict,contracts:dict,recommendations:list,plan:dict)->dict:
    source=preparation["source_packet"]; nodes=[]; edges=[]
    graph=preparation["authority"]["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]; base_ids={item["node_id"] for item in graph["nodes"]}
    for contract in contracts["contracts"]:
        nodes.append({"node_id":contract["contract_id"],"node_type":"measurement_contract","provenance":"measurement_ai_compiler","contract_id":contract["contract_id"],"journey_id":contract["journey_id"],"criterion_ids":contract["criterion_ids"]})
        for cid in contract["criterion_ids"]:
            eid=stable_id("edge",{"contract":contract["contract_id"],"criterion":cid}); edges.append({"edge_id":eid,"source_node_id":contract["contract_id"],"target_node_id":cid,"relationship":"governs_criterion","direct_fact_authority":"source_verified","criterion_id":cid,"criterion_path":[{"edge_id":eid,"traversal":"forward"}],"criterion_basis_authority":"source_verified","origin":"prepared_contract","references":[]})
        for signal in contract["required_signals"]:
            nodes.append({"node_id":signal["signal_id"],"node_type":"required_signal","provenance":"measurement_ai_compiler","signal_id":signal["signal_id"],"criterion_ids":signal["criterion_ids"],"state":signal["name_state"]})
            edges.append({"edge_id":stable_id("edge",{"contract":contract["contract_id"],"signal":signal["signal_id"]}),"source_node_id":contract["contract_id"],"target_node_id":signal["signal_id"],"relationship":"requires_signal","direct_fact_authority":"source_verified" if signal["name_state"]!="unresolved" else "not_inspected","criterion_id":None,"criterion_path":[],"criterion_basis_authority":"source_verified" if signal["name_state"]!="unresolved" else "not_inspected","origin":"prepared_contract","references":[]})
    conclusion_ids={}
    for role,result in results.items():
        for record in result["normalized"]["records"]:
            nid=stable_id("reviewer_conclusion",{"role":role,"criterion":record["criterion_id"],"summary":record["summary"],"work_order":result["normalized"]["work_order_id"]}); conclusion_ids[(role,record["criterion_id"])]=nid
            nodes.append({"node_id":nid,"node_type":"reviewer_conclusion","provenance":"measurement_reviewer","role_id":role,"criterion_id":record["criterion_id"],"conclusion_evidence_class":record["conclusion_evidence_class"],"semantic_review_authority":record["semantic_review_authority"],"result_semantic_hash":result["result_semantic_hash"]})
            eid=stable_id("edge",{"conclusion":nid,"criterion":record["criterion_id"]}); eff=(record["compiled_authority"]["criterion_basis_effective_authorities"] or ["not_inspected"])[0]
            edges.append({"edge_id":eid,"source_node_id":nid,"target_node_id":record["criterion_id"],"relationship":"assesses_criterion","direct_fact_authority":eff,"criterion_id":record["criterion_id"],"criterion_path":[{"edge_id":eid,"traversal":"forward"}],"criterion_basis_authority":eff,"origin":"portable_result","references":record["basis_ids"]+record["basis_path_ids"]})
    for item in recommendations:
        nid=stable_id("warning",{k:v for k,v in item.items() if k not in {"local_id","compiled_authority","eligible_guidance_rule_ids"}})
        nodes.append({"node_id":nid,"node_type":"measurement_warning","provenance":"measurement_reviewer","recommendation_id":nid,"criterion_id":item["criterion_id"],"recommendation_class":item["recommendation_class"],"effect":item["requested_effect"]})
        role=next((r for r,res in results.items() if any(x["criterion_id"]==item["criterion_id"] and x["local_id"]==item["local_id"] for x in res["normalized"]["recommendations"])),"measurement")
        source_id=conclusion_ids.get((role,item["criterion_id"]));
        if source_id:
            edges.append({"edge_id":stable_id("edge",{"conclusion":source_id,"warning":nid}),"source_node_id":source_id,"target_node_id":nid,"relationship":"identifies_warning","direct_fact_authority":"not_inspected","criterion_id":None,"criterion_path":[],"criterion_basis_authority":"not_inspected","origin":"portable_result","references":item["basis_ids"]})
    value={"schema_version":OVERLAY_SCHEMA,"release_id":source["release_id"],"release_commit":source["release_commit"],"product_intent_semantic_hash":source["product_intent_semantic_hash"],"graph_semantic_hash":source["graph_semantic_hash"],"nodes":nodes,"edges":edges}
    return validate_overlay(value,base_ids)
