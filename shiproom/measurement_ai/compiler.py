from __future__ import annotations

from copy import deepcopy

from .contracts import CHECK_IDS, COMPILER_VERSION, OVERLAY_SCHEMA, effective_basis_class, is_material_recommendation, semantic_without_local_ids, stable_id
from .overlay import validate_overlay
from .projection import PROJECTION_REGISTRY, validate_projection_coverage
from .registries import METRIC_DIMENSIONS


PRECEDENCE={"gap":0,"owner_confirmation_required":1,"not_inspected":2,"ready":3,"not_applicable":4}
DIMENSIONS=set(METRIC_DIMENSIONS)


def _contracts_for(prepared:list[dict],cid:str)->list[dict]: return [item for item in prepared if cid in item["criterion_ids"]]


def _base_derivation(cid:str,scope_state:str,record:dict|None)->dict:
    authority=(record or {}).get("compiled_authority",{})
    return {"criterion_id":cid,"scope_state":scope_state,"status":"not_applicable","reason_codes":[],"readiness_scope":["contract_definition"],"runtime_limitations":["Session 5 creates no runtime evidence and does not execute project commands."],"direct_fact_authorities":authority.get("direct_fact_authorities",[]),"criterion_path_authorities":authority.get("criterion_path_authorities",[]),"criterion_scoped_basis_authority":authority.get("criterion_scoped_basis_authority","not_inspected"),"reviewer_conclusion_authority":(record or {}).get("conclusion_evidence_class","not_inspected"),"semantic_review_authority":(record or {}).get("semantic_review_authority","not_performed"),"precedence_inputs":{"eligible_gaps":[],"owner_confirmation_reasons":[],"coverage_complete":bool(record and record.get("disposition")=="assessed"),"satisfied":False}}


def _record_scopes(record:dict|None)->list[str]:
    scopes={"contract_definition"}
    if not record: return sorted(scopes)
    for signal in record.get("signal_assessments",[]):
        if signal.get("event_candidates") or signal.get("property_results"): scopes.add("source_mapping")
        if signal.get("tests"): scopes.add("test_mapping")
        if signal.get("runtime_evidence"): scopes.add("upstream_runtime")
    if record.get("semantic_review_authority") not in {None,"not_performed"}: scopes.add("semantic_review")
    for rung in record.get("maturity_rungs",[]):
        if rung["rung"] in {"supplied_execution_result","deterministically_validated_result"} and rung["state"]=="established": scopes.add("test_mapping")
        if rung["rung"]=="production_trace_linkage" and rung["state"]=="established": scopes.add("upstream_runtime")
    return sorted(scopes)


def _gap_reasons(record:dict|None,check_id:str)->list[str]:
    return sorted({gap["gap_kind"] for gap in (record or {}).get("gaps",[]) if gap.get("permitted_check_id")==check_id and gap.get("derived_effect") in {"condition_candidate","blocker_candidate"}})


def _derive_one(check_id:str,cid:str,scope_state:str,record:dict|None,prepared:list[dict],canonical_recommendations:list[dict])->dict:
    out=_base_derivation(cid,scope_state,record); out["readiness_scope"]=_record_scopes(record)
    if scope_state not in {"applicable","owner_confirmation_required"}: return out
    if scope_state=="owner_confirmation_required":
        out["status"]="owner_confirmation_required"; out["reason_codes"]=["criterion_scope_requires_owner_confirmation"]; out["precedence_inputs"]["owner_confirmation_reasons"]=out["reason_codes"]; return out
    contracts=_contracts_for(prepared,cid); assessed=bool(record and record.get("disposition")=="assessed")
    eligible=_gap_reasons(record,check_id); owner=[]; uninspected=[]; satisfied=False
    if check_id=="DATA_OUTCOME_EVENT_DEFINED":
        signals=[signal for contract in contracts for signal in contract["required_signals"]]
        if not signals or any(signal["name_state"] not in {"owner_confirmed","source_declared"} for signal in signals): owner=["outcome_event_identity_unresolved"]
        elif not assessed: uninspected=["assigned_signal_review_not_completed"]
        else: satisfied=True
    elif check_id=="DATA_SUCCESS_AND_FAILURE_DISTINGUISHABLE":
        fields=[(contract["fields"]["success_condition"],contract["fields"]["failure_condition"]) for contract in contracts]
        if not fields or any(a["field_state"]=="unresolved" or b["field_state"]=="unresolved" or a["value"]==b["value"] for a,b in fields): owner=["success_or_failure_predicate_unresolved_or_indistinguishable"]
        elif not assessed: uninspected=["predicate_mapping_not_inspected"]
        else: satisfied=True
    elif check_id=="DATA_CRITICAL_EVENT_PROPERTIES_PRESENT":
        signals=[signal for contract in contracts for signal in contract["required_signals"]]
        if not signals or any(signal["name_state"]=="unresolved" or not signal["required_properties"] for signal in signals): owner=["required_signal_or_property_set_unresolved"]
        elif not assessed: uninspected=["required_property_mapping_not_inspected"]
        else:
            submitted={item["signal_id"]:item for item in record.get("signal_assessments",[])}; missing=[]; pending=[]
            for signal in signals:
                properties={item["property_name"]:item for item in submitted.get(signal["signal_id"],{}).get("property_results",[])}
                for name in signal["required_properties"]:
                    item=properties.get(name)
                    if item and item["state"]=="missing" and item["compiled_authority"]["criterion_scoped_basis_authority"] in {"source_verified","deterministically_established"}: missing.append(f"{signal['signal_id']}:{name}")
                    elif not item or item["state"]!="present": pending.append(f"{signal['signal_id']}:{name}")
            eligible.extend("required_property_missing:"+item for item in missing)
            if pending: uninspected.extend("required_property_not_inspected:"+item for item in pending)
            if not missing and not pending: satisfied=True
    elif check_id=="DATA_PRIMARY_METRIC_DECISION_USEFUL":
        unresolved=sorted({name for contract in contracts for name,field in contract["fields"].items() if field["field_state"]=="unresolved" and name in {"decision_question","decision_use_case","decision_owner","decision_timing","decision_rule_or_interpretation","unit_of_observation","eligible_population","observation_window"}})
        if unresolved: owner=["measurement_contract_structurally_unresolved:"+name for name in unresolved]
        elif not assessed: uninspected=["semantic_review_not_completed"]
        elif record["semantic_review_authority"]=="not_performed": uninspected=["semantic_review_not_performed"]
        else:
            dimensions={item["dimension"]:item["state"] for item in record["metric_dimensions"]}
            if set(dimensions)!=DIMENSIONS: uninspected=["metric_dimension_coverage_incomplete"]
            elif any(state=="insufficient_context" for state in dimensions.values()): owner=["insufficient_context_for_metric_quality_assessment"]
            elif any(state=="not_inspected" for state in dimensions.values()): uninspected=["metric_dimension_not_inspected"]
            elif any(state=="material_concern" for state in dimensions.values()):
                material=[item for item in canonical_recommendations if item["criterion_id"]==cid and is_material_recommendation(item)]
                if record["semantic_review_authority"]!="dual_reviewed_with_curated_guidance" or not material: owner=["material_metric_concern_requires_supported_verifier"]
                elif all(item.get("verifier_disposition")=="supported" for item in material): eligible.append("dual_reviewed_material_metric_concern")
                else: owner=["material_metric_concern_requires_owner_confirmation"]
            else: satisfied=True
    elif check_id=="AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS":
        if not assessed: uninspected=["AI_eval_sources_not_inspected"]
        else:
            rungs={item["rung"]:item for item in record["maturity_rungs"]}; required=("fixed_input","oracle_or_rubric","pass_condition","journey_or_criterion_linkage")
            if all(rungs[item]["state"]=="established" and rungs[item]["compiled_authority"]["criterion_scoped_basis_authority"] in {"source_verified","deterministically_established"} for item in required): satisfied=True
            elif eligible: pass
            else: uninspected=["qualified_fixed_eval_not_established"]
    elif check_id=="AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF":
        if not assessed: uninspected=["AI_claims_not_inspected"]
        else:
            dishonest=[claim["claim_id"] for claim in record["claims"] if claim["presented_as_proof"] and claim["compiled_authority"]["criterion_scoped_basis_authority"] not in {"source_verified","deterministically_established"}]
            if dishonest: eligible.extend("model_claim_presented_as_proof:"+item for item in dishonest)
            else: satisfied=True
    status="gap" if eligible else "owner_confirmation_required" if owner else "not_inspected" if (not assessed or uninspected) else "ready" if satisfied else "not_inspected"
    reasons=eligible if eligible else owner if owner else uninspected
    out["status"]=status; out["reason_codes"]=sorted(set(reasons)); out["precedence_inputs"]={"eligible_gaps":sorted(set(eligible)),"owner_confirmation_reasons":sorted(set(owner)),"coverage_complete":assessed and not uninspected,"satisfied":satisfied}
    return out


def _aggregate(check_id:str,derivations:list[dict])->dict:
    applicable=[item for item in derivations if item["status"]!="not_applicable"]
    status="not_applicable" if not applicable else min((item["status"] for item in applicable),key=lambda value:PRECEDENCE[value])
    semantic=sorted({item["semantic_review_authority"] for item in derivations})
    aggregate_authority=effective_basis_class([item["criterion_scoped_basis_authority"] for item in applicable]) if applicable else "not_inspected"
    return {"check_id":check_id,"status":status,"reason_codes":sorted({reason for item in derivations if item["status"]==status for reason in item["reason_codes"]}),"record_derivations":derivations,"direct_basis_classifications":sorted({value for item in derivations for value in item["direct_fact_authorities"]}),"criterion_path_classifications":sorted({value for item in derivations for value in item["criterion_path_authorities"]}),"criterion_scoped_basis_authority":aggregate_authority,"conclusion_evidence_class":"model_reviewed" if any(item["reviewer_conclusion_authority"]=="model_reviewed" for item in derivations) else "not_inspected","semantic_review_authority":semantic[-1] if semantic else "not_performed","check_authority":"compiler_derived_from_model_reviewed_assessment" if any(value!="not_performed" for value in semantic) else "compiler_derived_from_prepared_authority","readiness_scope":sorted({value for item in derivations for value in item["readiness_scope"]}),"coverage_boundary":{"criterion_ids":[item["criterion_id"] for item in derivations],"contract_defined":any("contract_definition" in item["readiness_scope"] for item in derivations),"source_mapped":any("source_mapping" in item["readiness_scope"] for item in derivations),"test_mapped":any("test_mapping" in item["readiness_scope"] for item in derivations),"runtime_verified":any("upstream_runtime" in item["readiness_scope"] and item["criterion_scoped_basis_authority"]=="deterministically_established" for item in derivations)}}


def _canonical_recommendations(results:dict[str,dict],verifiers:dict[str,dict])->list[dict]:
    reviews={}
    for verifier in verifiers.values():
        for review in verifier["result"]["recommendation_reviews"]: reviews[review["recommendation_id"]]=review
    output=[]
    for role,result in sorted(results.items()):
        for original in result["normalized"]["recommendations"]:
            item=deepcopy(original); review=reviews.get(item["recommendation_id"]); item["verifier_disposition"]=review["disposition"] if review else None
            if review:
                if review["disposition"]=="supported" and review["severity_supported"] and not review["unsupported_assumption_codes"] and not review["ignored_exception_ids"] and not review["abstention_required"]: pass
                elif review["disposition"]=="downgrade": item["derived_effect"]="non_blocking_warning"
                else: item["derived_effect"]="owner_confirmation"; item["recommendation_class"]="owner_confirmation_question"
            output.append(item)
    return sorted(output,key=lambda item:(item["criterion_id"],item["recommendation_class"],item["recommendation_id"]))


def _projection_map(results:dict[str,dict],has_verifiers:bool,has_owner_proposals:bool)->dict[str,list[str]]:
    accepted={field for result in results.values() for field in result["normalized"]["accepted_field_ledger"]}
    if has_verifiers: accepted.add("common.verifier_dispositions")
    if has_owner_proposals: accepted.add("common.owner_confirmation_proposals")
    accepted.add("common.bases")
    projected={field:set(PROJECTION_REGISTRY[field]) for field in accepted}; validate_projection_coverage(accepted,projected)
    return {field:sorted(values) for field,values in sorted(projected.items())}


def build_artifacts(preparation:dict,results:dict[str,dict],verifiers:dict[str,dict]|None=None)->dict:
    source=preparation["source_packet"]; prepared=source["prepared_measurement_contracts"]; scopes=source["role_scopes"]; verifiers=verifiers or {}
    records={role:{item["criterion_id"]:item for item in result["normalized"]["records"]} for role,result in results.items()}; canonical_recommendations=_canonical_recommendations(results,verifiers)
    candidate_ids=sorted(set(scopes["measurement"]["candidate_criterion_ids"]+scopes["ai_evaluation"]["candidate_criterion_ids"])); has_owner=bool(candidate_ids or any(scopes[role]["unbounded_candidate_count"] for role in scopes)); projections=_projection_map(results,bool(verifiers),has_owner)
    checks=[]; aggregate_inputs={}
    for check_id in CHECK_IDS:
        role="ai_evaluation" if check_id.startswith("AI_") else "measurement"; scope=scopes[role]; ids=sorted(set(scope["applicable_criterion_ids"]+scope["candidate_criterion_ids"])); derivations=[]
        for cid in ids:
            state="applicable" if cid in scope["applicable_criterion_ids"] else "owner_confirmation_required"
            derivations.append(_derive_one(check_id,cid,state,records.get(role,{}).get(cid),prepared,canonical_recommendations))
        checks.append(_aggregate(check_id,derivations)); aggregate_inputs[check_id]=[item["precedence_inputs"] for item in derivations]
    # Canonical artifacts never retain submission-local labels or operational
    # handles.  Results remain available as immutable snapshots, while the
    # substantive projection is stable across human and harness transports.
    all_records=[{"role_id":role,**semantic_without_local_ids(item)} for role,result in results.items() for item in result["normalized"]["records"]]
    measurement_records=[item for item in all_records if item["role_id"]=="measurement"]; ai_records=[item for item in all_records if item["role_id"]=="ai_evaluation"]
    canonical_contracts=deepcopy(prepared)
    by_criterion={item["criterion_id"]:item for item in measurement_records}
    for contract in canonical_contracts:
        for cid in contract["criterion_ids"]:
            for update in by_criterion.get(cid,{}).get("contract_updates",[]):
                field=contract["fields"].get(update["field_name"])
                if field is None: raise ValueError("reviewer proposed an unknown measurement contract field")
                field.setdefault("model_proposals",[]).append({"proposed_value":update["proposed_value"],"rationale":update["rationale"]})
        for field in contract["fields"].values():
            if "model_proposals" in field:
                field["model_proposals"]=sorted(field["model_proposals"],key=lambda value:(str(value["proposed_value"]),value["rationale"]))
    contracts={"schema_version":"measurement-contract.v3","release_id":source["release_id"],"contracts":canonical_contracts,"downstream_definitions":[{"path":item["path"],"definition_state":"declared_external" if item["declared_external"] else "supplied_and_inspected","execution_state":"not_inspected","data_accuracy_state":"not_inspected"} for item in preparation["applicability"]["measurement"]["measurement_definition_paths"]],"accepted_field_projections":projections}
    instrumentation={"schema_version":"instrumentation-coverage.v3","release_id":source["release_id"],"signals":[signal for contract in prepared for signal in contract["required_signals"]],"event_candidates":[{"signal_id":signal["signal_id"],**candidate} for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["event_candidates"]],"property_assessments":[{"signal_id":signal["signal_id"],**prop} for item in measurement_records for signal in item["signal_assessments"] for prop in signal["property_results"]],"test_candidates":[{"signal_id":signal["signal_id"],**candidate} for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["tests"]],"runtime_bindings":[{"signal_id":signal["signal_id"],**candidate} for item in measurement_records for signal in item["signal_assessments"] for candidate in signal["runtime_evidence"]],"observability_candidates":[candidate for item in ai_records for candidate in item["observability_candidates"]],"coverage_boundary":"Source candidates do not prove runtime emission, downstream execution, data accuracy, populated traces, dashboards, or production monitoring.","accepted_field_projections":projections}
    verifier_by_criterion={cid:sorted({item["verifier_disposition"] for item in canonical_recommendations if item["criterion_id"]==cid and item.get("verifier_disposition") is not None}) for cid in {item["criterion_id"] for item in all_records}}
    readiness={"schema_version":"measurement-ai-readiness.v3","release_id":source["release_id"],"compiler_version":COMPILER_VERSION,"skip_reason":source["skip_reason"],"checks":checks,"accepted_role_validations":[{"role_id":role,"result_semantic_hash":result["result_semantic_hash"]} for role,result in sorted(results.items())],"aggregate_precedence_inputs":aggregate_inputs,"metric_quality":[{"criterion_id":item["criterion_id"],"dimensions":item["metric_dimensions"],"semantic_review_authority":item["semantic_review_authority"],"criterion_scoped_basis_authority":item["compiled_authority"]["criterion_scoped_basis_authority"],"verifier_dispositions":verifier_by_criterion.get(item["criterion_id"],[])} for item in measurement_records],"ai_evaluation":[{"criterion_id":item["criterion_id"],"maturity_rungs":item["maturity_rungs"],"judge_assessments":item["judge_assessments"],"claims":item["claims"],"criterion_scoped_basis_authority":item["compiled_authority"]["criterion_scoped_basis_authority"],"verifier_dispositions":verifier_by_criterion.get(item["criterion_id"],[])} for item in ai_records],"accepted_field_projections":projections}
    canonical_recommendations=[semantic_without_local_ids(item) for item in canonical_recommendations]
    gaps=[semantic_without_local_ids(gap) for item in all_records for gap in item["gaps"]]; assumptions=sorted({value for result in results.values() for value in result["normalized"]["assumptions"]}); limitations=sorted({value for result in results.values() for value in result["normalized"]["limitations"]}); owner_proposals=([{"proposal_id":stable_id("owner_proposal",{"criteria":candidate_ids,"reason":"bounded applicability requires owner confirmation"}),"reason":"bounded applicability requires owner confirmation","criterion_ids":candidate_ids}] if has_owner else [])
    plan={"schema_version":"launch-measurement-plan.v3","release_id":source["release_id"],"warnings":canonical_recommendations,"proposals":[item for item in canonical_recommendations if item["recommendation_class"] in {"contextual_metric_proposal","contextual_hypothesis"}],"gaps":gaps,"owner_confirmation_proposals":owner_proposals,"assumptions":assumptions,"limitations":limitations,"accepted_field_projections":projections}
    overlay=build_overlay(preparation,results,contracts,instrumentation,readiness,canonical_recommendations,owner_proposals)
    return {"measurement-contract.json":contracts,"instrumentation-coverage.json":instrumentation,"measurement-ai-readiness.json":readiness,"launch-measurement-plan.json":plan,"measurement-ai-overlay.json":overlay}


def build_overlay(preparation:dict,results:dict,contracts:dict,instrumentation:dict,readiness:dict,recommendations:list,owner_proposals:list)->dict:
    source=preparation["source_packet"]; nodes=[]; edges=[]; graph=preparation["authority"]["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]; base_ids={item["node_id"] for item in graph["nodes"]}; node_paths={}; node_authority={}
    def node(value): nodes.append(value)
    def edge(source_id,target_id,relationship,cid,direct,origin,refs,path=None):
        eid=stable_id("edge",{"source":source_id,"target":target_id,"relationship":relationship,"criterion":cid}); steps=path if path is not None else ([{"edge_id":eid,"traversal":"forward"}] if target_id==cid else node_paths[source_id]); authority=effective_basis_class([next((item["direct_fact_authority"] for item in edges if item["edge_id"]==step["edge_id"]),direct) for step in steps]) if steps else direct
        value={"edge_id":eid,"source_node_id":source_id,"target_node_id":target_id,"relationship":relationship,"direct_fact_authority":direct,"criterion_id":cid,"criterion_path":steps,"criterion_basis_authority":authority,"origin":origin,"reference_ids":sorted(set(refs))}; edges.append(value); return value
    contract_nodes={}
    for contract in contracts["contracts"]:
        states=[field["field_state"] for field in contract["fields"].values()]
        # Owner confirmation establishes contract declaration only.  It is not
        # source, implementation, instrumentation, test, or runtime authority.
        direct="not_inspected" if "unresolved" in states else "source_verified" if "source_declared" in states else "not_inspected"
        nid=contract["contract_id"]; contract_nodes.update({cid:nid for cid in contract["criterion_ids"]}); node({"node_id":nid,"node_type":"measurement_contract","provenance":"measurement_ai_compiler","criterion_ids":contract["criterion_ids"],"contract_id":nid,"journey_id":contract["journey_id"],"field_states":{name:item["field_state"] for name,item in contract["fields"].items()},"metric_roles":contract["metric_roles"]})
        for cid in contract["criterion_ids"]:
            e=edge(nid,cid,"governs_criterion",cid,direct,"prepared_contract",[nid]); node_paths[nid]=[{"edge_id":e["edge_id"],"traversal":"forward"}]; node_authority[nid]=direct
        for signal in contract["required_signals"]:
            sid=signal["signal_id"]; node({"node_id":sid,"node_type":"required_signal","provenance":"measurement_ai_compiler","criterion_ids":signal["criterion_ids"],"signal_id":sid,"name":signal["name"],"name_state":signal["name_state"],"required_properties":signal["required_properties"]})
            if signal["criterion_ids"]:
                cid=signal["criterion_ids"][0]; e=edge(nid,sid,"requires_signal",cid,direct,"prepared_contract",[sid]); node_paths[sid]=[{"edge_id":e["edge_id"],"traversal":"reverse"}]+node_paths[nid]; node_authority[sid]=effective_basis_class([direct,node_authority[nid]])
    for definition in contracts["downstream_definitions"]:
        linked=[cid for contract in contracts["contracts"] for cid in contract["criterion_ids"]]
        did=stable_id("metric_definition",definition)
        node({"node_id":did,"node_type":"metric_definition","provenance":"measurement_ai_compiler","criterion_ids":linked,"path":definition["path"],"definition_state":definition["definition_state"],"execution_state":definition["execution_state"],"data_accuracy_state":definition["data_accuracy_state"]})
        for cid in linked:
            contract_id=contract_nodes[cid]
            edge(contract_id,did,"uses_metric_definition",cid,"source_verified","prepared_definition",[definition["path"]])
    basis={item["basis_id"]:item for context in preparation["contexts"].values() for item in context["basis_registry"]}
    for bid,item in sorted(basis.items()):
        if item["basis_type"]=="source_reference" and item.get("object_id") and "/" in str(item["object_id"]):
            nid=stable_id("source",{"basis":bid}); node({"node_id":nid,"node_type":"project_source_reference","provenance":"prepared_project_source","criterion_ids":item["criterion_ids"],"basis_id":bid,"path":item["object_id"],"blob_hash":next((ref for ref in item["reference_ids"] if str(ref).startswith("sha256:")),"sha256:"+"0"*64),"direct_fact_authority":item["direct_fact_authority"]})
    conclusion_ids={}
    for role,result in sorted(results.items()):
        for record in result["normalized"]["records"]:
            cid=record["criterion_id"]; nid=stable_id("reviewer_conclusion",semantic_without_local_ids({"role":role,"criterion":cid,"summary":record["summary"],"authority":record["semantic_review_authority"]})); conclusion_ids[(role,cid)]=nid
            node({"node_id":nid,"node_type":"reviewer_conclusion","provenance":"measurement_reviewer","criterion_ids":[cid],"role_id":role,"conclusion_evidence_class":record["conclusion_evidence_class"],"semantic_review_authority":record["semantic_review_authority"],"criterion_basis_authority":record["compiled_authority"]["criterion_scoped_basis_authority"],"result_semantic_hash":result["result_semantic_hash"],"summary":record["summary"]}); e=edge(nid,cid,"assesses_criterion",cid,record["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",record["basis_ids"]+record["basis_path_ids"]); node_paths[nid]=[{"edge_id":e["edge_id"],"traversal":"forward"}]
            if role=="ai_evaluation":
                case_id=stable_id("ai_case",{"criterion":cid,"record":semantic_without_local_ids(record)}); minimum={r["rung"]:r["state"] for r in record["maturity_rungs"]}; ready=all(minimum.get(key)=="established" for key in ("fixed_input","oracle_or_rubric","pass_condition","journey_or_criterion_linkage")); node({"node_id":case_id,"node_type":"ai_eval_case","provenance":"measurement_ai_compiler","criterion_ids":[cid],"record_id":case_id,"minimum_case_ready":ready}); ce=edge(case_id,cid,"evaluates_ai_criterion",cid,record["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",record["basis_ids"]); node_paths[case_id]=[{"edge_id":ce["edge_id"],"traversal":"forward"}]
                for rung in record["maturity_rungs"]:
                    rtype="production_trace" if rung["rung"]=="production_trace_linkage" else "ai_eval_execution" if rung["rung"] in {"supplied_execution_result","deterministically_validated_result"} else "ai_eval_rung"; rid=stable_id("ai_rung",{"criterion":cid,"rung":rung["rung"],"state":rung["state"],"bases":rung["basis_ids"]}); common={"node_id":rid,"node_type":rtype,"provenance":"measurement_ai_compiler","criterion_ids":[cid],"state":rung["state"],"basis_ids":rung["basis_ids"],"criterion_basis_authority":rung["compiled_authority"]["criterion_scoped_basis_authority"]}
                    if rtype=="ai_eval_rung": common.update({"rung":rung["rung"],"limitations":rung["limitations"]})
                    elif rtype=="ai_eval_execution": common["rung"]=rung["rung"]
                    node(common); edge(case_id,rid,"has_ai_rung",cid,record["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",rung["basis_ids"])
                for obs in record["observability_candidates"]:
                    oid=stable_id("observability",{"criterion":cid,"kind":obs["kind"],"bases":obs["basis_ids"]}); node({"node_id":oid,"node_type":"observability_candidate","provenance":"measurement_reviewer","criterion_ids":[cid],"kind":obs["kind"],"basis_ids":obs["basis_ids"],"supported_dimensions":obs["supported_dimensions"],"criterion_basis_authority":obs["compiled_authority"]["criterion_scoped_basis_authority"]}); edge(case_id,oid,"has_observability_candidate",cid,record["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",obs["basis_ids"])
    signal_nodes={signal["signal_id"]:signal["signal_id"] for signal in instrumentation["signals"]}
    for item in instrumentation["event_candidates"]+instrumentation["test_candidates"]+instrumentation["runtime_bindings"]:
        bid=item["basis_ids"][0] if item["basis_ids"] else "unbound"; b=basis.get(bid,{}); cid=(b.get("criterion_ids") or [None])[0]
        if cid is None: continue
        ntype="event_candidate" if item in instrumentation["event_candidates"] else "instrumentation_test" if item in instrumentation["test_candidates"] else "runtime_evidence_binding"; nid=stable_id(ntype,{"criterion":cid,"bases":item["basis_ids"]}); fields={"node_id":nid,"node_type":ntype,"provenance":"measurement_ai_compiler","criterion_ids":[cid],"basis_id":bid,"criterion_basis_authority":item["compiled_authority"]["criterion_scoped_basis_authority"]}
        if ntype=="event_candidate": fields["direct_fact_authority"]=b.get("direct_fact_authority","not_inspected")
        node(fields)
        signal_id=item["signal_id"]
        if signal_id in signal_nodes:
            relationship="has_event_candidate" if ntype=="event_candidate" else "covered_by_test" if ntype=="instrumentation_test" else "has_runtime_binding"
            edge(signal_id,nid,relationship,cid,item["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",item["basis_ids"])
    for item in instrumentation["property_assessments"]:
        bid=item["basis_ids"][0] if item["basis_ids"] else "unbound"; b=basis.get(bid,{}); cid=(b.get("criterion_ids") or [None])[0]
        if cid is None: continue
        signal_id=item["signal_id"]
        if signal_id not in signal_nodes: continue
        nid=stable_id("signal_property",{"criterion":cid,"signal":signal_id,"property":item["property_name"],"bases":item["basis_ids"]})
        node({"node_id":nid,"node_type":"signal_property","provenance":"measurement_ai_compiler","criterion_ids":[cid],"signal_id":signal_id,"property_name":item["property_name"],"state":item["state"],"basis_ids":item["basis_ids"],"criterion_basis_authority":item["compiled_authority"]["criterion_scoped_basis_authority"]})
        edge(signal_id,nid,"requires_property",cid,item["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",item["basis_ids"])
    guidance_nodes={}
    for item in recommendations:
        cid=item["criterion_id"]; role=next((role for role,result in results.items() if any(rec["criterion_id"]==cid for rec in result["normalized"]["records"])),"measurement"); source_id=conclusion_ids[(role,cid)]; nid=stable_id("warning",semantic_without_local_ids(item)); node({"node_id":nid,"node_type":"measurement_warning","provenance":"measurement_reviewer","criterion_ids":[cid],"recommendation_id":item["recommendation_id"],"recommendation_class":item["recommendation_class"],"derived_effect":item["derived_effect"],"verifier_disposition":item.get("verifier_disposition"),"criterion_basis_authority":item["compiled_authority"]["criterion_scoped_basis_authority"],"summary":item["summary"]}); we=edge(source_id,nid,"identifies_warning",cid,item["compiled_authority"]["criterion_scoped_basis_authority"],"portable_result",item["basis_ids"]); node_paths[nid]=[{"edge_id":we["edge_id"],"traversal":"reverse"}]+node_paths[source_id]
        for rule in item["guidance_rule_ids"]:
            gid=guidance_nodes.setdefault(rule,stable_id("guidance",{"rule":rule}));
            if not any(n["node_id"]==gid for n in nodes): node({"node_id":gid,"node_type":"guidance_rule_reference","provenance":"measurement_ai_compiler","criterion_ids":[cid],"rule_id":rule})
            edge(nid,gid,"applies_guidance_rule",cid,item["compiled_authority"]["criterion_scoped_basis_authority"],"guidance_registry",[rule])
    for proposal in owner_proposals:
        for cid in proposal["criterion_ids"]:
            pid=stable_id("owner_proposal",{"proposal":proposal["proposal_id"],"criterion":cid}); node({"node_id":pid,"node_type":"owner_confirmation_proposal","provenance":"measurement_ai_compiler","criterion_ids":[cid],"proposal_id":proposal["proposal_id"],"reason":proposal["reason"]}); source_id=next((value for (role,key),value in conclusion_ids.items() if key==cid),None)
            if source_id: edge(source_id,pid,"proposes_owner_confirmation",cid,"not_inspected","compiler",[proposal["proposal_id"]])
    value={"schema_version":OVERLAY_SCHEMA,"release_id":source["release_id"],"release_commit":source["release_commit"],"product_intent_semantic_hash":source["product_intent_semantic_hash"],"graph_semantic_hash":source["graph_semantic_hash"],"nodes":sorted(nodes,key=lambda item:item["node_id"]),"edges":sorted(edges,key=lambda item:item["edge_id"])}
    return validate_overlay(value,base_ids)
