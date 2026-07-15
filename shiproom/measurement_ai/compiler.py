from __future__ import annotations

from .contracts import CHECK_IDS, COMPILER_VERSION, OVERLAY_SCHEMA, stable_id
from .overlay import validate_overlay


def _authority(record: dict|None) -> tuple[str,str]:
    if not record: return "not_inspected","not_performed"
    return record["conclusion_evidence_class"],record["semantic_review_authority"]


def _check(check_id: str, *, applicable: bool, record: dict|None, prepared: list[dict], role_scope: dict) -> dict:
    conclusion,semantic=_authority(record); reasons=[]; status="not_applicable"; scope=["contract_definition"]
    unresolved=any(field["field_state"]=="unresolved" for contract in prepared for field in contract["fields"].values())
    if applicable:
        status="not_inspected" if record is None or record["disposition"]!="assessed" else "ready"
        if record and record["disposition"]=="assessed":
            gaps=[gap for gap in record["gaps"] if gap["effect"] in {"condition_candidate","blocker_candidate"}]
            if gaps: status="gap"; reasons=[gap["gap_kind"] for gap in gaps]
        if check_id=="DATA_OUTCOME_EVENT_DEFINED":
            signals=[signal for contract in prepared for signal in contract["required_signals"]]
            if not signals or any(signal["name_state"]=="unresolved" for signal in signals): status="owner_confirmation_required"; reasons=["outcome_event_identity_unresolved"]
        elif check_id=="DATA_SUCCESS_AND_FAILURE_DISTINGUISHABLE":
            names=("success_condition","failure_condition")
            if not prepared or any(contract["fields"][name]["field_state"]=="unresolved" for contract in prepared for name in names): status="owner_confirmation_required"; reasons=["success_or_failure_predicate_unresolved"]
        elif check_id=="DATA_CRITICAL_EVENT_PROPERTIES_PRESENT":
            signals=[signal for contract in prepared for signal in contract["required_signals"]]
            if not signals or any(signal["name_state"]=="unresolved" for signal in signals): status="owner_confirmation_required"; reasons=["required_signal_or_properties_unresolved"]
            else: scope.append("source_mapping")
        elif check_id=="DATA_PRIMARY_METRIC_DECISION_USEFUL":
            if unresolved: status="owner_confirmation_required"; reasons=["measurement_contract_structurally_unresolved"]
            elif semantic=="not_performed": status="not_inspected"; reasons=["semantic_review_not_performed"]
            scope.append("semantic_review")
        elif check_id=="AI_FIXED_EVAL_OR_REPRO_CASE_EXISTS":
            maturity=(record or {}).get("ai_maturity",{})
            required={"case_candidate","fixed_input","oracle_or_rubric","pass_condition","criterion_linkage"}
            if record and record["disposition"]=="assessed" and not all(maturity.get(item)=="established" for item in required): status="gap"; reasons=["qualified_fixed_eval_absent"]
            scope=["source_mapping","test_mapping"]
        elif check_id=="AI_MODEL_CLAIM_NOT_PRESENTED_AS_PROOF":
            dishonest=[claim for claim in (record or {}).get("claims",[]) if claim.get("presented_as_proof") and claim.get("basis_class") not in {"source_verified","deterministically_established"}]
            if dishonest: status="gap"; reasons=["model_claim_presented_as_proof"]
            scope=["contract_definition","semantic_review"]
    classes=sorted({basis["classification"] for basis in (record or {}).get("direct_bases",[])})
    effective="model_mapped_candidate" if "model_mapped_candidate" in classes else (classes[0] if len(classes)==1 else ("not_inspected" if not classes else "source_verified"))
    check_authority="compiler_derived_from_model_reviewed_assessment" if semantic!="not_performed" else "compiler_derived_from_prepared_authority"
    return {"check_id":check_id,"status":status,"reason_codes":reasons,"direct_basis_classifications":classes,"criterion_basis_effective_classifications":[effective] if classes else [],"conclusion_evidence_class":conclusion,"semantic_review_authority":semantic,"check_authority":check_authority,"readiness_scope":scope,"coverage_boundary":{"applicable_criterion_ids":role_scope["applicable_criterion_ids"],"candidate_criterion_ids":role_scope["candidate_criterion_ids"],"runtime_verified":False}}


def build_artifacts(preparation: dict, results: dict[str,dict]) -> dict:
    source=preparation["source_packet"]; prepared=source["prepared_measurement_contracts"]; scopes=source["role_scopes"]
    if source["skip_reason"]:
        checks=[_check(cid,applicable=False,record=None,prepared=[],role_scope={"applicable_criterion_ids":[],"candidate_criterion_ids":[]}) for cid in CHECK_IDS]
    else:
        mrecords={item["criterion_id"]:item for item in results.get("measurement",{}).get("normalized",{}).get("records",[])}; arecords={item["criterion_id"]:item for item in results.get("ai_evaluation",{}).get("normalized",{}).get("records",[])}
        mrecord=next(iter(mrecords.values()),None); arecord=next(iter(arecords.values()),None)
        checks=[]
        for cid in CHECK_IDS:
            ai=cid.startswith("AI_"); scope=scopes["ai_evaluation" if ai else "measurement"]
            checks.append(_check(cid,applicable=bool(scope["applicable_criterion_ids"]),record=arecord if ai else mrecord,prepared=prepared,role_scope=scope))
    warnings=[item for result in results.values() for item in result["normalized"]["warnings"]]
    proposals=[item for result in results.values() for item in result["normalized"]["proposals"]]
    contracts={"schema_version":"measurement-contract.v1","release_id":source["release_id"],"contracts":prepared,"downstream_definitions":[{"path":item["path"],"definition_state":"supplied_and_inspected" if not item["declared_external"] else "declared_external","execution_state":"not_inspected","data_accuracy_state":"not_inspected"} for item in preparation["applicability"]["measurement"]["measurement_definition_paths"]]}
    instrumentation={"schema_version":"instrumentation-coverage.v1","release_id":source["release_id"],"signals":[signal for contract in prepared for signal in contract["required_signals"]],"event_candidates":[],"observability_candidates":[],"coverage_boundary":"Source candidates do not prove runtime emission, populated fields, dashboards, or production monitoring."}
    readiness={"schema_version":"measurement-ai-readiness.v1","release_id":source["release_id"],"compiler_version":COMPILER_VERSION,"skip_reason":source["skip_reason"],"checks":checks,"accepted_role_validations":[{"role_id":role,"result_semantic_hash":result["result_semantic_hash"]} for role,result in sorted(results.items())]}
    plan={"schema_version":"launch-measurement-plan.v1","release_id":source["release_id"],"warnings":warnings,"proposals":proposals,"owner_confirmation_proposals":([{"proposal_id":stable_id("owner_proposal",source["role_scopes"]),"reason":"bounded applicability requires owner confirmation","criterion_ids":sorted(set(scopes["measurement"]["candidate_criterion_ids"]+scopes["ai_evaluation"]["candidate_criterion_ids"]))}] if any(scopes[role]["candidate_criterion_ids"] or scopes[role]["unbounded_candidate_count"] for role in scopes) else [])}
    overlay=build_overlay(preparation,results,contracts,warnings,plan)
    return {"measurement-contract.json":contracts,"instrumentation-coverage.json":instrumentation,"measurement-ai-readiness.json":readiness,"launch-measurement-plan.json":plan,"measurement-ai-overlay.json":overlay}


def build_overlay(preparation:dict,results:dict,contracts:dict,warnings:list,plan:dict)->dict:
    source=preparation["source_packet"]; nodes=[]; edges=[]; base_ids=set()
    graph=preparation["authority"]["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]; base_ids={item["node_id"] for item in graph["nodes"]}
    for contract in contracts["contracts"]:
        nodes.append({"node_id":contract["contract_id"],"node_type":"measurement_contract","provenance":"measurement_ai_compiler","detail":contract})
        for criterion in contract["criterion_ids"]:
            eid=stable_id("edge",{"contract":contract["contract_id"],"criterion":criterion}); edges.append({"edge_id":eid,"source_node_id":contract["contract_id"],"target_node_id":criterion,"relationship":"governs_criterion","basis_evidence_class":"source_verified","origin":"prepared_contract","references":[]})
        for signal in contract["required_signals"]:
            nodes.append({"node_id":signal["signal_id"],"node_type":"required_signal","provenance":"measurement_ai_compiler","detail":signal}); edges.append({"edge_id":stable_id("edge",{"contract":contract["contract_id"],"signal":signal["signal_id"]}),"source_node_id":contract["contract_id"],"target_node_id":signal["signal_id"],"relationship":"requires_signal","basis_evidence_class":"source_verified" if signal["name_state"]!="unresolved" else "not_inspected","origin":"prepared_contract","references":[]})
    for role,result in results.items():
        for record in result["normalized"]["records"]:
            nid=stable_id("reviewer_conclusion",{"role":role,"criterion":record["criterion_id"],"summary":record["summary"]}); nodes.append({"node_id":nid,"node_type":"reviewer_conclusion","provenance":"measurement_reviewer","detail":{"role_id":role,"criterion_id":record["criterion_id"],"conclusion_evidence_class":record["conclusion_evidence_class"],"semantic_review_authority":record["semantic_review_authority"],"result_semantic_hash":result["result_semantic_hash"]}}); edges.append({"edge_id":stable_id("edge",{"node":nid,"criterion":record["criterion_id"]}),"source_node_id":nid,"target_node_id":record["criterion_id"],"relationship":"assesses_criterion","basis_evidence_class":"model_reviewed" if record["disposition"]=="assessed" else "not_inspected","origin":"portable_result","references":[]})
    value={"schema_version":OVERLAY_SCHEMA,"release_id":source["release_id"],"release_commit":source["release_commit"],"product_intent_semantic_hash":source["product_intent_semantic_hash"],"graph_semantic_hash":source["graph_semantic_hash"],"nodes":nodes,"edges":edges}
    return validate_overlay(value,base_ids)
