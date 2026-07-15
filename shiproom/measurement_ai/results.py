from __future__ import annotations

from datetime import datetime

from shiproom.project import content_hash

from .contracts import (
    BASIS_EVIDENCE_CLASSES, DIMENSION_STATES, DISPOSITIONS, RECOMMENDATION_CLASSES,
    RESULT_BYTES_LIMIT, SEMANTIC_REVIEW_AUTHORITIES, UNCERTAINTIES, canonical_refs,
    load_json_bytes, require_exact, require_string_list, require_text, semantic_without_local_ids,
    sha256_bytes,
)
from .guidance import rule_map


RECORD_FIELDS={"local_id","criterion_id","disposition","uncertainty","direct_bases","criterion_basis_paths","conclusion_evidence_class","semantic_review_authority","summary","gaps","contract_updates","signal_assessments","metric_dimensions","ai_maturity","claims"}
WARNING_FIELDS={"local_id","criterion_id","recommendation_class","summary","project_basis_ids","basis_source_refs","guidance_rule_ids","exceptions_considered","missing_context","effect","semantic_review_authority"}
GAP_KINDS={"measurement_contract_gap","instrumentation_mapping_gap","critical_property_gap","metric_decision_gap","fixed_eval_gap","failure_case_gap","version_traceability_gap","claim_authority_gap","observability_gap"}


def _semantic_hash(role: str, version: str, graph_hash: str, normalized: dict) -> str:
    return content_hash({"role_id":role,"role_version":version,"base_graph_semantic_hash":graph_hash,"payload":semantic_without_local_ids({k:normalized[k] for k in ("records","warnings","proposals")}),"assumptions":normalized["assumptions"],"limitations":normalized["limitations"]})


def _validate_receipt(value: dict, work: dict, result_raw: bytes) -> dict:
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


def _bases(record: dict, context: dict) -> None:
    valid_ids={item["node_id"] for item in context["graph_context"]["nodes"]}|{item["edge_id"] for item in context["graph_context"]["edges"]}|{item["gap_id"] for item in context["graph_context"]["gaps"]}|set(context["assigned"]["criterion_ids"]+context["assigned"]["requirement_ids"]+context["assigned"]["journey_ids"])
    if not isinstance(record["direct_bases"],list): raise ValueError("direct_bases must be a list")
    seen=set()
    for basis in record["direct_bases"]:
        require_exact(basis,{"reference_type","reference_id","classification"},"direct basis")
        if basis["classification"] not in BASIS_EVIDENCE_CLASSES or basis["reference_id"] not in valid_ids: raise ValueError("invalid direct basis")
        key=(basis["reference_type"],basis["reference_id"])
        if key in seen: raise ValueError("duplicate direct basis")
        seen.add(key)
    if not isinstance(record["criterion_basis_paths"],list): raise ValueError("criterion basis paths must be a list")


def normalize_result(raw: bytes, receipt_raw: bytes, work: dict, context: dict, guidance: dict) -> dict:
    if len(raw)>RESULT_BYTES_LIMIT: raise ValueError("measurement AI result exceeds byte limit")
    value=load_json_bytes(raw); required={"schema_version","role_id","role_version","preparation_id","work_order_id","base_graph_semantic_hash","resolved_review_mode","records","warnings","proposals","assumptions","limitations"}; require_exact(value,required,"measurement AI result")
    role=work["role_id"]
    if value["schema_version"] != ("measurement-result.v1" if role=="measurement" else "ai-evaluation-result.v1") or value["role_id"]!=role or value["role_version"]!="1.0.0" or value["preparation_id"]!=work["preparation_id"] or value["work_order_id"]!=work["work_order_id"] or value["base_graph_semantic_hash"]!=work["inputs"]["graph_semantic_hash"] or value["resolved_review_mode"]!=work["resolved_review_mode"]: raise ValueError("unbound measurement AI result")
    require_string_list(value["assumptions"],"assumptions"); require_string_list(value["limitations"],"limitations")
    if not all(isinstance(value[x],list) for x in ("records","warnings","proposals")): raise ValueError("invalid result collections")
    assigned=set(context["assigned"]["criterion_ids"]); records={}
    for record in value["records"]:
        require_exact(record,RECORD_FIELDS,"role result record"); cid=record["criterion_id"]
        if cid not in assigned or cid in records or record["disposition"] not in DISPOSITIONS or record["uncertainty"] not in UNCERTAINTIES: raise ValueError("invalid assigned result coverage")
        assessed=record["disposition"]=="assessed"
        if assessed != (record["uncertainty"]!="not_assessed"): raise ValueError("disposition uncertainty mismatch")
        _bases(record,context)
        if assessed and not record["direct_bases"]: raise ValueError("assessed record requires project basis")
        if not assessed and (record["direct_bases"] or record["criterion_basis_paths"] or record["gaps"] or record["contract_updates"] or record["signal_assessments"] or record["metric_dimensions"] or record["ai_maturity"] or record["claims"]): raise ValueError("non-assessed record must use empty sentinels")
        if record["conclusion_evidence_class"] not in {"model_reviewed","not_inspected"} or record["semantic_review_authority"] not in SEMANTIC_REVIEW_AUTHORITIES: raise ValueError("reviewer attempted authority upgrade")
        if record["metric_dimensions"] and any(item.get("state") not in DIMENSION_STATES for item in record["metric_dimensions"]): raise ValueError("invalid metric dimension")
        for gap in record["gaps"]:
            require_exact(gap,{"gap_kind","aspect_code","summary","effect"},"assessment gap")
            if gap["gap_kind"] not in GAP_KINDS or not assessed: raise ValueError("invalid assessment gap")
        records[cid]=record
    if set(records)!=assigned: raise ValueError("incomplete assigned result coverage")
    rules=rule_map(guidance); warnings=[]
    for warning in value["warnings"]:
        require_exact(warning,WARNING_FIELDS,"measurement recommendation")
        if warning["criterion_id"] not in assigned or warning["recommendation_class"] not in RECOMMENDATION_CLASSES or warning["semantic_review_authority"] not in SEMANTIC_REVIEW_AUTHORITIES: raise ValueError("invalid recommendation")
        require_string_list(warning["project_basis_ids"],"project basis"); require_string_list(warning["guidance_rule_ids"],"guidance rules"); require_string_list(warning["exceptions_considered"],"exceptions")
        warning["basis_source_refs"]=canonical_refs(warning["basis_source_refs"],context["sources"])
        if warning["recommendation_class"] in {"research_backed_warning","contextual_metric_proposal"}:
            if not warning["project_basis_ids"] and not warning["basis_source_refs"]: raise ValueError("formal recommendation requires project basis")
            if not warning["guidance_rule_ids"] or any(rule not in rules for rule in warning["guidance_rule_ids"]): raise ValueError("formal recommendation requires guidance basis")
            ceilings={rules[rule]["maximum_effect"] for rule in warning["guidance_rule_ids"]}
            if warning["effect"]=="blocker_candidate" or (warning["effect"]=="condition_candidate" and "condition_candidate_only_after_expert_dual_review" not in ceilings): raise ValueError("recommendation effect exceeds guidance ceiling")
        if value["resolved_review_mode"]=="contract_only" and warning["recommendation_class"] in {"research_backed_warning","contextual_metric_proposal"}: raise ValueError("contract-only review cannot issue semantic advice")
        warnings.append(warning)
    receipt=_validate_receipt(load_json_bytes(receipt_raw),work,raw)
    normalized={**value,"records":[records[cid] for cid in sorted(records)],"warnings":sorted(warnings,key=lambda x:(x["criterion_id"],x["local_id"])),"proposals":sorted(value["proposals"],key=lambda x:str(x.get("local_id",""))),"assumptions":sorted(value["assumptions"]),"limitations":sorted(value["limitations"])}
    return {"normalized":normalized,"receipt":receipt,"result_snapshot_hash":sha256_bytes(raw),"receipt_snapshot_hash":sha256_bytes(receipt_raw),"result_semantic_hash":_semantic_hash(role,value["role_version"],value["base_graph_semantic_hash"],normalized)}
