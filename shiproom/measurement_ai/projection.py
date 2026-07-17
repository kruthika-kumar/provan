from __future__ import annotations

from .registries import PROJECTION_REGISTRY


def projection_destinations(field_path: str) -> tuple[str, ...]:
    try:
        return PROJECTION_REGISTRY[field_path]
    except KeyError as exc:
        raise ValueError(f"accepted reviewer field has no canonical projection: {field_path}") from exc


def validate_projection_coverage(accepted: set[str], projected: dict[str, set[str]]) -> None:
    unknown = accepted - set(PROJECTION_REGISTRY)
    if unknown:
        raise ValueError("accepted reviewer fields lack projection handlers: " + ",".join(sorted(unknown)))
    for field in sorted(accepted):
        expected = set(PROJECTION_REGISTRY[field])
        actual = projected.get(field, set())
        if actual != expected:
            raise ValueError(f"canonical projection mismatch for {field}")


def expected_projection_tuples(results:dict,artifacts:dict)->list[dict]:
    expected=[]
    def add(record_id:str,kind:str,criterion_id:str,journey_id:str|None,authority:str,*destinations:str):
        for destination in destinations: expected.append({"record_id":record_id,"record_kind":kind,"criterion_id":criterion_id,"journey_id":journey_id,"authority":authority,"destination":destination,"target_record_id":record_id})
    for result in results.values():
        for record in result["normalized"]["records"]:
            cid=record["criterion_id"]; journey=(record.get("journey_ids") or [None])[0]; authority=record["compiled_authority"]["criterion_scoped_basis_authority"]
            for update in record.get("contract_updates",[]): add(update["proposal_id"],"contract_proposal",cid,journey,authority,"measurement-contract.json","measurement-ai-overlay.json")
            for signal in record.get("signal_assessments",[]):
                for item in signal.get("event_candidates",[]): add(item["canonical_record_id"],"event_candidate",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"instrumentation-coverage.json","measurement-ai-overlay.json")
                for item in signal.get("property_results",[]): add(item["canonical_record_id"],"property_assertion",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"instrumentation-coverage.json","measurement-ai-overlay.json")
                for item in signal.get("tests",[]): add(item["canonical_record_id"],"test_assertion",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"instrumentation-coverage.json","measurement-ai-overlay.json")
                for item in signal.get("runtime_evidence",[]): add(item["canonical_record_id"],"runtime_assertion",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"instrumentation-coverage.json","measurement-ai-overlay.json")
            for item in record.get("metric_dimensions",[]): add(item["canonical_record_id"],"metric_dimension",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"measurement-ai-readiness.json")
            for item in record.get("maturity_rungs",[]): add(item["canonical_record_id"],"ai_maturity_rung",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"measurement-ai-readiness.json","measurement-ai-overlay.json")
            for item in record.get("judge_assessments",[]): add(item["canonical_record_id"],"llm_judge_assessment",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"measurement-ai-readiness.json","measurement-ai-overlay.json")
            for item in record.get("claims",[]): add(item["claim_id"],"ai_claim_assessment",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"measurement-ai-readiness.json","measurement-ai-overlay.json")
            for item in record.get("observability_candidates",[]): add(item["canonical_record_id"],"observability_candidate",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"measurement-ai-readiness.json","measurement-ai-overlay.json")
            for item in record.get("gaps",[]): add(item["gap_id"],"gap",cid,journey,item["compiled_authority"]["criterion_scoped_basis_authority"],"launch-measurement-plan.json","measurement-ai-overlay.json")
        for recommendation in result["normalized"]["recommendations"]:
            cid=recommendation["criterion_id"]; authority=recommendation["compiled_authority"]["criterion_scoped_basis_authority"]; add(recommendation["recommendation_id"],"recommendation",cid,None,authority,"launch-measurement-plan.json","measurement-ai-overlay.json")
            for exception in recommendation["exception_dispositions"]: add(exception["exception_analysis_id"],"exception_analysis",cid,None,authority,"launch-measurement-plan.json","measurement-ai-overlay.json")
    for proposal in artifacts["launch-measurement-plan.json"]["owner_confirmation_proposals"]:
        for cid in proposal["criterion_ids"]: add(proposal["proposal_id"],"owner_confirmation_proposal",cid,proposal["journey_id"],"not_inspected","launch-measurement-plan.json","measurement-ai-overlay.json")
    return sorted(expected,key=lambda item:(item["record_id"],item["destination"],item["criterion_id"]))


def verify_projected_records(results:dict,artifacts:dict)->list[dict]:
    expected=expected_projection_tuples(results,artifacts); indexes={name:set() for name in ("measurement-contract.json","instrumentation-coverage.json","measurement-ai-readiness.json","launch-measurement-plan.json","measurement-ai-overlay.json")}
    for contract in artifacts["measurement-contract.json"]["contracts"]:
        for field in contract["fields"].values(): indexes["measurement-contract.json"].update(item["proposal_id"] for item in field.get("model_proposals",[]))
    inst=artifacts["instrumentation-coverage.json"]
    for key in ("event_candidates","property_assessments","test_candidates","runtime_bindings"): indexes["instrumentation-coverage.json"].update(item["canonical_record_id"] for item in inst[key])
    readiness=artifacts["measurement-ai-readiness.json"]
    for item in readiness["metric_quality"]: indexes["measurement-ai-readiness.json"].update(entry["canonical_record_id"] for entry in item["dimensions"])
    for item in readiness["ai_evaluation"]:
        indexes["measurement-ai-readiness.json"].update(entry["canonical_record_id"] for entry in item["maturity_rungs"]+item["judge_assessments"]+item.get("observability_candidates",[])); indexes["measurement-ai-readiness.json"].update(entry["claim_id"] for entry in item["claims"])
    plan=artifacts["launch-measurement-plan.json"]
    indexes["launch-measurement-plan.json"].update(item["gap_id"] for item in plan["gaps"]); indexes["launch-measurement-plan.json"].update(item["recommendation_id"] for item in plan["warnings"]); indexes["launch-measurement-plan.json"].update(item["proposal_id"] for item in plan["owner_confirmation_proposals"])
    for item in plan["warnings"]: indexes["launch-measurement-plan.json"].update(entry["exception_analysis_id"] for entry in item["exception_dispositions"])
    indexes["measurement-ai-overlay.json"].update(node.get("record_id") for node in artifacts["measurement-ai-overlay.json"]["nodes"] if node.get("record_id"))
    for item in expected:
        if item["destination"]!="measurement-ai-overlay.json" and item["record_id"] not in indexes[item["destination"]]: raise ValueError(f"missing canonical projection: {item['record_kind']} -> {item['destination']}")
    return expected
