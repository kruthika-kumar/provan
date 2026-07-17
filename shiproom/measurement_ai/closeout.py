"""Executable Session 5 integrity claims; prose references never satisfy a claim."""
from __future__ import annotations

import importlib

CLAIMS=(
 {"claim_id":"blind_qualification","implementation_refs":["shiproom.measurement_ai.qualification.load_qualification_bundle"],"positive_test_ids":["test_qualification_packet_is_blind_and_capabilities_are_independent"],"negative_test_ids":["test_public_response_fixtures_do_not_depend_on_private_grader"],"artifact_assertions":[{"artifact":"qualification-task.json","assertion":"private_rubric_fields_absent"}]},
 {"claim_id":"qualification_bundle_regrading","implementation_refs":["shiproom.measurement_ai.qualification.grade_qualification_result"],"positive_test_ids":["test_qualification_bundle_is_regraded_not_receipt_trusted[qualification-result.json]"],"negative_test_ids":["test_qualification_bundle_is_regraded_not_receipt_trusted[qualification-receipt.json]"],"artifact_assertions":[{"artifact":"qualification-receipt.json","assertion":"bundle_regraded"}]},
 {"claim_id":"participant_executor_binding","implementation_refs":["shiproom.measurement_ai.results.validate_executor"],"positive_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"negative_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"artifact_assertions":[{"artifact":"work-order.json","assertion":"participants_are_exact"}]},
 {"claim_id":"source_hash_correctness","implementation_refs":["shiproom.measurement_ai.authority.source_record"],"positive_test_ids":["test_instrumentation_requirement_issues_only_measurement_role"],"negative_test_ids":["test_all_27_contracts_report_python_json_schema_parity"],"artifact_assertions":[{"artifact":"measurement-ai-overlay.json","assertion":"source_hashes_are_real"}]},
 {"claim_id":"typed_basis_authority","implementation_refs":["shiproom.measurement_ai.results._typed_authority"],"positive_test_ids":["test_measurement_result_compiles_without_upgrading_prepared_authority"],"negative_test_ids":["test_forged_reviewer_authority_and_contract_only_guidance_are_rejected"],"artifact_assertions":[{"artifact":"instrumentation-coverage.json","assertion":"typed_bases_preserved"}]},
 {"claim_id":"claim_scope_honesty","implementation_refs":["shiproom.measurement_ai.results._claim_honesty"],"positive_test_ids":["test_measurement_result_compiles_without_upgrading_prepared_authority"],"negative_test_ids":["test_forged_reviewer_authority_and_contract_only_guidance_are_rejected"],"artifact_assertions":[{"artifact":"measurement-ai-readiness.json","assertion":"claim_scope_honest"}]},
 {"claim_id":"multi_record_aggregation","implementation_refs":["shiproom.measurement_ai.compiler._aggregate"],"positive_test_ids":["test_skip_generation_has_all_six_not_applicable_checks"],"negative_test_ids":["test_measurement_result_compiles_without_upgrading_prepared_authority"],"artifact_assertions":[{"artifact":"measurement-ai-readiness.json","assertion":"aggregate_inputs_retained"}]},
 {"claim_id":"verifier_canonical_effects","implementation_refs":["shiproom.measurement_ai.compiler._canonical_recommendations"],"positive_test_ids":["test_verifier_disposition_changes_canonical_effect[supported-condition_candidate-gap]"],"negative_test_ids":["test_verifier_disposition_changes_canonical_effect[disputed-owner_confirmation-owner_confirmation_required]"],"artifact_assertions":[{"artifact":"launch-measurement-plan.json","assertion":"verifier_effect_applied"}]},
 {"claim_id":"substantive_projection","implementation_refs":["shiproom.measurement_ai.projection.verify_projected_records"],"positive_test_ids":["test_projection_references_are_scoped_and_resolved"],"negative_test_ids":["test_projection_rejects_orphan_placeholders"],"artifact_assertions":[{"artifact":"measurement-ai-overlay.json","assertion":"projection_references_resolve"}]},
 {"claim_id":"downstream_linkage","implementation_refs":["shiproom.measurement_ai.compiler.build_artifacts"],"positive_test_ids":["test_downstream_definition_scope_is_exact"],"negative_test_ids":["test_preparation_semantic_tamper_and_unlinked_definition_do_not_create_scope"],"artifact_assertions":[{"artifact":"measurement-contract.json","assertion":"downstream_scope_exact"}]},
 {"claim_id":"harness_neutral_semantics","implementation_refs":["shiproom.measurement_ai.results._semantic_hash"],"positive_test_ids":["test_canonical_artifacts_ignore_preparation_handles_and_local_labels"],"negative_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"artifact_assertions":[{"artifact":"manifest.json","assertion":"semantic_bundle_handle_independent"}]},
 {"claim_id":"read_only_operation","implementation_refs":["shiproom.measurement_ai.persistence.compile_generation"],"positive_test_ids":["test_domain_core_records_zero_external_operations"],"negative_test_ids":["test_trusted_directory_creation_rejects_symlinked_ancestor"],"artifact_assertions":[{"artifact":"measurement-ai-compiler-receipts.json","assertion":"zero_external_operations"}]},
 {"claim_id":"stale_version_handling","implementation_refs":["shiproom.measurement_ai.persistence.load_generation"],"positive_test_ids":["test_old_preparation_and_pointer_fail_closed_without_mutation"],"negative_test_ids":["test_late_generation_failure_preserves_previous_pointer"],"artifact_assertions":[{"artifact":"current-measurement-ai.json","assertion":"pointer_preserved"}]},
)

def _symbol(reference:str):
    module,name=reference.rsplit(".",1); value=getattr(importlib.import_module(module),name,None)
    if value is None: raise ValueError(f"missing closeout implementation symbol: {reference}")

def _private_absent(value):
    forbidden={"allowed_semantic_assessments","required_guidance_rules","required_exception_ids","maximum_effect","qualified_capabilities"}
    return not any(forbidden&set(case) for case in value.get("cases",[]))

ARTIFACT_ASSERTIONS={
 "private_rubric_fields_absent":_private_absent,
 "bundle_regraded":lambda v: bool(v.get("passed_capabilities") is not None and v.get("failed_capabilities") is not None and v.get("private_rubric_semantic_hash")),
 "participants_are_exact":lambda v: v.get("resolved_review_mode")=="contract_only" or len(v.get("review_participants",[]))==1,
 "source_hashes_are_real":lambda v: all(node.get("git_blob_hash") and node.get("normalized_text_hash","").startswith("sha256:") for node in v.get("nodes",[]) if node.get("node_type")=="project_source_reference"),
 "typed_bases_preserved":lambda v: all(item.get("basis_ids") and item.get("compiled_authority") for key in ("event_candidates","property_assessments") for item in v.get(key,[])),
 "claim_scope_honest":lambda v: all(claim.get("honesty_state") in {"honest","unsupported_proof"} for item in v.get("ai_evaluation",[]) for claim in item.get("claims",[])),
 "aggregate_inputs_retained":lambda v: bool(v.get("aggregate_precedence_inputs") is not None),
 "verifier_effect_applied":lambda v: all(item.get("verifier_disposition") is None or item.get("derived_effect") in {"none","non_blocking_warning","owner_confirmation","condition_candidate","blocker_candidate"} for item in v.get("warnings",[])),
 "projection_references_resolve":lambda v: all(node.get("criterion_ids") and node.get("canonical_record_id")==node.get("target_record_id") for node in v.get("nodes",[]) if node.get("node_type")=="projection_reference"),
 "downstream_scope_exact":lambda v: all(set(item)>={"requirement_ids","criterion_ids","journey_ids","definition_authority"} for item in v.get("downstream_definitions",[])),
 "semantic_bundle_handle_independent":lambda v: bool(v.get("semantic_bundle_hash")),
 "zero_external_operations":lambda v: all(item.get("count")==0 for item in v.get("validations",[]) if item.get("kind")=="external_operation"),
 "pointer_preserved":lambda v: bool(v.get("generation") or v.get("preparation_id")),
}

def resolve_claims(passed_test_ids:set[str],artifacts:dict[str,dict])->list[dict]:
    ids=[item["claim_id"] for item in CLAIMS]
    if len(ids)!=len(set(ids)) or any(not value for value in ids): raise ValueError("invalid closeout claim IDs")
    resolved=[]
    for claim in CLAIMS:
        for reference in claim["implementation_refs"]: _symbol(reference)
        missing=(set(claim["positive_test_ids"]+claim["negative_test_ids"])-passed_test_ids)
        if missing: raise ValueError("closeout proof tests did not pass: "+",".join(sorted(missing)))
        for assertion in claim["artifact_assertions"]:
            name=assertion["artifact"]; check=ARTIFACT_ASSERTIONS.get(assertion["assertion"])
            if name not in artifacts or check is None or check(artifacts[name]) is not True: raise ValueError(f"closeout artifact assertion failed: {claim['claim_id']}")
        resolved.append({**claim,"status":"resolved"})
    return resolved
