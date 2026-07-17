"""Executable Session 5 integrity claims; prose references never satisfy a claim."""
from __future__ import annotations

import importlib

CLAIMS=(
 {"claim_id":"blind_qualification","implementation_refs":["shiproom.measurement_ai.qualification.load_qualification_bundle"],"positive_test_ids":["test_qualification_packet_is_blind_and_capabilities_are_independent"],"negative_test_ids":["test_public_response_fixtures_do_not_depend_on_private_grader"],"artifact_assertions":[{"artifact":"qualification-task.json","assertion":"private_rubric_fields_absent"}]},
 {"claim_id":"participant_executor_binding","implementation_refs":["shiproom.measurement_ai.results.validate_executor"],"positive_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"negative_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"artifact_assertions":[{"artifact":"work-order.json","assertion":"participants_are_exact"}]},
 {"claim_id":"source_hash_correctness","implementation_refs":["shiproom.measurement_ai.authority.source_record"],"positive_test_ids":["test_instrumentation_requirement_issues_only_measurement_role"],"negative_test_ids":["test_all_27_contracts_report_python_json_schema_parity"],"artifact_assertions":[{"artifact":"measurement-ai-overlay.json","assertion":"source_hashes_are_real"}]},
 {"claim_id":"substantive_projection","implementation_refs":["shiproom.measurement_ai.projection.verify_projected_records"],"positive_test_ids":["test_projection_references_are_scoped_and_resolved"],"negative_test_ids":["test_projection_rejects_orphan_placeholders"],"artifact_assertions":[{"artifact":"measurement-ai-overlay.json","assertion":"projection_references_resolve"}]},
 {"claim_id":"downstream_linkage","implementation_refs":["shiproom.measurement_ai.compiler.build_artifacts"],"positive_test_ids":["test_downstream_definition_scope_is_exact"],"negative_test_ids":["test_preparation_semantic_tamper_and_unlinked_definition_do_not_create_scope"],"artifact_assertions":[{"artifact":"measurement-contract.json","assertion":"downstream_scope_exact"}]},
 {"claim_id":"harness_neutral_semantics","implementation_refs":["shiproom.measurement_ai.results._semantic_hash"],"positive_test_ids":["test_canonical_artifacts_ignore_preparation_handles_and_local_labels"],"negative_test_ids":["test_primary_executor_truth_table_rejects_bidirectional_impersonation"],"artifact_assertions":[{"artifact":"manifest.json","assertion":"semantic_bundle_handle_independent"}]},
)

def _symbol(reference:str):
    module,name=reference.rsplit(".",1); value=getattr(importlib.import_module(module),name,None)
    if value is None: raise ValueError(f"missing closeout implementation symbol: {reference}")

def resolve_claims(passed_test_ids:set[str],artifacts:dict[str,dict],assertions:dict[str,callable])->list[dict]:
    ids=[item["claim_id"] for item in CLAIMS]
    if len(ids)!=len(set(ids)) or any(not value for value in ids): raise ValueError("invalid closeout claim IDs")
    resolved=[]
    for claim in CLAIMS:
        for reference in claim["implementation_refs"]: _symbol(reference)
        missing=(set(claim["positive_test_ids"]+claim["negative_test_ids"])-passed_test_ids)
        if missing: raise ValueError("closeout proof tests did not pass: "+",".join(sorted(missing)))
        for assertion in claim["artifact_assertions"]:
            name=assertion["artifact"]; check=assertions.get(assertion["assertion"])
            if name not in artifacts or check is None or check(artifacts[name]) is not True: raise ValueError(f"closeout artifact assertion failed: {claim['claim_id']}")
        resolved.append({**claim,"status":"resolved"})
    return resolved
