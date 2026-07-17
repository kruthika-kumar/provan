"""Executable, claim-specific Session 5 closeout proofs."""
from __future__ import annotations

import importlib

CLAIMS=(
 {"claim_id":"blind_qualification","implementation_refs":["shiproom.measurement_ai.qualification.load_qualification_bundle"],"positive_test_ids":["test_blind_qualification_claim_specific_proofs"],"negative_test_ids":["test_blind_qualification_adversarial_answers_and_rubric_tamper"],"artifact_assertions":[{"artifact":"qualification-task.json","assertion":"blind_public_task","minimum_records":1},{"artifact":"qualification-receipt.json","assertion":"material_capability_outcomes","minimum_records":2}]},
 {"claim_id":"qualification_bundle_regrading","implementation_refs":["shiproom.measurement_ai.qualification.load_qualification_bundle"],"positive_test_ids":["test_qualification_bundle_is_regraded_not_receipt_trusted[qualification-result.json]"],"negative_test_ids":["test_qualification_regrading_rejects_task_result_receipt_and_rubric_tamper"],"artifact_assertions":[{"artifact":"qualification-receipt.json","assertion":"regraded_bundle_fields","minimum_records":1}]},
 {"claim_id":"participant_executor_binding","implementation_refs":["shiproom.measurement_ai.results.validate_executor","shiproom.measurement_ai.verifier._receipt"],"positive_test_ids":["test_executor_truth_table_complete"],"negative_test_ids":["test_executor_binding_adversarial_matrix"],"artifact_assertions":[{"artifact":"work-order.json","assertion":"exact_participant_binding","minimum_records":1}]},
 {"claim_id":"source_hash_correctness","implementation_refs":["shiproom.measurement_ai.authority.source_record","shiproom.measurement_ai.authority._binding_record"],"positive_test_ids":["test_typed_source_identity_contract_accepts_real_sha1_binding"],"negative_test_ids":["test_typed_source_identity_contract_rejects_hash_mutations"],"artifact_assertions":[{"artifact":"source-identity-proof.json","assertion":"exact_source_nodes","minimum_records":1}]},
 {"claim_id":"typed_basis_authority","implementation_refs":["shiproom.measurement_ai.results._typed_authority"],"positive_test_ids":["test_typed_basis_compatibility_positive_matrix"],"negative_test_ids":["test_typed_basis_compatibility_rejects_generic_cross_signal_and_candidate"],"artifact_assertions":[{"artifact":"instrumentation-coverage.json","assertion":"typed_instrumentation_records","minimum_records":1}]},
 {"claim_id":"claim_scope_honesty","implementation_refs":["shiproom.measurement_ai.results._claim_honesty"],"positive_test_ids":["test_ai_claim_scope_honesty_positive_configuration"],"negative_test_ids":["test_ai_claim_scope_honesty_rejects_behavioral_proof_substitution"],"artifact_assertions":[{"artifact":"measurement-ai-readiness.json","assertion":"material_claim_honesty","minimum_records":1}]},
 {"claim_id":"multi_record_aggregation","implementation_refs":["shiproom.measurement_ai.compiler._aggregate"],"positive_test_ids":["test_multi_record_aggregation_is_conservative"],"negative_test_ids":["test_aggregate_ready_rejects_lower_precedence_records"],"artifact_assertions":[{"artifact":"measurement-ai-readiness.json","assertion":"mixed_status_aggregate","minimum_records":2}]},
 {"claim_id":"verifier_canonical_effects","implementation_refs":["shiproom.measurement_ai.compiler._canonical_recommendations"],"positive_test_ids":["test_verifier_disposition_changes_canonical_effect[supported-condition_candidate-gap]"],"negative_test_ids":["test_verifier_disposition_changes_canonical_effect[disputed-owner_confirmation-owner_confirmation_required]"],"artifact_assertions":[{"artifact":"launch-measurement-plan.json","assertion":"material_verifier_effect","minimum_records":1}]},
 {"claim_id":"substantive_projection","implementation_refs":["shiproom.measurement_ai.projection.verify_projected_records"],"positive_test_ids":["test_projection_references_are_scoped_and_resolved"],"negative_test_ids":["test_projection_rejects_orphan_authority_scope_duplicate_and_target_tamper"],"artifact_assertions":[{"artifact":"measurement-ai-overlay.json","assertion":"substantive_projection_records","minimum_records":1}]},
 {"claim_id":"downstream_linkage","implementation_refs":["shiproom.measurement_ai.compiler.build_artifacts"],"positive_test_ids":["test_downstream_definition_scope_is_exact"],"negative_test_ids":["test_declared_external_definition_is_not_source_content_proof"],"artifact_assertions":[{"artifact":"measurement-contract.json","assertion":"exact_downstream_authority","minimum_records":1}]},
 {"claim_id":"harness_neutral_semantics","implementation_refs":["shiproom.measurement_ai.results._semantic_hash"],"positive_test_ids":["test_canonical_artifacts_ignore_preparation_handles_and_local_labels"],"negative_test_ids":["test_executor_binding_adversarial_matrix"],"artifact_assertions":[{"artifact":"harness-neutral-proof.json","assertion":"four_way_semantic_identity","minimum_records":4}]},
 {"claim_id":"read_only_operation","implementation_refs":["shiproom.measurement_ai.persistence.compile_generation"],"positive_test_ids":["test_domain_core_records_zero_external_operations"],"negative_test_ids":["test_external_execution_and_out_of_root_writes_are_forbidden"],"artifact_assertions":[{"artifact":"measurement-ai-compiler-receipts.json","assertion":"all_external_operations_zero","minimum_records":6}]},
 {"claim_id":"stale_version_handling","implementation_refs":["shiproom.measurement_ai.persistence.load_generation"],"positive_test_ids":["test_old_preparation_and_pointer_fail_closed_without_mutation"],"negative_test_ids":["test_recomputed_superficial_hash_tamper_preserves_pointer"],"artifact_assertions":[{"artifact":"stale-pointer-proof.json","assertion":"pointer_bytes_preserved","minimum_records":2}]},
)

def _symbol(reference:str):
    module,name=reference.rsplit(".",1);value=getattr(importlib.import_module(module),name,None)
    if value is None:raise ValueError("missing closeout implementation symbol: "+reference)

PRIVATE_FIELDS={"allowed_semantic_assessments","forbidden_semantic_assessments","required_recommendation_classes","forbidden_recommendation_classes","required_guidance_rules","required_exception_ids","maximum_effect","abstention_required","forbidden_claim_codes","required_authority_labels","automatic_replacement_prohibitions","capability_award_rules"}
def _recursive_private(value):
    if isinstance(value,dict):return bool(PRIVATE_FIELDS&set(value)) or any(_recursive_private(v) for v in value.values())
    if isinstance(value,list):return any(_recursive_private(v) for v in value)
    return False

def _count(value,path):
    for part in path.split("."):value=value.get(part,[]) if isinstance(value,dict) else []
    return len(value) if isinstance(value,(list,dict)) else int(bool(value))

def _blind(v):return len(v.get("cases",[]))>0 and all(str(c.get("case_id","")).startswith("qual_case_") for c in v["cases"]) and not _recursive_private(v)
def _caps(v):return bool(v.get("passed_capabilities")) and bool(v.get("failed_capabilities"))
def _regraded(v):return all(v.get(k) for k in ("private_rubric_semantic_hash","private_rubric_snapshot_hash","grading_engine_version","result_semantic_hash","result_snapshot_hash")) and _caps(v)
def _participants(v):
    participants=v.get("review_participants",[])
    if v.get("resolved_review_mode")=="contract_only":return len(participants)==0
    return len(participants)==1 and (participants[0].get("type")=="human" or all(participants[0].get(k) for k in ("candidate_id","provider_id","model_id","qualification_id","qualification_bundle_hash")))
def _sources(v):
    pairs=v.get("pairs",[]);keys=("path","git_object_format","git_blob_hash","normalized_text_hash")
    return bool(pairs) and all(all(p["overlay"].get(k)==p["source_packet"].get(k) for k in keys) and p["overlay"].get("git_object_format")=="sha1" and len(p["overlay"].get("git_blob_hash",""))==40 for p in pairs)
def _typed(v):return bool(v.get("event_candidates") or v.get("property_assessments")) and all(i.get("basis_ids") and i.get("compiled_authority") for k in ("event_candidates","property_assessments") for i in v.get(k,[]))
def _claims(v):
    values=[c for r in v.get("ai_evaluation",[]) for c in r.get("claims",[])]
    return bool(values) and all(c.get("honesty_state") in {"honest","unsupported_proof"} and c.get("honesty_reason_codes") for c in values)
def _aggregate(v):
    derivations=[d for c in v.get("checks",[]) for d in c.get("record_derivations",[])]
    statuses={d.get("status") for d in derivations};rank={"gap":0,"owner_confirmation_required":1,"not_inspected":2,"ready":3,"not_applicable":4}
    return len(derivations)>=2 and len(statuses)>=2 and all(c.get("status")==min((d.get("status") for d in c.get("record_derivations",[])),key=lambda s:rank[s]) for c in v.get("checks",[]) if c.get("record_derivations"))
def _verifier(v):
    values=[w for w in v.get("warnings",[]) if w.get("verifier_disposition")]
    allowed={"supported":{"condition_candidate","blocker_candidate","non_blocking_warning","none"},"downgrade":{"non_blocking_warning","none"},"disputed":{"owner_confirmation","none"},"owner_confirmation_required":{"owner_confirmation","none"}}
    return bool(values) and all(w.get("derived_effect") in allowed[w["verifier_disposition"]] for w in values)
def _projection(v):
    refs=[n for n in v.get("nodes",[]) if n.get("node_type")=="projection_reference"]
    return bool(refs) and len({(n["canonical_record_id"],n["destination_artifact"],tuple(n["criterion_ids"])) for n in refs})==len(refs) and all(len(n.get("criterion_ids",[]))==1 and n.get("canonical_record_id")==n.get("target_record_id") for n in refs)
def _downstream(v):
    values=v.get("downstream_definitions",[])
    return bool(values) and all((d["definition_state"]=="declared_external" and d["declaration_authority"]=="deterministically_established" and d["definition_content_authority"]=="not_inspected" and d["definition_assertion_scope"]=="external_definition_declaration") or (d["definition_state"]=="supplied_and_inspected" and d["definition_content_authority"]=="source_verified" and d["definition_assertion_scope"]=="source_definition") or d["definition_state"]=="not_inspected" for d in values)
def _harness(v):return len(v.get("runs",[]))>=4 and len({r.get("semantic_bundle_hash") for r in v["runs"]})==1 and len({r.get("principal_artifacts_hash") for r in v["runs"]})==1 and len({r.get("overlay_hash") for r in v["runs"]})==1
def _zero(v):
    ops=[i for i in v.get("validations",[]) if i.get("kind")=="external_operation"]
    return len(ops)==6 and {i["operation"] for i in ops}=={"model","command","network","browser","sql","external_service"} and all(i["count"]==0 for i in ops)
def _pointer(v):return len(v.get("snapshots",[]))==2 and v["snapshots"][0]==v["snapshots"][1] and bool(v["snapshots"][0]) and v.get("stale_error_code")

ARTIFACT_ASSERTIONS={"blind_public_task":(_blind,"cases"),"material_capability_outcomes":(_caps,"requested_capabilities"),"regraded_bundle_fields":(_regraded,"passed_capabilities"),"exact_participant_binding":(_participants,"review_participants"),"exact_source_nodes":(_sources,"pairs"),"typed_instrumentation_records":(_typed,"event_candidates"),"material_claim_honesty":(_claims,"ai_evaluation"),"mixed_status_aggregate":(_aggregate,"checks"),"material_verifier_effect":(_verifier,"warnings"),"substantive_projection_records":(_projection,"nodes"),"exact_downstream_authority":(_downstream,"downstream_definitions"),"four_way_semantic_identity":(_harness,"runs"),"all_external_operations_zero":(_zero,"validations"),"pointer_bytes_preserved":(_pointer,"snapshots")}

def resolve_claims(passed_test_ids:set[str],artifacts:dict[str,dict])->list[dict]:
    ids=[c["claim_id"] for c in CLAIMS]
    if len(ids)!=len(set(ids)) or any(not i for i in ids):raise ValueError("invalid closeout claim IDs")
    rows=[]
    for claim in CLAIMS:
        for ref in claim["implementation_refs"]:_symbol(ref)
        positive=set(claim["positive_test_ids"]);negative=set(claim["negative_test_ids"])
        if positive==negative:raise ValueError("closeout positive and adversarial evidence must be distinct")
        missing=(positive|negative)-passed_test_ids
        if missing:raise ValueError("closeout proof tests did not pass: "+",".join(sorted(missing)))
        evidence=[]
        for assertion in claim["artifact_assertions"]:
            artifact=artifacts.get(assertion["artifact"]);entry=ARTIFACT_ASSERTIONS.get(assertion["assertion"])
            if artifact is None or entry is None:raise ValueError("missing closeout artifact evidence: "+claim["claim_id"])
            predicate,count_path=entry;actual=_count(artifact,count_path)
            if actual<assertion["minimum_records"] or predicate(artifact) is not True:raise ValueError("closeout artifact assertion failed: "+claim["claim_id"])
            evidence.append({**assertion,"actual_record_count":actual})
        rows.append({**claim,"artifact_assertions":evidence,"status":"resolved"})
    return rows
