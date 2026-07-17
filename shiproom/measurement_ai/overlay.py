from __future__ import annotations

from .contracts import BASIS_EVIDENCE_CLASSES, OVERLAY_SCHEMA, effective_basis_class, require_exact


COMMON={"node_id","node_type","provenance","criterion_ids"}
NODE_FIELDS={
    "measurement_contract":COMMON|{"contract_id","journey_id","field_states","metric_roles"},
    "metric_definition":COMMON|{"path","requirement_ids","journey_ids","declared_external","definition_state","execution_state","data_accuracy_state","definition_authority","git_object_format","git_blob_hash","normalized_text_hash"},
    "required_signal":COMMON|{"signal_id","name","name_state","required_properties"},
    "event_candidate":COMMON|{"basis_id","direct_fact_authority","criterion_basis_authority"},
    "signal_property":COMMON|{"signal_id","property_name","state","basis_ids","criterion_basis_authority"},
    "instrumentation_test":COMMON|{"basis_id","criterion_basis_authority"},
    "runtime_evidence_binding":COMMON|{"basis_id","criterion_basis_authority"},
    "reviewer_conclusion":COMMON|{"role_id","conclusion_evidence_class","semantic_review_authority","criterion_basis_authority","result_semantic_hash","summary"},
    "guidance_rule_reference":COMMON|{"rule_id"},
    "measurement_warning":COMMON|{"recommendation_id","recommendation_class","derived_effect","verifier_disposition","criterion_basis_authority","summary"},
    "ai_eval_case":COMMON|{"record_id","minimum_case_ready"},
    "ai_eval_rung":COMMON|{"rung","state","basis_ids","criterion_basis_authority","limitations"},
    "ai_eval_execution":COMMON|{"rung","state","basis_ids","criterion_basis_authority"},
    "production_trace":COMMON|{"state","basis_ids","criterion_basis_authority"},
    "observability_candidate":COMMON|{"kind","basis_ids","supported_dimensions","criterion_basis_authority"},
    "owner_confirmation_proposal":COMMON|{"proposal_id","reason"},
    "project_source_reference":COMMON|{"basis_id","path","git_object_format","git_blob_hash","normalized_text_hash","direct_fact_authority"},
    "projection_reference":COMMON|{"journey_id","record_kind","canonical_record_id","destination_artifact","target_record_id","authority"},
}

RELATION_MATRIX={
    "governs_criterion":({"measurement_contract"},{"base"}),
    "measures_journey":({"measurement_contract"},{"base"}),
    "uses_metric_definition":({"measurement_contract"},{"metric_definition"}),
    "requires_signal":({"measurement_contract"},{"required_signal"}),
    "has_event_candidate":({"required_signal"},{"event_candidate"}),
    "requires_property":({"required_signal"},{"signal_property"}),
    "covered_by_test":({"required_signal"},{"instrumentation_test"}),
    "has_runtime_binding":({"required_signal"},{"runtime_evidence_binding"}),
    "mapped_to_project_source":({"event_candidate","ai_eval_rung","observability_candidate"},{"project_source_reference"}),
    "binds_base_runtime_evidence":({"runtime_evidence_binding","ai_eval_execution","production_trace"},{"base"}),
    "assesses_contract":({"reviewer_conclusion"},{"measurement_contract"}),
    "assesses_criterion":({"reviewer_conclusion"},{"base"}),
    "applies_guidance_rule":({"measurement_warning"},{"guidance_rule_reference"}),
    "identifies_warning":({"reviewer_conclusion"},{"measurement_warning"}),
    "proposes_owner_confirmation":({"reviewer_conclusion","measurement_warning"},{"owner_confirmation_proposal"}),
    "evaluates_ai_criterion":({"ai_eval_case"},{"base"}),
    "has_ai_rung":({"ai_eval_case"},{"ai_eval_rung","ai_eval_execution","production_trace"}),
    "has_observability_candidate":({"ai_eval_case"},{"observability_candidate"}),
    "projects_record_for_criterion":({"projection_reference"},{"base"}),
}


def evaluate_basis_path(steps:list[dict],edges:dict[str,dict],start:str,criterion_id:str)->str:
    current=start; classes=[]
    for step in steps:
        require_exact(step,{"edge_id","traversal"},"measurement AI path step")
        if step["traversal"] not in {"forward","reverse"} or step["edge_id"] not in edges: raise ValueError("invalid measurement AI path step")
        edge=edges[step["edge_id"]]; source=edge["source_node_id"] if step["traversal"]=="forward" else edge["target_node_id"]; target=edge["target_node_id"] if step["traversal"]=="forward" else edge["source_node_id"]
        if source!=current: raise ValueError("disconnected measurement AI criterion path")
        current=target; classes.append(edge["direct_fact_authority"])
    if current!=criterion_id: raise ValueError("measurement AI criterion path does not terminate at criterion")
    return effective_basis_class(classes)


def validate_overlay(value:dict,base_node_ids:set[str])->dict:
    require_exact(value,{"schema_version","release_id","release_commit","product_intent_semantic_hash","graph_semantic_hash","nodes","edges","projection_verification"},"measurement AI overlay")
    if value["schema_version"]!=OVERLAY_SCHEMA or not isinstance(value["nodes"],list) or not isinstance(value["edges"],list): raise ValueError("invalid measurement AI overlay")
    nodes={}
    for node in value["nodes"]:
        if not isinstance(node,dict) or node.get("node_type") not in NODE_FIELDS or set(node)!=NODE_FIELDS[node["node_type"]] or node["node_id"] in nodes: raise ValueError("invalid measurement AI overlay node")
        if node["node_type"]=="projection_reference" and (len(node["criterion_ids"])!=1 or not node["canonical_record_id"] or not node["target_record_id"]): raise ValueError("invalid scoped projection reference")
        if node["provenance"] not in {"measurement_ai_compiler","measurement_reviewer","prepared_project_source","upstream_binding"}: raise ValueError("invalid overlay provenance")
        nodes[node["node_id"]]=node
    edges={}
    for edge in value["edges"]:
        require_exact(edge,{"edge_id","source_node_id","target_node_id","relationship","direct_fact_authority","criterion_id","criterion_path","criterion_basis_authority","origin","reference_ids"},"measurement AI overlay edge")
        if edge["edge_id"] in edges or edge["relationship"] not in RELATION_MATRIX or edge["direct_fact_authority"] not in BASIS_EVIDENCE_CLASSES-{"model_reviewed"}: raise ValueError("invalid measurement AI overlay relationship")
        if edge["source_node_id"] not in nodes or (edge["target_node_id"] not in nodes and edge["target_node_id"] not in base_node_ids): raise ValueError("dangling measurement AI overlay edge")
        source_type=nodes[edge["source_node_id"]]["node_type"]; target_type=nodes[edge["target_node_id"]]["node_type"] if edge["target_node_id"] in nodes else "base"
        allowed_source,allowed_target=RELATION_MATRIX[edge["relationship"]]
        if source_type not in allowed_source or target_type not in allowed_target: raise ValueError("invalid measurement AI relationship source or target")
        edges[edge["edge_id"]]=edge
    for edge in edges.values():
        if edge["criterion_id"] not in base_node_ids: raise ValueError("invalid overlay criterion")
        effective=evaluate_basis_path(edge["criterion_path"],edges,edge["source_node_id"],edge["criterion_id"])
        if effective!=edge["criterion_basis_authority"]: raise ValueError("stale measurement AI criterion path authority")
    if not isinstance(value["projection_verification"],list) or len({(item.get("record_id"),item.get("destination"),item.get("criterion_id")) for item in value["projection_verification"]})!=len(value["projection_verification"]): raise ValueError("invalid canonical projection verification")
    for item in value["projection_verification"]: require_exact(item,{"record_id","record_kind","criterion_id","journey_id","authority","destination","target_record_id"},"canonical projection verification")
    return value
