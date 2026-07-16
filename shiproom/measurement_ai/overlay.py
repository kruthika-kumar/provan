from __future__ import annotations

from .contracts import BASIS_EVIDENCE_CLASSES, NODE_TYPES, OVERLAY_SCHEMA, RELATIONSHIPS, effective_basis_class, require_exact


def evaluate_basis_path(steps:list[dict],edges:dict[str,dict],start_node_id:str,terminal_node_id:str)->str:
    current=start_node_id; classes=[]
    for step in steps:
        require_exact(step,{"edge_id","traversal"},"basis path step")
        if step["traversal"] not in {"forward","reverse"} or step["edge_id"] not in edges: raise ValueError("invalid basis path traversal")
        edge=edges[step["edge_id"]]
        if step["traversal"]=="forward":
            if edge["source_node_id"]!=current: raise ValueError("disconnected basis path")
            current=edge["target_node_id"]
        else:
            if edge["target_node_id"]!=current: raise ValueError("disconnected basis path")
            current=edge["source_node_id"]
        classes.append(edge.get("direct_fact_authority",edge.get("basis_evidence_class")))
    if current!=terminal_node_id: raise ValueError("basis path does not reach criterion")
    return effective_basis_class(classes)


NODE_FIELDS={
    "measurement_contract":{"node_id","node_type","provenance","contract_id","journey_id","criterion_ids"},
    "metric_definition":{"node_id","node_type","provenance","contract_id","journey_id","criterion_ids"},
    "required_signal":{"node_id","node_type","provenance","signal_id","criterion_ids","state"},
    "event_candidate":{"node_id","node_type","provenance","signal_id","criterion_ids","state"},
    "signal_property":{"node_id","node_type","provenance","signal_id","criterion_ids","state"},
    "instrumentation_test":{"node_id","node_type","provenance","signal_id","criterion_ids","state"},
    "runtime_evidence_binding":{"node_id","node_type","provenance","signal_id","criterion_ids","state"},
    "reviewer_conclusion":{"node_id","node_type","provenance","role_id","criterion_id","conclusion_evidence_class","semantic_review_authority","result_semantic_hash"},
    "guidance_rule_reference":{"node_id","node_type","provenance","rule_id","guidance_pack_hash"},
    "measurement_warning":{"node_id","node_type","provenance","recommendation_id","criterion_id","recommendation_class","effect"},
    "owner_confirmation_proposal":{"node_id","node_type","provenance","proposal_id","criterion_ids","reason"},
    "project_source_reference":{"node_id","node_type","provenance","basis_id","path","blob_hash"},
    "ai_eval_case":{"node_id","node_type","provenance","basis_id","path","blob_hash"},
    "ai_eval_execution":{"node_id","node_type","provenance","basis_id","path","blob_hash"},
    "observability_candidate":{"node_id","node_type","provenance","basis_id","path","blob_hash"},
}
RELATION_MATRIX={
    "governs_criterion":({"measurement_contract"},{"base"}), "measures_journey":({"measurement_contract"},{"base"}),
    "requires_signal":({"measurement_contract"},{"required_signal"}), "assesses_criterion":({"reviewer_conclusion"},{"base"}),
    "identifies_warning":({"reviewer_conclusion"},{"measurement_warning"}), "applies_guidance_rule":({"reviewer_conclusion","measurement_warning"},{"guidance_rule_reference"}),
    "proposes_owner_confirmation":({"reviewer_conclusion"},{"owner_confirmation_proposal"}),
}


def validate_overlay(value:dict,base_node_ids:set[str])->dict:
    require_exact(value,{"schema_version","release_id","release_commit","product_intent_semantic_hash","graph_semantic_hash","nodes","edges"},"measurement AI overlay")
    if value["schema_version"]!=OVERLAY_SCHEMA or not isinstance(value["nodes"],list) or not isinstance(value["edges"],list): raise ValueError("invalid measurement AI overlay")
    nodes={}
    for node in value["nodes"]:
        if not isinstance(node,dict) or node.get("node_type") not in NODE_TYPES or set(node)!=NODE_FIELDS[node["node_type"]] or node["node_id"] in nodes or node["provenance"] not in {"measurement_ai_compiler","measurement_reviewer","prepared_project_source","upstream_binding"}: raise ValueError("invalid measurement AI overlay node")
        nodes[node["node_id"]]=node
    edge_map={}; known=set(nodes)|base_node_ids
    fields={"edge_id","source_node_id","target_node_id","relationship","direct_fact_authority","criterion_id","criterion_path","criterion_basis_authority","origin","references"}
    for edge in value["edges"]:
        if not isinstance(edge,dict) or set(edge)!=fields or edge["edge_id"] in edge_map or edge["relationship"] not in RELATIONSHIPS or edge["direct_fact_authority"] not in BASIS_EVIDENCE_CLASSES-{"model_reviewed"} or edge["criterion_basis_authority"] not in BASIS_EVIDENCE_CLASSES-{"model_reviewed"} or edge["source_node_id"] not in known or edge["target_node_id"] not in known or not isinstance(edge["criterion_path"],list) or not isinstance(edge["references"],list): raise ValueError("invalid measurement AI overlay edge")
        edge_map[edge["edge_id"]]=edge
    for edge in value["edges"]:
        source_type=nodes.get(edge["source_node_id"],{}).get("node_type","base"); target_type=nodes.get(edge["target_node_id"],{}).get("node_type","base")
        if edge["relationship"] in RELATION_MATRIX:
            sources,targets=RELATION_MATRIX[edge["relationship"]]
            if source_type not in sources or target_type not in targets: raise ValueError("invalid overlay relationship source/target")
        if edge["criterion_id"] is not None:
            if edge["criterion_id"] not in base_node_ids or not edge["criterion_path"]: raise ValueError("criterion-scoped overlay edge requires a path")
            calculated=evaluate_basis_path(edge["criterion_path"],edge_map,edge["source_node_id"],edge["criterion_id"])
            if calculated!=edge["criterion_basis_authority"]: raise ValueError("stale criterion basis authority")
        elif edge["criterion_path"]: raise ValueError("unscoped overlay edge cannot carry a criterion path")
    return value
