from __future__ import annotations

from .contracts import (
    BASIS_EVIDENCE_CLASSES, NODE_TYPES, OVERLAY_SCHEMA, RELATIONSHIPS,
    effective_basis_class, require_exact,
)


def evaluate_basis_path(steps: list[dict], edges: dict[str, dict], start_node_id: str, terminal_node_id: str) -> str:
    current = start_node_id; classes = []
    for step in steps:
        require_exact(step, {"edge_id", "traversal"}, "basis path step")
        if step["traversal"] not in {"forward", "reverse"} or step["edge_id"] not in edges:
            raise ValueError("invalid basis path traversal")
        edge = edges[step["edge_id"]]
        if step["traversal"] == "forward":
            if edge["source_node_id"] != current: raise ValueError("disconnected basis path")
            current = edge["target_node_id"]
        else:
            if edge["target_node_id"] != current: raise ValueError("disconnected basis path")
            current = edge["source_node_id"]
        classes.append(edge["basis_evidence_class"])
    if current != terminal_node_id:
        raise ValueError("basis path does not reach criterion")
    return effective_basis_class(classes)


def validate_overlay(value: dict, base_node_ids: set[str]) -> dict:
    require_exact(value, {"schema_version", "release_id", "release_commit", "product_intent_semantic_hash", "graph_semantic_hash", "nodes", "edges"}, "measurement AI overlay")
    if value["schema_version"] != OVERLAY_SCHEMA or not isinstance(value["nodes"], list) or not isinstance(value["edges"], list):
        raise ValueError("invalid measurement AI overlay")
    nodes = {}
    for node in value["nodes"]:
        if not isinstance(node, dict) or set(node) != {"node_id", "node_type", "provenance", "detail"} or node["node_type"] not in NODE_TYPES or node["node_id"] in nodes or node["provenance"] not in {"measurement_ai_compiler", "measurement_reviewer", "prepared_project_source", "upstream_binding"} or not isinstance(node["detail"], dict):
            raise ValueError("invalid measurement AI overlay node")
        nodes[node["node_id"]] = node
    edge_map = {}
    known_nodes = set(nodes) | base_node_ids
    for edge in value["edges"]:
        fields = {"edge_id", "source_node_id", "target_node_id", "relationship", "basis_evidence_class", "origin", "references"}
        if not isinstance(edge, dict) or set(edge) != fields or edge["edge_id"] in edge_map or edge["relationship"] not in RELATIONSHIPS or edge["basis_evidence_class"] not in BASIS_EVIDENCE_CLASSES or edge["source_node_id"] not in known_nodes or edge["target_node_id"] not in known_nodes or not isinstance(edge["references"], list):
            raise ValueError("invalid measurement AI overlay edge")
        edge_map[edge["edge_id"]] = edge
    return value
