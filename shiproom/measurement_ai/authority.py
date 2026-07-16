from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
from importlib import resources
from pathlib import Path, PurePosixPath

from shiproom.assessment import load_measurement_ai_input
from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.project import canonical_json, content_hash

from .contracts import (
    APPLICABILITY_SCHEMA, CAPABILITIES_SCHEMA, DEFINITION_STATES, FIELD_STATES,
    ROLE_FILE_LIMIT, ROLE_TEXT_LIMIT, ROLES, SCOPE_STATES, SOURCE_LIMIT,
    effective_basis_class, load_json_bytes, require_exact, require_string_list, require_text,
    sha256_bytes, stable_id, validate_relative_path,
)
from .trust import validate_ancestry


MEASUREMENT_FIELDS = (
    "decision_question", "decision_use_case", "decision_owner", "decision_timing",
    "decision_rule_or_interpretation", "intended_outcome", "unit", "unit_of_observation",
    "eligible_population", "exposure_or_opportunity_definition", "numerator", "denominator",
    "aggregation_level", "observation_window", "attribution_rule", "expected_direction",
    "decision_threshold_or_interpretation", "journey_start", "success_condition", "failure_condition",
    "guardrails", "experiment_exposure", "inference_intent", "outcome_delay",
    "minimum_maturity_window", "incomplete_observation_possible", "censoring_limitation",
    "denominator_state", "eligible_denominator_population", "zero_denominator_handling",
    "release_can_affect_denominator", "definition_state", "execution_state", "data_accuracy_state",
)
AI_IMPORTS = {"openai", "anthropic", "cohere", "google.generativeai", "google.genai", "mistralai"}


def domain_root(ctx: LocalExecutionContext) -> Path:
    return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "measurement-ai-readiness"


def default_capabilities() -> dict:
    return {
        "schema_version": CAPABILITIES_SCHEMA,
        "substrate": {"id": "manual_external", "execution_mode": "manual_external"},
        "capabilities": {"file_read": {"available": True}, "shell": {"available": False}, "browser": {"available": False}, "network": {"available": False}},
        "permissions": {"file_read": {"granted": True, "scope": "prepared_packet_only"}, "shell": {"granted": False}, "browser": {"granted": False}, "network": {"granted": False}},
    }


def validate_capabilities(value: dict) -> dict:
    require_exact(value, {"schema_version", "substrate", "capabilities", "permissions"}, "measurement AI capabilities")
    if value["schema_version"] != CAPABILITIES_SCHEMA:
        raise ValueError("invalid measurement AI capabilities version")
    require_exact(value["substrate"], {"id", "execution_mode"}, "capability substrate")
    require_text(value["substrate"]["id"], "substrate.id", 200); require_text(value["substrate"]["execution_mode"], "substrate.execution_mode", 200)
    if set(value["capabilities"]) != {"file_read", "shell", "browser", "network"} or set(value["permissions"]) != {"file_read", "shell", "browser", "network"}:
        raise ValueError("invalid measurement AI capability set")
    for name, item in value["capabilities"].items():
        require_exact(item, {"available"}, f"{name} capability")
        if not isinstance(item["available"], bool): raise ValueError("capability availability must be Boolean")
    require_exact(value["permissions"]["file_read"], {"granted", "scope"}, "file read permission")
    if value["permissions"]["file_read"] != {"granted": True, "scope": "prepared_packet_only"} or not value["capabilities"]["file_read"]["available"]:
        raise ValueError("prepared packet file read is required")
    for name in ("shell", "browser", "network"):
        require_exact(value["permissions"][name], {"granted"}, f"{name} permission")
        if value["permissions"][name]["granted"] or value["capabilities"][name]["available"]:
            raise ValueError(f"Session 5 {name} capability is unavailable")
    return value


def default_applicability() -> dict:
    return {
        "schema_version": APPLICABILITY_SCHEMA,
        "measurement": {"requirement_ids": [], "criterion_ids": [], "journey_ids": [], "paths": [], "measurement_definition_paths": [], "contracts": []},
        "ai": {"requirement_ids": [], "criterion_ids": [], "journey_ids": [], "paths": []},
    }


def validate_applicability(value: dict) -> dict:
    require_exact(value, {"schema_version", "measurement", "ai"}, "measurement AI applicability")
    if value["schema_version"] != APPLICABILITY_SCHEMA: raise ValueError("invalid applicability version")
    measurement = require_exact(value["measurement"], {"requirement_ids", "criterion_ids", "journey_ids", "paths", "measurement_definition_paths", "contracts"}, "measurement applicability")
    ai = require_exact(value["ai"], {"requirement_ids", "criterion_ids", "journey_ids", "paths"}, "AI applicability")
    for scope in (measurement, ai):
        for key in ("requirement_ids", "criterion_ids", "journey_ids"):
            require_string_list(scope[key], key)
        scope["paths"] = [validate_relative_path(item, "owner path") for item in require_string_list(scope["paths"], "paths")]
    definitions = measurement["measurement_definition_paths"]
    if not isinstance(definitions, list): raise ValueError("measurement_definition_paths must be a list")
    seen_paths = set()
    for item in definitions:
        require_exact(item, {"path", "requirement_ids", "criterion_ids", "journey_ids", "declared_external"}, "measurement definition path")
        item["path"] = validate_relative_path(item["path"], "measurement definition path")
        if item["path"] in seen_paths: raise ValueError("duplicate measurement definition path")
        seen_paths.add(item["path"])
        for key in ("requirement_ids", "criterion_ids", "journey_ids"): require_string_list(item[key], key)
        if not isinstance(item["declared_external"], bool): raise ValueError("declared_external must be Boolean")
    if not isinstance(measurement["contracts"], list): raise ValueError("contracts must be a list")
    local_contracts = set()
    for item in measurement["contracts"]:
        require_exact(item, {"local_id", "journey_id", "criterion_ids", "fields", "metric_roles", "required_signals"}, "owner measurement contract")
        require_text(item["local_id"], "contract.local_id", 100); require_text(item["journey_id"], "contract.journey_id", 200)
        if item["local_id"].casefold() in local_contracts: raise ValueError("duplicate owner contract local ID")
        local_contracts.add(item["local_id"].casefold()); require_string_list(item["criterion_ids"], "contract.criterion_ids")
        if not isinstance(item["fields"], dict) or not set(item["fields"]).issubset(MEASUREMENT_FIELDS): raise ValueError("invalid owner measurement fields")
        for name, field in item["fields"].items():
            require_exact(field, {"value", "state"}, f"owner field {name}")
            if field["state"] != "owner_confirmed": raise ValueError("owner declaration fields must be owner_confirmed")
        if not isinstance(item["metric_roles"], list) or not isinstance(item["required_signals"], list): raise ValueError("invalid metric roles or signals")
    return value


def _read_release_local_input(ctx: LocalExecutionContext, path_value: str | None, filename: str, default: dict, validator) -> dict:
    if path_value is None:
        raw = (json.dumps(default, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        return {"value": validator(load_json_bytes(raw)), "bytes": raw, "filename": filename}
    path = Path(path_value)
    root = domain_root(ctx) / "inputs"
    if path.parent.absolute()!=root.absolute(): raise ValueError("measurement AI input must be directly under the release-local inputs directory")
    validate_ancestry(root,path,directory=False,label="measurement AI input")
    raw = path.read_bytes()
    if len(raw) > 256 * 1024: raise ValueError("measurement AI input exceeds byte limit")
    return {"value": validator(load_json_bytes(raw)), "bytes": raw, "filename": path.name}


def load_capabilities_input(ctx: LocalExecutionContext, path: str | None) -> dict:
    return _read_release_local_input(ctx, path, "capabilities.json", default_capabilities(), validate_capabilities)


def load_applicability_input(ctx: LocalExecutionContext, path: str | None) -> dict:
    return _read_release_local_input(ctx, path, "applicability.json", default_applicability(), validate_applicability)


def normalize_text(text: str) -> str:
    return text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def source_record(ctx: LocalExecutionContext, path: str, *, mandatory: bool, rules: list[str], reason: str, provenance: str) -> dict:
    blob = ctx.read_release_blob(path, SOURCE_LIMIT)
    if blob["classification"] != "text" or blob["text"] is None: raise ValueError(f"measurement AI source is not UTF-8 text: {path}")
    text = normalize_text(blob["text"]); raw = text.encode("utf-8")
    return {"path": blob["path"], "returned_git_path": blob["path"], "git_blob_hash": blob["blob_hash"], "normalized_text_hash": sha256_bytes(raw), "size_bytes": len(raw), "text": text, "mandatory": mandatory, "selection_rule_ids": sorted(set(rules)), "selection_reason": reason, "provenance": provenance}


def _node_paths(graph: dict, role: str) -> list[tuple[str, str, str]]:
    nodes = {item["node_id"]: item for item in graph["nodes"]}; result = []
    for edge in graph["edges"]:
        if edge["relationship"] not in {"may_be_implemented_by", "may_be_verified_by", "may_be_observed_by"}: continue
        target = nodes.get(edge["target_node_id"], {})
        path = target.get("path")
        if not path: continue
        if role == "measurement" and target.get("node_type") not in {"implementation_reference", "test_reference", "instrumentation_reference"}: continue
        if role == "ai_evaluation" and target.get("node_type") not in {"implementation_reference", "test_reference"}: continue
        result.append((path, edge["source_node_id"], edge["establishment_classification"]))
    return sorted(set(result))


def _python_imports(text: str) -> set[str]:
    try: tree = ast.parse(text)
    except SyntaxError: return set()
    result = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import): result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: result.add(node.module)
    return result


def _has_ai_import(source: dict) -> bool:
    if source["path"].endswith(".py"):
        imports = _python_imports(source["text"])
        return any(name == allowed or name.startswith(allowed + ".") for name in imports for allowed in AI_IMPORTS)
    if PurePosixPath(source["path"]).suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        return any(re.search(rf"(?:from\s+|require\()['\"]{re.escape(name)}(?:['\"/])", source["text"]) for name in AI_IMPORTS)
    return False


def _test_candidates(path: str) -> list[str]:
    source = PurePosixPath(path); stem = source.stem; parent = source.parent
    if source.suffix == ".py":
        return [f"tests/test_{stem}.py", (parent / f"test_{stem}.py").as_posix(), (parent / f"{stem}_test.py").as_posix()]
    if source.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        return [(parent / f"{stem}{kind}{ext}").as_posix() for kind in (".test", ".spec") for ext in (source.suffix,)] + [(parent / "__tests__" / f"{stem}{source.suffix}").as_posix()]
    return []


def select_sources(ctx: LocalExecutionContext, inputs: dict, applicability: dict, owner_paths: dict[str, list[str]]) -> dict[str, dict]:
    graph = inputs["graph_artifacts"]["requirement-evidence-graph.json"]
    selected: dict[str, dict[str, dict]] = {role: {} for role in ROLES}; limitations = {role: [] for role in ROLES}
    graph_paths = {role: _node_paths(graph, role) for role in ROLES}
    definitions = applicability["measurement"]["measurement_definition_paths"]
    seeds: dict[str, list[tuple[str, bool, str, str]]] = {role: [] for role in ROLES}
    for role in ROLES:
        for path, _, classification in graph_paths[role]: seeds[role].append((path, True, "relevant_graph_mapped_path", classification))
        for path in owner_paths[role]: seeds[role].append((path, True, "owner_role_path", "owner_declared"))
    for item in definitions: seeds["measurement"].append((item["path"], True, "measurement_definition_path", "owner_declared"))
    for role in ROLES:
        for path, mandatory, rule, provenance in seeds[role]:
            try:
                record = source_record(ctx, path, mandatory=mandatory, rules=[rule], reason=rule.replace("_", " "), provenance=provenance)
            except (FileNotFoundError, PermissionError, ValueError) as exc:
                if mandatory: raise
                limitations[role].append({"kind":"source_unavailable","path":path,"detail":str(exc)}); continue
            if path in selected[role] and selected[role][path]["git_blob_hash"] != record["git_blob_hash"]: raise ValueError("source selection collision")
            selected[role][path] = record
        original = list(selected[role])
        for path in original:
            for candidate in _test_candidates(path):
                if candidate in selected[role]: continue
                try: selected[role][candidate] = source_record(ctx, candidate, mandatory=False, rules=["exact_test_name_match"], reason=f"test name match for {path}", provenance="discovery_registry")
                except (FileNotFoundError, PermissionError, ValueError): pass
    output = {}
    for role in ROLES:
        records = sorted(selected[role].values(), key=lambda item: item["path"])
        mandatory = [item for item in records if item["mandatory"]]; supplemental = [item for item in records if not item["mandatory"]]
        if len(mandatory) > ROLE_FILE_LIMIT or sum(item["size_bytes"] for item in mandatory) > ROLE_TEXT_LIMIT: raise ValueError(f"mandatory {role} source budget exceeded")
        included = list(mandatory); omitted = []
        for item in supplemental:
            if len(included) >= ROLE_FILE_LIMIT or sum(record["size_bytes"] for record in included) + item["size_bytes"] > ROLE_TEXT_LIMIT: omitted.append(item["path"])
            else: included.append(item)
        output[role] = {"sources": included, "coverage": {"coverage_status":"bounded_incomplete" if omitted else "complete","candidate_files_considered":len(records),"files_included":len(included),"files_omitted_due_to_cap":len(omitted),"omitted_paths":omitted}, "limitations": limitations[role]}
    return output


def build_authority_input(ctx: LocalExecutionContext, applicability: dict, owner_paths: dict[str, list[str]]) -> dict:
    graph_input = load_assessment_input(ctx)
    assessment_input = load_measurement_ai_input(ctx)
    sources = select_sources(ctx, graph_input, applicability, owner_paths)
    requirements = graph_input["intent_artifacts"]["requirements.json"]["requirements"]
    criteria = graph_input["intent_artifacts"]["acceptance-criteria.json"]["criteria"]
    graph = graph_input["graph_artifacts"]["requirement-evidence-graph.json"]
    graph_nodes = {item["node_id"]: item for item in graph["nodes"]}; graph_edges = graph["edges"]
    journey_nodes = [item for item in graph["nodes"] if item["node_type"] == "critical_journey"]
    valid_req = {item["requirement_id"] for item in requirements}; valid_crit = {item["criterion_id"] for item in criteria}; valid_journey = {item["node_id"] for item in journey_nodes}
    for section in (applicability["measurement"], applicability["ai"]):
        if not set(section["requirement_ids"]).issubset(valid_req) or not set(section["criterion_ids"]).issubset(valid_crit) or not set(section["journey_ids"]).issubset(valid_journey): raise ValueError("owner applicability references unknown intent IDs")
    measurement_applicable = {item["criterion_id"] for item in criteria if "instrumentation" in item["required_evidence_categories"]}
    measurement_candidate = set(); ai_applicable = set(applicability["ai"]["criterion_ids"]); ai_candidate = set()
    for edge in graph_edges:
        if edge["relationship"] == "may_be_observed_by" and edge["source_node_id"] in valid_crit:
            if edge["establishment_classification"] == "deterministically_established": measurement_applicable.add(edge["source_node_id"])
            elif edge["establishment_classification"] == "model_mapped_candidate": measurement_candidate.add(edge["source_node_id"])
    measurement_applicable.update(applicability["measurement"]["criterion_ids"])
    definition_linked = set()
    for definition in applicability["measurement"]["measurement_definition_paths"]:
        definition_linked.update(definition["criterion_ids"])
    measurement_applicable.update(definition_linked)
    for path, _, classification in _node_paths(graph, "ai_evaluation"):
        source = next((item for item in sources["ai_evaluation"]["sources"] if item["path"] == path), None)
        if source and _has_ai_import(source):
            criterion_ids = {edge["source_node_id"] for edge in graph_edges if edge["target_node_id"] in graph_nodes and graph_nodes[edge["target_node_id"]].get("path") == path and edge["source_node_id"] in valid_crit}
            (ai_applicable if classification == "deterministically_established" else ai_candidate).update(criterion_ids)
    linked_definitions = [item for item in applicability["measurement"]["measurement_definition_paths"] if item["requirement_ids"] or item["criterion_ids"] or item["journey_ids"]]
    unlinked_definitions = [item for item in applicability["measurement"]["measurement_definition_paths"] if not (item["requirement_ids"] or item["criterion_ids"] or item["journey_ids"])]
    measurement_candidate.update(set(applicability["measurement"]["criterion_ids"]) - measurement_applicable)
    role_scopes = {
        "measurement": {"applicable_criterion_ids": sorted(measurement_applicable), "candidate_criterion_ids": sorted(measurement_candidate - measurement_applicable), "unbounded_candidate_count": len(unlinked_definitions)},
        "ai_evaluation": {"applicable_criterion_ids": sorted(ai_applicable), "candidate_criterion_ids": sorted(ai_candidate - ai_applicable), "unbounded_candidate_count": 0},
    }
    assessment_dependency = {"state":"not_used","generation":None,"semantic_hash":None}
    # Assessment is consumed only when exact assigned criteria have assessment records.
    if assessment_input["assessment_state"] == "present":
        relevant = set(role_scopes["measurement"]["applicable_criterion_ids"] + role_scopes["ai_evaluation"]["applicable_criterion_ids"])
        effective = assessment_input["artifacts"].get("effective-assessment-view.json", {}).get("criteria", [])
        selected = [item for item in effective if item.get("criterion_id") in relevant]
        if selected:
            assessment_dependency = {"state":"required_present","generation":assessment_input["generation"],"semantic_hash":assessment_input["manifest"]["semantic_bundle_hash"]}
    return {"graph_input":graph_input,"assessment_input":assessment_input,"assessment_dependency":assessment_dependency,"requirements":requirements,"criteria":criteria,"journeys":journey_nodes,"role_scopes":role_scopes,"role_sources":sources,"linked_measurement_definitions":linked_definitions,"unlinked_measurement_definitions":unlinked_definitions}


def prepared_contracts(authority: dict, applicability: dict) -> list[dict]:
    criteria = {item["criterion_id"]: item for item in authority["criteria"]}; journeys = {item["node_id"]: item for item in authority["journeys"]}; contracts = []
    owner_by_journey = {item["journey_id"]: item for item in applicability["measurement"]["contracts"]}
    applicable = set(authority["role_scopes"]["measurement"]["applicable_criterion_ids"])
    requirements = {item["requirement_id"]: item for item in authority["requirements"]}
    for journey_id, journey in sorted(journeys.items()):
        related = sorted(cid for cid in applicable if journey.get("journey_text") in requirements[criteria[cid]["requirement_id"]].get("related_journey_ids", []))
        owner = owner_by_journey.get(journey_id)
        if owner: related = sorted(set(related) | set(owner["criterion_ids"]))
        if not related and not owner: continue
        prepared = {}
        for name in MEASUREMENT_FIELDS:
            candidates = []
            if owner and name in owner["fields"]: candidates.append({"value":owner["fields"][name]["value"],"field_state":"owner_confirmed","provenance":"owner_applicability_declaration","source_refs":[],"base_ids":[journey_id]})
            if name == "intended_outcome":
                for cid in related:
                    for outcome in criteria[cid].get("expected_outcomes", []): candidates.append({"value":outcome,"field_state":"source_declared","provenance":"product_intent","source_refs":criteria[cid].get("field_source_refs", {}).get("expected_outcomes", []),"base_ids":[cid]})
            if name == "success_condition":
                values = [outcome for cid in related for outcome in criteria[cid].get("expected_outcomes", [])]
                for value in values: candidates.append({"value":value,"field_state":"source_declared","provenance":"product_intent","source_refs":[],"base_ids":related})
            if name == "failure_condition":
                for cid in related:
                    if criteria[cid].get("failure_behavior") is not None: candidates.append({"value":criteria[cid]["failure_behavior"],"field_state":"source_declared","provenance":"product_intent","source_refs":[],"base_ids":[cid]})
            unique = {canonical_json(item["value"]): item for item in candidates}
            if not candidates: field = {"value":None,"field_state":"unresolved","assertion_scope":"not_inspected","provenance":[],"source_refs":[],"base_ids":[],"competing_values":[],"model_proposals":[]}
            elif len(unique) == 1:
                value = next(iter(unique.values())); field = {"value":value["value"],"field_state":value["field_state"],"assertion_scope":"contract_declaration","provenance":sorted({item["provenance"] for item in candidates}),"source_refs":[],"base_ids":sorted({base for item in candidates for base in item["base_ids"]}),"competing_values":[],"model_proposals":[]}
            else: field = {"value":None,"field_state":"unresolved","assertion_scope":"contract_declaration","provenance":sorted({item["provenance"] for item in candidates}),"source_refs":[],"base_ids":sorted({base for item in candidates for base in item["base_ids"]}),"competing_values":[json.loads(key) for key in sorted(unique)],"model_proposals":[]}
            prepared[name] = field
        signals = []
        owner_signals = owner["required_signals"] if owner else []
        for index, signal in enumerate(owner_signals):
            if not isinstance(signal, dict) or set(signal) != {"name", "required_properties"}: raise ValueError("invalid owner required signal")
            signals.append({"signal_id":stable_id("signal",{"journey":journey_id,"name":signal["name"]}),"name":signal["name"],"name_state":"owner_confirmed","required_properties":sorted(signal["required_properties"]),"criterion_ids":related})
        if not signals:
            signals.append({"signal_id":stable_id("signal",{"journey":journey_id,"criteria":related}),"name":None,"name_state":"unresolved","required_properties":[],"criterion_ids":related})
        contracts.append({
            "contract_id":stable_id("measurement_contract",{"journey":journey_id,"criteria":related}),
            "journey_id":journey_id,"journey_text":journey["journey_text"],"criterion_ids":related,
            "fields":prepared,"metric_roles":owner["metric_roles"] if owner else [],"required_signals":signals,
            "definition_state":prepared["definition_state"]["value"] or "not_supplied",
            "execution_state":prepared["execution_state"]["value"] or "not_inspected",
            "data_accuracy_state":prepared["data_accuracy_state"]["value"] or "not_inspected",
        })
    return contracts


def build_basis_registry(authority: dict, prepared: list[dict]) -> tuple[list[dict], list[dict]]:
    """Create the only factual references reviewers may cite.

    Classifications and criterion paths are compiler-owned.  Reviewers receive
    stable IDs and cannot submit either authority labels or arbitrary paths.
    """
    graph = authority["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]
    nodes = {item["node_id"]: item for item in graph["nodes"]}
    criterion_ids = {item["criterion_id"] for item in authority["criteria"]}
    class_map = {
        "source_backed": "source_verified",
        "owner_confirmed": "deterministically_established",
        "deterministically_established": "deterministically_established",
        "model_mapped_candidate": "model_mapped_candidate",
        "not_inspected": "not_inspected",
        "missing": "not_inspected",
    }
    registry: dict[str, dict] = {}
    paths: list[dict] = []

    for cid in sorted(criterion_ids):
        bid = stable_id("basis", {"type": "criterion", "id": cid})
        registry[bid] = {"basis_id": bid, "basis_type": "source_reference", "object_id": cid,
            "role_ids": list(ROLES), "criterion_ids": [cid], "journey_ids": [],
            "field_state":"source_declared","assertion_scope":"contract_declaration",
            "direct_fact_authority": "source_verified", "origin":"product_intent",
            "reference_ids":[cid],"allowed_relationships": ["assesses_criterion"]}

    for edge in sorted(graph["edges"], key=lambda item: item["edge_id"]):
        cid = edge["source_node_id"] if edge["source_node_id"] in criterion_ids else edge["target_node_id"] if edge["target_node_id"] in criterion_ids else None
        other = edge["target_node_id"] if cid == edge["source_node_id"] else edge["source_node_id"]
        if not cid or other not in nodes:
            continue
        direct = class_map.get(edge.get("establishment_classification"), "not_inspected")
        role_ids = []
        ntype = nodes[other].get("node_type")
        if ntype in {"implementation_reference", "test_reference", "instrumentation_reference", "runtime_evidence", "finding", "closure_evidence"}:
            role_ids.append("measurement")
        if ntype in {"implementation_reference", "test_reference", "runtime_evidence", "finding", "closure_evidence"}:
            role_ids.append("ai_evaluation")
        if not role_ids:
            continue
        bid = stable_id("basis", {"type": "graph_node", "id": other, "edge": edge["edge_id"]})
        basis_type={
            "implementation_reference":"implementation_reference","instrumentation_reference":"instrumentation_reference",
            "test_reference":"test_reference","runtime_evidence":"runtime_evidence",
        }.get(ntype,"source_reference")
        assertion_scope={"implementation_reference":"implementation","instrumentation_reference":"instrumentation","test_reference":"test","runtime_evidence":"runtime"}.get(ntype,"source_definition")
        registry[bid] = {"basis_id": bid, "basis_type": basis_type, "object_id": other,
            "role_ids": sorted(role_ids), "criterion_ids": [cid], "journey_ids": [],
            "field_state":"not_inspected" if direct=="not_inspected" else "source_declared",
            "assertion_scope":assertion_scope,"direct_fact_authority": direct,
            "origin":"requirement_evidence_graph","reference_ids":[other,edge["edge_id"]],
            "allowed_relationships": ["supports_conclusion", "supports_warning"]}
        traversal = "reverse" if edge["target_node_id"] == other else "forward"
        # The path starts at the factual node and terminates at the criterion.
        traversal = "reverse" if edge["target_node_id"] == other else "forward"
        pid = stable_id("basis_path", {"basis": bid, "criterion": cid, "edge": edge["edge_id"]})
        paths.append({"path_id": pid, "role_ids": sorted(role_ids), "criterion_id": cid,
            "start_basis_id": bid, "steps": [{"edge_id": edge["edge_id"], "traversal": traversal}],
            "required":True,"effective_authority": direct})

    for role in ROLES:
        for source in authority["role_sources"][role]["sources"]:
            mappings=[(cid,classification) for path,cid,classification in _node_paths(graph,role) if path==source["path"]]
            linked = sorted({cid for cid,_ in mappings})
            mapped_authorities=[class_map.get(classification,"not_inspected") for _,classification in mappings]
            direct=effective_basis_class(mapped_authorities) if mapped_authorities else "not_inspected"
            bid = stable_id("basis", {"type": "project_source", "role": role, "path": source["path"], "blob": source["git_blob_hash"]})
            registry[bid] = {"basis_id": bid, "basis_type": "source_reference", "object_id": source["path"],
                "role_ids": [role], "criterion_ids": linked, "journey_ids": [],
                "field_state":"source_declared" if linked else "not_inspected","assertion_scope":"source_definition",
                "direct_fact_authority": direct,"origin":"project_source",
                "reference_ids":[source["path"],source["git_blob_hash"]],
                "allowed_relationships": ["supports_conclusion", "supports_warning"]}
            for cid,classification in mappings:
                for edge in graph["edges"]:
                    target=nodes.get(edge["target_node_id"],{})
                    if edge["source_node_id"]==cid and target.get("path")==source["path"] and edge["establishment_classification"]==classification:
                        pid=stable_id("basis_path",{"basis":bid,"criterion":cid,"edge":edge["edge_id"]})
                        paths.append({"path_id":pid,"role_ids":[role],"criterion_id":cid,"start_basis_id":bid,"steps":[{"edge_id":edge["edge_id"],"traversal":"reverse"}],"required":True,"effective_authority":class_map.get(classification,"not_inspected")})

    for contract in prepared:
        bid = stable_id("basis", {"type": "prepared_contract", "id": contract["contract_id"]})
        states = {field["field_state"] for field in contract["fields"].values()}
        direct = "not_inspected" if "unresolved" in states else ("deterministically_established" if states=={"owner_confirmed"} else "source_verified")
        registry[bid] = {"basis_id": bid, "basis_type": "owner_declaration" if "owner_confirmed" in states else "source_reference", "object_id": contract["contract_id"],
            "role_ids": ["measurement"], "criterion_ids": contract["criterion_ids"], "journey_ids": [contract["journey_id"]],
            "field_state":"unresolved" if direct=="not_inspected" else ("owner_confirmed" if "owner_confirmed" in states else "source_declared"),
            "assertion_scope":"contract_declaration","direct_fact_authority": direct,
            "origin":"owner_declaration" if "owner_confirmed" in states else "product_intent",
            "reference_ids":[contract["contract_id"]],"allowed_relationships": ["supports_conclusion", "supports_warning"]}
    return sorted(registry.values(), key=lambda item: item["basis_id"]), sorted(paths, key=lambda item: item["path_id"])
