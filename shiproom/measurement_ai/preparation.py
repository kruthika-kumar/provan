from __future__ import annotations

import json
import re
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.project import canonical_json, content_hash

from .authority import (
    build_authority_input, build_basis_registry, domain_root, load_applicability_input,
    load_capabilities_input, prepared_contracts,
)
from .contracts import (
    PREPARATION_COMPILER_VERSION, PREPARATION_POINTER_SCHEMA, RECEIPT_SCHEMA,
    RESULT_SCHEMAS, REVIEW_MODES, ROLE_CONTEXT_SCHEMA, ROLE_VERSIONS, ROLES,
    SOURCE_PACKET_SCHEMA, WORK_ORDER_SCHEMA, WORK_ORDERS_SCHEMA, load_json_bytes,
    render_json, require_exact, sha256_bytes, stable_id, validate_relative_path, work_order_hash,
)
from .guidance import GUIDANCE_FILES, eligible_rule_ids, load_guidance_pack, load_guidance_pack_from_directory, rule_map
from .qualification import build_qualification_task, load_qualification_receipt, qualification_store
from .trust import exact_children, safe_entry, validate_ancestry


def _atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(render_json(value)); temporary.replace(path)


def _resource(package: str, name: str) -> dict:
    raw = resources.files(package).joinpath(name).read_bytes(); value = load_json_bytes(raw)
    return {"name": name, "bytes": raw, "value": value, "semantic_hash": content_hash(value), "snapshot_hash": sha256_bytes(raw)}


def _roles() -> dict[str, dict]:
    result = {}
    for role in ROLES:
        item = _resource("shiproom.measurement_ai_roles", role + ".v3.json")
        if item["value"].get("role_id") != role or item["value"].get("role_version") != ROLE_VERSIONS[role]:
            raise ValueError("invalid measurement AI role definition")
        result[role] = item
    return result


def _discovery() -> dict:
    return _resource("shiproom.measurement_ai_roles", "source-discovery.v1.json")


CONTRACT_NAMES = (
        "work-order.v6.json", "measurement-result.v3.json", "ai-evaluation-result.v3.json",
        "measurement-ai-source-packet.v3.json", "measurement-ai-role-context.v3.json",
        "measurement-ai-work-orders.v3.json", "measurement-ai-overlay.v3.json",
        "measurement-contract.v3.json", "instrumentation-coverage.v3.json",
        "measurement-ai-readiness.v3.json", "launch-measurement-plan.v3.json",
        "measurement-ai-compiler-receipts.v3.json", "portable-measurement-ai-manifest.v3.json",
        "measurement-verifier-preparation.v3.json", "measurement-verifier-work-order.v3.json",
        "measurement-verifier-result.v3.json", "measurement-ai-completion-receipt.v3.json",
        "measurement-reviewer-qualification-task.v3.json", "measurement-reviewer-qualification-result.v3.json",
        "measurement-reviewer-qualification-receipt.v3.json", "measurement-ai-capabilities.v3.json",
        "measurement-ai-applicability.v3.json", "measurement-review-capabilities.v3.json",
        "measurement-review-permission.v3.json", "measurement-ai-role.v3.json",
        "active-measurement-ai-preparation.v3.json", "current-portable-measurement-ai.v3.json",
)


def _contracts() -> dict[str, dict]:
    return {name: _resource("shiproom.measurement_ai_schemas", name) for name in CONTRACT_NAMES}


def _safe_entry(path:Path,directory:bool,label:str)->None:
    safe_entry(path,directory=directory,label=label)


def _read_safe(path:Path,label:str)->bytes:
    _safe_entry(path,False,label); return path.read_bytes()


def _owner_paths(values: list[str] | None) -> dict[str, list[str]]:
    result = {role: [] for role in ROLES}
    for value in values or []:
        if ":" not in value: raise ValueError("--path must use role:path")
        role, path = value.split(":", 1)
        if role not in result: raise ValueError("unknown measurement AI role path")
        result[role].append(validate_relative_path(path, "role path"))
    for role in result:
        if len(result[role]) != len(set(result[role])): raise ValueError("duplicate role path")
        result[role].sort()
    return result


def _review_resolution(requested: str, review_capabilities: dict | None, permission: dict | None,
                       repository_root:Path, guidance:dict, receipt_bundles:list[dict]|None=None) -> tuple[dict,list[dict]]:
    if requested not in REVIEW_MODES: raise ValueError("invalid measurement review mode")
    if review_capabilities is not None:
        if review_capabilities.get("executor_type")=="human":
            require_exact(review_capabilities,{"schema_version","executor_type","reviewer_label"},"human review capabilities")
        elif review_capabilities.get("executor_type")=="agent_harness":
            require_exact(review_capabilities,{"schema_version","executor_type","active_candidate_id","qualification_receipt_path","configured_candidates","fresh_session_supported","automatic_switch_allowed","cost_disclosure"},"model review capabilities")
            if review_capabilities["automatic_switch_allowed"] is not False: raise ValueError("automatic model switching is forbidden")
            for item in review_capabilities["configured_candidates"]: require_exact(item,{"candidate_id","provider_id","model_id","qualification_receipt_path"},"configured model candidate")
        else: raise ValueError("invalid review capability executor")
        if review_capabilities.get("schema_version")!="measurement-review-capabilities.v3": raise ValueError("invalid review capabilities version")
    if permission is not None:
        require_exact(permission,{"schema_version","release_id","expert_review_granted","model_switch"},"measurement review permission")
        if permission["schema_version"]!="measurement-review-permission.v3" or permission["release_id"] is None or not isinstance(permission["expert_review_granted"],bool): raise ValueError("invalid measurement review permission")
        if permission["model_switch"].get("decision") in {"not_requested","declined"}: require_exact(permission["model_switch"],{"decision"},"model switch decision")
        elif permission["model_switch"].get("decision")=="granted":
            require_exact(permission["model_switch"],{"decision","candidate_id","provider_id","model_id","fresh_session_granted"},"model switch grant")
            if permission["model_switch"]["fresh_session_granted"] is not True: raise ValueError("model switch requires a fresh-session grant")
        else: raise ValueError("invalid model switch decision")
    if requested == "contract_only": return {"requested":requested,"resolved":"contract_only","reason":"requested_contract_only","participants":[]},[]
    # A human may complete guided review using the bound pack without model qualification.
    if review_capabilities and review_capabilities.get("executor_type") == "human":
        if requested == "expert_escalated_review" and not (permission or {}).get("expert_review_granted", False):
            return {"requested":requested,"resolved":"contract_only","reason":"expert_permission_not_granted","participants":[]},[]
        return {"requested":requested,"resolved":requested,"reason":"guided_human_reviewer","participants":[{"type":"human"}]},[]
    if review_capabilities and review_capabilities.get("executor_type")=="agent_harness":
        task=build_qualification_task(guidance); chosen=None; switched=False; chosen_candidate=None
        supplied={item["value"]["qualification_id"]:item for item in (receipt_bundles or [])}
        receipt_path=review_capabilities.get("qualification_receipt_path")
        if receipt_path:
            active_id=review_capabilities.get("active_candidate_id")
            chosen_candidate=next((item for item in review_capabilities.get("configured_candidates",[]) if item.get("candidate_id")==active_id),None)
            try:
                if receipt_bundles is not None:
                    chosen=next((item for item in supplied.values() if chosen_candidate and item["value"]["provider_id"]==chosen_candidate["provider_id"] and item["value"]["model_id"]==chosen_candidate["model_id"]),None)
                else:
                    candidate=Path(receipt_path); candidate=candidate if candidate.is_absolute() else repository_root/candidate
                    validate_ancestry(qualification_store(repository_root),candidate,directory=False,label="qualification receipt")
                    chosen=load_qualification_receipt(candidate,task)
            except (ValueError,OSError): chosen=None
        if chosen is None:
            granted=(permission or {}).get("model_switch",{}).get("decision")=="granted"
            candidate_id=(permission or {}).get("model_switch",{}).get("candidate_id")
            candidate=next((item for item in review_capabilities.get("configured_candidates",[]) if item.get("candidate_id")==candidate_id),None)
            if granted and candidate and review_capabilities.get("fresh_session_supported"):
                grant=permission["model_switch"]
                if (grant["provider_id"],grant["model_id"])!=(candidate["provider_id"],candidate["model_id"]): raise ValueError("model-switch permission candidate identity mismatch")
                try:
                    if receipt_bundles is not None:
                        chosen=next((item for item in supplied.values() if item["value"]["provider_id"]==candidate["provider_id"] and item["value"]["model_id"]==candidate["model_id"]),None)
                    else:
                        path=Path(candidate["qualification_receipt_path"]); path=path if path.is_absolute() else repository_root/path
                        validate_ancestry(qualification_store(repository_root),path,directory=False,label="qualification receipt")
                        chosen=load_qualification_receipt(path,task)
                    chosen_candidate=candidate; switched=True
                except (ValueError,OSError): chosen=None
        if chosen is not None:
            if chosen_candidate is None or (chosen["value"]["provider_id"],chosen["value"]["model_id"])!=(chosen_candidate["provider_id"],chosen_candidate["model_id"]): raise ValueError("qualification receipt candidate identity mismatch")
            if requested=="expert_escalated_review" and not (permission or {}).get("expert_review_granted",False): return {"requested":requested,"resolved":"contract_only","reason":"expert_permission_not_granted","participants":[]},[]
            participant={"type":"model","candidate_id":chosen_candidate["candidate_id"],"provider_id":chosen["value"]["provider_id"],"model_id":chosen["value"]["model_id"],"qualification_id":chosen["value"]["qualification_id"],"qualification_snapshot_hash":chosen["snapshot_hash"],"qualified_capabilities":chosen["value"]["qualified_capabilities"],"model_switch":switched}
            return {"requested":requested,"resolved":requested,"reason":"qualified_model_participant","participants":[participant]},[chosen]
    return {"requested":requested,"resolved":"contract_only","reason":"no_qualified_model_participant","participants":[]},[]


def _assigned(authority: dict, role: str) -> dict:
    scope = authority["role_scopes"][role]
    criterion_ids = sorted(set(scope["applicable_criterion_ids"] + scope["candidate_criterion_ids"]))
    criteria = [item for item in authority["criteria"] if item["criterion_id"] in criterion_ids]
    requirement_ids = sorted({item["requirement_id"] for item in criteria})
    journey_ids = sorted({item["journey_id"] for item in authority.get("linked_measurement_definitions", []) for _ in [0]} | ({item["node_id"] for item in authority["journeys"]} if role == "measurement" and criterion_ids else set()))
    return {"requirement_ids":requirement_ids,"criterion_ids":criterion_ids,"journey_ids":journey_ids}


def _issue_role(authority: dict, role: str) -> bool:
    scope = authority["role_scopes"][role]
    return bool(scope["applicable_criterion_ids"] or scope["candidate_criterion_ids"])


def _required_qualification_capabilities(issued:list[str],prepared:list[dict],guidance:dict)->dict[str,list[str]]:
    required={role:set() for role in ROLES}
    if "measurement" in issued:
        required["measurement"].update({"contract_structure","metric_decision_alignment"})
        rules=rule_map(guidance)
        for contract in prepared:
            facts={"contract."+name:field for name,field in contract["fields"].items()}
            numerator=contract["fields"]["numerator"]["value"]; denominator=contract["fields"]["denominator"]["value"]
            facts["metric.form"]="ratio" if numerator is not None and denominator is not None else "absolute_count" if numerator is not None else None
            for rule_id in eligible_rule_ids(guidance,facts):
                # Measurement preparation evaluates only measurement guidance.
                # AI rules intentionally use absent/not-equals predicates and
                # would otherwise make an unrelated measurement packet demand
                # AI-review capabilities.
                if rule_id.startswith("MEAS_"):
                    required["measurement"].add(rules[rule_id]["qualified_capability"])
    if "ai_evaluation" in issued: required["ai_evaluation"].update({"ai_eval_structure","ai_claim_authority_review"})
    return {role:sorted(values) for role,values in required.items()}


def _intent_requirement(item:dict)->dict:
    keys=("requirement_id","statement","classification","status","source_refs","claim_ids","related_journey_ids","materiality","rationale","owner_confirmation_required","ambiguity_dependencies")
    return {key:item[key] for key in keys}


def _intent_criterion(item:dict)->dict:
    keys=("criterion_id","requirement_id","actor","preconditions","action","expected_outcomes","failure_behavior","required_evidence_categories","source_refs","field_source_refs","classification","confirmation_state","blocker_eligible","candidate_blocker_after_confirmation","ambiguity_dependencies")
    return {key:item[key] for key in keys}


def _graph_node(item:dict)->dict:
    return {"node_id":item["node_id"],"node_type":item["node_type"],"provenance":item["provenance"],"criterion_id":item.get("criterion_id"),"requirement_id":item.get("requirement_id"),"classification":item.get("classification"),"confirmation_state":item.get("confirmation_state"),"action":item.get("action"),"expected_outcomes":item.get("expected_outcomes",[]),"finding_id":item.get("canonical_finding_id"),"status":item.get("status"),"url":item.get("url"),"http_status":item.get("http_status"),"command_id":item.get("command_id"),"test_id":item.get("test_id"),"path":item.get("path"),"quote":item.get("quote"),"line_start":item.get("line_start"),"line_end":item.get("line_end")}


def _graph_edge(item:dict)->dict:
    return {key:item[key] for key in ("edge_id","source_node_id","target_node_id","relationship","establishment_classification","rationale","origin","references")}


def _graph_gap(item:dict)->dict:
    return {"gap_id":item["gap_id"],"criterion_id":item["criterion_id"],"gap_type":item["gap_type"],"state":item["state"],"basis_node_ids":item["basis_node_ids"],"basis_edge_ids":item["basis_edge_ids"],"evidence_needed":item["evidence_needed"],"linked_canonical_finding_ids":item["linked_canonical_finding_ids"],"product_intent_ambiguity_ids":item["product_intent_ambiguity_ids"],"candidate_linked_failure":item.get("candidate_linked_failure",False)}


def _build(ctx: LocalExecutionContext, preparation_id: str, *, capabilities_bundle: dict, applicability_bundle: dict,
           owner_paths: dict, review: dict, review_inputs:dict, roles: dict, discovery: dict, contracts: dict, guidance: dict,
           assessment_dependency:dict|None=None) -> dict:
    authority = build_authority_input(ctx, applicability_bundle["value"], owner_paths)
    if assessment_dependency is not None:
        if assessment_dependency.get("state")=="not_used": authority["assessment_dependency"]={"state":"not_used","generation":None,"semantic_hash":None}
        elif authority["assessment_dependency"]!=assessment_dependency: raise ValueError("consumed portable assessment dependency is stale")
    prepared = prepared_contracts(authority, applicability_bundle["value"])
    basis_registry, basis_paths = build_basis_registry(authority, prepared)
    issued = [role for role in ROLES if _issue_role(authority, role)]
    required_by_role=_required_qualification_capabilities(issued,prepared,guidance)
    model_participants=[item for item in review.get("participants",[]) if item.get("type")=="model"]
    required=sorted({cap for role in issued for cap in required_by_role[role]}) if review["resolved"]!="contract_only" else []
    if model_participants and any(not set(required).issubset(set(item.get("qualified_capabilities",[]))) for item in model_participants):
        review={"requested":review["requested"],"resolved":"contract_only","reason":"qualification_capabilities_incomplete","participants":[]}; required=[]
    skip_reason = None if issued else "no_applicable_measurement_or_ai_surface"
    semantic_basis = {
        "compiler_version":PREPARATION_COMPILER_VERSION,"release_id":ctx.release["release_id"],
        "release_commit":ctx.authority_binding["repository_commit"],
        "product_intent_semantic_hash":authority["graph_input"]["intent_manifest"]["semantic_bundle_hash"],
        "graph_generation":authority["graph_input"]["graph_generation"],
        "graph_semantic_hash":authority["graph_input"]["graph_manifest"]["semantic_bundle_hash"],
        "assessment_dependency":authority["assessment_dependency"],"capabilities":capabilities_bundle["value"],
        "applicability":applicability_bundle["value"],"owner_paths":owner_paths,"review":review,
        "review_inputs":review_inputs,
        "role_hashes":{role:roles[role]["semantic_hash"] for role in ROLES},
        "discovery_hash":discovery["semantic_hash"],"guidance_hash":guidance["pack_hash"],
        "policy_hash":guidance["snapshots"]["recommendation-policy.v2.json"]["semantic_hash"],"contract_hashes":{name:item["semantic_hash"] for name,item in contracts.items()},
        "role_scopes":authority["role_scopes"],"role_sources":authority["role_sources"],"prepared_contracts":prepared,
        "basis_registry":basis_registry,"basis_paths":basis_paths,
        "issued_roles":issued,"skip_reason":skip_reason,
    }
    semantic_hash = content_hash(semantic_basis)
    source_packet = {
        "schema_version":SOURCE_PACKET_SCHEMA,"compiler_version":PREPARATION_COMPILER_VERSION,
        "preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],
        "release_commit":ctx.authority_binding["repository_commit"],"product_intent_semantic_hash":semantic_basis["product_intent_semantic_hash"],
        "graph_generation":semantic_basis["graph_generation"],"graph_semantic_hash":semantic_basis["graph_semantic_hash"],
        "assessment_dependency":authority["assessment_dependency"],"role_scopes":authority["role_scopes"],
        "role_sources":authority["role_sources"],"prepared_measurement_contracts":prepared,"basis_registry":basis_registry,"basis_paths":basis_paths,"review_resolution":review,
        "coverage_boundary":"Commit-pinned bounded measurement and AI sources plus validated Product Intent and Requirement-to-Evidence Graph.",
        "skip_reason":skip_reason,"packet_hash":"",
    }
    source_packet["packet_hash"] = content_hash({k:v for k,v in source_packet.items() if k != "packet_hash"})
    contexts = {}; work_orders = {}
    for role in issued:
        assigned = _assigned(authority, role); sources = authority["role_sources"][role]
        context = {
            "schema_version":ROLE_CONTEXT_SCHEMA,"preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,
            "role_id":role,"role_version":ROLE_VERSIONS[role],"release_id":ctx.release["release_id"],
            "release_commit":ctx.authority_binding["repository_commit"],"assigned":assigned,"scope":authority["role_scopes"][role],
            "requirements":[_intent_requirement(item) for item in authority["requirements"] if item["requirement_id"] in assigned["requirement_ids"]],
            "criteria":[_intent_criterion(item) for item in authority["criteria"] if item["criterion_id"] in assigned["criterion_ids"]],
            "journeys":[item for item in authority["journeys"] if item["node_id"] in assigned["journey_ids"]],
            "graph_context":{"nodes":[],"edges":[],"gaps":[]},"sources":sources["sources"],"source_coverage":sources["coverage"],
            "limitations":sources["limitations"],"prepared_measurement_contracts":prepared if role == "measurement" else [],
            "basis_registry":[item for item in basis_registry if role in item["role_ids"]],
            "basis_paths":[item for item in basis_paths if role in item["role_ids"]],
        "review_resolution":review,"guidance_registry_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v2.json"]["semantic_hash"],"packet_hash":"",
        }
        # Referentially closed two-hop graph context around assigned criteria.
        graph = authority["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]
        selected = set(assigned["criterion_ids"] + assigned["requirement_ids"] + assigned["journey_ids"])
        for _ in range(2):
            for edge in graph["edges"]:
                if edge["source_node_id"] in selected or edge["target_node_id"] in selected:
                    selected.update((edge["source_node_id"],edge["target_node_id"]))
        context["graph_context"]["nodes"] = [_graph_node(item) for item in graph["nodes"] if item["node_id"] in selected]
        context["graph_context"]["edges"] = [_graph_edge(item) for item in graph["edges"] if item["source_node_id"] in selected and item["target_node_id"] in selected]
        edge_ids={item["edge_id"] for item in context["graph_context"]["edges"]}; node_ids={item["node_id"] for item in context["graph_context"]["nodes"]}
        context["graph_context"]["gaps"]=[_graph_gap(item) for item in authority["graph_input"]["graph_artifacts"]["evidence-gaps.json"]["gaps"] if item["criterion_id"] in assigned["criterion_ids"] and set(item["basis_node_ids"]).issubset(node_ids) and set(item["basis_edge_ids"]).issubset(edge_ids)]
        context["packet_hash"] = content_hash({k:v for k,v in context.items() if k != "packet_hash"}); contexts[role]=context
        wid = "wo_" + role + "_" + content_hash({"semantic":semantic_hash,"role":role,"assigned":assigned}).split(":",1)[1][:16]
        result_name = RESULT_SCHEMAS[role] + ".json"; result_contract=contracts[result_name]; receipt_contract=contracts["measurement-ai-completion-receipt.v3.json"]
        root_rel=f".shiproom/local/releases/{ctx.release['release_id']}/measurement-ai-readiness"
        work={
            "schema_version":WORK_ORDER_SCHEMA,"work_order_id":wid,"work_order_hash":"","preparation_id":preparation_id,
            "preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],
            "role_id":role,"role_version":ROLE_VERSIONS[role],"role_definition_hash":roles[role]["semantic_hash"],"role_definition_snapshot_hash":roles[role]["snapshot_hash"],
            "objective":roles[role]["value"]["mandate"],"requested_review_mode":review["requested"],"resolved_review_mode":review["resolved"],
            "inputs":{"packet_path":f"preparations/{preparation_id}/role-context/{role}.json","packet_hash":context["packet_hash"],**assigned,"surface_ids":[],"allowed_paths":[item["path"] for item in sources["sources"]],"product_intent_semantic_hash":semantic_basis["product_intent_semantic_hash"],"graph_semantic_hash":semantic_basis["graph_semantic_hash"],"assessment_dependency":authority["assessment_dependency"]["state"],"basis_registry_hash":content_hash(context["basis_registry"])},
            "capability_requirements":{"file_read":"required","shell":"unavailable","browser":"unavailable","network":"unavailable"},
            "permissions":{"repository":"read_only","allowed_paths":[item["path"] for item in sources["sources"]],"allowed_commands":[]},
            "required_output":{"schema_path":"contract-schemas/"+result_name,"schema_version":RESULT_SCHEMAS[role],"schema_semantic_hash":result_contract["semantic_hash"],"schema_snapshot_hash":result_contract["snapshot_hash"],"output_path":f"{root_rel}/inbox/{preparation_id}/{wid}/result.json","completion_receipt_schema_path":"contract-schemas/measurement-ai-completion-receipt.v3.json","completion_receipt_schema_version":RECEIPT_SCHEMA,"completion_receipt_schema_semantic_hash":receipt_contract["semantic_hash"],"completion_receipt_schema_snapshot_hash":receipt_contract["snapshot_hash"],"completion_receipt_path":f"{root_rel}/inbox/{preparation_id}/{wid}/completion-receipt.json"},
            "required_qualification_capabilities":required_by_role[role] if review["resolved"]!="contract_only" and model_participants else [],"qualification_receipt_hashes":[item["qualification_snapshot_hash"] for item in model_participants],
            "review_participants":review["participants"],
            "forbidden_claims":roles[role]["value"]["forbidden_claims"],
        }
        work["work_order_hash"]=work_order_hash(work); work_orders[role]=work
    entries=[]
    for role,work in work_orders.items(): entries.append({"role_id":role,"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"snapshot_hash":sha256_bytes(render_json(work))})
    manifest={"schema_version":WORK_ORDERS_SCHEMA,"compiler_version":PREPARATION_COMPILER_VERSION,"preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"issued_roles":issued,"skip_reason":skip_reason,"source_packet_hash":source_packet["packet_hash"],"capabilities_hash":content_hash(capabilities_bundle["value"]),"applicability_hash":content_hash(applicability_bundle["value"]),"review_inputs_hash":content_hash(review_inputs),"role_definition_hashes":semantic_basis["role_hashes"],"discovery_hash":discovery["semantic_hash"],"guidance_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v2.json"]["semantic_hash"],"contract_schema_hashes":semantic_basis["contract_hashes"],"work_orders":entries,"manifest_hash":""}
    manifest["manifest_hash"]=content_hash({k:v for k,v in manifest.items() if k != "manifest_hash"})
    pointer={"schema_version":PREPARATION_POINTER_SCHEMA,"preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"manifest_snapshot_hash":sha256_bytes(render_json(manifest))}
    return {"authority":authority,"source_packet":source_packet,"contexts":contexts,"work_orders":work_orders,"manifest":manifest,"pointer":pointer,"semantic_basis":semantic_basis}


def prepare(ctx: LocalExecutionContext, *, review_mode: str="contract_only", capabilities_path: str|None=None,
            applicability_path: str|None=None, review_capabilities: dict|None=None, permission: dict|None=None,
            owner_paths: list[str]|None=None) -> dict:
    ctx.require("file.read"); prep_id="prep_"+uuid.uuid4().hex
    capabilities=load_capabilities_input(ctx,capabilities_path); applicability=load_applicability_input(ctx,applicability_path)
    roles=_roles(); discovery=_discovery(); contracts=_contracts(); guidance=load_guidance_pack()
    if permission is not None and permission.get("release_id")!=ctx.release["release_id"]: raise ValueError("measurement review permission release binding mismatch")
    review,receipts=_review_resolution(review_mode,review_capabilities,permission,ctx.repository_root,guidance)
    review_inputs={"requested_mode":review_mode,"review_capabilities":review_capabilities,"permission":permission,"qualification_receipt_hashes":sorted(item["snapshot_hash"] for item in receipts)}
    expected=_build(ctx,prep_id,capabilities_bundle=capabilities,applicability_bundle=applicability,owner_paths=_owner_paths(owner_paths),review=review,review_inputs=review_inputs,roles=roles,discovery=discovery,contracts=contracts,guidance=guidance)
    root=domain_root(ctx); directory=root/"preparations"/prep_id; directory.mkdir(parents=True)
    _atomic(directory/"preparation-inputs.json",{"owner_paths":_owner_paths(owner_paths),"review_inputs":review_inputs,"review_resolution":review,"assessment_dependency":expected["source_packet"]["assessment_dependency"]})
    receipt_root=directory/"qualification-receipts"; receipt_root.mkdir()
    for item in receipts: (receipt_root/(item["value"]["qualification_id"]+".json")).write_bytes(item["bytes"])
    (directory/"capabilities.json").write_bytes(capabilities["bytes"]); (directory/"applicability.json").write_bytes(applicability["bytes"])
    _atomic(directory/"measurement-ai-source-packet.json",expected["source_packet"]); _atomic(directory/"measurement-ai-work-orders.json",expected["manifest"])
    (directory/"source-discovery.v1.json").write_bytes(discovery["bytes"])
    for role,item in roles.items(): p=directory/"role-definitions"/(role+".json"); p.parent.mkdir(exist_ok=True); p.write_bytes(item["bytes"])
    for name,item in contracts.items(): p=directory/"contract-schemas"/name; p.parent.mkdir(exist_ok=True); p.write_bytes(item["bytes"])
    for name in ("guidance-registry.v2.json","sources.v1.json","recommendation-policy.v2.json","qualification-suite.v2.json","metric-design.v1.md","experimentation.v1.md","ai-evaluation.v1.md"):
        p=directory/"guidance-pack"/name; p.parent.mkdir(exist_ok=True); p.write_bytes(resources.files("shiproom.measurement_guidance").joinpath(name).read_bytes())
    (directory/"role-context").mkdir(exist_ok=True); (directory/"work-orders").mkdir(exist_ok=True)
    for role,context in expected["contexts"].items(): _atomic(directory/"role-context"/(role+".json"),context)
    for role,work in expected["work_orders"].items():
        p=directory/"work-orders"/(work["work_order_id"]+".json"); _atomic(p,work); (root/"inbox"/prep_id/work["work_order_id"]).mkdir(parents=True,exist_ok=True)
    _atomic(root/"active-preparation.json",expected["pointer"])
    return {"preparation_id":prep_id,"preparation_semantic_hash":expected["manifest"]["preparation_semantic_hash"],"skip_reason":expected["manifest"]["skip_reason"],"work_orders":expected["manifest"]["work_orders"],"resolved_review_mode":expected["semantic_basis"]["review"]["resolved"]}


def load_preparation(ctx: LocalExecutionContext, preparation_id: str|None=None, *, directory: Path|None=None) -> dict:
    root=domain_root(ctx); pointer=None
    if directory is None and preparation_id is None:
        p=root/"active-preparation.json"
        try: pointer=load_json_bytes(_read_safe(p,"active measurement AI preparation pointer"))
        except FileNotFoundError as exc: raise ValueError("active measurement AI preparation unavailable") from exc
        preparation_id=pointer.get("preparation_id")
    if not isinstance(preparation_id,str) or not re.fullmatch(r"prep_[0-9a-f]{32}",preparation_id): raise ValueError("invalid measurement AI preparation ID")
    directory=directory or root/"preparations"/preparation_id
    validate_ancestry(root,directory,directory=True,label="measurement AI preparation directory")
    stored=load_json_bytes(_read_safe(directory/"measurement-ai-work-orders.json","preparation manifest"))
    if stored.get("compiler_version") != PREPARATION_COMPILER_VERSION: raise ValueError("stale_measurement_ai_preparation_compiler_version: create a new v3 preparation; automatic migration is unavailable")
    inputs=load_json_bytes(_read_safe(directory/"preparation-inputs.json","preparation inputs")); cap_raw=_read_safe(directory/"capabilities.json","capabilities"); app_raw=_read_safe(directory/"applicability.json","applicability"); capabilities={"value":load_json_bytes(cap_raw),"bytes":cap_raw}; applicability={"value":load_json_bytes(app_raw),"bytes":app_raw}
    role_root=directory/"role-definitions"; _safe_entry(role_root,True,"role definitions"); expected_role_files={role+".json" for role in ROLES}
    if {p.name for p in role_root.iterdir()}!=expected_role_files: raise ValueError("role definition snapshot set is invalid")
    roles={role:_resource_from_bytes(role+".json",_read_safe(role_root/(role+".json"),"role definition")) for role in ROLES}
    discovery=_resource_from_bytes("source-discovery.v1.json",_read_safe(directory/"source-discovery.v1.json","source discovery registry"))
    contract_root=directory/"contract-schemas"; _safe_entry(contract_root,True,"contract schema directory"); expected_contracts=set(CONTRACT_NAMES)
    if {p.name for p in contract_root.iterdir()}!=expected_contracts: raise ValueError("contract schema snapshot set is invalid")
    contracts={name:_resource_from_bytes(name,_read_safe(contract_root/name,"contract schema")) for name in sorted(expected_contracts)}
    guidance_root=directory/"guidance-pack"; _safe_entry(guidance_root,True,"guidance pack")
    if {p.name for p in guidance_root.iterdir()}!=set(GUIDANCE_FILES): raise ValueError("guidance snapshot set is invalid")
    for name in GUIDANCE_FILES: _safe_entry(guidance_root/name,False,"guidance resource")
    guidance=load_guidance_pack_from_directory(guidance_root)
    receipt_root=directory/"qualification-receipts"; _safe_entry(receipt_root,True,"qualification receipt snapshots")
    task=build_qualification_task(guidance); receipt_bundles=[]
    for path in sorted(receipt_root.iterdir(),key=lambda item:item.name):
        if not path.name.endswith(".json"): raise ValueError("qualification receipt snapshot set is invalid")
        receipt_bundles.append(load_qualification_receipt(path,task))
    review_inputs=inputs["review_inputs"]
    if review_inputs["permission"] is not None and review_inputs["permission"].get("release_id")!=ctx.release["release_id"]: raise ValueError("measurement review permission release binding mismatch")
    review,_used=_review_resolution(review_inputs["requested_mode"],review_inputs["review_capabilities"],review_inputs["permission"],ctx.repository_root,guidance,receipt_bundles)
    if sorted(item["snapshot_hash"] for item in _used)!=review_inputs["qualification_receipt_hashes"] or review!=inputs["review_resolution"]: raise ValueError("measurement review resolution semantic rederivation failed")
    expected=_build(ctx,preparation_id,capabilities_bundle=capabilities,applicability_bundle=applicability,owner_paths=inputs["owner_paths"],review=review,review_inputs=review_inputs,roles=roles,discovery=discovery,contracts=contracts,guidance=guidance,assessment_dependency=inputs["assessment_dependency"])
    if stored != expected["manifest"] or (directory/"measurement-ai-work-orders.json").read_bytes()!=render_json(expected["manifest"]):
        differing=sorted(key for key in set(stored)|set(expected["manifest"]) if stored.get(key)!=expected["manifest"].get(key))
        raise ValueError("measurement AI preparation semantic rederivation failed: "+",".join(differing))
    if _read_safe(directory/"measurement-ai-source-packet.json","source packet")!=render_json(expected["source_packet"]): raise ValueError("measurement AI source packet semantic rederivation failed")
    expected_files={role+".json" for role in expected["contexts"]}; context_root=directory/"role-context"; _safe_entry(context_root,True,"role context directory"); actual={p.name for p in context_root.iterdir()}
    if actual != expected_files: raise ValueError("measurement AI role context set mismatch")
    for role,context in expected["contexts"].items():
        if _read_safe(context_root/(role+".json"),"role context")!=render_json(context): raise ValueError("measurement AI role context semantic rederivation failed")
    work_root=directory/"work-orders"; _safe_entry(work_root,True,"work-order directory"); actual_work={p.name for p in work_root.iterdir()}; expected_work={w["work_order_id"]+".json" for w in expected["work_orders"].values()}
    if actual_work != expected_work: raise ValueError("measurement AI work-order set mismatch")
    for work in expected["work_orders"].values():
        if _read_safe(work_root/(work["work_order_id"]+".json"),"work order")!=render_json(work): raise ValueError("measurement AI work order semantic rederivation failed")
    expected_top={"preparation-inputs.json","capabilities.json","applicability.json","measurement-ai-source-packet.json","measurement-ai-work-orders.json","source-discovery.v1.json","role-definitions","contract-schemas","guidance-pack","qualification-receipts","role-context","work-orders"}
    if {p.name for p in directory.iterdir()}!=expected_top: raise ValueError("measurement AI preparation file set mismatch")
    if pointer is not None and pointer != expected["pointer"]: raise ValueError("measurement AI preparation pointer binding is stale")
    return {"directory":directory,**expected,"contracts":contracts,"guidance":guidance,"capabilities":capabilities["value"],"applicability":applicability["value"]}


def _resource_from_bytes(name: str, raw: bytes) -> dict:
    value=load_json_bytes(raw); return {"name":name,"bytes":raw,"value":value,"semantic_hash":content_hash(value),"snapshot_hash":sha256_bytes(raw)}
