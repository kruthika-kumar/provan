from __future__ import annotations

import json
import re
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.project import canonical_json, content_hash

from .authority import (
    build_authority_input, domain_root, load_applicability_input,
    load_capabilities_input, prepared_contracts,
)
from .contracts import (
    PREPARATION_COMPILER_VERSION, PREPARATION_POINTER_SCHEMA, RECEIPT_SCHEMA,
    RESULT_SCHEMAS, REVIEW_MODES, ROLE_CONTEXT_SCHEMA, ROLE_VERSIONS, ROLES,
    SOURCE_PACKET_SCHEMA, WORK_ORDER_SCHEMA, WORK_ORDERS_SCHEMA, load_json_bytes,
    render_json, sha256_bytes, stable_id, validate_relative_path, work_order_hash,
)
from .guidance import load_guidance_pack


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
        item = _resource("shiproom.measurement_ai_roles", role + ".json")
        if item["value"].get("role_id") != role or item["value"].get("role_version") != ROLE_VERSIONS[role]:
            raise ValueError("invalid measurement AI role definition")
        result[role] = item
    return result


def _discovery() -> dict:
    return _resource("shiproom.measurement_ai_roles", "source-discovery.v1.json")


def _contracts() -> dict[str, dict]:
    result = {
        "work-order.v4.json": _resource("shiproom.measurement_ai_schemas", "work-order.v4.json"),
        "measurement-result.v1.json": _resource("shiproom.measurement_ai_schemas", "measurement-result.v1.json"),
        "ai-evaluation-result.v1.json": _resource("shiproom.measurement_ai_schemas", "ai-evaluation-result.v1.json"),
        "assessment-completion-receipt.v2.json": _resource("shiproom.assessment_schemas", "assessment-completion-receipt.v2.json"),
    }
    return result


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


def _review_resolution(requested: str, review_capabilities: dict | None, permission: dict | None) -> dict:
    if requested not in REVIEW_MODES: raise ValueError("invalid measurement review mode")
    if requested == "contract_only": return {"requested":requested,"resolved":"contract_only","reason":"requested_contract_only","participants":[]}
    # A human may complete guided review using the bound pack without model qualification.
    if review_capabilities and review_capabilities.get("executor_type") == "human":
        if requested == "expert_escalated_review" and not (permission or {}).get("expert_review_granted", False):
            return {"requested":requested,"resolved":"contract_only","reason":"expert_permission_not_granted","participants":[]}
        return {"requested":requested,"resolved":requested,"reason":"guided_human_reviewer","participants":[{"type":"human"}]}
    return {"requested":requested,"resolved":"contract_only","reason":"no_qualified_model_participant","participants":[]}


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


def _build(ctx: LocalExecutionContext, preparation_id: str, *, capabilities_bundle: dict, applicability_bundle: dict,
           owner_paths: dict, review: dict, roles: dict, discovery: dict, contracts: dict, guidance: dict) -> dict:
    authority = build_authority_input(ctx, applicability_bundle["value"], owner_paths)
    prepared = prepared_contracts(authority, applicability_bundle["value"])
    issued = [role for role in ROLES if _issue_role(authority, role)]
    skip_reason = None if issued else "no_applicable_measurement_or_ai_surface"
    semantic_basis = {
        "compiler_version":PREPARATION_COMPILER_VERSION,"release_id":ctx.release["release_id"],
        "release_commit":ctx.authority_binding["repository_commit"],
        "product_intent_semantic_hash":authority["graph_input"]["intent_manifest"]["semantic_bundle_hash"],
        "graph_generation":authority["graph_input"]["graph_generation"],
        "graph_semantic_hash":authority["graph_input"]["graph_manifest"]["semantic_bundle_hash"],
        "assessment_dependency":authority["assessment_dependency"],"capabilities":capabilities_bundle["value"],
        "applicability":applicability_bundle["value"],"owner_paths":owner_paths,"review":review,
        "role_hashes":{role:roles[role]["semantic_hash"] for role in ROLES},
        "discovery_hash":discovery["semantic_hash"],"guidance_hash":guidance["pack_hash"],
        "policy_hash":guidance["snapshots"]["recommendation-policy.v1.json"]["semantic_hash"],"contract_hashes":{name:item["semantic_hash"] for name,item in contracts.items()},
        "role_scopes":authority["role_scopes"],"role_sources":authority["role_sources"],"prepared_contracts":prepared,
        "issued_roles":issued,"skip_reason":skip_reason,
    }
    semantic_hash = content_hash(semantic_basis)
    source_packet = {
        "schema_version":SOURCE_PACKET_SCHEMA,"compiler_version":PREPARATION_COMPILER_VERSION,
        "preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],
        "release_commit":ctx.authority_binding["repository_commit"],"product_intent_semantic_hash":semantic_basis["product_intent_semantic_hash"],
        "graph_generation":semantic_basis["graph_generation"],"graph_semantic_hash":semantic_basis["graph_semantic_hash"],
        "assessment_dependency":authority["assessment_dependency"],"role_scopes":authority["role_scopes"],
        "role_sources":authority["role_sources"],"prepared_measurement_contracts":prepared,"review_resolution":review,
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
            "requirements":[item for item in authority["requirements"] if item["requirement_id"] in assigned["requirement_ids"]],
            "criteria":[item for item in authority["criteria"] if item["criterion_id"] in assigned["criterion_ids"]],
            "journeys":[item for item in authority["journeys"] if item["node_id"] in assigned["journey_ids"]],
            "graph_context":{"nodes":[],"edges":[],"gaps":[]},"sources":sources["sources"],"source_coverage":sources["coverage"],
            "limitations":sources["limitations"],"prepared_measurement_contracts":prepared if role == "measurement" else [],
            "review_resolution":review,"guidance_registry_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v1.json"]["semantic_hash"],"packet_hash":"",
        }
        # Referentially closed two-hop graph context around assigned criteria.
        graph = authority["graph_input"]["graph_artifacts"]["requirement-evidence-graph.json"]
        selected = set(assigned["criterion_ids"] + assigned["requirement_ids"] + assigned["journey_ids"])
        for _ in range(2):
            for edge in graph["edges"]:
                if edge["source_node_id"] in selected or edge["target_node_id"] in selected:
                    selected.update((edge["source_node_id"],edge["target_node_id"]))
        context["graph_context"]["nodes"] = [item for item in graph["nodes"] if item["node_id"] in selected]
        context["graph_context"]["edges"] = [item for item in graph["edges"] if item["source_node_id"] in selected and item["target_node_id"] in selected]
        edge_ids={item["edge_id"] for item in context["graph_context"]["edges"]}; node_ids={item["node_id"] for item in context["graph_context"]["nodes"]}
        context["graph_context"]["gaps"]=[item for item in authority["graph_input"]["graph_artifacts"]["evidence-gaps.json"]["gaps"] if item["criterion_id"] in assigned["criterion_ids"] and set(item["basis_node_ids"]).issubset(node_ids) and set(item["basis_edge_ids"]).issubset(edge_ids)]
        context["packet_hash"] = content_hash({k:v for k,v in context.items() if k != "packet_hash"}); contexts[role]=context
        wid = "wo_" + role + "_" + content_hash({"semantic":semantic_hash,"role":role,"assigned":assigned}).split(":",1)[1][:16]
        result_name = RESULT_SCHEMAS[role] + ".json"; result_contract=contracts[result_name]; receipt_contract=contracts["assessment-completion-receipt.v2.json"]
        root_rel=f".shiproom/local/releases/{ctx.release['release_id']}/measurement-ai-readiness"
        work={
            "schema_version":WORK_ORDER_SCHEMA,"work_order_id":wid,"work_order_hash":"","preparation_id":preparation_id,
            "preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],
            "role_id":role,"role_version":ROLE_VERSIONS[role],"role_definition_hash":roles[role]["semantic_hash"],"role_definition_snapshot_hash":roles[role]["snapshot_hash"],
            "objective":roles[role]["value"]["mandate"],"requested_review_mode":review["requested"],"resolved_review_mode":review["resolved"],
            "inputs":{"packet_path":f"preparations/{preparation_id}/role-context/{role}.json","packet_hash":context["packet_hash"],**assigned,"surface_ids":[],"allowed_paths":[item["path"] for item in sources["sources"]],"product_intent_semantic_hash":semantic_basis["product_intent_semantic_hash"],"graph_semantic_hash":semantic_basis["graph_semantic_hash"],"assessment_dependency":authority["assessment_dependency"]["state"]},
            "capability_requirements":{"file_read":"required","shell":"unavailable","browser":"unavailable","network":"unavailable"},
            "permissions":{"repository":"read_only","allowed_paths":[item["path"] for item in sources["sources"]],"allowed_commands":[]},
            "required_output":{"schema_path":"contract-schemas/"+result_name,"schema_version":RESULT_SCHEMAS[role],"schema_semantic_hash":result_contract["semantic_hash"],"schema_snapshot_hash":result_contract["snapshot_hash"],"output_path":f"{root_rel}/inbox/{preparation_id}/{wid}/result.json","completion_receipt_schema_path":"contract-schemas/assessment-completion-receipt.v2.json","completion_receipt_schema_version":RECEIPT_SCHEMA,"completion_receipt_schema_semantic_hash":receipt_contract["semantic_hash"],"completion_receipt_schema_snapshot_hash":receipt_contract["snapshot_hash"],"completion_receipt_path":f"{root_rel}/inbox/{preparation_id}/{wid}/completion-receipt.json"},
            "forbidden_claims":roles[role]["value"]["forbidden_claims"],
        }
        work["work_order_hash"]=work_order_hash(work); work_orders[role]=work
    entries=[]
    for role,work in work_orders.items(): entries.append({"role_id":role,"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"snapshot_hash":sha256_bytes(render_json(work))})
    manifest={"schema_version":WORK_ORDERS_SCHEMA,"compiler_version":PREPARATION_COMPILER_VERSION,"preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"issued_roles":issued,"skip_reason":skip_reason,"source_packet_hash":source_packet["packet_hash"],"capabilities_hash":content_hash(capabilities_bundle["value"]),"applicability_hash":content_hash(applicability_bundle["value"]),"role_definition_hashes":semantic_basis["role_hashes"],"discovery_hash":discovery["semantic_hash"],"guidance_hash":guidance["pack_hash"],"recommendation_policy_hash":guidance["snapshots"]["recommendation-policy.v1.json"]["semantic_hash"],"contract_schema_hashes":semantic_basis["contract_hashes"],"work_orders":entries,"manifest_hash":""}
    manifest["manifest_hash"]=content_hash({k:v for k,v in manifest.items() if k != "manifest_hash"})
    pointer={"schema_version":PREPARATION_POINTER_SCHEMA,"preparation_id":preparation_id,"preparation_semantic_hash":semantic_hash,"manifest_snapshot_hash":sha256_bytes(render_json(manifest))}
    return {"authority":authority,"source_packet":source_packet,"contexts":contexts,"work_orders":work_orders,"manifest":manifest,"pointer":pointer,"semantic_basis":semantic_basis}


def prepare(ctx: LocalExecutionContext, *, review_mode: str="contract_only", capabilities_path: str|None=None,
            applicability_path: str|None=None, review_capabilities: dict|None=None, permission: dict|None=None,
            owner_paths: list[str]|None=None) -> dict:
    ctx.require("file.read"); prep_id="prep_"+uuid.uuid4().hex
    capabilities=load_capabilities_input(ctx,capabilities_path); applicability=load_applicability_input(ctx,applicability_path)
    roles=_roles(); discovery=_discovery(); contracts=_contracts(); guidance=load_guidance_pack(); review=_review_resolution(review_mode,review_capabilities,permission)
    expected=_build(ctx,prep_id,capabilities_bundle=capabilities,applicability_bundle=applicability,owner_paths=_owner_paths(owner_paths),review=review,roles=roles,discovery=discovery,contracts=contracts,guidance=guidance)
    root=domain_root(ctx); directory=root/"preparations"/prep_id; directory.mkdir(parents=True)
    _atomic(directory/"preparation-inputs.json",{"owner_paths":_owner_paths(owner_paths),"review_resolution":review})
    (directory/"capabilities.json").write_bytes(capabilities["bytes"]); (directory/"applicability.json").write_bytes(applicability["bytes"])
    _atomic(directory/"measurement-ai-source-packet.json",expected["source_packet"]); _atomic(directory/"measurement-ai-work-orders.json",expected["manifest"])
    (directory/"source-discovery.v1.json").write_bytes(discovery["bytes"])
    for role,item in roles.items(): p=directory/"role-definitions"/(role+".json"); p.parent.mkdir(exist_ok=True); p.write_bytes(item["bytes"])
    for name,item in contracts.items(): p=directory/"contract-schemas"/name; p.parent.mkdir(exist_ok=True); p.write_bytes(item["bytes"])
    for name in ("guidance-registry.v1.json","sources.v1.json","recommendation-policy.v1.json","qualification-suite.v1.json","metric-design.v1.md","experimentation.v1.md","ai-evaluation.v1.md"):
        p=directory/"guidance-pack"/name; p.parent.mkdir(exist_ok=True); p.write_bytes(resources.files("shiproom.measurement_guidance").joinpath(name).read_bytes())
    for role,context in expected["contexts"].items(): _atomic(directory/"role-context"/(role+".json"),context)
    for role,work in expected["work_orders"].items():
        p=directory/"work-orders"/(work["work_order_id"]+".json"); _atomic(p,work); (root/"inbox"/prep_id/work["work_order_id"]).mkdir(parents=True,exist_ok=True)
    _atomic(root/"active-preparation.json",expected["pointer"])
    return {"preparation_id":prep_id,"preparation_semantic_hash":expected["manifest"]["preparation_semantic_hash"],"skip_reason":expected["manifest"]["skip_reason"],"work_orders":expected["manifest"]["work_orders"],"resolved_review_mode":review["resolved"]}


def load_preparation(ctx: LocalExecutionContext, preparation_id: str|None=None, *, directory: Path|None=None) -> dict:
    root=domain_root(ctx); pointer=None
    if directory is None and preparation_id is None:
        p=root/"active-preparation.json"
        if p.is_symlink() or not p.is_file(): raise ValueError("active measurement AI preparation unavailable")
        pointer=load_json_bytes(p.read_bytes()); preparation_id=pointer.get("preparation_id")
    if not isinstance(preparation_id,str) or not re.fullmatch(r"prep_[0-9a-f]{32}",preparation_id): raise ValueError("invalid measurement AI preparation ID")
    directory=directory or root/"preparations"/preparation_id
    if directory.is_symlink() or not directory.is_dir(): raise ValueError("invalid measurement AI preparation directory")
    stored=load_json_bytes((directory/"measurement-ai-work-orders.json").read_bytes())
    if stored.get("compiler_version") != PREPARATION_COMPILER_VERSION: raise ValueError("stale_measurement_ai_preparation_compiler_version")
    inputs=load_json_bytes((directory/"preparation-inputs.json").read_bytes()); capabilities={"value":load_json_bytes((directory/"capabilities.json").read_bytes()),"bytes":(directory/"capabilities.json").read_bytes()}; applicability={"value":load_json_bytes((directory/"applicability.json").read_bytes()),"bytes":(directory/"applicability.json").read_bytes()}
    roles={role:_resource_from_bytes(role+".json",(directory/"role-definitions"/(role+".json")).read_bytes()) for role in ROLES}
    discovery=_resource_from_bytes("source-discovery.v1.json",(directory/"source-discovery.v1.json").read_bytes())
    contracts={p.name:_resource_from_bytes(p.name,p.read_bytes()) for p in (directory/"contract-schemas").iterdir() if p.is_file()}
    guidance=load_guidance_pack(); expected=_build(ctx,preparation_id,capabilities_bundle=capabilities,applicability_bundle=applicability,owner_paths=inputs["owner_paths"],review=inputs["review_resolution"],roles=roles,discovery=discovery,contracts=contracts,guidance=guidance)
    if stored != expected["manifest"] or (directory/"measurement-ai-work-orders.json").read_bytes()!=render_json(expected["manifest"]):
        differing=sorted(key for key in set(stored)|set(expected["manifest"]) if stored.get(key)!=expected["manifest"].get(key))
        raise ValueError("measurement AI preparation semantic rederivation failed: "+",".join(differing))
    if (directory/"measurement-ai-source-packet.json").read_bytes()!=render_json(expected["source_packet"]): raise ValueError("measurement AI source packet semantic rederivation failed")
    expected_files={role+".json" for role in expected["contexts"]}; context_root=directory/"role-context"; actual={p.name for p in context_root.iterdir()} if context_root.exists() else set()
    if actual != expected_files: raise ValueError("measurement AI role context set mismatch")
    for role,context in expected["contexts"].items():
        if (context_root/(role+".json")).read_bytes()!=render_json(context): raise ValueError("measurement AI role context semantic rederivation failed")
    work_root=directory/"work-orders"; actual_work={p.name for p in work_root.iterdir()} if work_root.exists() else set(); expected_work={w["work_order_id"]+".json" for w in expected["work_orders"].values()}
    if actual_work != expected_work: raise ValueError("measurement AI work-order set mismatch")
    for work in expected["work_orders"].values():
        if (work_root/(work["work_order_id"]+".json")).read_bytes()!=render_json(work): raise ValueError("measurement AI work order semantic rederivation failed")
    if pointer is not None and pointer != expected["pointer"]: raise ValueError("measurement AI preparation pointer binding is stale")
    return {"directory":directory,**expected,"contracts":contracts,"capabilities":capabilities["value"],"applicability":applicability["value"]}


def _resource_from_bytes(name: str, raw: bytes) -> dict:
    value=load_json_bytes(raw); return {"name":name,"bytes":raw,"value":value,"semantic_hash":content_hash(value),"snapshot_hash":sha256_bytes(raw)}
