from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import uuid
from pathlib import Path
from typing import Any

from .authority import LocalExecutionContext
from .intent import load_graph_input
from .project import canonical_json, content_hash

GRAPH_SCHEMA = "requirement-evidence-graph.v1"
SUMMARY_SCHEMA = "criterion-evidence-summary.v1"
GAPS_SCHEMA = "evidence-gaps.v1"
PACKET_SCHEMA = "evidence-mapping-source-packet.v1"
PROPOSAL_SCHEMA = "evidence-mapping-proposal.v1"
MANIFEST_SCHEMA = "requirement-evidence-graph-manifest.v1"
POINTER_SCHEMA = "requirement-evidence-graph-current-generation.v1"
COMPILER_VERSION = "requirement-evidence-graph.v1"
LIMIT = 256 * 1024
ARTIFACTS = ("requirement-evidence-graph.json", "criterion-evidence-summary.json", "evidence-gaps.json")
NODE_TYPES = {"source", "requirement", "acceptance_criterion", "critical_journey", "implementation_reference", "test_reference", "instrumentation_reference", "runtime_evidence", "finding", "owner_decision", "remediation_plan", "closure_evidence"}
CLASSIFICATIONS = {"deterministically_established", "source_backed", "model_mapped_candidate", "owner_confirmed", "missing", "not_inspected"}
SLOT_TYPES = {"implementation": "implementation_reference", "test": "test_reference", "instrumentation": "instrumentation_reference", "runtime": "runtime_evidence"}
RELATIONSHIPS = {
    "supports_requirement": ({"source"}, {"requirement"}, {"source_backed"}),
    "supports_acceptance_criterion": ({"source"}, {"acceptance_criterion"}, {"source_backed"}),
    "decomposes_into": ({"requirement"}, {"acceptance_criterion"}, {"deterministically_established"}),
    "affects_critical_journey": ({"requirement"}, {"critical_journey"}, {"deterministically_established", "source_backed"}),
    "may_be_implemented_by": ({"acceptance_criterion"}, {"implementation_reference"}, {"model_mapped_candidate", "not_inspected"}),
    "may_be_verified_by": ({"acceptance_criterion"}, {"test_reference"}, {"model_mapped_candidate", "not_inspected"}),
    "may_be_observed_by": ({"acceptance_criterion"}, {"instrumentation_reference"}, {"model_mapped_candidate", "not_inspected"}),
    "has_runtime_evidence": ({"acceptance_criterion"}, {"runtime_evidence"}, {"deterministically_established", "model_mapped_candidate", "not_inspected"}),
    "concerns_criterion": ({"finding"}, {"acceptance_criterion"}, {"deterministically_established", "model_mapped_candidate", "not_inspected"}),
    "supported_by_evidence": ({"finding"}, {"source", "runtime_evidence", "test_reference", "instrumentation_reference"}, {"deterministically_established", "source_backed"}),
    "requires_owner_decision": ({"finding"}, {"owner_decision"}, {"deterministically_established", "not_inspected"}),
    "resolved_or_conditioned_by": ({"owner_decision"}, {"finding"}, {"owner_confirmed", "deterministically_established"}),
    "addressed_by": ({"finding"}, {"remediation_plan"}, {"deterministically_established", "not_inspected"}),
    "requires_closure_evidence": ({"finding", "remediation_plan"}, {"closure_evidence"}, {"deterministically_established", "missing", "not_inspected"}),
    "closes": ({"closure_evidence"}, {"finding"}, {"deterministically_established"}),
    "fails_to_close": ({"closure_evidence"}, {"finding"}, {"deterministically_established"}),
}


def _id(prefix: str, value: object) -> str: return prefix + "_" + hashlib.sha256(canonical_json(value).encode()).hexdigest()[:16]
def _hash(value: bytes) -> str: return "sha256:" + hashlib.sha256(value).hexdigest()
def _root(ctx: LocalExecutionContext) -> Path: return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "requirement-evidence-graph"
def _authority(ctx: LocalExecutionContext) -> dict: return {k: ctx.authority_binding[k] for k in ("project_id", "contract_hash", "contract_source", "authority_policy_version")}
def _normal(value: str) -> str: return re.sub(r"\s+", " ", value.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n").strip())
def _sort(values: list[Any]) -> list[Any]: return [json.loads(v) for v in sorted({canonical_json(x) for x in values})]


def _atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"); os.replace(temp, path)


def _safe_check(check: dict, index: int, release_hash: str) -> dict:
    check_id = check.get("check_id") or _id("check", {"release_projection_hash": release_hash, "original_index": index, "criterion_id": check.get("criterion_id"), "type": check.get("type"), "target": check.get("target"), "status": check.get("status"), "passed": check.get("passed"), "evidence_status": check.get("evidence_status")})
    return {k: check.get(k) for k in ("criterion_id", "type", "target", "status", "passed", "evidence_status", "runtime_outcome", "error_type", "granted_path", "deployment_grant_hash", "rerun_of") if k in check} | {"check_id": check_id, "original_index": index}


def _projection(ctx: LocalExecutionContext) -> tuple[dict, str]:
    release = ctx.release
    # checks deliberately stay in original order: rerun_of is an array index.
    raw = {"release_id": release["release_id"], "repository": {k: release.get("repository", {}).get(k) for k in ("commit_sha", "path")}, "project_authority": _authority(ctx), "product": {"critical_journey": release.get("product", {}).get("critical_journey", []), "promise": release.get("product", {}).get("promise"), "target_user": release.get("product", {}).get("target_user"), "owner_constraints": release.get("owner_constraints", [])}, "checks": release.get("checks", []), "findings": release.get("findings", []), "owner_decisions": release.get("owner_decisions", []), "remediation_tasks": release.get("remediation_tasks", []), "runtime_artifacts": release.get("runtime_artifacts", []), "state": release.get("state"), "verdict": release.get("verdict", {})}
    digest = content_hash(raw)
    checks = [_safe_check(check, index, digest) for index, check in enumerate(release.get("checks", []))]
    findings = [{k: item.get(k) for k in ("id", "criterion_id", "title", "severity", "blocking", "state", "evidence")} for item in release.get("findings", [])]
    projection = {"release_id": release["release_id"], "release_projection_hash": digest, "checks": checks, "findings": findings, "owner_decisions": release.get("owner_decisions", []), "remediation_tasks": release.get("remediation_tasks", []), "runtime_artifacts": release.get("runtime_artifacts", []), "state": release.get("state"), "verdict": release.get("verdict", {})}
    return projection, digest


def _binding(ctx: LocalExecutionContext) -> tuple[dict, dict, dict, dict, str]:
    intent_manifest, intent_artifacts, intent_packet = load_graph_input(ctx)
    projection, projection_hash = _projection(ctx)
    return intent_manifest, intent_artifacts, intent_packet, projection, projection_hash


def _locators(text: str) -> list[dict]: return [{"start_line": n, "end_line": n, "quote_hash": _hash(line.encode())} for n, line in enumerate(text.split("\n"), 1)]


def _packet_expected(ctx: LocalExecutionContext, paths: list[str]) -> dict:
    im, ia, ip, projection, projection_hash = _binding(ctx); requested = []
    seen = set()
    for path in paths:
        if not isinstance(path, str): raise ValueError("invalid or duplicate mapping path")
        lexical = posixpath.normpath(path.replace("\\", "/"))
        if not lexical or lexical.startswith("/") or ".." in Path(lexical).parts or lexical.casefold() in seen: raise ValueError("invalid or duplicate mapping path")
        seen.add(lexical.casefold()); blob = ctx.read_release_blob(lexical, byte_limit=LIMIT)
        if blob["classification"] != "text" or blob["text"] is None: raise ValueError("mapping source must be UTF-8 text")
        text = blob["text"].removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
        if any(item["returned_git_path"].casefold() == blob["path"].casefold() for item in requested): raise ValueError("mapping paths resolve to the same committed Git path")
        requested.append({"path": blob["path"], "returned_git_path": blob["path"], "git_blob_hash": blob["blob_hash"], "normalized_text_hash": _hash(text.encode()), "text": text, "locators": _locators(text)})
    checks = projection["checks"]
    runtime = [{"runtime_evidence_id": _id("runtime", check), "check_id": check["check_id"], "status": check.get("status"), "target": check.get("target"), "evidence_status": check.get("evidence_status"), "original_index": check["original_index"]} for check in checks]
    packet = {"schema_version": PACKET_SCHEMA, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": _authority(ctx), "product_intent_semantic_bundle_hash": im["semantic_bundle_hash"], "product_intent_source_packet_hash": im["source_packet_hash"], "release_projection_hash": projection_hash, "requirement_ids": sorted(r["requirement_id"] for r in ia["requirements.json"]["requirements"]), "criterion_ids": sorted(c["criterion_id"] for c in ia["acceptance-criteria.json"]["criteria"]), "canonical_checks": checks, "canonical_runtime_evidence": runtime, "canonical_findings": sorted(projection["findings"], key=canonical_json), "selected_sources": sorted(requested, key=lambda x: x["path"]), "coverage_boundary": "Only explicitly selected commit-pinned files; no discovery.", "packet_hash": ""}
    packet["packet_hash"] = content_hash({k: v for k, v in packet.items() if k != "packet_hash"}); return packet


def mapping_prepare(ctx: LocalExecutionContext, paths: list[str]) -> dict:
    ctx.require("file.read")
    packet = _packet_expected(ctx, paths)
    _atomic(_root(ctx) / "mapping-source-packet.json", packet); (_root(ctx) / "inbox").mkdir(parents=True, exist_ok=True)
    return packet


def _load_mapping_packet(ctx: LocalExecutionContext) -> tuple[dict | None, bytes | None]:
    path = _root(ctx) / "mapping-source-packet.json"
    if not path.exists(): return None, None
    if path.is_symlink() or not path.is_file(): raise ValueError("mapping packet is invalid")
    raw = path.read_bytes(); packet = json.loads(raw.decode("utf-8"))
    required = {"schema_version", "release_id", "release_commit", "project_authority", "product_intent_semantic_bundle_hash", "product_intent_source_packet_hash", "release_projection_hash", "requirement_ids", "criterion_ids", "canonical_checks", "canonical_runtime_evidence", "canonical_findings", "selected_sources", "coverage_boundary", "packet_hash"}
    if set(packet) != required or packet["schema_version"] != PACKET_SCHEMA or packet["packet_hash"] != content_hash({k: v for k, v in packet.items() if k != "packet_hash"}): raise ValueError("mapping packet is invalid")
    expected = _packet_expected(ctx, [x["path"] for x in packet["selected_sources"]])
    if packet != expected: raise ValueError("mapping packet is stale")
    return packet, raw


def _proposal_path(ctx: LocalExecutionContext, value: str) -> Path:
    inbox = (_root(ctx) / "inbox").resolve(); raw = Path(value).absolute()
    if raw.is_symlink(): raise ValueError("mapping proposal must be a regular inbox JSON file")
    path = raw.resolve()
    if inbox not in path.parents or path.suffix.lower() != ".json" or path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT: raise ValueError("mapping proposal must be a bounded regular inbox JSON file")
    return path


def _quote(mapping: dict, sources: dict) -> None:
    if not {"path", "returned_git_path", "git_blob_hash"}.issubset(mapping): raise ValueError("mapping reference is incomplete")
    source = sources.get(mapping["path"])
    if not source or any(mapping[k] != source[k] for k in ("returned_git_path", "git_blob_hash")): raise ValueError("mapping reference is stale")
    if any(k in mapping for k in ("start_line", "end_line", "quote", "quote_hash")):
        if not all(k in mapping for k in ("start_line", "end_line", "quote", "quote_hash")): raise ValueError("mapping quote is incomplete")
        lines = source["text"].split("\n"); start, end = mapping["start_line"], mapping["end_line"]
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > len(lines): raise ValueError("mapping quote range is invalid")
        actual = "\n".join(lines[start - 1:end])
        if actual.count(mapping["quote"]) != 1 or mapping["quote_hash"] != _hash(mapping["quote"].encode()): raise ValueError("mapping quote is invalid")


def _validate_proposal(proposal: dict, packet: dict) -> None:
    required = {"schema_version", "release_id", "release_commit", "product_intent_semantic_bundle_hash", "release_projection_hash", "mapping_packet_hash", "mappings"}
    if set(proposal) != required or proposal.get("schema_version") != PROPOSAL_SCHEMA or any(proposal[k] != packet[{"release_id": "release_id", "release_commit": "release_commit", "product_intent_semantic_bundle_hash": "product_intent_semantic_bundle_hash", "release_projection_hash": "release_projection_hash", "mapping_packet_hash": "packet_hash"}[k]] for k in required - {"schema_version", "mappings"}): raise ValueError("mapping proposal binding is invalid")
    if not isinstance(proposal["mappings"], list): raise ValueError("mapping proposal mappings are invalid")
    sources = {x["path"]: x for x in packet["selected_sources"]}; criteria = set(packet["criterion_ids"]); checks = {x["check_id"] for x in packet["canonical_checks"]}; runtime = {x["runtime_evidence_id"] for x in packet["canonical_runtime_evidence"]}; findings = {x.get("id") for x in packet["canonical_findings"]}; seen = set()
    for item in proposal["mappings"]:
        allowed = {"mapping_id", "criterion_id", "target_type", "rationale", "reference", "quality_assessment", "canonical_id", "journey_id"}
        if not isinstance(item, dict) or not set(item).issubset(allowed) or not all(k in item for k in ("mapping_id", "criterion_id", "target_type", "rationale")) or item["criterion_id"] not in criteria or item["target_type"] not in {"implementation_reference", "test_reference", "instrumentation_reference", "runtime_evidence", "finding", "critical_journey"} or not isinstance(item["mapping_id"], str) or item["mapping_id"] in seen: raise ValueError("invalid mapping")
        seen.add(item["mapping_id"])
        if item["target_type"] in {"implementation_reference", "test_reference", "instrumentation_reference"}:
            if not isinstance(item.get("reference"), dict): raise ValueError("repository mapping requires reference")
            _quote(item["reference"], sources)
            if item.get("quality_assessment") not in {None, "plausible", "partial", "inadequate", "unknown"}: raise ValueError("invalid mapping assessment")
        elif item["target_type"] == "runtime_evidence" and item.get("canonical_id") not in runtime | checks: raise ValueError("runtime mapping is not packet allowlisted")
        elif item["target_type"] == "finding" and item.get("canonical_id") not in findings: raise ValueError("finding mapping is not packet allowlisted")
        elif item["target_type"] == "critical_journey" and not isinstance(item.get("journey_id"), str): raise ValueError("journey mapping requires journey_id")


def _normalize_proposal(proposal: dict, packet: dict) -> dict:
    value = json.loads(canonical_json(proposal))
    for item in value["mappings"]:
        item.pop("mapping_id", None); item["establishment_classification"] = "model_mapped_candidate"
    value["mappings"] = sorted(value["mappings"], key=canonical_json)
    return value


def _edge(nodes: dict, source: str, target: str, relationship: str, classification: str, rationale: str, origin: str, refs: list[dict] | None = None) -> dict:
    allowed = RELATIONSHIPS.get(relationship)
    if not allowed or nodes[source]["node_type"] not in allowed[0] or nodes[target]["node_type"] not in allowed[1] or classification not in allowed[2]: raise ValueError("invalid graph relationship")
    value = {"source_node_id": source, "target_node_id": target, "relationship": relationship, "establishment_classification": classification, "rationale": rationale, "origin": origin, "references": _sort(refs or [])}
    return {"edge_id": _id("edge", value), **value}


def _node(node_type: str, identity: object, **fields: Any) -> dict:
    if node_type not in NODE_TYPES: raise ValueError("invalid graph node type")
    return {"node_id": _id(node_type, identity), "node_type": node_type, **fields}


def _compile(ctx: LocalExecutionContext, packet: dict | None, normalized: dict | None) -> tuple[dict, dict, dict]:
    im, ia, ip, projection, projection_hash = _binding(ctx); requirements = ia["requirements.json"]["requirements"]; criteria = ia["acceptance-criteria.json"]["criteria"]; ambiguities = ia["ambiguities.json"]["ambiguities"]
    nodes: dict[str, dict] = {}; edges: list[dict] = []; req_nodes = {}; criterion_nodes = {}
    def add(item: dict) -> str: nodes.setdefault(item["node_id"], item); return item["node_id"]
    source_packet = {x["source_id"]: x for x in ip["sources"]}
    source_nodes = {}
    for source_id, source in source_packet.items(): source_nodes[source_id] = add(_node("source", {"packet": ip["packet_hash"], "source_id": source_id}, source_id=source_id, authority_tier=source["authority_tier"], path=source["path"], normalized_text_hash=source["normalized_text_hash"]))
    journeys = {}
    for text in ia["product-intent.json"].get("release_scope", []): journeys[_normal(text)] = add(_node("critical_journey", {"intent": im["semantic_bundle_hash"], "journey": _normal(text)}, journey_text=_normal(text), origin="product_intent"))
    for requirement in requirements:
        rid = add(_node("requirement", requirement["requirement_id"], requirement_id=requirement["requirement_id"], statement=requirement["statement"], classification=requirement["classification"], status=requirement["status"])); req_nodes[requirement["requirement_id"]] = rid
        for ref in requirement["source_refs"]:
            if ref["source_id"] in source_nodes: edges.append(_edge(nodes, source_nodes[ref["source_id"]], rid, "supports_requirement", "source_backed", "Validated Product Intent source reference.", "product_intent", [ref]))
        for journey in requirement.get("related_journey_ids", []):
            target = journeys.get(_normal(journey))
            if target: edges.append(_edge(nodes, rid, target, "affects_critical_journey", "deterministically_established", "Exact normalized Product Intent journey reference.", "product_intent"))
    for criterion in criteria:
        cid = add(_node("acceptance_criterion", criterion["criterion_id"], criterion_id=criterion["criterion_id"], requirement_id=criterion["requirement_id"], classification=criterion["classification"], confirmation_state=criterion["confirmation_state"], action=criterion.get("action"), expected_outcomes=criterion.get("expected_outcomes", []))); criterion_nodes[criterion["criterion_id"]] = cid
        edges.append(_edge(nodes, req_nodes[criterion["requirement_id"]], cid, "decomposes_into", "deterministically_established", "Validated Product Intent requirement ownership.", "product_intent"))
        for ref in criterion.get("source_refs", []):
            if ref["source_id"] in source_nodes: edges.append(_edge(nodes, source_nodes[ref["source_id"]], cid, "supports_acceptance_criterion", "source_backed", "Validated Product Intent criterion source reference.", "product_intent", [ref]))
    check_nodes = {}; runtime_nodes = {}; original_checks = projection["checks"]
    for check in original_checks:
        runtime = add(_node("runtime_evidence", {"projection": projection_hash, "check_id": check["check_id"]}, check_id=check["check_id"], original_index=check["original_index"], status=check.get("status"), passed=check.get("passed"), target=check.get("target"), evidence_status=check.get("evidence_status"), slot_status="actual", inspection_boundary="canonical_release_state")); check_nodes[check["check_id"]] = runtime; runtime_nodes[_id("runtime", check)] = runtime
    finding_nodes = {}
    for finding in projection["findings"]:
        fid = finding.get("id") or _id("finding", finding); finding_nodes[fid] = add(_node("finding", {"projection": projection_hash, "finding": finding}, canonical_finding_id=fid, criterion_id=finding.get("criterion_id"), title=finding.get("title"), severity=finding.get("severity"), blocking=bool(finding.get("blocking")), state=finding.get("state"), evidence=_sort(finding.get("evidence", []))))
    decision_nodes = {}
    for decision in projection["owner_decisions"]:
        did = decision.get("id") or _id("decision", decision); decision_nodes[did] = add(_node("owner_decision", {"projection": projection_hash, "decision": decision}, canonical_decision_id=did, title=decision.get("title"), choice=decision.get("choice"), resolution=decision.get("resolution")))
    remediation_nodes = {}
    for task in projection["remediation_tasks"]:
        tid = task.get("id") or _id("remediation", task); remediation_nodes[tid] = add(_node("remediation_plan", {"projection": projection_hash, "task": task}, canonical_task_id=tid, remediation_class=task.get("class"), base_branch=task.get("base_branch"), branch=task.get("branch"), status=task.get("status"), auto_merge=task.get("auto_merge"), base_commit=task.get("base_commit"), commit_sha=task.get("commit_sha"), targets=_sort(task.get("targets", []))))
    mappings = (normalized or {"mappings": []})["mappings"]
    by_criterion: dict[str, list[dict]] = {key: [] for key in criterion_nodes}
    for mapping in mappings: by_criterion[mapping["criterion_id"]].append(mapping)
    for criterion_id, cid in criterion_nodes.items():
        concrete = {slot: [] for slot in SLOT_TYPES}
        # A canonical check can be actual runtime evidence only when it already
        # names this final Product Intent criterion.  Historical aliases need a
        # mapping proposal and therefore remain candidate-only.
        for check in original_checks:
            if check.get("criterion_id") == criterion_id:
                concrete["runtime"].append(check_nodes[check["check_id"]])
        for mapping in by_criterion[criterion_id]:
            target_type = mapping["target_type"]
            if target_type in {"implementation_reference", "test_reference", "instrumentation_reference"}:
                ref = mapping["reference"]; nid = add(_node(target_type, {"packet": packet["packet_hash"], "criterion": criterion_id, "mapping": mapping}, slot_status="candidate_present", path=ref["path"], returned_git_path=ref["returned_git_path"], git_blob_hash=ref["git_blob_hash"], label=ref.get("label"), quality_assessment=mapping.get("quality_assessment"), rationale=mapping["rationale"])); concrete[next(slot for slot, kind in SLOT_TYPES.items() if kind == target_type)].append(nid)
                relation = {"implementation_reference": "may_be_implemented_by", "test_reference": "may_be_verified_by", "instrumentation_reference": "may_be_observed_by"}[target_type]
                edges.append(_edge(nodes, cid, nid, relation, "model_mapped_candidate", mapping["rationale"], "normalized_mapping_proposal", [ref]))
            elif target_type == "runtime_evidence":
                nid = runtime_nodes.get(mapping["canonical_id"]) or check_nodes.get(mapping["canonical_id"])
                if nid: concrete["runtime"].append(nid); edges.append(_edge(nodes, cid, nid, "has_runtime_evidence", "model_mapped_candidate", mapping["rationale"], "normalized_mapping_proposal"))
            elif target_type == "finding" and mapping["canonical_id"] in finding_nodes:
                edges.append(_edge(nodes, finding_nodes[mapping["canonical_id"]], cid, "concerns_criterion", "model_mapped_candidate", mapping["rationale"], "normalized_mapping_proposal"))
        for slot, kind in SLOT_TYPES.items():
            if not concrete[slot]:
                nid = add(_node(kind, {"criterion": criterion_id, "slot": slot, "projection": projection_hash}, slot_status="not_inspected", evidence_slot=slot, inspection_boundary="No mapping packet/proposal or qualified canonical inspection.")); relation = {"implementation": "may_be_implemented_by", "test": "may_be_verified_by", "instrumentation": "may_be_observed_by", "runtime": "has_runtime_evidence"}[slot]
                edges.append(_edge(nodes, cid, nid, relation, "not_inspected", "No qualified mapping or canonical inspection exists.", "graph_compiler"))
    # Canonical check/finding relationships only use exact matching final criterion IDs.
    for check in original_checks:
        if check.get("criterion_id") in criterion_nodes: edges.append(_edge(nodes, criterion_nodes[check["criterion_id"]], check_nodes[check["check_id"]], "has_runtime_evidence", "deterministically_established", "Canonical check names this final criterion.", "release_projection"))
    for finding in projection["findings"]:
        fid = finding.get("id") or _id("finding", finding)
        if finding.get("criterion_id") in criterion_nodes: edges.append(_edge(nodes, finding_nodes[fid], criterion_nodes[finding["criterion_id"]], "concerns_criterion", "deterministically_established", "Canonical finding names this final criterion.", "release_projection"))
    for check in original_checks:
        if isinstance(check.get("rerun_of"), int) and 0 <= check["rerun_of"] < len(original_checks):
            original = original_checks[check["rerun_of"]]
            for finding in projection["findings"]:
                fid = finding.get("id") or _id("finding", finding)
                if finding.get("criterion_id") == check.get("criterion_id") and finding.get("state") == "CLOSED":
                    closure = add(_node("closure_evidence", {"projection": projection_hash, "rerun": check["check_id"], "original": original["check_id"], "finding": fid}, slot_status="actual", rerun_check_id=check["check_id"], original_check_id=original["check_id"], inspection_boundary="canonical_release_state")); edges.append(_edge(nodes, closure, finding_nodes[fid], "closes", "deterministically_established", "Canonical rerun index resolves to original check and closed finding.", "release_projection"))
    gaps = []
    ambiguity_ids = {a["ambiguity_id"] for a in ambiguities}
    for criterion in criteria:
        cid = criterion["criterion_id"]; base = criterion_nodes[cid]
        if criterion["classification"] == "inferred_requires_owner" or criterion["confirmation_state"] != "proposal_needed": gaps.append({"gap_id": _id("gap", {"criterion": cid, "type": "specification_gap"}), "criterion_id": cid, "gap_type": "specification_gap", "state": "open", "basis_node_ids": [base], "basis_edge_ids": [], "description": "Criterion remains inferred or unconfirmed.", "evidence_needed": "Owner-confirmed Product Intent.", "linked_canonical_finding_ids": [], "linked_canonical_blocker": False, "owner_input_required": True, "product_intent_ambiguity_ids": []})
        requirement = next(r for r in requirements if r["requirement_id"] == criterion["requirement_id"])
        if requirement["status"] == "blocked_by_ambiguity": gaps.append({"gap_id": _id("gap", {"criterion": cid, "type": "source_conflict", "ambiguities": sorted(ambiguity_ids)}), "criterion_id": cid, "gap_type": "source_conflict", "state": "open", "basis_node_ids": [base], "basis_edge_ids": [], "description": "Product Intent ambiguity blocks the owning requirement.", "evidence_needed": "Resolved Product Intent ambiguity.", "linked_canonical_finding_ids": [], "linked_canonical_blocker": False, "owner_input_required": True, "product_intent_ambiguity_ids": sorted(ambiguity_ids)})
        for check in original_checks:
            if check.get("status") == 404:
                gaps.append({"gap_id": _id("gap", {"criterion": cid, "type": "runtime_evidence_gap", "check": check["check_id"]}), "criterion_id": cid, "gap_type": "runtime_evidence_gap", "state": "open", "basis_node_ids": [base, check_nodes[check["check_id"]]], "basis_edge_ids": [], "description": "Canonical runtime observation returned HTTP 404.", "evidence_needed": "Canonical successful qualifying runtime evidence.", "linked_canonical_finding_ids": [], "linked_canonical_blocker": False, "owner_input_required": False, "product_intent_ambiguity_ids": []})
    summaries = []
    for criterion in criteria:
        cid = criterion["criterion_id"]; related_edges = [e for e in edges if e["source_node_id"] == criterion_nodes[cid] or e["target_node_id"] == criterion_nodes[cid]]; slots = {slot: [nodes[e["target_node_id"]] for e in related_edges if e["source_node_id"] == criterion_nodes[cid] and nodes[e["target_node_id"]]["node_type"] == kind] for slot, kind in SLOT_TYPES.items()}
        requirement = next(r for r in requirements if r["requirement_id"] == criterion["requirement_id"])
        summaries.append({"criterion_id": cid, "requirement_id": criterion["requirement_id"], "requirement_statement": requirement["statement"], "criterion": criterion, "source_node_ids": sorted({e["source_node_id"] for e in edges if e["target_node_id"] == criterion_nodes[cid] and nodes[e["source_node_id"]]["node_type"] == "source"}), "critical_journey_context": _sort(requirement.get("related_journey_ids", [])), "implementation": slots["implementation"], "tests": slots["test"], "instrumentation": slots["instrumentation"], "runtime": slots["runtime"], "gaps": [g["gap_id"] for g in gaps if g["criterion_id"] == cid], "canonical_blocker_ids": sorted(f for f, node in finding_nodes.items() if nodes[node].get("blocking")), "owner_decision_ids": sorted(decision_nodes), "closure_evidence_required": "not_inspected"})
    common = {"release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": _authority(ctx), "product_intent_semantic_bundle_hash": im["semantic_bundle_hash"], "product_intent_source_packet_hash": im["source_packet_hash"], "release_projection_hash": projection_hash, "compiler_version": COMPILER_VERSION}
    graph = {"schema_version": GRAPH_SCHEMA, **common, "mapping_packet_state": "present" if packet else "absent", "mapping_packet_hash": packet["packet_hash"] if packet else None, "nodes": sorted(nodes.values(), key=lambda x: x["node_id"]), "edges": sorted({e["edge_id"]: e for e in edges}.values(), key=lambda x: x["edge_id"]), "coverage_boundary": "Validated Product Intent, canonical release projection, and optional explicitly selected mapping packet only."}
    summary = {"schema_version": SUMMARY_SCHEMA, **common, "criteria": sorted(summaries, key=lambda x: x["criterion_id"])}
    gap_artifact = {"schema_version": GAPS_SCHEMA, **common, "gaps": sorted(gaps, key=lambda x: x["gap_id"])}
    return graph, summary, gap_artifact


def _validate_artifacts(artifacts: dict) -> None:
    if set(artifacts) != set(ARTIFACTS): raise ValueError("graph artifact set is invalid")
    graph = artifacts[ARTIFACTS[0]]; nodes = {n["node_id"]: n for n in graph.get("nodes", [])}
    if graph.get("schema_version") != GRAPH_SCHEMA or len(nodes) != len(graph.get("nodes", [])) or any(n.get("node_type") not in NODE_TYPES for n in nodes.values()): raise ValueError("graph nodes are invalid")
    seen = set()
    def reject_local_ids(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "local_id" or key.endswith("_local_id") or key.endswith("_local_ids"):
                    raise ValueError("final graph artifacts cannot contain proposal-local IDs")
                reject_local_ids(child)
        elif isinstance(value, list):
            for child in value: reject_local_ids(child)
    reject_local_ids(artifacts)
    for edge in graph.get("edges", []):
        if edge.get("edge_id") in seen or edge.get("source_node_id") not in nodes or edge.get("target_node_id") not in nodes: raise ValueError("graph edge is invalid")
        expected = _edge(nodes, edge["source_node_id"], edge["target_node_id"], edge["relationship"], edge["establishment_classification"], edge["rationale"], edge["origin"], edge.get("references", []))
        if edge != expected: raise ValueError("graph edge is noncanonical")
        seen.add(edge["edge_id"])
    if artifacts[ARTIFACTS[1]].get("schema_version") != SUMMARY_SCHEMA or artifacts[ARTIFACTS[2]].get("schema_version") != GAPS_SCHEMA: raise ValueError("graph artifact schema is invalid")


def _persist(ctx: LocalExecutionContext, packet: dict | None, packet_bytes: bytes | None, submitted: dict | None, submitted_bytes: bytes | None, normalized: dict | None, artifacts: dict) -> dict:
    root = _root(ctx); directory = root / "generations" / ("gen_" + uuid.uuid4().hex); directory.mkdir(parents=True); hashes = {}
    for name, artifact in artifacts.items(): _atomic(directory / name, artifact); hashes[name] = _hash((directory / name).read_bytes())
    if packet_bytes: (directory / "mapping-source-packet.json").write_bytes(packet_bytes)
    if submitted_bytes: (directory / "submitted-mapping-proposal.json").write_bytes(submitted_bytes); _atomic(directory / "normalized-mapping-proposal.json", normalized)
    im, _, _, _, projection_hash = _binding(ctx)
    normalized_bytes = (directory / "normalized-mapping-proposal.json").read_bytes() if normalized else None
    manifest = {"schema_version": MANIFEST_SCHEMA, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": _authority(ctx), "product_intent_semantic_bundle_hash": im["semantic_bundle_hash"], "product_intent_source_packet_hash": im["source_packet_hash"], "release_projection_hash": projection_hash, "mapping_packet_state": "present" if packet else "absent", "mapping_packet_hash": packet["packet_hash"] if packet else None, "mapping_packet_snapshot_hash": _hash(packet_bytes) if packet_bytes else None, "submitted_proposal_hash": content_hash(submitted) if submitted else None, "submitted_proposal_snapshot_hash": _hash(submitted_bytes) if submitted_bytes else None, "normalized_proposal_hash": content_hash(normalized) if normalized else None, "normalized_proposal_snapshot_hash": _hash(normalized_bytes) if normalized_bytes else None, "compiler_version": COMPILER_VERSION, "artifact_filenames": list(ARTIFACTS), "artifact_hashes": hashes}
    manifest["semantic_bundle_hash"] = content_hash({"intent": manifest["product_intent_semantic_bundle_hash"], "packet": manifest["mapping_packet_hash"], "projection": projection_hash, "compiler": COMPILER_VERSION, "artifacts": {k: hashes[k] for k in sorted(hashes)}}); manifest["bundle_hash"] = content_hash(manifest)
    _atomic(directory / "manifest.json", manifest); _atomic(root / "current-generation.json", {"schema_version": POINTER_SCHEMA, "generation": directory.name, "manifest_hash": _hash((directory / "manifest.json").read_bytes())}); return manifest


def compile_bundle(ctx: LocalExecutionContext, proposal_file: str | None = None) -> dict:
    ctx.require("file.read"); packet, packet_bytes = _load_mapping_packet(ctx)
    submitted = normalized = None; submitted_bytes = None
    if proposal_file:
        if not packet: raise ValueError("mapping proposal requires an active mapping packet")
        submitted_bytes = _proposal_path(ctx, proposal_file).read_bytes(); submitted = json.loads(submitted_bytes.decode("utf-8")); _validate_proposal(submitted, packet); normalized = _normalize_proposal(submitted, packet)
    artifacts = dict(zip(ARTIFACTS, _compile(ctx, packet, normalized))); _validate_artifacts(artifacts)
    return _persist(ctx, packet, packet_bytes, submitted, submitted_bytes, normalized, artifacts)


def load_bundle(ctx: LocalExecutionContext) -> tuple[dict, dict]:
    im, _, _, _, projection_hash = _binding(ctx); pointer_path = _root(ctx) / "current-generation.json"
    if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("complete graph generation is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8")); generation = pointer.get("generation")
    if set(pointer) != {"schema_version", "generation", "manifest_hash"} or pointer["schema_version"] != POINTER_SCHEMA or not isinstance(generation, str): raise ValueError("graph pointer is invalid")
    directory = _root(ctx) / "generations" / generation; manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or _hash(manifest_path.read_bytes()) != pointer["manifest_hash"]: raise ValueError("graph generation is invalid")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("bundle_hash") != content_hash({k: v for k, v in manifest.items() if k != "bundle_hash"}) or manifest.get("release_id") != ctx.release["release_id"] or manifest.get("release_commit") != ctx.authority_binding["repository_commit"] or manifest.get("project_authority") != _authority(ctx) or manifest.get("product_intent_semantic_bundle_hash") != im["semantic_bundle_hash"] or manifest.get("product_intent_source_packet_hash") != im["source_packet_hash"] or manifest.get("release_projection_hash") != projection_hash or manifest.get("artifact_filenames") != list(ARTIFACTS): raise ValueError("graph generation is stale")
    packet, packet_bytes = _load_mapping_packet(ctx)
    if (manifest.get("mapping_packet_state") == "present") != bool(packet) or (packet and manifest.get("mapping_packet_hash") != packet["packet_hash"]): raise ValueError("graph mapping packet is stale")
    if packet and (not (directory / "mapping-source-packet.json").is_file() or (directory / "mapping-source-packet.json").read_bytes() != packet_bytes): raise ValueError("graph packet snapshot is stale")
    if manifest.get("submitted_proposal_hash"):
        submitted_path, normalized_path = directory / "submitted-mapping-proposal.json", directory / "normalized-mapping-proposal.json"
        if not packet or not submitted_path.is_file() or not normalized_path.is_file(): raise ValueError("graph proposal snapshot is invalid")
        submitted_bytes = submitted_path.read_bytes(); normalized_bytes = normalized_path.read_bytes()
        submitted = json.loads(submitted_bytes.decode("utf-8")); _validate_proposal(submitted, packet); normalized = _normalize_proposal(submitted, packet)
        if _hash(submitted_bytes) != manifest.get("submitted_proposal_snapshot_hash") or content_hash(submitted) != manifest.get("submitted_proposal_hash") or _hash(normalized_bytes) != manifest.get("normalized_proposal_snapshot_hash") or normalized != json.loads(normalized_bytes.decode("utf-8")) or content_hash(normalized) != manifest.get("normalized_proposal_hash"): raise ValueError("graph normalized proposal is invalid")
    artifacts = {}
    for name in ARTIFACTS:
        path = directory / name
        if not path.is_file() or _hash(path.read_bytes()) != manifest.get("artifact_hashes", {}).get(name): raise ValueError("graph artifact is invalid")
        artifacts[name] = json.loads(path.read_text(encoding="utf-8"))
    semantic = content_hash({"intent": manifest["product_intent_semantic_bundle_hash"], "packet": manifest["mapping_packet_hash"], "projection": projection_hash, "compiler": COMPILER_VERSION, "artifacts": {k: manifest["artifact_hashes"][k] for k in sorted(ARTIFACTS)}})
    if manifest.get("semantic_bundle_hash") != semantic: raise ValueError("graph semantic bundle is invalid")
    _validate_artifacts(artifacts); return manifest, artifacts


def show(ctx: LocalExecutionContext, criterion_id: str | None = None) -> str:
    _, artifacts = load_bundle(ctx); summaries = artifacts["criterion-evidence-summary.json"]["criteria"]
    if criterion_id: summaries = [s for s in summaries if s["criterion_id"] == criterion_id]
    if criterion_id and not summaries: raise ValueError("criterion is unavailable")
    gaps = {g["gap_id"]: g for g in artifacts["evidence-gaps.json"]["gaps"]}; lines = []
    for summary in summaries:
        lines += [f"Requirement: {summary['requirement_statement']}", f"Criterion: {summary['criterion_id']}", f"Journey context: {', '.join(summary['critical_journey_context']) or 'not inspected'}"]
        for label, field in (("Implementation", "implementation"), ("Test evidence", "tests"), ("Instrumentation", "instrumentation"), ("Runtime", "runtime")):
            values = summary[field]; lines.append(f"{label}: " + ", ".join(f"{v.get('slot_status', 'actual')} ({v.get('node_type')})" for v in values))
        lines.append("Gaps: " + ", ".join(gaps[x]["gap_type"] for x in summary["gaps"]) if summary["gaps"] else "Gaps: none")
        lines.append("Closure: " + summary["closure_evidence_required"])
    return "\n".join(lines)
