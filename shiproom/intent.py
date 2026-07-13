from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path

from .authority import LocalExecutionContext
from .project import canonical_json, content_hash

SOURCE_PACKET_SCHEMA = "intent-source-packet.v1"; PROPOSAL_SCHEMA = "intent-proposal.v1"
INTENT_SCHEMA = "product-intent.v1"; REQUIREMENTS_SCHEMA = "requirements.v1"; CRITERIA_SCHEMA = "acceptance-criteria.v1"; AMBIGUITIES_SCHEMA = "intent-ambiguities.v1"
MANIFEST_SCHEMA = "product-intent-bundle-manifest.v1"; POINTER_SCHEMA = "product-intent-current-generation.v1"; COMPILER_VERSION = "product-intent.v1"
SOURCE_LIMIT = PROPOSAL_LIMIT = 256 * 1024
TIERS = ("release_owner_input", "current_release_source", "project_contract", "supporting_source")
CLASSIFICATIONS = {"explicit", "inferred_requires_owner"}; STATUSES = {"active", "proposed", "blocked_by_ambiguity", "superseded"}
CONFIRMATIONS = {"confirmed", "proposal_needed", "owner_confirmation_required"}; EVIDENCE = {"browser_or_http", "content_assertion", "command_result", "file_or_artifact", "source_inspection", "instrumentation", "owner_confirmation"}
ARTIFACTS = ("product-intent.json", "requirements.json", "acceptance-criteria.json", "ambiguities.json")


def _id(prefix: str, value: object) -> str: return prefix + "_" + hashlib.sha256(canonical_json(value).encode()).hexdigest()[:16]
def _hash_bytes(value: bytes) -> str: return "sha256:" + hashlib.sha256(value).hexdigest()
def _normal_text(value: str) -> str: return value.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
def _mechanical(value: str) -> str: return re.sub(r"\s+", " ", _normal_text(value).strip())
def _root(ctx: LocalExecutionContext) -> Path: return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "product-intent"
def _authority(ctx: LocalExecutionContext) -> dict: return {key: ctx.authority_binding[key] for key in ("project_id", "contract_hash", "contract_source", "authority_policy_version")}
def _source_hash(text: str) -> str: return _hash_bytes(text.encode("utf-8"))


def _locators(text: str) -> list[dict]:
    lines = text.split("\n"); result = []
    for i, line in enumerate(lines, 1):
        result.append({"start_line": i, "end_line": i, "quote_hash": _source_hash(line)})
    return result


def _structured(ctx: LocalExecutionContext) -> list[dict]:
    product = {k: ctx.release["product"].get(k) for k in ("name", "target_user", "promise", "critical_journey", "non_goals")}; product["owner_constraints"] = ctx.release.get("owner_constraints", [])
    contract = {k: ctx.activation["contract"].get(k) for k in ("project_name", "product_purpose", "primary_users", "project_principles")}
    out = []
    for source_id, tier, value in (("release_owner_input", "release_owner_input", product), ("project_contract", "project_contract", contract)):
        text = canonical_json(value); out.append({"source_id": source_id, "path": None, "source_class": "structured", "authority_tier": tier, "git_blob_hash": None, "normalized_text_hash": _source_hash(text), "text": text, "locators": _locators(text)})
    return out


def _read(ctx: LocalExecutionContext, path: str, source_class: str) -> dict:
    if Path(path).suffix.lower() not in {".md", ".markdown"}: raise ValueError(f"unsupported_type: {path}")
    try: blob = ctx.read_release_blob(path, byte_limit=SOURCE_LIMIT)
    except PermissionError as exc: raise PermissionError(f"excluded_by_policy: {path}") from exc
    except FileNotFoundError as exc: raise FileNotFoundError(f"missing: {path}") from exc
    except ValueError as exc:
        if "exceeds byte limit" in str(exc): raise ValueError(f"rejected_oversized: {path}; supply a smaller release-specific source") from exc
        raise ValueError(f"unsupported_type: {path}") from exc
    if blob["classification"] != "text" or blob["text"] is None: raise ValueError(f"unsupported_type: {path}")
    text = _normal_text(blob["text"]); return {"source_id": _id("src", {"path": blob["path"], "class": source_class, "blob": blob["blob_hash"]}), "path": blob["path"], "source_class": source_class, "authority_tier": "current_release_source" if source_class == "current_release" else "supporting_source", "git_blob_hash": blob["blob_hash"], "normalized_text_hash": _source_hash(text), "text": text, "locators": _locators(text)}


def _packet(ctx: LocalExecutionContext, requested: list[dict]) -> dict:
    sources = _structured(ctx); coverage = []
    for item in requested:
        source = _read(ctx, item["path"], item["source_class"]); sources.append(source); coverage.append({"path": item["path"], "source_class": item["source_class"], "status": "fully_included"})
    packet = {"schema_version": SOURCE_PACKET_SCHEMA, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": _authority(ctx), "compiler_version": COMPILER_VERSION, "requested_sources": requested, "sources": sources, "source_coverage": coverage, "coverage_boundary": "Complete normalized text for every explicitly selected Markdown source; no discovery or truncation."}
    packet["packet_hash"] = content_hash(packet); return packet


def validate_packet(packet: dict) -> None:
    fields = {"schema_version", "release_id", "release_commit", "project_authority", "compiler_version", "requested_sources", "sources", "source_coverage", "coverage_boundary", "packet_hash"}
    if set(packet) != fields or packet["schema_version"] != SOURCE_PACKET_SCHEMA or packet["packet_hash"] != content_hash({k: v for k, v in packet.items() if k != "packet_hash"}): raise ValueError("invalid source packet")
    if not isinstance(packet["requested_sources"], list) or len(packet["requested_sources"]) != len(packet["source_coverage"]): raise ValueError("invalid source coverage")
    expected = {(x["path"], x["source_class"]) for x in packet["requested_sources"]}
    if any(set(x) != {"path", "source_class"} or x["source_class"] not in {"current_release", "supporting_source"} for x in packet["requested_sources"]) or len(expected) != len(packet["requested_sources"]): raise ValueError("invalid requested sources")
    if any(x != {"path": x["path"], "source_class": x["source_class"], "status": "fully_included"} for x in packet["source_coverage"]): raise ValueError("partial source coverage is not allowed")
    ids = set()
    for source in packet["sources"]:
        required = {"source_id", "path", "source_class", "authority_tier", "git_blob_hash", "normalized_text_hash", "text", "locators"}
        if set(source) != required or not isinstance(source["source_id"], str) or source["source_id"] in ids or source["authority_tier"] not in TIERS or not isinstance(source["text"], str) or source["normalized_text_hash"] != _source_hash(source["text"]): raise ValueError("invalid packet source")
        if source["locators"] != _locators(source["text"]): raise ValueError("invalid packet locators")
        ids.add(source["source_id"])


def _atomic_file(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"); os.replace(temp, path)


def prepare(ctx: LocalExecutionContext, sources: list[str], supporting_sources: list[str]) -> dict:
    ctx.require("file.read"); requested = [{"path": x, "source_class": "current_release"} for x in sources] + [{"path": x, "source_class": "supporting_source"} for x in supporting_sources]
    if not requested: raise ValueError("at least one explicitly selected source is required")
    packet = _packet(ctx, requested); validate_packet(packet); root = _root(ctx); (root / "inbox").mkdir(parents=True, exist_ok=True); _atomic_file(root / "source-packet.json", packet); return packet


def _load_packet(ctx: LocalExecutionContext) -> tuple[dict, bytes]:
    path = _root(ctx) / "source-packet.json"
    if path.is_symlink() or not path.is_file(): raise ValueError("prepared source packet is missing")
    raw = path.read_bytes(); packet = json.loads(raw.decode("utf-8")); validate_packet(packet)
    expected = _packet(ctx, packet["requested_sources"])
    if packet != expected: raise ValueError("active source packet differs from release-bound authority")
    return packet, raw


def _proposal_path(ctx: LocalExecutionContext, value: str) -> Path:
    inbox = (_root(ctx) / "inbox").resolve(); raw = Path(value).absolute()
    if raw.is_symlink(): raise ValueError("proposal must be a regular inbox JSON file")
    path = raw.resolve()
    if inbox not in path.parents or path.suffix.lower() != ".json" or path.is_symlink() or not path.is_file() or path.stat().st_size > PROPOSAL_LIMIT: raise ValueError("proposal must be a bounded regular JSON file in the release-local inbox")
    return path


def _quote(ref: dict, sources: dict) -> None:
    fields = {"source_id", "start_line", "end_line", "quote", "quote_hash"}
    if set(ref) != fields or ref["source_id"] not in sources or not isinstance(ref["start_line"], int) or not isinstance(ref["end_line"], int) or not isinstance(ref["quote"], str) or ref["start_line"] < 1 or ref["end_line"] < ref["start_line"]: raise ValueError("invalid quote reference")
    lines = sources[ref["source_id"]]["text"].split("\n"); actual = "\n".join(lines[ref["start_line"] - 1:ref["end_line"]])
    if actual != ref["quote"] or ref["quote_hash"] != _source_hash(actual): raise ValueError("quote range or hash is invalid")


def _refs(refs: object, sources: dict) -> list[dict]:
    if not isinstance(refs, list) or not refs: raise ValueError("source support is required")
    for ref in refs: _quote(ref, sources)
    return refs


def _supported(value: object, refs: list[dict]) -> bool:
    return isinstance(value, str) and any(_mechanical(value) == _mechanical(ref["quote"]) for ref in refs)


def _validate_proposal(proposal: dict, packet: dict) -> None:
    fields = {"schema_version", "release_id", "release_commit", "source_packet_hash", "claims", "requirements", "criteria", "ambiguities"}
    if set(proposal) != fields or proposal.get("schema_version") != PROPOSAL_SCHEMA or proposal["release_id"] != packet["release_id"] or proposal["release_commit"] != packet["release_commit"] or proposal["source_packet_hash"] != packet["packet_hash"]: raise ValueError("invalid or unbound proposal")
    sources = {x["source_id"]: x for x in packet["sources"]}; claim_ids = set(); requirement_ids = set(); ambiguity_ids = set(); criterion_ids = set()
    for claim in proposal["claims"]:
        if set(claim) != {"local_id", "claim_key", "cardinality", "value", "classification", "source_refs", "requirement_local_ids"} or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", claim["claim_key"]) or claim["cardinality"] not in {"single", "multi"} or claim["classification"] not in CLASSIFICATIONS or not isinstance(claim["local_id"], str) or claim["local_id"] in claim_ids: raise ValueError("invalid claim")
        refs = _refs(claim["source_refs"], sources)
        if claim["classification"] == "explicit" and not _supported(str(claim["value"]), refs): raise ValueError("explicit claim lacks exact quote support")
        claim_ids.add(claim["local_id"])
    for item in proposal["requirements"]:
        required = {"local_id", "statement", "classification", "status", "source_refs", "claim_local_ids", "related_journey_ids", "materiality", "rationale", "owner_confirmation_required", "ambiguity_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in requirement_ids or not isinstance(item["statement"], str) or not item["statement"].strip() or item["classification"] not in CLASSIFICATIONS or item["status"] not in STATUSES or not isinstance(item["owner_confirmation_required"], bool) or not set(item["claim_local_ids"]).issubset(claim_ids): raise ValueError("invalid requirement")
        refs = _refs(item["source_refs"], sources)
        if item["classification"] == "explicit" and not _supported(item["statement"], refs): raise ValueError("explicit requirement lacks exact quote support")
        if item["classification"] == "inferred_requires_owner" and not item["owner_confirmation_required"]: raise ValueError("inferred requirement requires owner confirmation")
        requirement_ids.add(item["local_id"])
    for item in proposal["ambiguities"]:
        required = {"local_id", "title", "source_refs", "why_material", "options", "recommendation", "blocked_conclusions", "affected_requirement_local_ids", "affected_criterion_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in ambiguity_ids or not isinstance(item["options"], list) or len(item["options"]) > 3 or not set(item["affected_requirement_local_ids"]).issubset(requirement_ids): raise ValueError("invalid ambiguity")
        _refs(item["source_refs"], sources); ambiguity_ids.add(item["local_id"])
    if any(not set(x["requirement_local_ids"]).issubset(requirement_ids) for x in proposal["claims"]): raise ValueError("claim references unknown requirement")
    if any(not set(x["ambiguity_local_ids"]).issubset(ambiguity_ids) for x in proposal["requirements"]): raise ValueError("requirement references unknown ambiguity")
    for item in proposal["criteria"]:
        required = {"local_id", "parent_requirement_local_id", "actor", "preconditions", "action", "expected_outcomes", "failure_behavior", "required_evidence_categories", "source_refs", "field_source_refs", "classification", "confirmation_state", "blocker_eligible", "ambiguity_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in criterion_ids or item["parent_requirement_local_id"] not in requirement_ids or item["classification"] not in CLASSIFICATIONS or item["confirmation_state"] not in CONFIRMATIONS or not isinstance(item["blocker_eligible"], bool) or not isinstance(item["required_evidence_categories"], list) or not item["required_evidence_categories"] or not set(item["required_evidence_categories"]).issubset(EVIDENCE) or not set(item["ambiguity_local_ids"]).issubset(ambiguity_ids): raise ValueError("invalid criterion")
        _refs(item["source_refs"], sources)
        for field, refs in item["field_source_refs"].items():
            if field not in {"actor", "action", "failure_behavior"} or not _supported(item[field], _refs(refs, sources)): raise ValueError("criterion field lacks exact quote support")
        for field in ("actor", "action", "failure_behavior"):
            if item[field] is not None and field not in item["field_source_refs"]: item["classification"] = "inferred_requires_owner"
        if item["preconditions"] or item["expected_outcomes"]: item["classification"] = "inferred_requires_owner"
        if item["classification"] == "inferred_requires_owner": item["confirmation_state"] = "owner_confirmation_required"; item["blocker_eligible"] = False
        if item["blocker_eligible"] and (item["classification"] != "explicit" or item["ambiguity_local_ids"] or item["confirmation_state"] != "confirmed"): raise ValueError("criterion is not eligible to block")
        criterion_ids.add(item["local_id"])
    if any(not set(x["affected_criterion_local_ids"]).issubset(criterion_ids) for x in proposal["ambiguities"]): raise ValueError("ambiguity references unknown criterion")
    if any(x["status"] == "blocked_by_ambiguity" and not x["ambiguity_local_ids"] for x in proposal["requirements"]): raise ValueError("blocked requirement lacks ambiguity")


def _claims(proposal: dict, packet: dict) -> tuple[list[dict], dict[str, str]]:
    sources = {x["source_id"]: x for x in packet["sources"]}; groups: dict[str, list[dict]] = {}
    for claim in proposal["claims"]: groups.setdefault(claim["claim_key"], []).append(claim)
    ledger = []; statuses = {}
    for key, claims in groups.items():
        cardinality = claims[0]["cardinality"]
        if any(x["cardinality"] != cardinality for x in claims): raise ValueError("claim key cardinality is inconsistent")
        ranked = [(min(TIERS.index(sources[r["source_id"]]["authority_tier"]) for r in c["source_refs"]), c) for c in claims]
        top = min(rank for rank, _ in ranked); top_values = {canonical_json(c["value"]) for rank, c in ranked if rank == top}
        for rank, claim in ranked:
            status = "resolved" if cardinality == "multi" or (rank == top and len(top_values) == 1) else ("conflicted" if rank == top else "superseded")
            if claim["classification"] == "inferred_requires_owner": status = "inferred_requires_owner"
            statuses[claim["local_id"]] = status
            ledger.append({"claim_id": _id("claim", {"packet": packet["packet_hash"], "claim": claim}), "local_id": claim["local_id"], "claim_key": key, "cardinality": cardinality, "value": claim["value"], "source_refs": claim["source_refs"], "authority_tier": TIERS[rank], "classification": claim["classification"], "resolution_status": status, "working_value": claim["value"] if status == "resolved" else None})
    return ledger, statuses


def _validate_artifacts(artifacts: dict, packet: dict) -> None:
    if set(artifacts) != set(ARTIFACTS): raise ValueError("exact artifact set is required")
    req = artifacts["requirements.json"]; crit = artifacts["acceptance-criteria.json"]; amb = artifacts["ambiguities.json"]; intent = artifacts["product-intent.json"]
    common = {"release_id", "release_commit", "project_authority", "compiler_version", "source_packet_hash"}
    intent_fields = {"schema_version", *common, "project_name", "product_purpose", "target_users", "release_promise", "release_scope", "non_goals", "owner_constraints", "claims", "working_intent", "source_coverage", "coverage_boundary"}
    if set(intent) != intent_fields or set(req) != {"schema_version", *common, "requirements"} or set(crit) != {"schema_version", *common, "criteria"} or set(amb) != {"schema_version", *common, "ambiguities"}: raise ValueError("artifact fields mismatch")
    if intent.get("schema_version") != INTENT_SCHEMA or req.get("schema_version") != REQUIREMENTS_SCHEMA or crit.get("schema_version") != CRITERIA_SCHEMA or amb.get("schema_version") != AMBIGUITIES_SCHEMA: raise ValueError("artifact schema mismatch")
    for value in artifacts.values():
        if value.get("release_id") != packet["release_id"] or value.get("release_commit") != packet["release_commit"] or value.get("source_packet_hash") != packet["packet_hash"] or value.get("project_authority") != packet["project_authority"]: raise ValueError("artifact binding mismatch")
    req_ids = {x["requirement_id"] for x in req["requirements"]}; amb_ids = {x["ambiguity_id"] for x in amb["ambiguities"]}
    if not all(isinstance(value, list) for value in (req["requirements"], crit["criteria"], amb["ambiguities"], intent["claims"], intent["source_coverage"])) or not isinstance(intent["working_intent"], dict): raise ValueError("artifact field types are invalid")
    for x in crit["criteria"]:
        if x["requirement_id"] not in req_ids or not set(x["ambiguity_dependencies"]).issubset(amb_ids) or (x["classification"] == "inferred_requires_owner" and x["blocker_eligible"]): raise ValueError("invalid criterion artifact")


def compile_bundle(ctx: LocalExecutionContext, proposal_file: str | None = None) -> dict:
    ctx.require("file.read"); packet, packet_bytes = _load_packet(ctx); proposal = None; proposal_bytes = None
    if proposal_file:
        proposal_bytes = _proposal_path(ctx, proposal_file).read_bytes(); proposal = json.loads(proposal_bytes.decode("utf-8")); _validate_proposal(proposal, packet)
    common = {"release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "compiler_version": COMPILER_VERSION, "source_packet_hash": packet["packet_hash"]}
    if proposal:
        ledger, claim_status = _claims(proposal, packet); local_req = {x["local_id"]: _id("req", {"packet": packet["packet_hash"], "item": x}) for x in proposal["requirements"]}; local_amb = {x["local_id"]: _id("ambiguity", {"packet": packet["packet_hash"], "item": x}) for x in proposal["ambiguities"]}
        requirements = []
        for x in proposal["requirements"]:
            state = "superseded" if x["claim_local_ids"] and all(claim_status[c] == "superseded" for c in x["claim_local_ids"]) else ("blocked_by_ambiguity" if any(claim_status[c] == "conflicted" for c in x["claim_local_ids"]) else x["status"])
            requirements.append({"requirement_id": local_req[x["local_id"]], **{k: v for k, v in x.items() if k != "local_id"}, "status": state, "ambiguity_dependencies": [local_amb[a] for a in x["ambiguity_local_ids"]]})
        criteria = []
        for x in proposal["criteria"]:
            parent = next(r for r in requirements if r["requirement_id"] == local_req[x["parent_requirement_local_id"]]); deps = [local_amb[a] for a in x["ambiguity_local_ids"]]
            criteria.append({"criterion_id": _id("criterion", {"packet": packet["packet_hash"], "item": x}), "requirement_id": parent["requirement_id"], **{k: v for k, v in x.items() if k not in {"local_id", "parent_requirement_local_id"}}, "ambiguity_dependencies": deps, "blocker_eligible": bool(x["blocker_eligible"] and parent["status"] == "active" and not deps)})
        ambiguities = [{"ambiguity_id": local_amb[x["local_id"]], **{k: v for k, v in x.items() if k != "local_id"}, "affected_requirement_ids": [local_req[v] for v in x["affected_requirement_local_ids"]], "affected_criterion_ids": [next(c["criterion_id"] for c in criteria if c["local_id"] == v) for v in x["affected_criterion_local_ids"]]} for x in proposal["ambiguities"]]
    else:
        owner = packet["sources"][0]; ref = {"source_id": owner["source_id"], "start_line": 1, "end_line": len(owner["text"].split("\n")), "quote": owner["text"], "quote_hash": _source_hash(owner["text"])}; promise = ctx.release["product"].get("promise"); journeys = ctx.release["product"].get("critical_journey", [])
        requirements = ([{"requirement_id": _id("req", {"promise": promise, "packet": packet["packet_hash"]}), "statement": promise, "classification": "explicit", "status": "active", "source_refs": [ref], "claim_local_ids": [], "related_journey_ids": [], "materiality": "release_scope", "rationale": "release owner promise", "owner_confirmation_required": False, "ambiguity_local_ids": [], "ambiguity_dependencies": []}] if promise else [])
        ambiguities = [{"ambiguity_id": _id("ambiguity", {"packet": packet["packet_hash"], "kind": "acceptance"}), "title": "Acceptance details are not supplied", "source_refs": [ref], "why_material": "Journey behavior has no detailed acceptance contract.", "options": [], "recommendation": "Provide a Product Intent proposal.", "blocked_conclusions": ["Blocker eligibility"], "affected_requirement_local_ids": [], "affected_criterion_local_ids": [], "affected_requirement_ids": [], "affected_criterion_ids": []}]
        criteria = [{"criterion_id": _id("criterion", {"journey": x, "packet": packet["packet_hash"]}), "requirement_id": requirements[0]["requirement_id"] if requirements else "", "local_id": None, "actor": None, "preconditions": [], "action": x, "expected_outcomes": [], "failure_behavior": None, "required_evidence_categories": ["owner_confirmation"], "source_refs": [ref], "field_source_refs": {}, "classification": "inferred_requires_owner", "confirmation_state": "owner_confirmation_required", "blocker_eligible": False, "ambiguity_local_ids": ["acceptance"], "ambiguity_dependencies": [ambiguities[0]["ambiguity_id"]]} for x in journeys if requirements]
        ledger = []
    product = ctx.release["product"]; recognized = {"release.promise": "release_promise", "release.target_user": "target_user", "release.publication_mode": "publication_mode"}; working = {recognized[x["claim_key"]]: x["working_value"] for x in ledger if x["claim_key"] in recognized and x["resolution_status"] == "resolved" and x["working_value"] is not None}
    intent = {"schema_version": INTENT_SCHEMA, **common, "project_name": ctx.activation["contract"]["project_name"], "product_purpose": ctx.activation["contract"]["product_purpose"], "target_users": [product.get("target_user")] if product.get("target_user") else [], "release_promise": product.get("promise"), "release_scope": product.get("critical_journey", []), "non_goals": product.get("non_goals", []), "owner_constraints": ctx.release.get("owner_constraints", []), "claims": ledger, "working_intent": working, "source_coverage": packet["source_coverage"], "coverage_boundary": packet["coverage_boundary"]}
    artifacts = {"product-intent.json": intent, "requirements.json": {"schema_version": REQUIREMENTS_SCHEMA, **common, "requirements": requirements}, "acceptance-criteria.json": {"schema_version": CRITERIA_SCHEMA, **common, "criteria": criteria}, "ambiguities.json": {"schema_version": AMBIGUITIES_SCHEMA, **common, "ambiguities": ambiguities}}
    _validate_artifacts(artifacts, packet); return _persist(ctx, packet, packet_bytes, proposal, proposal_bytes, artifacts)


def _persist(ctx: LocalExecutionContext, packet: dict, packet_bytes: bytes, proposal: dict | None, proposal_bytes: bytes | None, artifacts: dict) -> dict:
    root = _root(ctx); generations = root / "generations"; generation = "gen_" + uuid.uuid4().hex; directory = generations / generation; directory.mkdir(parents=True)
    hashes = {}
    for name, value in artifacts.items(): path = directory / name; _atomic_file(path, value); hashes[name] = _hash_bytes(path.read_bytes())
    (directory / "source-packet.json").write_bytes(packet_bytes); snapshot_hash = _hash_bytes(packet_bytes)
    if proposal_bytes: (directory / "proposal.json").write_bytes(proposal_bytes)
    manifest = {"schema_version": MANIFEST_SCHEMA, "release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "source_packet_hash": packet["packet_hash"], "source_packet_snapshot_hash": snapshot_hash, "proposal_hash": content_hash(proposal) if proposal else "explicit-only", "proposal_snapshot_hash": _hash_bytes(proposal_bytes) if proposal_bytes else "explicit-only", "compiler_version": COMPILER_VERSION, "artifact_filenames": list(ARTIFACTS), "artifact_hashes": hashes}
    manifest["bundle_hash"] = content_hash(manifest); _atomic_file(directory / "manifest.json", manifest)
    pointer = {"schema_version": POINTER_SCHEMA, "generation": generation, "manifest_hash": _hash_bytes((directory / "manifest.json").read_bytes())}; _atomic_file(root / "current-generation.json", pointer); return manifest


def load_bundle(ctx: LocalExecutionContext) -> tuple[dict, dict]:
    packet, _ = _load_packet(ctx); pointer_path = _root(ctx) / "current-generation.json"
    if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("complete Product Intent generation is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    if set(pointer) != {"schema_version", "generation", "manifest_hash"} or pointer["schema_version"] != POINTER_SCHEMA or not re.fullmatch(r"gen_[0-9a-f]{32}", pointer["generation"]): raise ValueError("invalid Product Intent generation pointer")
    directory = _root(ctx) / "generations" / pointer["generation"]; manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or _hash_bytes(manifest_path.read_bytes()) != pointer["manifest_hash"]: raise ValueError("invalid Product Intent generation")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); fields = {"schema_version", "release_id", "release_commit", "project_authority", "source_packet_hash", "source_packet_snapshot_hash", "proposal_hash", "proposal_snapshot_hash", "compiler_version", "artifact_filenames", "artifact_hashes", "bundle_hash"}
    if set(manifest) != fields or manifest["schema_version"] != MANIFEST_SCHEMA or manifest["bundle_hash"] != content_hash({k: v for k, v in manifest.items() if k != "bundle_hash"}) or manifest["source_packet_hash"] != packet["packet_hash"] or manifest["artifact_filenames"] != list(ARTIFACTS): raise ValueError("stale or invalid Product Intent bundle")
    snapshot = directory / "source-packet.json"
    if not snapshot.is_file() or _hash_bytes(snapshot.read_bytes()) != manifest["source_packet_snapshot_hash"] or snapshot.read_bytes() != (_root(ctx) / "source-packet.json").read_bytes(): raise ValueError("bundle source packet snapshot is stale")
    artifacts = {}
    for name in ARTIFACTS:
        path = directory / name
        if not path.is_file() or _hash_bytes(path.read_bytes()) != manifest["artifact_hashes"].get(name): raise ValueError("invalid Product Intent artifact")
        artifacts[name] = json.loads(path.read_text(encoding="utf-8"))
    _validate_artifacts(artifacts, packet); return manifest, artifacts


def show(ctx: LocalExecutionContext) -> str:
    _, artifacts = load_bundle(ctx); intent = artifacts["product-intent.json"]; requirements = artifacts["requirements.json"]["requirements"]; criteria = artifacts["acceptance-criteria.json"]["criteria"]; ambiguities = artifacts["ambiguities.json"]["ambiguities"]
    lines = [f"Product Intent: {intent['project_name']}", f"Working promise: {intent['release_promise'] or 'not supplied'}", "Claims:"]
    lines += [f"- {x['claim_key']}={x['working_value']!r} [{x['resolution_status']}; {x['authority_tier']}]" for x in intent["claims"]] or ["- none"]
    lines += ["Requirements:"] + [f"- {x['requirement_id']} [{x['classification']}/{x['status']}] {x['statement']}" for x in requirements] + ["Criteria:"] + [f"- {x['criterion_id']} [{x['classification']}] blocker_eligible={x['blocker_eligible']}" for x in criteria] + ["Material ambiguities:"] + [f"- {x['title']}" for x in ambiguities] + ["Source coverage:"] + [f"- {x['path']} [{x['source_class']}] {x['status']}" for x in intent["source_coverage"]] + [f"Coverage boundary: {intent['coverage_boundary']}"]
    return "\n".join(lines)
