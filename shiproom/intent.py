from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .authority import LocalExecutionContext
from .project import canonical_json, content_hash

SOURCE_PACKET_SCHEMA = "intent-source-packet.v1"
PROPOSAL_SCHEMA = "intent-proposal.v1"
INTENT_SCHEMA = "product-intent.v1"
REQUIREMENTS_SCHEMA = "requirements.v1"
CRITERIA_SCHEMA = "acceptance-criteria.v1"
AMBIGUITIES_SCHEMA = "intent-ambiguities.v1"
MANIFEST_SCHEMA = "product-intent-bundle-manifest.v1"
COMPILER_VERSION = "product-intent.v1"
SOURCE_LIMIT = 256 * 1024
PROPOSAL_LIMIT = 256 * 1024
TIERS = ("release_owner_input", "current_release_source", "project_contract", "supporting_source")
EVIDENCE_CATEGORIES = {"browser_or_http", "content_assertion", "command_result", "file_or_artifact", "source_inspection", "instrumentation", "owner_confirmation"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _id(prefix: str, value: object) -> str:
    return prefix + "_" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:16]


def _normalize_text(raw: str) -> str:
    return raw.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def _normal(value: object) -> str:
    if not isinstance(value, (str, int, float, bool)) or isinstance(value, bool) and not isinstance(value, bool):
        raise ValueError("claim value must be a primitive")
    return re.sub(r"[\s_-]+", " ", str(value).strip().casefold())


def _root(context: LocalExecutionContext) -> Path:
    return context.repository_root / ".shiproom" / "local" / "releases" / context.release["release_id"] / "product-intent"


def _authority(context: LocalExecutionContext) -> dict:
    return {"project_id": context.activation["contract"]["project_id"], "contract_hash": context.authority_binding["contract_hash"], "contract_source": context.authority_binding["contract_source"], "authority_policy_version": context.authority_binding["authority_policy_version"]}


def _source_ref(source_id: str, locator: str, excerpt: str) -> dict:
    return {"source_id": source_id, "locator": locator, "excerpt_hash": "sha256:" + hashlib.sha256(excerpt.encode("utf-8")).hexdigest()}


def _headings(text: str) -> list[dict]:
    entries = [{"locator": "document", "line": 1, "excerpt_hash": _source_ref("", "", text)["excerpt_hash"]}]
    for number, line in enumerate(text.split("\n"), 1):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            locator = f"line:{number}:" + match.group(2)
            entries.append({"locator": locator, "line": number, "excerpt_hash": _source_ref("", "", line)["excerpt_hash"]})
    return entries


def _coverage(path: str, source_class: str, status: str, detail: str) -> dict:
    return {"path": path, "source_class": source_class, "status": status, "detail": detail}


def _read_markdown(context: LocalExecutionContext, path: str, source_class: str) -> tuple[dict | None, dict]:
    if Path(path).suffix.lower() not in {".md", ".markdown"}:
        return None, _coverage(path, source_class, "unsupported_type", "Only explicitly selected Markdown sources are supported")
    try:
        blob = context.read_release_blob(path, byte_limit=SOURCE_LIMIT)
    except PermissionError:
        return None, _coverage(path, source_class, "excluded_by_policy", "Source is excluded by project policy")
    except FileNotFoundError:
        return None, _coverage(path, source_class, "missing", "Source is absent from the release commit")
    except ValueError as exc:
        if "exceeds byte limit" in str(exc):
            return None, _coverage(path, source_class, "rejected_oversized", "Supply a smaller release-specific source")
        return None, _coverage(path, source_class, "unsupported_type", str(exc))
    if blob["classification"] != "text" or blob["text"] is None:
        return None, _coverage(path, source_class, "unsupported_type", "Source is binary or not UTF-8 text")
    text = _normalize_text(blob["text"])
    source_id = _id("src", {"path": blob["path"], "class": source_class, "blob": blob["blob_hash"]})
    source = {"source_id": source_id, "path": blob["path"], "source_class": source_class, "authority_tier": "current_release_source" if source_class == "current_release" else "supporting_source", "git_blob_hash": blob["blob_hash"], "normalized_text_hash": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(), "text": text, "locators": _headings(text)}
    return source, _coverage(path, source_class, "fully_included", "Complete normalized source included")


def _structured_sources(context: LocalExecutionContext) -> list[dict]:
    product = context.release["product"]
    owner = {key: product.get(key) for key in ("name", "target_user", "promise", "critical_journey", "non_goals")}
    owner["owner_constraints"] = context.release.get("owner_constraints", [])
    contract = {key: context.activation["contract"].get(key) for key in ("project_name", "product_purpose", "primary_users", "project_principles")}
    result = []
    for source_id, tier, value in (("release_owner_input", "release_owner_input", owner), ("project_contract", "project_contract", contract)):
        text = canonical_json(value)
        result.append({"source_id": source_id, "path": None, "source_class": "structured", "authority_tier": tier, "content_hash": content_hash(value), "text": text, "locators": [{"locator": "structured", "line": None, "excerpt_hash": "sha256:" + hashlib.sha256(text.encode()).hexdigest()}]})
    return result


def prepare(context: LocalExecutionContext, sources: list[str], supporting_sources: list[str]) -> dict:
    context.require("file.read")
    if len(set(sources + supporting_sources)) != len(sources + supporting_sources):
        raise ValueError("a source path may be supplied only once")
    records = _structured_sources(context); coverage = []
    for path, kind in [(p, "current_release") for p in sources] + [(p, "supporting_source") for p in supporting_sources]:
        source, item = _read_markdown(context, path, kind); coverage.append(item)
        if source: records.append(source)
    rejected = next((item for item in coverage if item["status"] in {"excluded_by_policy", "rejected_oversized"}), None)
    if rejected:
        if rejected["status"] == "rejected_oversized": raise ValueError(f"source {rejected['path']} is oversized; supply a smaller release-specific source")
        raise PermissionError(f"source {rejected['path']} is excluded by project policy")
    packet = {"schema_version": SOURCE_PACKET_SCHEMA, "release_id": context.release["release_id"], "release_commit": context.authority_binding["repository_commit"], "project_authority": _authority(context), "compiler_version": COMPILER_VERSION, "sources": records, "source_coverage": coverage, "coverage_boundary": "Only complete normalized text from explicitly selected Markdown sources under the per-file cap is included.", "generated_at": _now()}
    packet["packet_hash"] = content_hash({k: v for k, v in packet.items() if k not in {"generated_at", "packet_hash"}})
    validate_packet(packet)
    root = _root(context); root.mkdir(parents=True, exist_ok=True); (root / "inbox").mkdir(exist_ok=True)
    _write_json(root / "source-packet.json", packet)
    return packet


def validate_packet(packet: dict) -> None:
    required = {"schema_version", "release_id", "release_commit", "project_authority", "compiler_version", "sources", "source_coverage", "coverage_boundary", "generated_at", "packet_hash"}
    if set(packet) != required or packet["schema_version"] != SOURCE_PACKET_SCHEMA or not packet["sources"]:
        raise ValueError("invalid intent-source-packet.v1")
    if packet["packet_hash"] != content_hash({k: v for k, v in packet.items() if k not in {"generated_at", "packet_hash"}}): raise ValueError("source packet hash mismatch")
    ids = set()
    for source in packet["sources"]:
        if source.get("source_id") in ids or source.get("authority_tier") not in TIERS or not isinstance(source.get("locators"), list): raise ValueError("invalid packet source")
        ids.add(source["source_id"])


def _load_packet(context: LocalExecutionContext) -> dict:
    path = _root(context) / "source-packet.json"
    if path.is_symlink() or not path.is_file(): raise ValueError("prepared source packet is missing")
    packet = json.loads(path.read_text(encoding="utf-8")); validate_packet(packet)
    if packet["release_id"] != context.release["release_id"] or packet["release_commit"] != context.authority_binding["repository_commit"] or packet["project_authority"]["contract_hash"] != context.authority_binding["contract_hash"]: raise ValueError("source packet is stale for this release authority")
    return packet


def _proposal_path(context: LocalExecutionContext, value: str) -> Path:
    inbox = (_root(context) / "inbox").resolve(); raw = Path(value).absolute()
    if raw.is_symlink(): raise ValueError("proposal must be a bounded regular JSON file in the release-local inbox")
    candidate = raw.resolve()
    if inbox not in candidate.parents or candidate == inbox: raise ValueError("proposal must be inside the release-local product-intent inbox")
    if candidate.suffix.lower() != ".json" or candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > PROPOSAL_LIMIT: raise ValueError("proposal must be a bounded regular JSON file in the release-local inbox")
    return candidate


def _citation(ref: dict, sources: dict) -> None:
    if set(ref) != {"source_id", "locator", "excerpt_hash"} or ref["source_id"] not in sources: raise ValueError("proposal cites an unknown source")
    if not any(item["locator"] == ref["locator"] and item["excerpt_hash"] == ref["excerpt_hash"] for item in sources[ref["source_id"]]["locators"]): raise ValueError("proposal citation locator or excerpt hash is invalid")


def _citations(refs: object, sources: dict) -> list[dict]:
    if not isinstance(refs, list) or not refs: raise ValueError("proposal records require source references")
    for ref in refs: _citation(ref, sources)
    return refs


def _validate_proposal(proposal: dict, packet: dict) -> None:
    required = {"schema_version", "release_id", "release_commit", "source_packet_hash", "claims", "requirements", "criteria", "ambiguities"}
    if set(proposal) != required or proposal.get("schema_version") != PROPOSAL_SCHEMA: raise ValueError("invalid intent-proposal.v1")
    if proposal["release_id"] != packet["release_id"] or proposal["release_commit"] != packet["release_commit"] or proposal["source_packet_hash"] != packet["packet_hash"]: raise ValueError("proposal is not bound to this release source packet")
    sources = {s["source_id"]: s for s in packet["sources"]}; keys = set(); local_ids = set()
    for claim in proposal["claims"]:
        if set(claim) != {"claim_key", "value", "single_valued", "source_refs"} or not isinstance(claim["claim_key"], str) or not claim["single_valued"]: raise ValueError("claims must declare a single-valued schema-valid key")
        _normal(claim["value"]); _citations(claim["source_refs"], sources); keys.add(claim["claim_key"])
    for item in proposal["requirements"]:
        required_item = {"local_id", "statement", "classification", "status", "source_refs", "related_journey_ids", "materiality", "rationale", "owner_confirmation_required"}
        if set(item) != required_item or item["local_id"] in local_ids or item["classification"] not in {"explicit", "inferred_requires_owner"} or item["status"] not in {"active", "proposed", "blocked_by_ambiguity", "superseded"} or not isinstance(item["owner_confirmation_required"], bool): raise ValueError("invalid proposal requirement")
        _citations(item["source_refs"], sources); local_ids.add(item["local_id"])
    for item in proposal["criteria"]:
        required_item = {"parent_local_id", "actor", "preconditions", "action", "expected_outcomes", "failure_behavior", "required_evidence_categories", "source_refs", "classification", "confirmation_state", "blocker_eligible", "ambiguity_dependencies"}
        if set(item) != required_item or item["parent_local_id"] not in local_ids or item["classification"] not in {"explicit", "inferred_requires_owner"} or not set(item["required_evidence_categories"]).issubset(EVIDENCE_CATEGORIES): raise ValueError("invalid proposal criterion")
        _citations(item["source_refs"], sources)
        if item["blocker_eligible"] and (item["classification"] != "explicit" or item["ambiguity_dependencies"]): raise ValueError("inferred or ambiguous criteria cannot be blocker eligible")
    for item in proposal["ambiguities"]:
        if set(item) != {"title", "source_refs", "why_material", "options", "recommendation", "blocked_conclusions"} or len(item["options"]) > 3: raise ValueError("invalid proposal ambiguity")
        _citations(item["source_refs"], sources)


def _conflicts(proposal: dict, packet: dict) -> list[dict]:
    sources = {s["source_id"]: s for s in packet["sources"]}; grouped: dict[str, list[dict]] = {}
    for claim in proposal["claims"]: grouped.setdefault(claim["claim_key"], []).append(claim)
    conflicts = []
    for key, claims in grouped.items():
        values = {_normal(c["value"]) for c in claims}
        if len(values) < 2: continue
        refs = [ref for claim in claims for ref in claim["source_refs"]]
        if len({(ref["source_id"], ref["locator"], ref["excerpt_hash"]) for ref in refs}) < 2: continue
        ranks = {ref["source_id"]: TIERS.index(sources[ref["source_id"]]["authority_tier"]) for ref in refs}
        highest = min(ranks.values()); top_values = {_normal(claim["value"]) for claim in claims if any(ranks[r["source_id"]] == highest for r in claim["source_refs"])}
        conflicts.append({"conflict_id": _id("conflict", {"key": key, "claims": claims}), "claim_key": key, "claims": claims, "working_value": None if len(top_values) > 1 else next(iter(top_values)), "highest_tier_conflict": len(top_values) > 1, "source_refs": refs})
    return conflicts


def _explicit(context: LocalExecutionContext, packet: dict) -> tuple[list[dict], list[dict], list[dict]]:
    source = packet["sources"][0]; ref = _source_ref(source["source_id"], "structured", source["text"])
    product = context.release["product"]; requirements = []; criteria = []; ambiguities = []
    fields = [("promise", product.get("promise")), ("target_user", product.get("target_user"))]
    fields += [("critical_journey", value) for value in product.get("critical_journey", [])] + [("non_goal", value) for value in product.get("non_goals", [])]
    for field, value in fields:
        if not value: continue
        rid = _id("req", {"field": field, "value": value, "packet": packet["packet_hash"]})
        requirements.append({"requirement_id": rid, "statement": str(value), "classification": "explicit", "status": "active", "source_refs": [ref], "source_authority": "release_owner_input", "related_journey_ids": [str(value)] if field == "critical_journey" else [], "materiality": "release_scope", "rationale": f"Exact release owner input: {field}", "owner_confirmation_required": False})
        if field == "critical_journey":
            criteria.append({"criterion_id": _id("criterion", {"requirement_id": rid, "action": value}), "requirement_id": rid, "actor": None, "preconditions": [], "action": str(value), "expected_outcomes": [], "failure_behavior": None, "required_evidence_categories": ["owner_confirmation"], "source_refs": [ref], "classification": "explicit", "confirmation_state": "proposal_needed", "blocker_eligible": False, "ambiguity_dependencies": ["acceptance_details_missing"]})
    ambiguities.append({"ambiguity_id": _id("ambiguity", {"packet": packet["packet_hash"], "kind": "acceptance_details"}), "title": "Acceptance details are not supplied", "affected_requirement_ids": [r["requirement_id"] for r in requirements], "affected_criterion_ids": [c["criterion_id"] for c in criteria], "source_refs": [ref], "why_material": "Owner input defines scope but not detailed acceptance behavior.", "options": [], "recommendation": "Provide a structured Product Intent proposal.", "blocked_conclusions": ["Detailed acceptance outcomes and blocker eligibility"]})
    return requirements, criteria, ambiguities


def compile_bundle(context: LocalExecutionContext, proposal_file: str | None = None) -> dict:
    context.require("file.read"); packet = _load_packet(context); proposal = None
    if proposal_file:
        proposal = json.loads(_proposal_path(context, proposal_file).read_text(encoding="utf-8")); _validate_proposal(proposal, packet)
        requirements = []; local = {}
        for item in proposal["requirements"]:
            rid = _id("req", {k: v for k, v in item.items() if k != "local_id"} | {"packet": packet["packet_hash"]}); local[item["local_id"]] = rid
            requirements.append({"requirement_id": rid, **{k: v for k, v in item.items() if k != "local_id"}, "source_authority": min((next(s["authority_tier"] for s in packet["sources"] if s["source_id"] == r["source_id"]) for r in item["source_refs"]), key=TIERS.index)})
        conflicts = _conflicts(proposal, packet); conflict_refs = {r["source_id"] for c in conflicts for r in c["source_refs"] if c["highest_tier_conflict"]}
        for item in requirements:
            if any(r["source_id"] in conflict_refs for r in item["source_refs"]): item["status"] = "blocked_by_ambiguity"
        criteria = []
        for item in proposal["criteria"]:
            parent = local[item["parent_local_id"]]; blocked = next(r for r in requirements if r["requirement_id"] == parent)["status"] == "blocked_by_ambiguity"
            criteria.append({"criterion_id": _id("criterion", {k: v for k, v in item.items() if k != "parent_local_id"} | {"requirement_id": parent}), "requirement_id": parent, **{k: v for k, v in item.items() if k != "parent_local_id"}, "blocker_eligible": bool(item["blocker_eligible"] and not blocked)})
        ambiguities = [{"ambiguity_id": _id("ambiguity", x), "affected_requirement_ids": [], "affected_criterion_ids": [], **x} for x in proposal["ambiguities"]]
        for conflict in conflicts:
            ambiguities.append({"ambiguity_id": _id("ambiguity", conflict), "title": f"Conflicting {conflict['claim_key']}", "affected_requirement_ids": [r["requirement_id"] for r in requirements if any(ref["source_id"] in {x["source_id"] for x in conflict["source_refs"]} for ref in r["source_refs"])], "affected_criterion_ids": [], "source_refs": conflict["source_refs"], "why_material": "Conflicting source-backed values remain visible.", "options": [], "recommendation": None, "blocked_conclusions": ["Working release intent"]})
    else:
        requirements, criteria, ambiguities = _explicit(context, packet); conflicts = []
    product = context.release["product"]; intent = {"schema_version": INTENT_SCHEMA, "release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "compiler_version": COMPILER_VERSION, "project_name": context.activation["contract"]["project_name"], "product_purpose": context.activation["contract"]["product_purpose"], "target_users": [product.get("target_user")] if product.get("target_user") else [], "release_promise": product.get("promise"), "release_scope": product.get("critical_journey", []), "non_goals": product.get("non_goals", []), "owner_constraints": context.release.get("owner_constraints", []), "source_conflicts": conflicts, "unresolved_material_ambiguities": [a["ambiguity_id"] for a in ambiguities], "source_coverage": packet["source_coverage"], "coverage_boundary": packet["coverage_boundary"]}
    common = {"release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "compiler_version": COMPILER_VERSION, "source_packet_hash": packet["packet_hash"], "source_coverage": packet["source_coverage"], "coverage_boundary": packet["coverage_boundary"]}
    artifacts = {"product-intent.json": intent, "requirements.json": {"schema_version": REQUIREMENTS_SCHEMA, **common, "requirements": requirements}, "acceptance-criteria.json": {"schema_version": CRITERIA_SCHEMA, **common, "criteria": criteria}, "ambiguities.json": {"schema_version": AMBIGUITIES_SCHEMA, **common, "ambiguities": ambiguities}}
    _validate_bundle(artifacts, packet, proposal)
    return _persist(context, packet, proposal, artifacts)


def _validate_bundle(artifacts: dict, packet: dict, proposal: dict | None) -> None:
    requirements = artifacts["requirements.json"]["requirements"]; ids = {r["requirement_id"] for r in requirements}
    for criterion in artifacts["acceptance-criteria.json"]["criteria"]:
        if criterion["requirement_id"] not in ids: raise ValueError("criterion parent requirement is missing")
        if criterion["blocker_eligible"] and (criterion["classification"] != "explicit" or criterion["ambiguity_dependencies"]): raise ValueError("invalid blocker eligibility")


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _persist(context: LocalExecutionContext, packet: dict, proposal: dict | None, artifacts: dict) -> dict:
    root = _root(context); root.mkdir(parents=True, exist_ok=True); temporary = root / f".bundle-{uuid.uuid4().hex}"; temporary.mkdir()
    try:
        hashes = {}
        for filename, value in artifacts.items(): _write_json(temporary / filename, value); hashes[filename] = "sha256:" + hashlib.sha256((temporary / filename).read_bytes()).hexdigest()
        manifest = {"schema_version": MANIFEST_SCHEMA, "release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "source_packet_hash": packet["packet_hash"], "proposal_hash": content_hash(proposal) if proposal else "explicit-only", "compiler_version": COMPILER_VERSION, "artifact_filenames": sorted(hashes), "artifact_hashes": hashes}
        manifest["bundle_hash"] = content_hash(manifest)
        _write_json(temporary / "manifest.json", manifest)
        target = root / "bundle"; old = root / f".previous-{uuid.uuid4().hex}"
        if target.exists(): os.replace(target, old)
        try: os.replace(temporary, target)
        except Exception:
            if old.exists(): os.replace(old, target)
            raise
        if old.exists(): shutil.rmtree(old)
        return manifest
    except Exception:
        if temporary.exists(): shutil.rmtree(temporary)
        raise


def load_bundle(context: LocalExecutionContext) -> tuple[dict, dict]:
    root = _root(context) / "bundle"; manifest_path = root / "manifest.json"
    if not root.is_dir() or manifest_path.is_symlink() or not manifest_path.is_file(): raise ValueError("complete Product Intent bundle is unavailable")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    required = {"schema_version", "release_id", "release_commit", "project_authority", "source_packet_hash", "proposal_hash", "compiler_version", "artifact_filenames", "artifact_hashes", "bundle_hash"}
    if set(manifest) != required or manifest["schema_version"] != MANIFEST_SCHEMA or manifest["bundle_hash"] != content_hash({k: v for k, v in manifest.items() if k != "bundle_hash"}): raise ValueError("Product Intent bundle manifest is invalid")
    if manifest["release_id"] != context.release["release_id"] or manifest["release_commit"] != context.authority_binding["repository_commit"] or manifest["project_authority"]["contract_hash"] != context.authority_binding["contract_hash"]: raise ValueError("Product Intent bundle is stale")
    artifacts = {}
    for filename in manifest["artifact_filenames"]:
        path = root / filename
        if path.is_symlink() or not path.is_file() or "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() != manifest["artifact_hashes"].get(filename): raise ValueError("Product Intent bundle artifact is invalid")
        artifacts[filename] = json.loads(path.read_text(encoding="utf-8"))
    _validate_bundle(artifacts, _load_packet(context), None)
    return manifest, artifacts


def show(context: LocalExecutionContext) -> str:
    _, artifacts = load_bundle(context); intent = artifacts["product-intent.json"]; reqs = artifacts["requirements.json"]["requirements"]; criteria = artifacts["acceptance-criteria.json"]["criteria"]; ambiguities = artifacts["ambiguities.json"]["ambiguities"]
    lines = [f"Product Intent: {intent['project_name']}", f"Promise: {intent['release_promise'] or 'not supplied'}", "Requirements:"]
    lines += [f"- {r['requirement_id']} [{r['classification']}/{r['status']}] {r['statement']}" for r in reqs] or ["- none"]
    lines += ["Criteria:"] + [f"- {c['criterion_id']} [{c['classification']}] blocker_eligible={c['blocker_eligible']}" for c in criteria] + ["Material ambiguities:"] + [f"- {a['title']}" for a in ambiguities]
    return "\n".join(lines)
