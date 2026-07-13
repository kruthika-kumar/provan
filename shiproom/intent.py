from __future__ import annotations

import hashlib
import json
import math
import os
import re
import uuid
from pathlib import Path
from typing import Any

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
CLAIM_REGISTRY = {"release.promise": "single", "release.publication_mode": "single", "release.target_user": "single", "release.critical_journey": "multi", "release.non_goals": "multi", "project.product_purpose": "single", "project.primary_users": "multi"}
CLAIM_PROJECTION = {"release.promise": "release_promise", "release.publication_mode": "publication_mode", "release.target_user": "target_user", "release.critical_journey": "critical_journey", "release.non_goals": "non_goals", "project.product_purpose": "product_purpose", "project.primary_users": "primary_users"}


def _id(prefix: str, value: object) -> str: return prefix + "_" + hashlib.sha256(canonical_json(value).encode()).hexdigest()[:16]
def _hash_bytes(value: bytes) -> str: return "sha256:" + hashlib.sha256(value).hexdigest()
def _normal_text(value: str) -> str: return value.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
def _mechanical(value: str) -> str: return re.sub(r"\s+", " ", _normal_text(value).strip())
def _root(ctx: LocalExecutionContext) -> Path: return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "product-intent"
def _authority(ctx: LocalExecutionContext) -> dict: return {key: ctx.authority_binding[key] for key in ("project_id", "contract_hash", "contract_source", "authority_policy_version")}
def _source_hash(text: str) -> str: return _hash_bytes(text.encode("utf-8"))
def _sort(values: list[Any]) -> list[Any]: return [json.loads(x) for x in sorted({canonical_json(v) for v in values})]
def _primitive(value: object) -> bool: return value is not None and not isinstance(value, (list, dict)) and (not isinstance(value, float) or math.isfinite(value))
def _token(value: object) -> str:
    if not _primitive(value): raise ValueError("claim value must be a finite non-null JSON primitive")
    if isinstance(value, str): return "string:" + re.sub(r"[\s_-]+", " ", value.casefold()).strip()
    return "typed:" + canonical_json(value)


def _locators(text: str) -> list[dict]: return [{"start_line": i, "end_line": i, "quote_hash": _source_hash(line)} for i, line in enumerate(text.split("\n"), 1)]


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
    text = _normal_text(blob["text"])
    return {"source_id": _id("src", {"path": blob["path"], "class": source_class, "blob": blob["blob_hash"]}), "path": blob["path"], "source_class": source_class, "authority_tier": "current_release_source" if source_class == "current_release" else "supporting_source", "git_blob_hash": blob["blob_hash"], "normalized_text_hash": _source_hash(text), "text": text, "locators": _locators(text)}


def _lexical_path(path: str) -> str:
    if not isinstance(path, str) or not path or Path(path).is_absolute(): raise ValueError("invalid requested source path")
    pieces = []
    for part in path.replace("\\", "/").split("/"):
        if part in {"", "."}: continue
        if part == "..": raise ValueError("invalid requested source path")
        pieces.append(part)
    if not pieces: raise ValueError("invalid requested source path")
    return "/".join(pieces).casefold()


def _packet(ctx: LocalExecutionContext, requested: list[dict]) -> dict:
    sources = _structured(ctx); coverage = []
    resolved = set()
    for item in requested:
        source = _read(ctx, item["path"], item["source_class"])
        if source["path"] in resolved: raise ValueError(f"duplicate source path: {source['path']}")
        resolved.add(source["path"]); sources.append(source); coverage.append({"path": source["path"], "source_class": item["source_class"], "status": "fully_included"})
    packet = {"schema_version": SOURCE_PACKET_SCHEMA, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": _authority(ctx), "compiler_version": COMPILER_VERSION, "requested_sources": requested, "sources": sorted(sources, key=lambda x: x["source_id"]), "source_coverage": sorted(coverage, key=lambda x: (x["path"], x["source_class"])), "coverage_boundary": "Complete normalized text for every explicitly selected Markdown source; no discovery or truncation."}
    packet["packet_hash"] = content_hash(packet); return packet


def validate_packet(packet: dict) -> None:
    fields = {"schema_version", "release_id", "release_commit", "project_authority", "compiler_version", "requested_sources", "sources", "source_coverage", "coverage_boundary", "packet_hash"}
    if set(packet) != fields or packet["schema_version"] != SOURCE_PACKET_SCHEMA or packet["packet_hash"] != content_hash({k: v for k, v in packet.items() if k != "packet_hash"}): raise ValueError("invalid source packet")
    if not isinstance(packet["requested_sources"], list) or len(packet["requested_sources"]) != len(packet["source_coverage"]): raise ValueError("invalid source coverage")
    lexical = [_lexical_path(x.get("path")) for x in packet["requested_sources"] if isinstance(x, dict)]
    if len(lexical) != len(packet["requested_sources"]) or len(set(lexical)) != len(lexical) or any(set(x) != {"path", "source_class"} or x["source_class"] not in {"current_release", "supporting_source"} for x in packet["requested_sources"]): raise ValueError("invalid requested sources")
    if any(x != {"path": x["path"], "source_class": x["source_class"], "status": "fully_included"} for x in packet["source_coverage"]): raise ValueError("partial source coverage is not allowed")
    ids = set(); paths = set()
    for source in packet["sources"]:
        required = {"source_id", "path", "source_class", "authority_tier", "git_blob_hash", "normalized_text_hash", "text", "locators"}
        if set(source) != required or not isinstance(source["source_id"], str) or source["source_id"] in ids or source["authority_tier"] not in TIERS or not isinstance(source["text"], str) or source["normalized_text_hash"] != _source_hash(source["text"]) or source["locators"] != _locators(source["text"]): raise ValueError("invalid packet source")
        if source["path"] is not None and (source["path"] in paths or source["source_class"] not in {"current_release", "supporting_source"}): raise ValueError("duplicate or invalid packet source")
        ids.add(source["source_id"]); paths.add(source["path"])


def _atomic_file(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"); os.replace(temp, path)


def prepare(ctx: LocalExecutionContext, sources: list[str], supporting_sources: list[str]) -> dict:
    ctx.require("file.read")
    requested = [{"path": x, "source_class": "current_release"} for x in sources] + [{"path": x, "source_class": "supporting_source"} for x in supporting_sources]
    lexical = [_lexical_path(x["path"]) for x in requested]
    if len(set(lexical)) != len(lexical): raise ValueError("duplicate requested source path")
    requested.sort(key=lambda x: (_lexical_path(x["path"]), x["source_class"]))
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


def _pointer_get(value: object, pointer: str) -> object:
    if not isinstance(pointer, str) or not pointer.startswith("/"): raise ValueError("invalid structured authority reference")
    current = value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current: current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current): current = current[int(part)]
        else: raise ValueError("structured authority field is unavailable")
    return current


def _quote(ref: dict, sources: dict) -> None:
    fields = {"source_id", "start_line", "end_line", "quote", "quote_hash"}
    if set(ref) != fields or ref["source_id"] not in sources or sources[ref["source_id"]]["source_class"] == "structured" or not isinstance(ref["start_line"], int) or not isinstance(ref["end_line"], int) or not isinstance(ref["quote"], str) or ref["start_line"] < 1 or ref["end_line"] < ref["start_line"]: raise ValueError("invalid quote reference")
    lines = sources[ref["source_id"]]["text"].split("\n")
    if ref["end_line"] > len(lines): raise ValueError("quote range is invalid")
    actual = "\n".join(lines[ref["start_line"] - 1:ref["end_line"]])
    if actual.count(ref["quote"]) != 1 or ref["quote_hash"] != _source_hash(ref["quote"]): raise ValueError("quote range or hash is invalid")


def _structured_ref(ref: dict, sources: dict) -> None:
    fields = {"source_id", "field_path", "value_hash"}
    if set(ref) != fields or ref["source_id"] not in sources or sources[ref["source_id"]]["source_class"] != "structured" or not isinstance(ref["value_hash"], str): raise ValueError("invalid structured authority reference")
    value = _pointer_get(json.loads(sources[ref["source_id"]]["text"]), ref["field_path"])
    if ref["value_hash"] != _hash_bytes(canonical_json(value).encode("utf-8")): raise ValueError("structured authority value hash is invalid")


def _refs(refs: object, sources: dict) -> list[dict]:
    if not isinstance(refs, list) or not refs: raise ValueError("source support is required")
    for ref in refs:
        if not isinstance(ref, dict): raise ValueError("invalid source reference")
        if set(ref) == {"source_id", "start_line", "end_line", "quote", "quote_hash"}: _quote(ref, sources)
        elif set(ref) == {"source_id", "field_path", "value_hash"}: _structured_ref(ref, sources)
        else: raise ValueError("invalid source reference")
    return _sort(refs)


def _ref_supports(value: object, ref: dict, sources: dict) -> bool:
    if isinstance(value, str) and "quote" in ref: return _mechanical(value) == _mechanical(ref["quote"])
    if "field_path" in ref:
        structured = _pointer_get(json.loads(sources[ref["source_id"]]["text"]), ref["field_path"])
        return type(value) is type(structured) and value == structured
    return False


def _supported(value: object, refs: list[dict], sources: dict) -> bool: return isinstance(value, str) and any(_ref_supports(value, ref, sources) for ref in refs)
def _field_supported(value: object, refs: object, sources: dict) -> bool:
    if isinstance(value, list): return isinstance(refs, list) and len(value) == len(refs) and all(isinstance(item, str) and all(_ref_supports(item, ref, sources) for ref in _refs(item_refs, sources)) for item, item_refs in zip(value, refs))
    return isinstance(value, str) and all(_ref_supports(value, ref, sources) for ref in _refs(refs, sources))


def _canonical_field_pairs(values: list[str], ref_groups: object, sources: dict) -> tuple[list[str], list[list[dict]]]:
    if not isinstance(ref_groups, list) or len(values) != len(ref_groups): raise ValueError("criterion list evidence is invalid")
    grouped: dict[str, list[dict]] = {}
    for value, refs in zip(values, ref_groups):
        normalized = _mechanical(value); checked = _refs(refs, sources)
        if not normalized or not all(_ref_supports(value, ref, sources) for ref in checked): raise ValueError("criterion field lacks exact quote support")
        grouped.setdefault(normalized, []).extend(checked)
    pairs = sorted(({"value": value, "source_refs": _refs(refs, sources)} for value, refs in grouped.items()), key=canonical_json)
    return [pair["value"] for pair in pairs], [pair["source_refs"] for pair in pairs]


def _validate_proposal(proposal: dict, packet: dict) -> None:
    fields = {"schema_version", "release_id", "release_commit", "source_packet_hash", "claims", "requirements", "criteria", "ambiguities"}
    if set(proposal) != fields or proposal.get("schema_version") != PROPOSAL_SCHEMA or proposal["release_id"] != packet["release_id"] or proposal["release_commit"] != packet["release_commit"] or proposal["source_packet_hash"] != packet["packet_hash"] or not all(isinstance(proposal[x], list) for x in ("claims", "requirements", "criteria", "ambiguities")): raise ValueError("invalid or unbound proposal")
    sources = {x["source_id"]: x for x in packet["sources"]}; claim_ids = set(); requirement_ids = set(); ambiguity_ids = set(); criterion_ids = set()
    for claim in proposal["claims"]:
        allowed = {"local_id", "claim_key", "cardinality", "value", "classification", "source_refs", "requirement_local_ids"}
        if not set(claim).issubset(allowed) or set(claim) - {"requirement_local_ids"} != allowed - {"requirement_local_ids"} or not isinstance(claim.get("local_id"), str) or claim["local_id"] in claim_ids or claim["local_id"].casefold().startswith("seed_") or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", claim["claim_key"]) or claim["cardinality"] not in {"single", "multi"} or claim["classification"] not in CLASSIFICATIONS or not _primitive(claim["value"]) or (claim["claim_key"] in CLAIM_REGISTRY and claim["cardinality"] != CLAIM_REGISTRY[claim["claim_key"]]): raise ValueError("invalid claim")
        refs = _refs(claim["source_refs"], sources)
        if claim["classification"] == "explicit" and not isinstance(claim["value"], str) and (any("quote" in r for r in refs) or not all(_ref_supports(claim["value"], ref, sources) for ref in refs)): raise ValueError("explicit non-string claims require exactly matching structured authority")
        if claim["classification"] == "explicit" and isinstance(claim["value"], str) and not all(_ref_supports(claim["value"], ref, sources) for ref in refs): raise ValueError("explicit claim lacks exact support")
        claim_ids.add(claim["local_id"])
    for item in proposal["requirements"]:
        required = {"local_id", "statement", "classification", "status", "source_refs", "claim_local_ids", "related_journey_ids", "materiality", "rationale", "owner_confirmation_required", "ambiguity_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in requirement_ids or not isinstance(item["statement"], str) or not item["statement"].strip() or item["classification"] not in CLASSIFICATIONS or item["status"] not in STATUSES or not isinstance(item["owner_confirmation_required"], bool): raise ValueError("invalid requirement")
        refs = _refs(item["source_refs"], sources)
        if item["classification"] == "explicit" and not all(_ref_supports(item["statement"], ref, sources) for ref in refs): raise ValueError("every explicit requirement citation lacks exact quote support")
        if item["classification"] == "inferred_requires_owner" and not item["owner_confirmation_required"]: raise ValueError("inferred requirement requires owner confirmation")
        requirement_ids.add(item["local_id"])
    for item in proposal["ambiguities"]:
        required = {"local_id", "title", "source_refs", "why_material", "options", "recommendation", "blocked_conclusions", "affected_requirement_local_ids", "affected_criterion_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in ambiguity_ids or not isinstance(item["options"], list) or len(item["options"]) > 3: raise ValueError("invalid ambiguity")
        _refs(item["source_refs"], sources); ambiguity_ids.add(item["local_id"])
    for item in proposal["criteria"]:
        required = {"local_id", "parent_requirement_local_id", "actor", "preconditions", "action", "expected_outcomes", "failure_behavior", "required_evidence_categories", "source_refs", "field_source_refs", "classification", "confirmation_state", "blocker_eligible", "ambiguity_local_ids"}
        if set(item) != required or not isinstance(item["local_id"], str) or item["local_id"] in criterion_ids or item["parent_requirement_local_id"] not in requirement_ids or item["classification"] not in CLASSIFICATIONS or item["confirmation_state"] not in CONFIRMATIONS or not isinstance(item["blocker_eligible"], bool) or not isinstance(item["preconditions"], list) or not isinstance(item["expected_outcomes"], list) or not isinstance(item["required_evidence_categories"], list) or not item["required_evidence_categories"] or not set(item["required_evidence_categories"]).issubset(EVIDENCE) or not isinstance(item["field_source_refs"], dict) or not set(item["field_source_refs"]).issubset({"actor", "preconditions", "action", "expected_outcomes", "failure_behavior"}): raise ValueError("invalid criterion")
        _refs(item["source_refs"], sources)
        for field, refs in item["field_source_refs"].items():
            if not _field_supported(item[field], refs, sources): raise ValueError("criterion field lacks exact quote support")
        criterion_ids.add(item["local_id"])
    if any(not isinstance(x.get("claim_local_ids"), list) or not isinstance(x.get("ambiguity_local_ids"), list) or not set(x["claim_local_ids"]).issubset(claim_ids) or not set(x["ambiguity_local_ids"]).issubset(ambiguity_ids) for x in proposal["requirements"]): raise ValueError("invalid requirement relationships")
    if any(not isinstance(x.get("ambiguity_local_ids"), list) or not set(x["ambiguity_local_ids"]).issubset(ambiguity_ids) for x in proposal["criteria"]): raise ValueError("invalid criterion relationships")
    if any(not set(x["affected_requirement_local_ids"]).issubset(requirement_ids) or not set(x["affected_criterion_local_ids"]).issubset(criterion_ids) for x in proposal["ambiguities"]): raise ValueError("ambiguity references unknown record")
    if any(x["status"] == "blocked_by_ambiguity" and not x["ambiguity_local_ids"] for x in proposal["requirements"]): raise ValueError("blocked requirement lacks ambiguity")
    for claim in proposal["claims"]:
        reverse = claim.get("requirement_local_ids")
        if reverse is not None and set(reverse) != {r["local_id"] for r in proposal["requirements"] if claim["local_id"] in r["claim_local_ids"]}: raise ValueError("claim reverse relationship mismatch")
    for ambiguity in proposal["ambiguities"]:
        req_reverse = {r["local_id"] for r in proposal["requirements"] if ambiguity["local_id"] in r["ambiguity_local_ids"]}; crit_reverse = {c["local_id"] for c in proposal["criteria"] if ambiguity["local_id"] in c["ambiguity_local_ids"]}
        if set(ambiguity["affected_requirement_local_ids"]) != req_reverse or set(ambiguity["affected_criterion_local_ids"]) != crit_reverse: raise ValueError("ambiguity reverse relationship mismatch")


def _normalize_proposal(proposal: dict, packet: dict) -> dict:
    value = json.loads(canonical_json(proposal)); sources = {x["source_id"]: x for x in packet["sources"]}
    for claim in value["claims"]:
        claim.pop("requirement_local_ids", None)
        claim["source_refs"] = _refs(claim["source_refs"], sources)
    equivalents: dict[tuple[str, str, str], object] = {}
    for claim in value["claims"]:
        if claim["classification"] == "explicit":
            marker = (claim["claim_key"], claim["cardinality"], _token(claim["value"]))
            equivalents.setdefault(marker, claim["value"])
            if canonical_json(claim["value"]) < canonical_json(equivalents[marker]): equivalents[marker] = claim["value"]
    for claim in value["claims"]:
        if claim["classification"] == "explicit": claim["value"] = equivalents[(claim["claim_key"], claim["cardinality"], _token(claim["value"]))]
    for ambiguity in value["ambiguities"]:
        ambiguity.pop("affected_requirement_local_ids"); ambiguity.pop("affected_criterion_local_ids"); ambiguity["source_refs"] = _refs(ambiguity["source_refs"], sources)
    for requirement in value["requirements"]:
        requirement["claim_local_ids"] = sorted(set(requirement["claim_local_ids"])); requirement["ambiguity_local_ids"] = sorted(set(requirement["ambiguity_local_ids"])); requirement["source_refs"] = _refs(requirement["source_refs"], sources)
    for criterion in value["criteria"]:
        populated = {"actor": criterion["actor"], "preconditions": criterion["preconditions"], "action": criterion["action"], "expected_outcomes": criterion["expected_outcomes"], "failure_behavior": criterion["failure_behavior"]}
        explicit = criterion["classification"] == "explicit" and all(not field_value or field_name in criterion["field_source_refs"] and _field_supported(field_value, criterion["field_source_refs"][field_name], sources) for field_name, field_value in populated.items())
        criterion["classification"] = "explicit" if explicit else "inferred_requires_owner"; criterion["confirmation_state"] = "proposal_needed" if explicit else "owner_confirmation_required"; criterion["blocker_eligible"] = False; criterion["candidate_blocker_after_confirmation"] = bool(explicit and criterion["expected_outcomes"] and not criterion["ambiguity_local_ids"])
        criterion["ambiguity_local_ids"] = sorted(set(criterion["ambiguity_local_ids"])); criterion["source_refs"] = _refs(criterion["source_refs"], sources)
        normalized_fields = {}
        for field in sorted(criterion["field_source_refs"]):
            if field in {"preconditions", "expected_outcomes"}:
                criterion[field], normalized_fields[field] = _canonical_field_pairs(criterion[field], criterion["field_source_refs"][field], sources)
            else: normalized_fields[field] = _refs(criterion["field_source_refs"][field], sources)
        criterion["field_source_refs"] = normalized_fields
    for key in ("claims", "requirements", "criteria", "ambiguities"): value[key].sort(key=lambda x: canonical_json(x))
    return value


def _seed_claims(ctx: LocalExecutionContext, packet: dict) -> list[dict]:
    product, contract = ctx.release["product"], ctx.activation["contract"]
    values = {"release.promise": product.get("promise"), "release.target_user": product.get("target_user"), "release.critical_journey": product.get("critical_journey", []), "release.non_goals": product.get("non_goals", []), "project.product_purpose": contract.get("product_purpose"), "project.primary_users": contract.get("primary_users", [])}
    source_paths = {"release_owner_input": "/", "project_contract": "/"}; result = []
    for key, value in values.items():
        items = value if CLAIM_REGISTRY[key] == "multi" else [value]; source_id = "release_owner_input" if key.startswith("release.") else "project_contract"
        field = {"release.promise": "/promise", "release.target_user": "/target_user", "release.critical_journey": "/critical_journey", "release.non_goals": "/non_goals", "project.product_purpose": "/product_purpose", "project.primary_users": "/primary_users"}[key]
        for index, item in enumerate(items):
            if item is not None:
                pointer = field + ("/" + str(index) if CLAIM_REGISTRY[key] == "multi" else "")
                result.append({"local_id": f"seed_{key}_{index}", "claim_key": key, "cardinality": CLAIM_REGISTRY[key], "value": item, "classification": "explicit", "source_refs": [{"source_id": source_id, "field_path": pointer, "value_hash": _hash_bytes(canonical_json(item).encode("utf-8"))}]})
    return result


def _claims(ctx: LocalExecutionContext, proposal: dict | None, packet: dict) -> tuple[list[dict], dict[str, str]]:
    sources = {x["source_id"]: x for x in packet["sources"]}; groups: dict[str, list[dict]] = {}
    for claim in _seed_claims(ctx, packet) + (proposal["claims"] if proposal else []): groups.setdefault(claim["claim_key"], []).append(claim)
    ledger = []; statuses = {}
    for key in sorted(groups):
        claims = groups[key]; cardinality = claims[0]["cardinality"]
        if any(x["cardinality"] != cardinality for x in claims): raise ValueError("claim key cardinality is inconsistent")
        ranked = [(min(TIERS.index(sources[r["source_id"]]["authority_tier"]) for r in c["source_refs"]), c) for c in claims]
        explicit = [(rank, c) for rank, c in ranked if c["classification"] == "explicit"]
        top = min((rank for rank, _ in explicit), default=99); tokens = {_token(c["value"]): [] for rank, c in explicit if rank == top}
        for rank, c in explicit:
            if rank == top: tokens[_token(c["value"])].append(c)
        conflict = cardinality == "single" and len(tokens) > 1
        buckets: dict[tuple[int, str, str], list[dict]] = {}
        for rank, claim in ranked:
            status = "inferred_requires_owner" if claim["classification"] == "inferred_requires_owner" else ("resolved" if cardinality == "multi" or (rank == top and not conflict) else ("conflicted" if rank == top else "superseded"))
            statuses[claim["local_id"]] = status
            buckets.setdefault((rank, claim["classification"], _token(claim["value"])), []).append(claim)
        for (rank, classification, token), members in buckets.items():
            status = statuses[members[0]["local_id"]]
            refs = _refs([ref for member in members for ref in member["source_refs"]], sources)
            linked = sorted({r["local_id"] for r in (proposal or {"requirements": []})["requirements"] for member in members if member["local_id"] in r["claim_local_ids"]})
            representative = json.loads(sorted(canonical_json(member["value"]) for member in members)[0])
            ledger.append({"claim_id": _id("claim", {"packet": packet["packet_hash"], "claim_key": key, "cardinality": cardinality, "token": token, "classification": classification, "authority_tier": TIERS[rank], "source_refs": refs}), "claim_key": key, "cardinality": cardinality, "value": representative, "source_refs": refs, "authority_tier": TIERS[rank], "classification": classification, "resolution_status": status, "working_value": representative if status == "resolved" else None, "linked_requirement_local_ids": linked})
    return sorted(ledger, key=lambda x: x["claim_id"]), statuses


def _finalize_artifacts(ctx: LocalExecutionContext, packet: dict, proposal: dict | None, ledger: list[dict], statuses: dict[str, str]) -> dict:
    common = {"release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "compiler_version": COMPILER_VERSION, "source_packet_hash": packet["packet_hash"]}
    if proposal:
        local_req = {x["local_id"]: _id("req", {"packet": packet["packet_hash"], "item": x}) for x in proposal["requirements"]}; local_criterion = {x["local_id"]: _id("criterion", {"packet": packet["packet_hash"], "item": x}) for x in proposal["criteria"]}; local_amb = {x["local_id"]: _id("ambiguity", {"packet": packet["packet_hash"], "item": x}) for x in proposal["ambiguities"]}
        requirements = []
        for x in proposal["requirements"]:
            linked = [statuses[c] for c in x["claim_local_ids"]]; state = "blocked_by_ambiguity" if "conflicted" in linked else ("superseded" if linked and all(v == "superseded" for v in linked) else x["status"])
            requirements.append({"requirement_id": local_req[x["local_id"]], "statement": x["statement"], "classification": x["classification"], "status": state, "source_refs": x["source_refs"], "claim_ids": sorted(q["claim_id"] for q in ledger if x["local_id"] in q["linked_requirement_local_ids"]), "related_journey_ids": _sort(x["related_journey_ids"]), "materiality": x["materiality"], "rationale": x["rationale"], "owner_confirmation_required": x["owner_confirmation_required"], "ambiguity_dependencies": sorted({local_amb[a] for a in x["ambiguity_local_ids"]})})
        criteria = []
        for x in proposal["criteria"]:
            criteria.append({"criterion_id": local_criterion[x["local_id"]], "requirement_id": local_req[x["parent_requirement_local_id"]], "actor": x["actor"], "preconditions": _sort(x["preconditions"]), "action": x["action"], "expected_outcomes": _sort(x["expected_outcomes"]), "failure_behavior": x["failure_behavior"], "required_evidence_categories": sorted(set(x["required_evidence_categories"])), "source_refs": x["source_refs"], "field_source_refs": x["field_source_refs"], "classification": x["classification"], "confirmation_state": x["confirmation_state"], "blocker_eligible": False, "candidate_blocker_after_confirmation": False, "ambiguity_dependencies": sorted({local_amb[a] for a in x["ambiguity_local_ids"]})})
        ambiguities = [{"ambiguity_id": local_amb[x["local_id"]], "title": x["title"], "source_refs": x["source_refs"], "why_material": x["why_material"], "options": _sort(x["options"]), "recommendation": x["recommendation"], "blocked_conclusions": _sort(x["blocked_conclusions"]), "affected_requirement_ids": sorted(local_req[v] for v in proposal["requirements"] and [r["local_id"] for r in proposal["requirements"] if x["local_id"] in r["ambiguity_local_ids"]]), "affected_criterion_ids": sorted(local_criterion[v] for v in [c["local_id"] for c in proposal["criteria"] if x["local_id"] in c["ambiguity_local_ids"]])} for x in proposal["ambiguities"]]
    else:
        owner = next(x for x in packet["sources"] if x["source_id"] == "release_owner_input"); promise = ctx.release["product"].get("promise"); ref = {"source_id": owner["source_id"], "field_path": "/promise", "value_hash": _hash_bytes(canonical_json(promise).encode("utf-8"))}
        requirements = ([{"requirement_id": _id("req", {"promise": promise, "packet": packet["packet_hash"]}), "statement": promise, "classification": "explicit", "status": "active", "source_refs": [ref], "claim_ids": [], "related_journey_ids": [], "materiality": "release_scope", "rationale": "release owner promise", "owner_confirmation_required": False, "ambiguity_dependencies": []}] if promise else [])
        criteria = []; ambiguities = []
    # Conflicts are claim-global, even without linked records.
    for key in sorted({x["claim_key"] for x in ledger if x["resolution_status"] == "conflicted"}):
        top = [x for x in ledger if x["claim_key"] == key and x["resolution_status"] == "conflicted"]
        values = _sort([x["value"] for x in top]); aid = _id("ambiguity", {"claim": key, "values": values})
        affected_req = sorted({r["requirement_id"] for r in requirements if any(c["claim_id"] in r["claim_ids"] for c in top)})
        affected_crit = sorted({c["criterion_id"] for c in criteria if c["requirement_id"] in affected_req})
        for r in requirements:
            if r["requirement_id"] in affected_req: r["status"] = "blocked_by_ambiguity"; r["ambiguity_dependencies"] = sorted(set(r["ambiguity_dependencies"] + [aid]))
        for c in criteria:
            if c["criterion_id"] in affected_crit: c["ambiguity_dependencies"] = sorted(set(c["ambiguity_dependencies"] + [aid]))
        refs = _sort([ref for x in top for ref in x["source_refs"]])
        ambiguities.append({"ambiguity_id": aid, "title": f"Conflicting {key}", "claim_key": key, "competing_values": values, "source_refs": refs, "why_material": "Same-highest-authority values conflict.", "options": [], "recommendation": None, "blocked_conclusions": ["Working value"], "affected_requirement_ids": affected_req, "affected_criterion_ids": affected_crit})
    req_status = {r["requirement_id"]: r["status"] for r in requirements}
    for c in criteria:
        c["candidate_blocker_after_confirmation"] = bool(c["classification"] == "explicit" and c["expected_outcomes"] and not c["ambiguity_dependencies"] and req_status.get(c["requirement_id"]) == "active")
    working = {}
    for key, field in CLAIM_PROJECTION.items():
        values = [x["working_value"] for x in ledger if x["claim_key"] == key and x["resolution_status"] == "resolved" and x["working_value"] is not None]
        if CLAIM_REGISTRY[key] == "single" and values: working[field] = _sort(values)[0]
        elif CLAIM_REGISTRY[key] == "multi": working[field] = _sort(values)
    product = ctx.release["product"]
    public_ledger = [{k: v for k, v in claim.items() if k != "linked_requirement_local_ids"} for claim in ledger]
    intent = {"schema_version": INTENT_SCHEMA, **common, "project_name": ctx.activation["contract"]["project_name"], "product_purpose": ctx.activation["contract"]["product_purpose"], "target_users": [product.get("target_user")] if product.get("target_user") else [], "release_promise": product.get("promise"), "release_scope": product.get("critical_journey", []), "non_goals": product.get("non_goals", []), "owner_constraints": ctx.release.get("owner_constraints", []), "claims": sorted(public_ledger, key=lambda x: x["claim_id"]), "working_intent": working, "source_coverage": packet["source_coverage"], "coverage_boundary": packet["coverage_boundary"]}
    return {"product-intent.json": intent, "requirements.json": {"schema_version": REQUIREMENTS_SCHEMA, **common, "requirements": sorted(requirements, key=lambda x: x["requirement_id"])}, "acceptance-criteria.json": {"schema_version": CRITERIA_SCHEMA, **common, "criteria": sorted(criteria, key=lambda x: x["criterion_id"])}, "ambiguities.json": {"schema_version": AMBIGUITIES_SCHEMA, **common, "ambiguities": sorted(ambiguities, key=lambda x: x["ambiguity_id"])}}


def _validate_artifacts(artifacts: dict, packet: dict) -> None:
    if set(artifacts) != set(ARTIFACTS): raise ValueError("exact artifact set is required")
    intent, req, crit, amb = (artifacts[x] for x in ARTIFACTS); common = {"release_id", "release_commit", "project_authority", "compiler_version", "source_packet_hash"}
    if set(intent) != {"schema_version", *common, "project_name", "product_purpose", "target_users", "release_promise", "release_scope", "non_goals", "owner_constraints", "claims", "working_intent", "source_coverage", "coverage_boundary"} or set(req) != {"schema_version", *common, "requirements"} or set(crit) != {"schema_version", *common, "criteria"} or set(amb) != {"schema_version", *common, "ambiguities"}: raise ValueError("artifact fields mismatch")
    if [intent["schema_version"], req["schema_version"], crit["schema_version"], amb["schema_version"]] != [INTENT_SCHEMA, REQUIREMENTS_SCHEMA, CRITERIA_SCHEMA, AMBIGUITIES_SCHEMA]: raise ValueError("artifact schema mismatch")
    for value in artifacts.values():
        if any(value.get(k) != ({"release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "compiler_version": COMPILER_VERSION, "source_packet_hash": packet["packet_hash"]})[k] for k in common): raise ValueError("artifact binding mismatch")
    def no_local_keys(value: object) -> bool:
        if isinstance(value, dict): return all(not (key == "local_id" or key.endswith("_local_id") or key.endswith("_local_ids")) and no_local_keys(item) for key, item in value.items())
        return not isinstance(value, list) or all(no_local_keys(item) for item in value)
    if not no_local_keys(artifacts): raise ValueError("final artifacts retain proposal-local identifiers")
    sources = {x["source_id"]: x for x in packet["sources"]}; claim_ids = set(); req_ids = set(); criterion_ids = set(); ambiguity_ids = set()
    claim_fields = {"claim_id", "claim_key", "cardinality", "value", "source_refs", "authority_tier", "classification", "resolution_status", "working_value"}
    for x in intent["claims"]:
        if set(x) != claim_fields or x["claim_id"] in claim_ids or x["cardinality"] not in {"single", "multi"} or x["authority_tier"] not in TIERS or x["classification"] not in CLASSIFICATIONS or x["resolution_status"] not in {"resolved", "conflicted", "superseded", "inferred_requires_owner"} or not _primitive(x["value"]): raise ValueError("invalid claim artifact")
        _refs(x["source_refs"], sources); claim_ids.add(x["claim_id"])
    req_fields = {"requirement_id", "statement", "classification", "status", "source_refs", "claim_ids", "related_journey_ids", "materiality", "rationale", "owner_confirmation_required", "ambiguity_dependencies"}
    for x in req["requirements"]:
        if set(x) != req_fields or x["requirement_id"] in req_ids or x["classification"] not in CLASSIFICATIONS or x["status"] not in STATUSES or len(x["claim_ids"]) != len(set(x["claim_ids"])) or len(x["ambiguity_dependencies"]) != len(set(x["ambiguity_dependencies"])): raise ValueError("invalid requirement artifact")
        refs = _refs(x["source_refs"], sources)
        if x["classification"] == "explicit" and not all(_ref_supports(x["statement"], r, sources) for r in refs): raise ValueError("explicit requirement citation invalid")
        req_ids.add(x["requirement_id"])
    criterion_fields = {"criterion_id", "requirement_id", "actor", "preconditions", "action", "expected_outcomes", "failure_behavior", "required_evidence_categories", "source_refs", "field_source_refs", "classification", "confirmation_state", "blocker_eligible", "candidate_blocker_after_confirmation", "ambiguity_dependencies"}
    for x in crit["criteria"]:
        if set(x) != criterion_fields or x["criterion_id"] in criterion_ids or x["classification"] not in CLASSIFICATIONS or x["confirmation_state"] not in CONFIRMATIONS or x["blocker_eligible"] is not False or not isinstance(x["candidate_blocker_after_confirmation"], bool) or len(x["ambiguity_dependencies"]) != len(set(x["ambiguity_dependencies"])): raise ValueError("invalid criterion artifact")
        for field in ("preconditions", "expected_outcomes"):
            refs = x["field_source_refs"].get(field)
            if x[field] and not _field_supported(x[field], refs, sources): raise ValueError("criterion list evidence alignment is invalid")
        criterion_ids.add(x["criterion_id"])
    for x in amb["ambiguities"]:
        fields = {"ambiguity_id", "title", "source_refs", "why_material", "options", "recommendation", "blocked_conclusions", "affected_requirement_ids", "affected_criterion_ids"}
        if "claim_key" in x: fields |= {"claim_key", "competing_values"}
        if set(x) != fields or x["ambiguity_id"] in ambiguity_ids or len(x["affected_requirement_ids"]) != len(set(x["affected_requirement_ids"])) or len(x["affected_criterion_ids"]) != len(set(x["affected_criterion_ids"])): raise ValueError("invalid ambiguity artifact")
        _refs(x["source_refs"], sources); ambiguity_ids.add(x["ambiguity_id"])
    if any(not set(x["claim_ids"]).issubset(claim_ids) or not set(x["ambiguity_dependencies"]).issubset(ambiguity_ids) or (x["status"] == "blocked_by_ambiguity" and not x["ambiguity_dependencies"]) for x in req["requirements"]): raise ValueError("invalid requirement references")
    if any(x["requirement_id"] not in req_ids or not set(x["ambiguity_dependencies"]).issubset(ambiguity_ids) or (x["candidate_blocker_after_confirmation"] and (x["classification"] != "explicit" or not x["expected_outcomes"] or x["ambiguity_dependencies"] or next(r for r in req["requirements"] if r["requirement_id"] == x["requirement_id"])["status"] != "active")) for x in crit["criteria"]): raise ValueError("invalid criterion references")
    if any(not set(x["affected_requirement_ids"]).issubset(req_ids) or not set(x["affected_criterion_ids"]).issubset(criterion_ids) for x in amb["ambiguities"]): raise ValueError("invalid ambiguity references")
    expected = {}
    for key, field in CLAIM_PROJECTION.items():
        values = [x["working_value"] for x in intent["claims"] if x["claim_key"] == key and x["resolution_status"] == "resolved" and x["working_value"] is not None]
        if CLAIM_REGISTRY[key] == "single" and values: expected[field] = _sort(values)[0]
        elif CLAIM_REGISTRY[key] == "multi": expected[field] = _sort(values)
    if intent["working_intent"] != expected: raise ValueError("working intent is invalid")


def compile_bundle(ctx: LocalExecutionContext, proposal_file: str | None = None) -> dict:
    ctx.require("file.read"); packet, packet_bytes = _load_packet(ctx); submitted = None; submitted_bytes = None
    if proposal_file:
        submitted_bytes = _proposal_path(ctx, proposal_file).read_bytes(); submitted = json.loads(submitted_bytes.decode("utf-8")); _validate_proposal(submitted, packet)
    normalized = _normalize_proposal(submitted, packet) if submitted else None; ledger, statuses = _claims(ctx, normalized, packet); artifacts = _finalize_artifacts(ctx, packet, normalized, ledger, statuses); _validate_artifacts(artifacts, packet)
    return _persist(ctx, packet, packet_bytes, submitted, submitted_bytes, normalized, artifacts)


def _persist(ctx: LocalExecutionContext, packet: dict, packet_bytes: bytes, submitted: dict | None, submitted_bytes: bytes | None, normalized: dict | None, artifacts: dict) -> dict:
    root = _root(ctx); directory = root / "generations" / ("gen_" + uuid.uuid4().hex); directory.mkdir(parents=True); hashes = {}
    for name, value in artifacts.items(): _atomic_file(directory / name, value); hashes[name] = _hash_bytes((directory / name).read_bytes())
    (directory / "source-packet.json").write_bytes(packet_bytes)
    if submitted_bytes: (directory / "submitted-proposal.json").write_bytes(submitted_bytes); _atomic_file(directory / "normalized-proposal.json", normalized)
    normalized_bytes = (directory / "normalized-proposal.json").read_bytes() if normalized else None
    manifest = {"schema_version": MANIFEST_SCHEMA, "release_id": packet["release_id"], "release_commit": packet["release_commit"], "project_authority": packet["project_authority"], "source_packet_hash": packet["packet_hash"], "source_packet_snapshot_hash": _hash_bytes(packet_bytes), "submitted_proposal_hash": content_hash(submitted) if submitted else "explicit-only", "submitted_proposal_snapshot_hash": _hash_bytes(submitted_bytes) if submitted_bytes else "explicit-only", "normalized_proposal_hash": content_hash(normalized) if normalized else "explicit-only", "normalized_proposal_snapshot_hash": _hash_bytes(normalized_bytes) if normalized_bytes else "explicit-only", "compiler_version": COMPILER_VERSION, "artifact_filenames": list(ARTIFACTS), "artifact_hashes": hashes}
    manifest["semantic_bundle_hash"] = content_hash({"source_packet_hash": manifest["source_packet_hash"], "normalized_proposal_hash": manifest["normalized_proposal_hash"], "compiler_version": COMPILER_VERSION, "schemas": [SOURCE_PACKET_SCHEMA, PROPOSAL_SCHEMA, INTENT_SCHEMA, REQUIREMENTS_SCHEMA, CRITERIA_SCHEMA, AMBIGUITIES_SCHEMA], "artifact_hashes": {name: hashes[name] for name in sorted(hashes)}})
    manifest["bundle_hash"] = content_hash(manifest); _atomic_file(directory / "manifest.json", manifest); _atomic_file(root / "current-generation.json", {"schema_version": POINTER_SCHEMA, "generation": directory.name, "manifest_hash": _hash_bytes((directory / "manifest.json").read_bytes())}); return manifest


def load_bundle(ctx: LocalExecutionContext) -> tuple[dict, dict]:
    packet, active_bytes = _load_packet(ctx); pointer_path = _root(ctx) / "current-generation.json"
    if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("complete Product Intent generation is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    if set(pointer) != {"schema_version", "generation", "manifest_hash"} or pointer["schema_version"] != POINTER_SCHEMA or not re.fullmatch(r"gen_[0-9a-f]{32}", pointer["generation"]): raise ValueError("invalid Product Intent generation pointer")
    directory = _root(ctx) / "generations" / pointer["generation"]; manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or _hash_bytes(manifest_path.read_bytes()) != pointer["manifest_hash"]: raise ValueError("invalid Product Intent generation")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); fields = {"schema_version", "release_id", "release_commit", "project_authority", "source_packet_hash", "source_packet_snapshot_hash", "submitted_proposal_hash", "submitted_proposal_snapshot_hash", "normalized_proposal_hash", "normalized_proposal_snapshot_hash", "compiler_version", "artifact_filenames", "artifact_hashes", "semantic_bundle_hash", "bundle_hash"}
    if set(manifest) != fields or manifest["schema_version"] != MANIFEST_SCHEMA or manifest["bundle_hash"] != content_hash({k: v for k, v in manifest.items() if k != "bundle_hash"}) or manifest["source_packet_hash"] != packet["packet_hash"] or manifest["artifact_filenames"] != list(ARTIFACTS) or manifest["release_id"] != ctx.release["release_id"] or manifest["release_commit"] != ctx.authority_binding["repository_commit"] or manifest["project_authority"] != _authority(ctx) or manifest["compiler_version"] != COMPILER_VERSION: raise ValueError("stale or invalid Product Intent bundle")
    snapshot = directory / "source-packet.json"
    if not snapshot.is_file() or _hash_bytes(snapshot.read_bytes()) != manifest["source_packet_snapshot_hash"] or snapshot.read_bytes() != active_bytes: raise ValueError("bundle source packet snapshot is stale")
    expected_semantic = content_hash({"source_packet_hash": manifest["source_packet_hash"], "normalized_proposal_hash": manifest["normalized_proposal_hash"], "compiler_version": COMPILER_VERSION, "schemas": [SOURCE_PACKET_SCHEMA, PROPOSAL_SCHEMA, INTENT_SCHEMA, REQUIREMENTS_SCHEMA, CRITERIA_SCHEMA, AMBIGUITIES_SCHEMA], "artifact_hashes": {name: manifest["artifact_hashes"][name] for name in sorted(manifest["artifact_hashes"])}})
    if manifest["semantic_bundle_hash"] != expected_semantic: raise ValueError("semantic Product Intent bundle is invalid")
    if manifest["submitted_proposal_hash"] != "explicit-only":
        submitted_path, normalized_path = directory / "submitted-proposal.json", directory / "normalized-proposal.json"
        if not submitted_path.is_file() or not normalized_path.is_file() or _hash_bytes(submitted_path.read_bytes()) != manifest["submitted_proposal_snapshot_hash"]: raise ValueError("proposal snapshot is invalid")
        submitted = json.loads(submitted_path.read_text(encoding="utf-8")); _validate_proposal(submitted, packet); recomputed = _normalize_proposal(submitted, packet); stored = json.loads(normalized_path.read_text(encoding="utf-8"))
        if recomputed != stored or content_hash(submitted) != manifest["submitted_proposal_hash"] or content_hash(stored) != manifest["normalized_proposal_hash"] or _hash_bytes(normalized_path.read_bytes()) != manifest["normalized_proposal_snapshot_hash"]: raise ValueError("normalized proposal snapshot is invalid")
    artifacts = {}
    for name in ARTIFACTS:
        path = directory / name
        if not path.is_file() or _hash_bytes(path.read_bytes()) != manifest["artifact_hashes"].get(name): raise ValueError("invalid Product Intent artifact")
        artifacts[name] = json.loads(path.read_text(encoding="utf-8"))
    _validate_artifacts(artifacts, packet); return manifest, artifacts


def show(ctx: LocalExecutionContext) -> str:
    _, artifacts = load_bundle(ctx); intent = artifacts["product-intent.json"]; requirements = artifacts["requirements.json"]["requirements"]; criteria = artifacts["acceptance-criteria.json"]["criteria"]; ambiguities = artifacts["ambiguities.json"]["ambiguities"]
    lines = [f"Product Intent: {intent['project_name']}", f"Working promise: {intent['working_intent'].get('release_promise', 'not supplied')}", "Claims:"]
    lines += [f"- {x['claim_key']}={x['working_value']!r} [{x['resolution_status']}; {x['authority_tier']}]" for x in intent["claims"]] or ["- none"]
    lines += ["Owner constraints:"] + [f"- {x}" for x in intent["owner_constraints"]] + ["Requirements:"] + [f"- {x['requirement_id']} [{x['classification']}/{x['status']}] {x['statement']}" for x in requirements] + ["Criteria:"] + [f"- {x['criterion_id']} [{x['classification']}] blocker_eligible={x['blocker_eligible']}" for x in criteria] + ["Material ambiguities:"] + [f"- {x['title']}" for x in ambiguities] + ["Source coverage:"] + [f"- {x['path']} [{x['source_class']}] {x['status']}" for x in intent["source_coverage"]] + [f"Coverage boundary: {intent['coverage_boundary']}"]
    return "\n".join(lines)
