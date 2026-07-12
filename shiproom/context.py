from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

CONTEXT_SCHEMA = "project_context.v0"
AUTHORITY_POLICY_VERSION = "source_authority_policy.v1"
CONTEXT_FILES = ("AGENTS.md", ".hermes.md", "HERMES.md")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source(source_type: str, ref: str, content_hash: str) -> dict:
    return {"source_id": f"src_{_hash(f'{source_type}:{ref}:{content_hash}')[:12]}", "type": source_type, "ref": ref, "content_hash": content_hash}


def _exact_facts(text: str, source: dict) -> tuple[dict, list[dict], list[dict]]:
    commands: dict[str, dict] = {}
    constraints: list[dict] = []
    notes: list[dict] = []
    patterns = {"build": re.compile(r"^\s*(?:build command|build)\s*:\s*`?([^`\r\n]+)`?\s*$", re.I), "test": re.compile(r"^\s*(?:test command|test)\s*:\s*`?([^`\r\n]+)`?\s*$", re.I)}
    for line in text.splitlines():
        for kind, pattern in patterns.items():
            match = pattern.match(line)
            if match and kind not in commands:
                commands[kind] = {"value": match.group(1).strip(), "source_ref": source["ref"], "source_id": source["source_id"], "content_hash": source["content_hash"], "extraction_method": "exact", "classification": "exact"}
        for prefix, target, note_type in (("constraint:", constraints, "constraint"), ("architecture:", notes, "architecture"), ("deployment:", notes, "deployment")):
            if line.strip().lower().startswith(prefix):
                target.append({"type": note_type, "value": line.split(":", 1)[1].strip(), "source_ref": source["ref"], "source_id": source["source_id"], "classification": "exact"})
    return commands, constraints, notes


def compile_project_context(*, project_id: str, repository_url: str, commit_sha: str, release_input: dict, repository_root: Path | None = None, owner_constraints: list[str] | None = None, prior_decisions: list[dict] | None = None) -> dict:
    release_hash = _hash(_canonical(release_input))
    sources = [_source("release_input", "release_input", release_hash)]
    commands: dict[str, dict] = {}; extracted_constraints: list[dict] = []; advisory_notes: list[dict] = []
    if repository_root:
        for name in CONTEXT_FILES:
            path = repository_root / name
            if path.is_file():
                text = path.read_text(encoding="utf-8")[:20000]
                source = _source("repository_context", name, _hash(text)); sources.append(source)
                commands, extracted_constraints, advisory_notes = _exact_facts(text, source)
                break
    identity = {"schema_version": CONTEXT_SCHEMA, "project_id": project_id, "repository_url": repository_url, "commit_sha": commit_sha, "sources": [{"source_id": s["source_id"], "content_hash": s["content_hash"]} for s in sources]}
    context = {"schema_version": CONTEXT_SCHEMA, "project_context_id": f"ctx_{_hash(_canonical(identity))[:16]}", "project_id": project_id, "repository": {"url": repository_url, "commit_sha": commit_sha}, "commands": commands, "context_sources": sources, "owner_constraints": owner_constraints or [], "extracted_constraints": extracted_constraints, "advisory_notes": advisory_notes, "prior_decisions": prior_decisions or [], "source_conflicts": []}
    validate_project_context(context); return context


def validate_project_context(context: dict) -> None:
    required = {"schema_version", "project_context_id", "project_id", "repository", "commands", "context_sources", "owner_constraints", "extracted_constraints", "advisory_notes", "prior_decisions", "source_conflicts"}
    if set(context) != required or context.get("schema_version") != CONTEXT_SCHEMA or not str(context.get("project_context_id", "")).startswith("ctx_"):
        raise ValueError("invalid project context")
    for command in context["commands"].values():
        if command.get("classification") != "exact" or command.get("extraction_method") != "exact": raise ValueError("executable commands require exact source extraction")


def context_projection(context: dict) -> dict:
    return {"schema_version": context["schema_version"], "project_context_id": context["project_context_id"], "project_id": context["project_id"], "repository": context["repository"], "commands": context["commands"], "source_refs": [{key: source[key] for key in ("source_id", "type", "ref", "content_hash")} for source in context["context_sources"]], "owner_constraints": context["owner_constraints"], "prior_decisions": context["prior_decisions"], "source_conflicts": context["source_conflicts"]}


def context_event_metadata(context: dict) -> dict:
    return {"project_context_id": context["project_context_id"], "source_hashes": [source["content_hash"] for source in context["context_sources"]]}


def verify_context_handoff(context: dict, events: list[dict], required_agents=("manager", "specialist", "verifier")) -> bool:
    expected = context_event_metadata(context)
    by_agent = {event.get("agent_id"): event.get("metadata", {}) for event in events}
    return all(by_agent.get(agent, {}).get("project_context_id") == expected["project_context_id"] and by_agent.get(agent, {}).get("source_hashes") == expected["source_hashes"] for agent in required_agents)


def verify_context_isolation(a: dict, b: dict, *, a_run_id: str, b_run_id: str, a_storage: str, b_storage: str) -> bool:
    def scoped(context: dict) -> dict:
        return {"context_id": context["project_context_id"], "project_id": context["project_id"], "repository": context["repository"], "source_ids": [s["source_id"] for s in context["context_sources"]], "source_hashes": [s["content_hash"] for s in context["context_sources"]], "commands": context["commands"], "decision_ids": [d.get("id") for d in context["prior_decisions"]]}
    left, right = scoped(a), scoped(b)
    return all((left[key] != right[key]) for key in ("context_id", "project_id", "repository", "source_ids", "source_hashes", "commands", "decision_ids")) and a_run_id != b_run_id and a_storage != b_storage


def record_source_conflict(context: dict, *, product_claim: dict, observed_claim: dict, owner_decision_required: bool) -> dict:
    conflict = {"conflict_id": f"conf_{_hash(_canonical([product_claim, observed_claim]))[:12]}", "claims": [product_claim, observed_claim], "authoritative_observed_behavior": observed_claim, "owner_decision_required": owner_decision_required, "authority_policy_version": AUTHORITY_POLICY_VERSION}
    context["source_conflicts"].append(conflict); return conflict
