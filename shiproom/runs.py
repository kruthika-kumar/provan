from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

EVENT_SCHEMA = "run_event.v1"
RECORD_SCHEMA = "run_record.v1"


class RunStore:
    def append(self, release_id: str, event_type: str, *, parent_event_id: str | None = None, agent_id: str | None = None, module_id: str | None = None, delegation_id: str | None = None, criterion_id: str | None = None, operation: str | None = None, status: str = "completed", evidence_references: list[str] | None = None, metadata: dict | None = None, timestamp: str | None = None) -> dict:
        raise NotImplementedError
    def events(self, release_id: str) -> list[dict]: raise NotImplementedError


def _sanitize(value):
    encoded = json.dumps(value or {})
    forbidden = ("password", "token", "authorization", "environment", "raw_prompt", "model_response", "source_excerpt", "command_args")
    if any(term in encoded.lower() for term in forbidden): raise ValueError("run event metadata contains forbidden content")
    return value or {}


class LocalRunStore(RunStore):
    def __init__(self, root: Path = Path("run-history")): self.root = root
    def append(self, release_id: str, event_type: str, **kwargs) -> dict:
        sequence = len(self.events(release_id)) + 1
        event = {"schema_version": EVENT_SCHEMA, "event_id": f"evt_{uuid.uuid4().hex[:16]}", "sequence": sequence, "release_id": release_id, "event_type": event_type, "timestamp": kwargs.pop("timestamp", None) or datetime.now(UTC).isoformat(), "parent_event_id": kwargs.pop("parent_event_id", None), "agent_id": kwargs.pop("agent_id", None), "module_id": kwargs.pop("module_id", None), "delegation_id": kwargs.pop("delegation_id", None), "criterion_id": kwargs.pop("criterion_id", None), "operation": kwargs.pop("operation", None), "status": kwargs.pop("status", "completed"), "evidence_references": kwargs.pop("evidence_references", None) or [], "metadata": _sanitize(kwargs.pop("metadata", None))}
        if kwargs: raise ValueError(f"unknown event fields: {sorted(kwargs)}")
        target = self.root / release_id / "events.jsonl"; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle: handle.write(json.dumps(event) + "\n")
        return event
    def events(self, release_id: str) -> list[dict]:
        target = self.root / release_id / "events.jsonl"
        return [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()] if target.exists() else []
    def releases(self) -> list[str]: return sorted(path.name for path in self.root.iterdir() if path.is_dir()) if self.root.exists() else []


def materialize(release: dict, events: list[dict]) -> dict:
    ordered = sorted(events, key=lambda event: (event.get("sequence", 0), event["timestamp"], event["event_id"]))
    event_ids = {event["event_id"] for event in ordered}
    if any(event.get("parent_event_id") and event["parent_event_id"] not in event_ids for event in ordered): raise ValueError("orphan run event parent")
    started = ordered[0]["timestamp"] if ordered else None; ended = ordered[-1]["timestamp"] if ordered else None
    revisions = [event for event in ordered if event["event_type"] in {"result_rejected", "revision_requested", "revision_accepted"}]
    record = {"schema_version": RECORD_SCHEMA, "release_id": release["release_id"], "mode": release.get("mode", "controlled"), "hermes_session_id": release.get("telemetry", {}).get("hermes_session_id"), "manager_agent_id": next((e.get("agent_id") for e in ordered if e["event_type"] == "manager_planning"), None), "delegation_ids": sorted({e["delegation_id"] for e in ordered if e.get("delegation_id")}), "selected_modules": release.get("panel", {}).get("selected_modules", []), "skipped_modules": release.get("panel", {}).get("skipped_modules", []), "module_versions": {e["module_id"]: e["metadata"].get("module_version") for e in ordered if e.get("module_id") and e["metadata"].get("module_version")}, "criterion_ids": sorted({e["criterion_id"] for e in ordered if e.get("criterion_id")}), "events": ordered, "reviewer_revisions": revisions, "findings": release.get("findings", []), "owner_interruptions": [e for e in ordered if e["event_type"] == "owner_interruption"], "remediation_attempts": release.get("remediation_tasks", []), "artifacts": release.get("integrations", {}), "final_verdict": release.get("verdict", {}), "started_at": started, "ended_at": ended, "duration_seconds": _duration(started, ended), "tokens": release.get("telemetry", {}).get("tokens", "unavailable"), "estimated_cost": release.get("telemetry", {}).get("estimated_cost", "unavailable"), "human_intervention": release.get("telemetry", {}).get("human_intervention", "none"), "classification": "success" if release.get("verdict", {}).get("status") in {"READY", "SHIP_WITH_CONDITIONS"} else "failure"}
    return record


def _duration(start, end):
    if not start or not end: return 0.0
    return max(0.0, (datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds())
