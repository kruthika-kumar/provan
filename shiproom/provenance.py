from __future__ import annotations

import json
import sqlite3
from pathlib import Path

RUNTIME_SCHEMA = "runtime_provenance.v1"


def extract_hermes_runtime(database: Path, session_id: str) -> dict:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True); connection.row_factory = sqlite3.Row
    row = connection.execute("select id, model, model_config from sessions where id=?", (session_id,)).fetchone(); connection.close()
    if not row: raise ValueError("Hermes session not found")
    try: config = json.loads(row["model_config"] or "{}")
    except json.JSONDecodeError: config = {}
    def field(value, source_field):
        return {"value": value if value not in (None, "") else "not_recorded", "provenance": {"source_type": "hermes_session_record", "session_id": session_id, "source_field": source_field}}
    return {"schema_version": RUNTIME_SCHEMA, "model_id": field(row["model"], "sessions.model"), "reasoning_effort": field(config.get("reasoning_config", {}).get("effort"), "sessions.model_config.reasoning_config.effort"), "model_policy_version": field(None, "not_recorded"), "escalation_count": field(None, "not_recorded")}


def evidence_counts(release: dict) -> dict:
    checks = release.get("checks", []); findings = release.get("findings", [])
    return {"deterministic_check_count": sum(c.get("evidence_status") == "deterministically_verified" for c in checks), "browser_observed_count": sum(c.get("evidence_status") == "browser_observed" for c in checks), "source_backed_finding_count": sum(any(e.get("status") == "source_verified" for e in f.get("evidence", [])) for f in findings), "model_reviewed_finding_count": sum(any(e.get("status") == "model_reviewed" for e in f.get("evidence", [])) for f in findings), "agent_reported_count": sum(any(e.get("status") == "agent_reported" for e in f.get("evidence", [])) for f in findings), "missing_evidence_count": sum(not c.get("evidence_status") or c.get("evidence_status") == "missing_evidence" for c in checks)}
