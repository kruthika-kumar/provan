from __future__ import annotations

import json
import sqlite3

from shiproom.context import AUTHORITY_POLICY_VERSION, compile_project_context, context_event_metadata, record_source_conflict, verify_context_handoff, verify_context_isolation
from shiproom.provenance import extract_hermes_runtime
from shiproom.external import compile_release, eligible_modules
from shiproom.registry import discover


def make_context(tmp_path, project, command, decision):
    root=tmp_path/project; root.mkdir(); (root/"AGENTS.md").write_text(f"Build: {command} build\nTest: {command} test\nArchitecture: advisory only\n",encoding="utf-8")
    return compile_project_context(project_id=project,repository_url=f"https://github.com/example/{project}",commit_sha=project[0]*40,release_input={"promise":project},repository_root=root,prior_decisions=[{"id":decision}])


def test_context_id_is_deterministic_and_commands_are_exact(tmp_path):
    context=make_context(tmp_path,"alpha","python alpha.py","decision-alpha")
    again=compile_project_context(project_id="alpha",repository_url="https://github.com/example/alpha",commit_sha="a"*40,release_input={"promise":"alpha"},repository_root=tmp_path/"alpha",prior_decisions=[{"id":"decision-alpha"}])
    assert context["project_context_id"]==again["project_context_id"]
    assert context["commands"]["build"]["classification"]=="exact" and context["commands"]["test"]["extraction_method"]=="exact"
    assert context["advisory_notes"][0]["type"]=="architecture" and "command" not in context["advisory_notes"][0]


def test_handoff_conflict_and_structured_isolation(tmp_path):
    a=make_context(tmp_path,"alpha","python alpha.py","decision-alpha"); b=make_context(tmp_path,"beta","node beta.js","decision-beta")
    metadata=context_event_metadata(a); events=[{"agent_id":agent,"metadata":metadata} for agent in ("manager","specialist","verifier")]
    assert verify_context_handoff(a,events)
    assert verify_context_isolation(a,b,a_run_id="run-a",b_run_id="run-b",a_storage="scope-a",b_storage="scope-b")
    conflict=record_source_conflict(a,product_claim={"claim":"automatic","source_ref":"product/README"},observed_claim={"claim":"owner approval","source_ref":"live config"},owner_decision_required=True)
    assert len(conflict["claims"])==2 and conflict["authority_policy_version"]==AUTHORITY_POLICY_VERSION and conflict["owner_decision_required"]


def test_runtime_provenance_is_session_field_backed(tmp_path):
    database=tmp_path/"state.db"; connection=sqlite3.connect(database); connection.execute("create table sessions (id text, model text, model_config text)"); connection.execute("insert into sessions values (?,?,?)",("session-native","model-recorded",json.dumps({"reasoning_config":{"effort":"medium"}}))); connection.commit(); connection.close()
    runtime=extract_hermes_runtime(database,"session-native")
    assert runtime["model_id"]["value"]=="model-recorded" and runtime["model_id"]["provenance"]=={"source_type":"hermes_session_record","session_id":"session-native","source_field":"sessions.model"}
    assert runtime["reasoning_effort"]["value"]=="medium" and runtime["model_policy_version"]["value"]=="not_recorded" and runtime["escalation_count"]["value"]=="not_recorded"


def test_context_cannot_bypass_module_applicability_or_capabilities():
    capabilities={key:key=="inspect_public_surfaces" for key in ("inspect_public_surfaces","run_safe_commands","publish_report","comment_upstream","create_local_diff","push_branch","open_pr","modify_deployment")}
    release=compile_release({"schema_version":"external_release_contract.v1","project_name":"Conventional","repository_url":"https://github.com/example/conventional","live_url":"https://example.com","target_user":"users","product_promise":"Render a page","critical_journey":["Open"],"non_goals":[],"owner_constraints":[],"capabilities":capabilities})
    release["project_context"]["advisory_notes"].append({"type":"architecture","value":"AI model analytics","classification":"model_reviewed"})
    eligible,_=eligible_modules(release,discover())
    assert "data" not in eligible and release["capabilities"]["run_safe_commands"] is False
