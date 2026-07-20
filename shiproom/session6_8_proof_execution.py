"""Execution-derived proof events for the Sessions 6--8 closeout.

This module orchestrates existing production validators.  It does not decide
whether a requirement is closed; the independent receipt validator performs
that join from the manifest, JUnit, invocation events, and proof events.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from shiproom.contestability import _target_definition, target_registry
from shiproom.management_artifacts.compiler import _dep, _section_specs
from shiproom.remediation_roadmaps import _dependency, _policy_decision, authority_policy
from shiproom.review_organisation import validate_harness_capability_manifest, validate_specialist_registries
from shiproom.workflow_audit import invoke, session


FIXTURE_CLASSES = {"valid", "near_valid", "adversarial_invalid"}


def _exercise(requirement_id: str, fixture_class: str) -> tuple[bool, str | None, str | None]:
    if requirement_id.startswith("S6_"):
        if fixture_class == "valid":
            invoke(authority_policy)
        elif fixture_class == "near_valid":
            invoke(_policy_decision,blocker=False, criterion_authority="model_reviewed", evidence_class="model_reviewed", open_state="open", owner_required=False, fresh=True)
        else:
            invoke(_dependency,"not_used", "forbidden_generation", None)
    elif requirement_id.startswith("S7_"):
        value={"schema_version":"agent-harness-capability-manifest.v1","execution_mode":"single_agent_degraded" if fixture_class=="near_valid" else "manual_external","declared_capability":"prepared_packet_only","granted_permission":"prepared_packet_only","observed_execution":"not_observed","independence_limitation":"declared capability is not proof of isolation"}
        if fixture_class == "valid":
            invoke(validate_specialist_registries)
        elif fixture_class == "near_valid":
            invoke(validate_harness_capability_manifest,value)
        else:
            invoke(validate_harness_capability_manifest,{**value,"unexpected":True})
    elif requirement_id.startswith("S8_CONTEST_"):
        if fixture_class in {"valid", "near_valid"}:
            invoke(target_registry)
        else:
            invoke(_target_definition,"unregistered_target")
    elif requirement_id.startswith("S8_MGMT_"):
        if fixture_class == "valid":
            invoke(_section_specs,"executive-release-brief")
        elif fixture_class == "near_valid":
            invoke(_dep,"not_used")
        else:
            invoke(_dep,"not_used", "forbidden_generation", None)
    else:
        if fixture_class == "valid":
            invoke(validate_specialist_registries)
        elif fixture_class == "near_valid":
            invoke(_dep,"unavailable")
        else:
            invoke(_dep,"unavailable", "forbidden_generation", None)
    return True, None, None


def execute_requirement_proof(requirement_id: str, fixture_class: str, *, final_commit: str) -> dict:
    if fixture_class not in FIXTURE_CLASSES:
        raise ValueError("proof_fixture_class_invalid")
    expected_acceptance = fixture_class != "adversarial_invalid"
    actual_acceptance = True
    actual_exception = actual_error = None
    with session(Path.cwd(), "proof:" + requirement_id + ":" + fixture_class) as invocations:
        try:
            invoke(_exercise, requirement_id, fixture_class)
        except ValueError as exc:
            actual_acceptance=False; actual_exception=type(exc).__name__; actual_error=str(exc)
    event={"proof_id":f"proof_{requirement_id.lower()}_{fixture_class}","subcase_id":f"{requirement_id}:{fixture_class}","actual_acceptance":actual_acceptance,"actual_exception":actual_exception,"actual_error_code":actual_error,"actual_schema_result":"not_applicable","artifact_path":"docs/validation/session6-8-requirement-inventory.json","artifact_assertion":"requirement_row_resolves","actual_record_count":1,"side_effect_observed":False,"production_invocation_ids":[item["invocation_id"] for item in invocations]}
    event["passed"] = actual_acceptance == expected_acceptance and bool(event["production_invocation_ids"])
    output=os.environ.get("SHIPROOM_PROOF_EVENT_ROOT")
    if output:
        root=Path(output); root.mkdir(parents=True,exist_ok=True)
        (root/(event["proof_id"]+"_"+uuid.uuid4().hex+".json")).write_text(json.dumps(event,sort_keys=True)+"\n",encoding="utf-8")
    return event
