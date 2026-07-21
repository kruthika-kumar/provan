"""Append-only contestation ledger; no action rewrites upstream authority."""
from __future__ import annotations

import hashlib
import json
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.remediation_roadmaps import load_generation as load_remediation
from shiproom.review_organisation import load as load_review_plan
from shiproom.assessment import load_assessment
from shiproom.measurement_ai.persistence import load_generation as load_measurement_ai
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import checked_children, ensure_directory, read_bytes, read_json, replace_bytes, safe_entry, write_bytes, reject_private_alpha_operation


ACTIONS={"accept_finding","dispute_with_evidence","clarify_requirement","add_evidence","accept_named_risk","defer","request_remediation"}
OWNER_ONLY={"accept_named_risk"}
COMPILER_VERSION="portable-contestability.v1"


def guard_prohibited_operation(operation: str) -> None:
    """Contestation is a ledger only; it cannot reach external adapters."""
    reject_private_alpha_operation(operation)


def root(ctx:LocalExecutionContext)->Path:return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"contestability"
def _json(value:object)->bytes:return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _sha(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _semantic(value:dict)->dict:return {key:item for key,item in value.items() if key not in {"created_at","sequence","previous_action_hash","action_semantic_hash","target_registry_materiality"}}

def target_registry(value: dict | None = None)->dict:
    value = json.loads(resources.files("shiproom.contestability_schemas").joinpath("contestation-target-registry.v1.json").read_text(encoding="utf-8")) if value is None else value
    required = {"target_type", "source_domain", "source_artifact", "record_id_field", "production_loader", "permitted_actions", "evidence_relevance_rule", "materiality_rule", "owner_decision_eligibility"}
    domains = {"release", "graph", "assessment", "measurement_ai", "remediation", "review_plan"}
    targets = value.get("targets")
    if set(value)!={"schema_version","targets"} or value.get("schema_version") != "contestation-target-registry.v1" or not isinstance(targets, list) or not targets:
        raise ValueError("contestation_target_registry_invalid")
    ids = []
    for target in targets:
        if set(target) != required or not isinstance(target.get("target_type"), str) or not target["target_type"] or target["source_domain"] not in domains or not isinstance(target["permitted_actions"], list) or not set(target["permitted_actions"]) <= ACTIONS or not target["permitted_actions"] or not isinstance(target["owner_decision_eligibility"], bool):
            raise ValueError("contestation_target_registry_invalid")
        ids.append(target["target_type"])
        module_name, separator, attribute = target["production_loader"].rpartition(".")
        if not separator or not callable(getattr(__import__(module_name, fromlist=[attribute]), attribute, None)):
            raise ValueError("contestation_target_registry_invalid")
    if len(ids) != len(set(ids)):
        raise ValueError("contestation_target_registry_invalid")
    return value


def validate_action_contract(action: dict) -> dict:
    required={"action_id","release_id","actor_type","actor_label","action","target_type","target_id","source_generation","submitted_evidence","rationale","created_at","owner_authority_ref","owner_authority_snapshot_hash"}
    if not isinstance(action,dict) or set(action)!=required:
        raise ValueError("contestation_action_contract_invalid")
    if action.get("action") not in ACTIONS or not all(isinstance(action.get(name),str) and action[name] for name in ("action_id","release_id","actor_type","actor_label","target_type","target_id","source_generation","rationale","created_at")):
        raise ValueError("contestation_action_contract_invalid")
    if action["action"] in OWNER_ONLY and (not action.get("owner_authority_ref") or not action.get("owner_authority_snapshot_hash")):
        raise ValueError("contestation_owner_authority_required")
    return action

def _target_definition(target_type:str)->dict:
    values=[item for item in target_registry()["targets"] if item["target_type"]==target_type]
    if len(values)!=1:raise ValueError("contestation_target_unregistered")
    return values[0]

def _release_target(ctx:LocalExecutionContext,target_id:str)->dict|None:
    return next((item for item in ctx.release.get("findings",[]) if item.get("id")==target_id),None)

def _graph_target(ctx:LocalExecutionContext,target_id:str)->dict|None:
    input_value = load_assessment_input(ctx)
    return next((item for item in input_value["intent_artifacts"]["acceptance-criteria.json"].get("criteria", []) if item.get("criterion_id") == target_id), None)


def _remediation_target(ctx: LocalExecutionContext, target_id: str, source_generation: str) -> dict | None:
    manifest, artifacts = load_remediation(ctx)
    if source_generation != manifest.get("generation"):
        raise ValueError("contestation_target_generation_mismatch")
    return next((item for item in artifacts["remediation-plan.json"].get("packets", []) if item.get("remediation_id") == target_id), None)


def _assessment_target(ctx: LocalExecutionContext, target_id: str, source_generation: str) -> dict | None:
    manifest, artifacts = load_assessment(ctx)
    if source_generation != manifest.get("generation"):
        raise ValueError("contestation_target_generation_mismatch")
    return next((item for item in artifacts.get("assessment-graph-overlay.json", {}).get("nodes", []) if item.get("node_id") == target_id and item.get("node_type") == "assessment_gap"), None)


def _measurement_ai_target(ctx: LocalExecutionContext, target_id: str, source_generation: str) -> dict | None:
    manifest, artifacts = load_measurement_ai(ctx)
    if source_generation != manifest.get("generation"):
        raise ValueError("contestation_target_generation_mismatch")
    return next((item for item in artifacts.get("measurement-ai-readiness.json", {}).get("checks", []) if item.get("check_id") == target_id), None)


def _review_plan_target(ctx: LocalExecutionContext, target_id: str, source_generation: str) -> dict | None:
    manifest, artifacts = load_review_plan(ctx)
    if source_generation != manifest.get("generation"):
        raise ValueError("contestation_target_generation_mismatch")
    return next((item for item in artifacts.get("review-plan.json", {}).get("specialists", []) if item.get("specialist_id") == target_id), None)

def _validate_target(ctx:LocalExecutionContext, action:dict)->dict:
    definition=_target_definition(action["target_type"])
    if action["action"] not in definition["permitted_actions"]:raise ValueError("contestation_action_not_permitted_for_target")
    if definition["source_domain"]=="release": target=_release_target(ctx,action["target_id"])
    elif definition["source_domain"]=="graph": target=_graph_target(ctx,action["target_id"])
    elif definition["source_domain"] == "remediation": target = _remediation_target(ctx, action["target_id"], action["source_generation"])
    elif definition["source_domain"] == "assessment": target = _assessment_target(ctx, action["target_id"], action["source_generation"])
    elif definition["source_domain"] == "measurement_ai": target = _measurement_ai_target(ctx, action["target_id"], action["source_generation"])
    elif definition["source_domain"] == "review_plan": target = _review_plan_target(ctx, action["target_id"], action["source_generation"])
    else: raise ValueError("contestation_target_unregistered")
    if target is None:raise ValueError("contestation_target_not_found")
    return definition


def _accepted_evidence(ctx: LocalExecutionContext, reference: dict, target_type: str, target_id: str) -> None:
    """Evidence is an already-accepted canonical record, never action prose."""
    compiler = reference.get("compiler")
    if compiler == "remediation":
        manifest, artifacts = load_remediation(ctx)
        if reference["generation"] != manifest["generation"]:
            raise ValueError("contestation_evidence_generation_mismatch")
        records = artifacts["remediation-plan.json"].get("packets", [])
        if not any(item.get("remediation_id") == reference["record_id"] for item in records):
            raise ValueError("contestation_evidence_record_not_found")
        if target_type == "remediation" and reference["record_id"] != target_id:
            raise ValueError("contestation_evidence_irrelevant")
        return
    if compiler == "review_plan":
        manifest, artifacts = load_review_plan(ctx)
        if reference["generation"] != manifest["generation"]:
            raise ValueError("contestation_evidence_generation_mismatch")
        if not any(item.get("specialist_id") == reference["record_id"] for item in artifacts["review-plan.json"].get("specialists", [])):
            raise ValueError("contestation_evidence_record_not_found")
        return
    if compiler == "assessment":
        manifest, artifacts = load_assessment(ctx)
        if reference["generation"] != manifest["generation"]:
            raise ValueError("contestation_evidence_generation_mismatch")
        records = artifacts.get("assessment-graph-overlay.json", {}).get("nodes", [])
        if not any(item.get("node_id") == reference["record_id"] for item in records):
            raise ValueError("contestation_evidence_record_not_found")
        if target_type == "assessment_gap" and reference["record_id"] != target_id:
            raise ValueError("contestation_evidence_irrelevant")
        return
    if compiler == "measurement_ai":
        manifest, artifacts = load_measurement_ai(ctx)
        if reference["generation"] != manifest["generation"]:
            raise ValueError("contestation_evidence_generation_mismatch")
        records = artifacts.get("measurement-ai-readiness.json", {}).get("checks", [])
        if not any(item.get("check_id") == reference["record_id"] for item in records):
            raise ValueError("contestation_evidence_record_not_found")
        if target_type == "measurement_ai_check" and reference["record_id"] != target_id:
            raise ValueError("contestation_evidence_irrelevant")
        return
    raise ValueError("contestation_evidence_compiler_unregistered")


def _owner_authority(ctx:LocalExecutionContext, action:dict)->None:
    reference=action.get("owner_authority_ref"); snapshot=action.get("owner_authority_snapshot_hash")
    valid=[item for item in ctx.release.get("owner_authorities",[]) if item.get("authority_id")==reference and item.get("release_id")==ctx.release["release_id"] and item.get("snapshot_hash")==snapshot]
    if len(valid)!=1:raise ValueError("owner_authority_invalid")


def _validate(ctx:LocalExecutionContext, action:dict)->dict:
    fields={"action_id","release_id","actor_type","actor_label","action","target_type","target_id","source_generation","submitted_evidence","rationale","created_at","owner_authority_ref","owner_authority_snapshot_hash"}
    if set(action)!=fields or action["release_id"]!=ctx.release["release_id"] or action["action"] not in ACTIONS:raise ValueError("contestation_action_invalid")
    if not all(isinstance(action[key],str) and action[key] for key in ("action_id","actor_type","actor_label","target_type","target_id","source_generation","rationale","created_at")):raise ValueError("contestation_action_invalid")
    definition=_validate_target(ctx,action)
    if action["action"] in OWNER_ONLY:
        if not definition["owner_decision_eligibility"]:raise ValueError("owner_decision_target_ineligible")
        _owner_authority(ctx,action)
    elif action["owner_authority_ref"] is not None or action["owner_authority_snapshot_hash"] is not None:raise ValueError("unexpected_owner_authority")
    evidence=action["submitted_evidence"]
    if action["action"]=="add_evidence":
        if not isinstance(evidence,dict) or set(evidence)!={"compiler","generation","record_id"} or not all(isinstance(value,str) and value for value in evidence.values()):raise ValueError("unvalidated_evidence_payload")
        _accepted_evidence(ctx, evidence, action["target_type"], action["target_id"])
    elif action["action"]=="dispute_with_evidence":
        if not isinstance(evidence,dict) or set(evidence)!={"compiler","generation","record_id"}:raise ValueError("counter_evidence_reference_required")
        _accepted_evidence(ctx, evidence, action["target_type"], action["target_id"])
    elif evidence is not None:raise ValueError("unexpected_submitted_evidence")
    action["target_registry_materiality"] = definition["materiality_rule"]
    return action


def _owner_decision_budget(ctx: LocalExecutionContext, actions: list[dict]) -> dict:
    candidates = []
    for action in actions:
        if action["action"] not in {"accept_named_risk", "defer"}:
            continue
        definition = _target_definition(action["target_type"])
        if not definition["owner_decision_eligibility"]:
            continue
        target = _release_target(ctx, action["target_id"]) if action["target_type"] == "finding" else None
        if target is None:
            continue
        deterministic = target.get("evidence_class") in {"deterministically_established", "source_verified"}
        if target.get("blocker") is True and target.get("owner_decision_required") is True and deterministic:
            priority, reason = 1, "verified_blocker_requires_owner_action"
        elif target.get("condition") is True or target.get("state") == "MATERIAL_CONDITION":
            priority, reason = 2, "canonical_material_condition"
        elif target.get("risk") in {"high", "critical"} or action["action"] in {"accept_named_risk", "defer"}:
            priority, reason = 3, "high_risk_unresolved_decision"
        else:
            continue
        candidates.append({
            "action_id": action["action_id"],
            "target_id": action["target_id"],
            "priority": priority,
            "priority_reason_code": reason,
            "source_reference": {
                "target_type": action["target_type"],
                "target_id": action["target_id"],
                "source_generation": action["source_generation"],
            },
        })
    ordered = sorted(candidates, key=lambda item: (item["priority"], item["action_id"]))
    return {
        "immediate_owner_decisions": ordered[:2],
        "overflow_owner_decisions": ordered[2:],
        "priority_reason_codes": [item["priority_reason_code"] for item in ordered],
        "source_references": [item["source_reference"] for item in ordered],
    }


def _current(ctx:LocalExecutionContext)->tuple[list[dict],dict|None]:
    pointer=root(ctx)/"current-contestation-generation.json"
    try:
        safe_entry(pointer, directory=False, label="contestation_pointer")
    except FileNotFoundError:
        return [],None
    value=read_json(ctx.repository_root,pointer,label="contestation_pointer");directory=root(ctx)/"generations"/value["generation"];safe_entry(directory,directory=True,label="contestation_generation");ledger=read_json(ctx.repository_root,directory/"contestation-ledger.json",label="contestation_ledger");return ledger["actions"],value


def append_action(ctx:LocalExecutionContext, action:dict)->dict:
    action=validate_action_contract(action); action=_validate(ctx,action); actions,_=_current(ctx); semantic=content_hash(_semantic(action))
    same=[item for item in actions if item["action_id"]==action["action_id"]]
    if same:
        if content_hash(_semantic(same[0]))==semantic:return {"status":"idempotent_replay","action_id":action["action_id"]}
        raise ValueError("conflicting_duplicate_action")
    previous=content_hash(_semantic(actions[-1])) if actions else None
    action={**action,"sequence":len(actions)+1,"previous_action_hash":previous,"action_semantic_hash":semantic}
    actions=actions+[action];generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="contestation_generation")
    ledger={"schema_version":"contestation-ledger.v1","release_id":ctx.release["release_id"],"actions":actions}
    derived={"schema_version":"contestation-effects.v1","named_risk_effects":[{"action_id":item["action_id"],"effect":"accepted_named_risk"} for item in actions if item["action"]=="accept_named_risk"],"remediation_requests":[item["action_id"] for item in actions if item["action"]=="request_remediation"], **_owner_decision_budget(ctx, actions)}
    write_bytes(ctx.repository_root,directory/"contestation-ledger.json",_json(ledger),label="contestation_ledger");write_bytes(ctx.repository_root,directory/"contestation-effects.json",_json(derived),label="contestation_effects")
    manifest={"schema_version":"contestation-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"actions_hash":content_hash([_semantic(item) for item in actions]),"artifact_hashes":{"contestation-ledger.json":_sha(_json(ledger)),"contestation-effects.json":_sha(_json(derived))},"semantic_bundle_hash":content_hash({"ledger":ledger,"effects":derived})}
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="contestation_manifest");replace_bytes(ctx.repository_root,root(ctx)/"current-contestation-generation.json",_json({"schema_version":"current-contestation-generation.v1","generation":generation,"manifest_hash":_sha(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="contestation_pointer")
    return {"status":"accepted","generation":generation,"action_id":action["action_id"]}


def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    actions,pointer=_current(ctx)
    if pointer is None:raise ValueError("contestation_generation_unavailable")
    directory=root(ctx)/"generations"/pointer["generation"];manifest=read_json(ctx.repository_root,directory/"manifest.json",label="contestation_manifest");ledger=read_json(ctx.repository_root,directory/"contestation-ledger.json",label="contestation_ledger");effects=read_json(ctx.repository_root,directory/"contestation-effects.json",label="contestation_effects")
    if manifest["compiler_version"]!=COMPILER_VERSION or manifest["actions_hash"]!=content_hash([_semantic(item) for item in ledger["actions"]]):raise ValueError("contestation_generation_tampered")
    if pointer.get("manifest_hash") != _sha(_json(manifest)) or pointer.get("semantic_bundle_hash") != manifest.get("semantic_bundle_hash"):
        raise ValueError("contestation_pointer_tampered")
    if {path.name for path in checked_children(ctx.repository_root, directory, label="contestation_generation")} != {"manifest.json", "contestation-ledger.json", "contestation-effects.json"}:
        raise ValueError("contestation_generation_file_set_mismatch")
    for name, digest in manifest["artifact_hashes"].items():
        if _sha(read_bytes(ctx.repository_root, directory / name, label="contestation_artifact")) != digest:
            raise ValueError("contestation_artifact_tampered")
    return manifest,{"contestation-ledger.json":ledger,"contestation-effects.json":effects}
