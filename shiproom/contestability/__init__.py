"""Append-only contestation ledger; no action rewrites upstream authority."""
from __future__ import annotations

import hashlib
import json
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.remediation_roadmaps import load_generation as load_remediation
from shiproom.review_organisation import load as load_review_plan
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import checked_children, ensure_directory, read_bytes, read_json, replace_bytes, safe_entry, write_bytes


ACTIONS={"accept_finding","dispute_with_evidence","clarify_requirement","add_evidence","accept_named_risk","defer","request_remediation"}
OWNER_ONLY={"accept_named_risk"}
COMPILER_VERSION="portable-contestability.v1"


def root(ctx:LocalExecutionContext)->Path:return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"contestability"
def _json(value:object)->bytes:return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _sha(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _semantic(value:dict)->dict:return {key:item for key,item in value.items() if key not in {"created_at","sequence","previous_action_hash","action_semantic_hash","target_registry_materiality"}}

def target_registry()->dict:
    return json.loads(resources.files("shiproom.contestability_schemas").joinpath("contestation-target-registry.v1.json").read_text(encoding="utf-8"))

def _target_definition(target_type:str)->dict:
    values=[item for item in target_registry()["targets"] if item["target_type"]==target_type]
    if len(values)!=1:raise ValueError("contestation_target_unregistered")
    return values[0]

def _release_target(ctx:LocalExecutionContext,target_id:str)->dict|None:
    return next((item for item in ctx.release.get("findings",[]) if item.get("id")==target_id),None)

def _graph_target(ctx:LocalExecutionContext,target_id:str)->dict|None:
    # The current graph loader is intentionally not duplicated here; a criterion ID is accepted only from intent linkage.
    return next((item for item in ctx.release.get("criteria",[]) if item.get("criterion_id")==target_id),None)

def _validate_target(ctx:LocalExecutionContext, action:dict)->dict:
    definition=_target_definition(action["target_type"])
    if action["action"] not in definition["permitted_actions"]:raise ValueError("contestation_action_not_permitted_for_target")
    if definition["source_domain"]=="release": target=_release_target(ctx,action["target_id"])
    elif definition["source_domain"]=="graph": target=_graph_target(ctx,action["target_id"])
    else: target={"remediation_id":action["target_id"]} if action["source_generation"] else None
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


def _current(ctx:LocalExecutionContext)->tuple[list[dict],dict|None]:
    pointer=root(ctx)/"current-contestation-generation.json"
    if not pointer.exists():return [],None
    value=read_json(ctx.repository_root,pointer,label="contestation_pointer");directory=root(ctx)/"generations"/value["generation"];safe_entry(directory,directory=True,label="contestation_generation");ledger=read_json(ctx.repository_root,directory/"contestation-ledger.json",label="contestation_ledger");return ledger["actions"],value


def append_action(ctx:LocalExecutionContext, action:dict)->dict:
    action=_validate(ctx,action); actions,_=_current(ctx); semantic=content_hash(_semantic(action))
    same=[item for item in actions if item["action_id"]==action["action_id"]]
    if same:
        if content_hash(_semantic(same[0]))==semantic:return {"status":"idempotent_replay","action_id":action["action_id"]}
        raise ValueError("conflicting_duplicate_action")
    previous=content_hash(_semantic(actions[-1])) if actions else None
    action={**action,"sequence":len(actions)+1,"previous_action_hash":previous,"action_semantic_hash":semantic}
    actions=actions+[action];generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="contestation_generation")
    ledger={"schema_version":"contestation-ledger.v1","release_id":ctx.release["release_id"],"actions":actions}
    derived={"schema_version":"contestation-effects.v1","named_risk_effects":[{"action_id":item["action_id"],"effect":"accepted_named_risk"} for item in actions if item["action"]=="accept_named_risk"],"remediation_requests":[item["action_id"] for item in actions if item["action"]=="request_remediation"]}
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
