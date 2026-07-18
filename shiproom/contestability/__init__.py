"""Append-only contestation ledger; no action rewrites upstream authority."""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import ensure_directory, replace_bytes, safe_entry, write_bytes


ACTIONS={"accept_finding","dispute_with_evidence","clarify_requirement","add_evidence","accept_named_risk","defer","request_remediation"}
OWNER_ONLY={"accept_named_risk"}
COMPILER_VERSION="portable-contestability.v1"


def root(ctx:LocalExecutionContext)->Path:return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"contestability"
def _json(value:object)->bytes:return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _sha(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _semantic(value:dict)->dict:return {key:item for key,item in value.items() if key!="created_at"}


def _owner_authority(ctx:LocalExecutionContext, action:dict)->None:
    reference=action.get("owner_authority_ref"); snapshot=action.get("owner_authority_snapshot_hash")
    valid=[item for item in ctx.release.get("owner_authorities",[]) if item.get("authority_id")==reference and item.get("release_id")==ctx.release["release_id"] and item.get("snapshot_hash")==snapshot]
    if len(valid)!=1:raise ValueError("owner_authority_invalid")


def _validate(ctx:LocalExecutionContext, action:dict)->dict:
    fields={"action_id","release_id","actor_type","actor_label","action","target_type","target_id","source_generation","submitted_evidence","rationale","created_at","owner_authority_ref","owner_authority_snapshot_hash"}
    if set(action)!=fields or action["release_id"]!=ctx.release["release_id"] or action["action"] not in ACTIONS:raise ValueError("contestation_action_invalid")
    if not all(isinstance(action[key],str) and action[key] for key in ("action_id","actor_type","actor_label","target_type","target_id","source_generation","rationale","created_at")):raise ValueError("contestation_action_invalid")
    if action["action"] in OWNER_ONLY:_owner_authority(ctx,action)
    elif action["owner_authority_ref"] is not None or action["owner_authority_snapshot_hash"] is not None:raise ValueError("unexpected_owner_authority")
    evidence=action["submitted_evidence"]
    if action["action"]=="add_evidence":
        if not isinstance(evidence,dict) or set(evidence)!={"compiler","generation","record_id"} or not all(isinstance(value,str) and value for value in evidence.values()):raise ValueError("unvalidated_evidence_payload")
    elif action["action"]=="dispute_with_evidence":
        if not isinstance(evidence,dict) or set(evidence)!={"compiler","generation","record_id"}:raise ValueError("counter_evidence_reference_required")
    elif evidence is not None:raise ValueError("unexpected_submitted_evidence")
    return action


def _current(ctx:LocalExecutionContext)->tuple[list[dict],dict|None]:
    pointer=root(ctx)/"current-contestation-generation.json"
    if not pointer.exists():return [],None
    value=json.loads(pointer.read_text(encoding="utf-8"));directory=root(ctx)/"generations"/value["generation"];safe_entry(directory,directory=True,label="contestation_generation");ledger=json.loads((directory/"contestation-ledger.json").read_text(encoding="utf-8"));return ledger["actions"],value


def append_action(ctx:LocalExecutionContext, action:dict)->dict:
    action=_validate(ctx,action); actions,_=_current(ctx); semantic=content_hash(_semantic(action))
    same=[item for item in actions if item["action_id"]==action["action_id"]]
    if same:
        if content_hash(_semantic(same[0]))==semantic:return {"status":"idempotent_replay","action_id":action["action_id"]}
        raise ValueError("conflicting_duplicate_action")
    actions=sorted(actions+[action],key=lambda item:item["action_id"]);generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="contestation_generation")
    ledger={"schema_version":"contestation-ledger.v1","release_id":ctx.release["release_id"],"actions":actions}
    derived={"schema_version":"contestation-effects.v1","named_risk_effects":[{"action_id":item["action_id"],"effect":"accepted_named_risk"} for item in actions if item["action"]=="accept_named_risk"],"remediation_requests":[item["action_id"] for item in actions if item["action"]=="request_remediation"]}
    write_bytes(ctx.repository_root,directory/"contestation-ledger.json",_json(ledger),label="contestation_ledger");write_bytes(ctx.repository_root,directory/"contestation-effects.json",_json(derived),label="contestation_effects")
    manifest={"schema_version":"contestation-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"actions_hash":content_hash([_semantic(item) for item in actions]),"artifact_hashes":{"contestation-ledger.json":_sha(_json(ledger)),"contestation-effects.json":_sha(_json(derived))},"semantic_bundle_hash":content_hash({"ledger":ledger,"effects":derived})}
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="contestation_manifest");replace_bytes(ctx.repository_root,root(ctx)/"current-contestation-generation.json",_json({"schema_version":"current-contestation-generation.v1","generation":generation,"manifest_hash":_sha(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="contestation_pointer")
    return {"status":"accepted","generation":generation,"action_id":action["action_id"]}


def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    actions,pointer=_current(ctx)
    if pointer is None:raise ValueError("contestation_generation_unavailable")
    directory=root(ctx)/"generations"/pointer["generation"];manifest=json.loads((directory/"manifest.json").read_text(encoding="utf-8"));ledger=json.loads((directory/"contestation-ledger.json").read_text(encoding="utf-8"));effects=json.loads((directory/"contestation-effects.json").read_text(encoding="utf-8"))
    if manifest["compiler_version"]!=COMPILER_VERSION or manifest["actions_hash"]!=content_hash([_semantic(item) for item in ledger["actions"]]):raise ValueError("contestation_generation_tampered")
    return manifest,{"contestation-ledger.json":ledger,"contestation-effects.json":effects}
