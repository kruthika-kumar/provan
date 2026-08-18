from __future__ import annotations

import ast
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .session10_validators import (validate_acceptance_preparation_serialized,
                                   validate_change_brief_serialized)

SHA = re.compile(r"sha256:[0-9a-f]{64}")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
EVIDENCE = {
    "source_verified", "owner_confirmed", "trusted_imported_receipt",
    "imported_unverified", "model_reviewed", "missing_evidence", "not_run",
    "unavailable", "tool_failure", "environment_failure", "inconclusive",
}
SOURCE_CHECKS = {"artifact_exists", "canonical_field_equals", "python_public_export_exists", "protected_invariant_satisfied"}
DECISIONS = {
    "cleared": {"accept", "accept_with_conditions", "hold", "reject"},
    "held": {"hold", "reject", "override_accept_risk"},
    "not_eligible": {"hold", "reject", "override_accept_risk"},
}
RISK_VALUES = {"low", "medium", "high", "unresolved"}
REVERSIBILITY_VALUES = {"easy", "bounded", "difficult", "unresolved"}
FUTURE_CAPABILITIES = {"verifier_runtime", "challenge"}
CAPABILITY_REASON_CODES = {
    "requested": "CAPABILITY_REQUESTED",
    "available": "CAPABILITY_METADATA_AVAILABLE",
    "unavailable": "CAPABILITY_UNAVAILABLE",
    "unqualified": "CAPABILITY_UNQUALIFIED",
    "degraded": "CAPABILITY_DEGRADED",
}

FORBIDDEN_SESSION11_CAPABILITIES={"execute","verify","challenge","remediate","deploy","sandbox","enterprise"}
CONTRACT_OBLIGATION_FIELDS=("intended_outcome","target_user","journeys","mandatory_criteria","conditional_criteria","non_applicable_criteria","unresolved_questions","protected_invariant_refs","closure_requirement_refs","allowed_evidence_classes","execution_policy","challenge_policy","risk","conditions","expires_at","reinspection_triggers")


def _independent_session11_schema_registry_raw() -> bytes:
    entries=[];session12_ids={"provan.foundry_acceptance_projection.v1","provan.contract_foundry_run.v1","provan.foundry_run_binding.v1","provan.verification_pattern_library.v1","provan.source_authority_ledger.v1","provan.intent_model.v1","provan.goal_obstacle_model.v1","provan.premortem_analysis.v1","provan.contract_candidate.v1","provan.contract_audit.v1","provan.contract_witness_set.v1","provan.contract_revision_record.v1","provan.contract_readiness.v1","provan.verification_pattern.v1","provan.verification_pattern_selection.v1","provan.model_routing_receipt.v1","provan.session_handoff.v2","provan.session12_implementation_binding.v1","provan.foundry_real_use_qualification.v1","provan.session12_reviewer_receipt.v1","provan.session12_closeout.v1"}
    for path in sorted(Path(__file__).with_name("schemas").glob("*.json"),key=lambda item:item.name):
        raw=path.read_bytes();value=json.loads(raw)
        if value.get("$id") in session12_ids:continue
        entries.append({"schema_id":value["$id"],"path":f"provan/schemas/{path.name}","sha256":sha256_bytes(raw),"normalized_sha256":sha256_bytes(canonical_bytes(value))})
    return canonical_bytes({"schema_id":"provan.session11_schema_registry.v1","sensitivity":"PUBLIC_SAFE","entries":entries,"registry_digest":sha256_bytes(canonical_bytes(entries))})


def validate_session11_capability_inventory(value:dict[str,Any])->dict[str,Any]:
    commands=value.get("commands");exports=value.get("exports");modules=value.get("modules")
    if not all(isinstance(rows,list) and all(isinstance(row,str) for row in rows) for rows in (commands,exports,modules)):
        raise ProvanError("SESSION11_CAPABILITY_INVENTORY_INVALID","inventory")
    exposed={part.lower().translate({45:95}) for row in commands+exports+modules for part in re.split(r"[^A-Za-z0-9_-]+",row) if part}
    forbidden=sorted(FORBIDDEN_SESSION11_CAPABILITIES & exposed)
    if forbidden:raise ProvanError("SESSION11_FORBIDDEN_CAPABILITY_REACHABLE",",".join(forbidden))
    if value.get("target_access")!="read_only" or value.get("target_execution") is not False or value.get("qualified_verifier") is not False or value.get("challenge_engine") is not False or value.get("remediation") is not False or value.get("enterprise_governance") is not False:
        raise ProvanError("SESSION11_FORBIDDEN_CAPABILITY_REACHABLE","authority flags")
    if value.get("topology_overlay_inputs")!=0:raise ProvanError("SESSION11_TOPOLOGY_OVERLAY_UNSUPPORTED","topology overlay")
    return value


def _load(raw: bytes, expected_schema: str) -> dict[str, Any]:
    try: value=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ProvanError("SESSION11_CANONICAL_JSON_INVALID",str(exc)) from exc
    if not isinstance(value,dict) or value.get("schema_id") != expected_schema: raise ProvanError("SESSION11_SCHEMA_ID_MISMATCH",expected_schema)
    if canonical_bytes(value) != raw: raise ProvanError("SESSION11_CANONICAL_BYTES_INVALID",expected_schema)
    return value


def _ref_matches(ref: dict[str,Any], value: dict[str,Any], raw: bytes, id_key: str) -> bool:
    return ref.get("id") == value.get(id_key) and ref.get("sha256") == sha256_bytes(raw)


def _uuid(value: Any, code: str) -> None:
    try: uuid.UUID(str(value))
    except (ValueError,TypeError,AttributeError) as exc: raise ProvanError(code,str(value)) from exc


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1]+"+00:00" if value.endswith("Z") else value)


def validate_seed_disposition_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.seed_disposition.v1");_uuid(value.get("disposition_id"),"SEED_DISPOSITION_ID_INVALID")
    actor=value.get("actor",{})
    if actor.get("authority_type")!="case_operator" or actor.get("authority_scope")!="case_intent_and_meaning" or actor.get("identity_assurance")!="self_asserted_label":raise ProvanError("SEED_DISPOSITION_ACTOR_AUTHORITY_INVALID",value["disposition_id"])
    ids=[]
    for row in value.get("items",[]):
        item_id=row.get("item_id");ids.append(item_id)
        if not SHA.fullmatch(str(item_id)) or row.get("action") not in {"confirm","reject","edit","unresolved"}:raise ProvanError("SEED_DISPOSITION_ITEM_INVALID",str(item_id))
        if row.get("actor")!=actor or not row.get("source_ref") or not row.get("kind") or not row.get("acted_at"):raise ProvanError("SEED_DISPOSITION_PROVENANCE_INVALID",str(item_id))
        if row.get("action")=="edit" and row.get("edited_value") is None:raise ProvanError("SEED_DISPOSITION_EDIT_VALUE_MISSING",str(item_id))
    if not ids or len(ids)!=len(set(ids)):raise ProvanError("SEED_DISPOSITION_COVERAGE_INVALID",value["disposition_id"])
    return value


def _independent_seed_disposition_items(brief: dict[str,Any], seed: dict[str,Any]) -> list[dict[str,Any]]:
    seed_digest=sha256_bytes(canonical_bytes(seed));items=[]
    sources=(
        ("intended_outcome","brief:intent",brief.get("claims",{}).get("source_attributed_product_intent",[])),
        ("journey","context:journey",brief.get("context_request",{}).get("journey_digests",[])),
        ("criterion","promotion:trigger",brief.get("promotion_decision",{}).get("applied_triggers",[])),
        ("context_use","context:record",brief.get("context_bundle",{}).get("records",[])),
        ("unresolved_question","seed:unresolved",seed.get("unresolved_questions",[])),
    )
    for kind,prefix,values in sources:
        for index,original_value in enumerate(values):
            source_ref=f"{prefix}:{index}"
            item_id=sha256_bytes(canonical_bytes({"seed":seed_digest,"kind":kind,"source_ref":source_ref,"value":original_value}))
            items.append({"item_id":item_id,"kind":kind,"source_ref":source_ref,"original_value":original_value})
    if not items:
        original_value="INTENDED_OUTCOME_UNRESOLVED";source_ref="seed:empty";kind="unresolved_question"
        item_id=sha256_bytes(canonical_bytes({"seed":seed_digest,"kind":kind,"source_ref":source_ref,"value":original_value}))
        items.append({"item_id":item_id,"kind":kind,"source_ref":source_ref,"original_value":original_value})
    return items


def _independent_contract_obligation_items(contract:dict[str,Any],seed:dict[str,Any])->list[dict[str,Any]]:
    seed_digest=sha256_bytes(canonical_bytes(seed));snapshot={key:contract[key] for key in CONTRACT_OBLIGATION_FIELDS};proposals=[("contract_obligation","contract:obligation:v1",snapshot)]
    for key,value in snapshot.items():
        if isinstance(value,list):proposals.extend((f"contract_{key}",f"contract:{key}:{index}",item) for index,item in enumerate(value))
        else:proposals.append((f"contract_{key}",f"contract:{key}",value))
    rows=[]
    for kind,source_ref,original_value in proposals:
        item_id=sha256_bytes(canonical_bytes({"seed":seed_digest,"kind":kind,"source_ref":source_ref,"value":original_value}));rows.append({"item_id":item_id,"kind":kind,"source_ref":source_ref,"original_value":original_value})
    return rows


def validate_verifier_work_order_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.verifier_work_order.v1");_uuid(value.get("work_order_id"),"VERIFIER_WORK_ORDER_ID_INVALID")
    criteria=value.get("criterion_refs",[]);requirements=value.get("completion_requirements",[]);capabilities=value.get("requested_capabilities",[])
    if not criteria or len(criteria)!=len(set(criteria)) or not requirements:raise ProvanError("VERIFIER_WORK_ORDER_COVERAGE_INVALID",value["work_order_id"])
    if not capabilities or any(item not in FUTURE_CAPABILITIES for item in capabilities):raise ProvanError("VERIFIER_CAPABILITY_CLASS_INVALID",value["work_order_id"])
    if value.get("target_policy")!="read_only" or value.get("remediation_allowed") is not False:raise ProvanError("VERIFIER_WORK_ORDER_AUTHORITY_ESCALATION",value["work_order_id"])
    prohibited=set(value.get("prohibited_actions",[]))
    if not {"target_mutation","target_execution","remediation","deployment"}.issubset(prohibited):raise ProvanError("VERIFIER_WORK_ORDER_PROHIBITIONS_INCOMPLETE",value["work_order_id"])
    if value.get("network_policy") not in {"none","allowlisted"}:raise ProvanError("VERIFIER_WORK_ORDER_NETWORK_POLICY_INVALID",value["work_order_id"])
    return value


def validate_verifier_capability_request_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.verifier_capability_request.v1");_uuid(value.get("request_id"),"VERIFIER_CAPABILITY_REQUEST_ID_INVALID")
    state=value.get("state")
    if value.get("capability") not in FUTURE_CAPABILITIES or value.get("reason_code")!=CAPABILITY_REASON_CODES.get(state):raise ProvanError("VERIFIER_CAPABILITY_STATE_INVALID",value["request_id"])
    return value


def validate_verification_result_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.verification_result.v1");_uuid(value.get("result_id"),"VERIFICATION_RESULT_ID_INVALID")
    state=value.get("state");evidence=value.get("evidence_refs",[])
    if state in {"passed","failed"} and not evidence:raise ProvanError("VERIFICATION_RESULT_EVIDENCE_MISSING",value["result_id"])
    if state in {"not_run","tool_failure","environment_failure","inconclusive","unavailable","not_applicable"} and evidence:raise ProvanError("VERIFICATION_RESULT_UNEXECUTED_EVIDENCE_FORBIDDEN",value["result_id"])
    return value


def _qualified_producer(value: dict[str,Any], qualified_producer_refs: set[str] | None) -> bool:
    ref=value.get("producer",{}).get("qualification_ref")
    return isinstance(ref,dict) and SHA.fullmatch(str(ref.get("sha256",""))) is not None and ref.get("id") in (qualified_producer_refs or set())


def validate_environment_receipt_serialized(raw: bytes, *, qualified_producer_refs: set[str] | None = None) -> dict[str,Any]:
    value=_load(raw,"provan.environment_receipt.v1");_uuid(value.get("receipt_id"),"ENVIRONMENT_RECEIPT_ID_INVALID")
    state=value.get("state")
    if state not in {"qualified","unqualified","unavailable","degraded","not_run"}:raise ProvanError("ENVIRONMENT_RECEIPT_STATE_INVALID",value["receipt_id"])
    if value.get("qualified") is True:
        if state!="qualified" or not _qualified_producer(value,qualified_producer_refs):raise ProvanError("RECEIPT_PRODUCER_QUALIFICATION_UNRESOLVED",value["receipt_id"])
    elif state=="qualified":raise ProvanError("ENVIRONMENT_RECEIPT_QUALIFICATION_MISMATCH",value["receipt_id"])
    return value


def validate_command_receipt_serialized(raw: bytes, *, qualified_producer_refs: set[str] | None = None) -> dict[str,Any]:
    value=_load(raw,"provan.command_receipt.v1");_uuid(value.get("receipt_id"),"COMMAND_RECEIPT_ID_INVALID")
    state=value.get("state");executed=value.get("executed")
    if state not in {"passed","failed","not_run","tool_failure","environment_failure","inconclusive","unavailable","unqualified"}:raise ProvanError("COMMAND_RECEIPT_STATE_INVALID",value["receipt_id"])
    if executed:
        if state not in {"passed","failed"} or not _qualified_producer(value,qualified_producer_refs):raise ProvanError("COMMAND_EXECUTION_AUTHORITY_UNRESOLVED",value["receipt_id"])
    elif state in {"passed","failed"}:raise ProvanError("COMMAND_RECEIPT_EXECUTION_MISMATCH",value["receipt_id"])
    return value


def validate_external_change_receipt_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.external_change_receipt.v1");_uuid(value.get("receipt_id"),"EXTERNAL_CHANGE_RECEIPT_ID_INVALID")
    if not FULL_COMMIT.fullmatch(str(value.get("original_head",""))) or not FULL_COMMIT.fullmatch(str(value.get("claimed_later_head",""))) or value.get("original_head")==value.get("claimed_later_head"):raise ProvanError("EXTERNAL_CHANGE_RECEIPT_LINEAGE_CLAIM_INVALID",value["receipt_id"])
    if value.get("provenance",{}).get("establishes_closure") is True:raise ProvanError("EXTERNAL_CHANGE_RECEIPT_CLOSURE_AUTHORITY_FORBIDDEN",value["receipt_id"])
    return value


def validate_closure_requirement_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.closure_requirement.v1")
    if value["required_evidence_class"] not in EVIDENCE: raise ProvanError("CLOSURE_EVIDENCE_CLASS_INVALID",value["required_evidence_class"])
    mode=value["check_mode"]; check=value["check"]
    if mode=="source_only":
        kind=check.get("type")
        if kind not in SOURCE_CHECKS: raise ProvanError("CLOSURE_SOURCE_CHECK_UNSUPPORTED",str(kind))
        if kind in {"artifact_exists","canonical_field_equals","python_public_export_exists"}:
            path=str(check.get("path","")); pure=PurePosixPath(path)
            if pure.is_absolute() or not path or any(part in {"",".",".."} for part in pure.parts): raise ProvanError("CLOSURE_SOURCE_PATH_UNSAFE",path)
        if kind=="canonical_field_equals":
            pointer=check.get("json_pointer")
            if not isinstance(pointer,str) or (pointer and not pointer.startswith("/")): raise ProvanError("CLOSURE_JSON_POINTER_INVALID",str(pointer))
            if "expected_value" not in check: raise ProvanError("CLOSURE_EXPECTED_VALUE_MISSING",value["criterion_ref"])
        if kind=="python_public_export_exists" and not re.fullmatch(r"[A-Za-z_]\w*",str(check.get("symbol",""))): raise ProvanError("CLOSURE_PYTHON_EXPORT_INVALID",str(check.get("symbol")))
        if kind=="protected_invariant_satisfied" and not isinstance(check.get("protected_invariant_ref"),dict): raise ProvanError("PROTECTED_INVARIANT_REF_MISSING",value["criterion_ref"])
    elif mode=="human_confirmation":
        if check != {"type":"canonical_case_operator_action"}: raise ProvanError("HUMAN_CONFIRMATION_CHECK_INVALID",value["criterion_ref"])
    elif mode in {"verifier_runtime","challenge"}:
        if check.get("type") != "future_capability": raise ProvanError("FUTURE_CAPABILITY_CHECK_INVALID",value["criterion_ref"])
    else: raise ProvanError("CLOSURE_CHECK_MODE_INVALID",str(mode))
    return value


def validate_protected_invariant_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.protected_invariant.v1")
    if value["required_evidence_class"] not in EVIDENCE: raise ProvanError("PROTECTED_INVARIANT_EVIDENCE_INVALID",value["protected_invariant_id"])
    if value["check_mode"]=="source_only" and value["check"].get("type") not in SOURCE_CHECKS-{"protected_invariant_satisfied"}: raise ProvanError("PROTECTED_INVARIANT_CHECK_UNSUPPORTED",value["protected_invariant_id"])
    if value["check"].get("callable") or value["check"].get("command") or value["check"].get("pattern"): raise ProvanError("PROTECTED_INVARIANT_FREEFORM_EVALUATOR_FORBIDDEN",value["protected_invariant_id"])
    return value


def validate_contract_serialized(raw: bytes, closures: dict[str,bytes], invariants: dict[str,bytes], *, predecessors: dict[str,bytes], schema_registry_raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.acceptance_contract.v1")
    _uuid(value.get("contract_id"),"CONTRACT_ID_INVALID")
    if not isinstance(value.get("version"),int) or value["version"]<1 or not value.get("disposition_refs") or len({r["id"] for r in value["disposition_refs"]})!=len(value["disposition_refs"]):raise ProvanError("CONTRACT_LINEAGE_PROVENANCE_INVALID",value["contract_id"])
    for name in ("preparation_ref","seed_ref","brief_ref"):
        ref=value.get(name,{})
        if not ref.get("id") or not SHA.fullmatch(str(ref.get("sha256",""))):raise ProvanError("CONTRACT_PREDECESSOR_REF_INVALID",name)
    predecessor_specs=(
        ("preparation_ref","provan.acceptance_preparation.v1","preparation_id"),
        ("brief_ref","provan.change_brief.v1","brief_id"),
        ("seed_ref","provan.acceptance_seed.v1","seed_id"),
    )
    resolved={}
    for name,schema_id,id_key in predecessor_specs:
        ref=value[name];predecessor_raw=predecessors.get(ref["id"])
        if predecessor_raw is None:raise ProvanError("CONTRACT_PREDECESSOR_UNRESOLVED",name)
        predecessor=_load(predecessor_raw,schema_id)
        if not _ref_matches(ref,predecessor,predecessor_raw,id_key):raise ProvanError("CONTRACT_PREDECESSOR_BINDING_MISMATCH",name)
        resolved[name]=(predecessor,predecessor_raw)
    preparation,preparation_raw=resolved["preparation_ref"];brief,brief_raw=resolved["brief_ref"];seed,seed_raw=resolved["seed_ref"]
    validate_acceptance_preparation_serialized(preparation_raw);validate_change_brief_serialized(brief_raw)
    if seed!=brief.get("acceptance_seed") or seed_raw!=canonical_bytes(brief.get("acceptance_seed")):
        raise ProvanError("CONTRACT_SEED_BRIEF_BINDING_MISMATCH",value["contract_id"])
    if preparation.get("brief_id")!=brief.get("brief_id") or preparation.get("case_id")!=brief.get("case_id") or preparation.get("candidate_digest")!=brief.get("candidate",{}).get("candidate_digest"):
        raise ProvanError("CONTRACT_PREPARATION_BRIEF_BINDING_MISMATCH",value["contract_id"])
    expected_seed_items={row["item_id"]:row for row in _independent_seed_disposition_items(brief,seed)};expected_obligation_items={row["item_id"]:row for row in _independent_contract_obligation_items(value,seed)};resolved_dispositions=[];seed_dispositions=0;obligation_dispositions=0
    for ref in value["disposition_refs"]:
        disposition_raw=predecessors.get(ref["id"])
        if disposition_raw is None:raise ProvanError("CONTRACT_DISPOSITION_UNRESOLVED",ref["id"])
        disposition=validate_seed_disposition_serialized(disposition_raw)
        if not _ref_matches(ref,disposition,disposition_raw,"disposition_id") or disposition.get("preparation_ref")!=value["preparation_ref"] or disposition.get("seed_ref")!=value["seed_ref"] or disposition.get("case_id")!=value.get("case_id"):
            raise ProvanError("CONTRACT_DISPOSITION_BINDING_MISMATCH",ref["id"])
        actual_items=disposition.get("items",[]);actual_ids={row.get("item_id") for row in actual_items}
        expected_disposition_items=expected_obligation_items if any(str(row.get("source_ref","")).startswith("contract:") for row in actual_items) else expected_seed_items
        if expected_disposition_items is expected_obligation_items:obligation_dispositions+=1
        else:seed_dispositions+=1
        if len(actual_items)!=len(expected_disposition_items) or actual_ids!=set(expected_disposition_items):
            raise ProvanError("CONTRACT_DISPOSITION_SEMANTICS_MISMATCH",ref["id"])
        for row in actual_items:
            expected=expected_disposition_items[row["item_id"]]
            if any(row.get(field)!=expected[field] for field in ("kind","source_ref","original_value")):
                raise ProvanError("CONTRACT_DISPOSITION_SEMANTICS_MISMATCH",row["item_id"])
            if expected_disposition_items is expected_obligation_items and (row.get("action")!="confirm" or row.get("edited_value") is not None):
                raise ProvanError("CONTRACT_OBLIGATION_ACTION_MISMATCH",row["item_id"])
        resolved_dispositions.append(disposition)
    if seed_dispositions!=1 or obligation_dispositions!=1:raise ProvanError("CONTRACT_DISPOSITION_COVERAGE_INVALID",value["contract_id"])
    if value.get("supersedes") is not None and (value["version"]<=1 or not value["supersedes"].get("id") or not SHA.fullmatch(str(value["supersedes"].get("sha256","")))):raise ProvanError("CONTRACT_SUPERSESSION_INVALID",value["contract_id"])
    if value["candidate"].get("mode") != "immutable" or not FULL_COMMIT.fullmatch(str(value["candidate"].get("head",""))): raise ProvanError("CONTRACT_CANDIDATE_NOT_IMMUTABLE",value["contract_id"])
    if value.get("case_id")!=brief.get("case_id") or value.get("candidate")!=brief.get("candidate") or value.get("repository_identity")!=brief.get("candidate",{}).get("repository_identity"):
        raise ProvanError("CONTRACT_CANDIDATE_PROVENANCE_MISMATCH",value["contract_id"])
    budget=value["challenge_policy"].get("challenge_budget",{}); cls=budget.get("class")
    caps=[budget.get("max_instances"),budget.get("max_wall_seconds"),budget.get("max_network_requests")]
    if cls=="not_required" and caps != [0,0,0]: raise ProvanError("CHALLENGE_NOT_REQUIRED_CAP_NONZERO",value["contract_id"])
    if cls=="bounded" and not (isinstance(caps[0],int) and 1<=caps[0]<=32 and isinstance(caps[1],int) and 1<=caps[1]<=3600 and isinstance(caps[2],int) and 0<=caps[2]<=128): raise ProvanError("CHALLENGE_BUDGET_INVALID",value["contract_id"])
    if cls not in {"not_required","bounded"}: raise ProvanError("CHALLENGE_BUDGET_INVALID",value["contract_id"])
    execution=value["execution_policy"]
    if execution.get("target_access")!="read_only" or execution.get("network_policy") not in {"none","allowlisted"}: raise ProvanError("CONTRACT_EXECUTION_POLICY_INVALID",value["contract_id"])
    allowed_risk_refs={value["preparation_ref"]["id"],value["seed_ref"]["id"],value["brief_ref"]["id"],*(ref["id"] for ref in value["disposition_refs"])}
    for name, allowed_values in (("tier",RISK_VALUES),("reversibility",REVERSIBILITY_VALUES)):
        row=value["risk"].get(name,{})
        refs=row.get("provenance_refs")
        if row.get("value") not in allowed_values or row.get("authority") not in {"source_verified","owner_confirmed","unresolved"} or not isinstance(refs,list) or not refs or not set(refs).issubset(allowed_risk_refs): raise ProvanError("RISK_AUTHORITY_INVALID",name)
        required_kind="risk_tier" if name=="tier" else "reversibility"
        if row["authority"]=="source_verified":
            if not any(item.get("kind")==required_kind for item in expected_seed_items.values()):raise ProvanError("RISK_AUTHORITY_INVALID",name)
        if row["authority"]=="owner_confirmed":
            if not set(refs).issubset({r["id"] for r in value["disposition_refs"]}):raise ProvanError("RISK_AUTHORITY_INVALID",name)
            if not any(item.get("kind")==required_kind and item.get("action") in {"confirm","edit"} for disposition in resolved_dispositions for item in disposition.get("items",[])):raise ProvanError("RISK_AUTHORITY_INVALID",name)
        if row["authority"]=="unresolved" and row["value"]!="unresolved":raise ProvanError("RISK_AUTHORITY_INVALID",name)
        if row["authority"]!="unresolved" and row["value"]=="unresolved":raise ProvanError("RISK_AUTHORITY_INVALID",name)
    if value.get("operator_authority",{}).get("authority_type")!="case_operator" or value["operator_authority"].get("authority_scope")!="case_intent_and_meaning" or value["operator_authority"].get("identity_assurance")!="self_asserted_label":raise ProvanError("CONTRACT_OPERATOR_AUTHORITY_INVALID",value["contract_id"])
    if value.get("decision_policy")!={"policy_id":"community.owner-decision-compatibility.v1","allowed":{k:sorted(v) for k,v in DECISIONS.items()}}:raise ProvanError("CONTRACT_DECISION_POLICY_INVALID",value["contract_id"])
    provenance=value.get("provenance",{})
    registry=_load(schema_registry_raw,"provan.session11_schema_registry.v1");entries=registry.get("entries")
    if not isinstance(entries,list) or registry.get("registry_digest")!=sha256_bytes(canonical_bytes(entries)):
        raise ProvanError("CONTRACT_SCHEMA_REGISTRY_INVALID",value["contract_id"])
    if schema_registry_raw!=_independent_session11_schema_registry_raw():
        raise ProvanError("CONTRACT_SCHEMA_REGISTRY_INVALID",value["contract_id"])
    if provenance.get("package_version") not in {"0.4.0","0.5.0"} or provenance.get("policy_id")!="community.acceptance.v1" or provenance.get("policy_version")!="1" or provenance.get("schema_registry_digest")!=registry["registry_digest"]:raise ProvanError("CONTRACT_PROVENANCE_INVALID",value["contract_id"])
    if value.get("expires_at") is not None:
        try: datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))
        except (ValueError,TypeError) as exc: raise ProvanError("CONTRACT_EXPIRY_INVALID",value["contract_id"]) from exc
    criterion_ids=[]
    for group in ("mandatory_criteria","conditional_criteria","non_applicable_criteria"):
        for row in value[group]:
            cid=row.get("criterion_id"); criterion_ids.append(cid)
            if not cid or not isinstance(row.get("closure_requirement_ref"),dict): raise ProvanError("CONTRACT_CRITERION_INCOMPLETE",str(cid))
            if group=="conditional_criteria" and row.get("activation_rule",{}).get("type") not in {"source_artifact_exists","source_artifact_absent","operator_confirmation"}: raise ProvanError("CONDITIONAL_ACTIVATION_RULE_INVALID",str(cid))
    if len(set(criterion_ids))!=len(criterion_ids): raise ProvanError("CONTRACT_CRITERION_DUPLICATE",value["contract_id"])
    criterion_rows=[row for group in ("mandatory_criteria","conditional_criteria","non_applicable_criteria") for row in value[group]]
    if {row["closure_requirement_ref"]["id"] for row in criterion_rows}!={ref["id"] for ref in value["closure_requirement_refs"]}:
        raise ProvanError("CONTRACT_CLOSURE_REQUIREMENT_COVERAGE_MISMATCH",value["contract_id"])
    for ref in value["closure_requirement_refs"]:
        raw_ref=closures.get(ref["id"])
        if raw_ref is None: raise ProvanError("CLOSURE_REQUIREMENT_UNRESOLVED",ref["id"])
        item=validate_closure_requirement_serialized(raw_ref)
        if not _ref_matches(ref,item,raw_ref,"closure_requirement_id"): raise ProvanError("CLOSURE_REQUIREMENT_BINDING_MISMATCH",ref["id"])
    for ref in value["protected_invariant_refs"]:
        raw_ref=invariants.get(ref["id"])
        if raw_ref is None: raise ProvanError("PROTECTED_INVARIANT_UNRESOLVED",ref["id"])
        item=validate_protected_invariant_serialized(raw_ref)
        if not _ref_matches(ref,item,raw_ref,"protected_invariant_id"): raise ProvanError("PROTECTED_INVARIANT_BINDING_MISMATCH",ref["id"])
    invariant_refs={ref["id"]:ref for ref in value["protected_invariant_refs"]}
    for ref in value["closure_requirement_refs"]:
        item=validate_closure_requirement_serialized(closures[ref["id"]])
        criterion=next(row for row in criterion_rows if row["closure_requirement_ref"]["id"]==ref["id"])
        if item["criterion_ref"]!=criterion["criterion_id"] or item["required_evidence_class"] not in criterion["required_evidence_classes"]:
            raise ProvanError("CONTRACT_CLOSURE_REQUIREMENT_SEMANTIC_MISMATCH",ref["id"])
        for invariant_ref in item["protected_invariant_refs"]:
            if invariant_refs.get(invariant_ref["id"])!=invariant_ref:raise ProvanError("CLOSURE_PROTECTED_INVARIANT_BINDING_MISMATCH",ref["id"])
        if item["check"].get("type")=="protected_invariant_satisfied" and item["check"].get("protected_invariant_ref") not in item["protected_invariant_refs"]:raise ProvanError("CLOSURE_PROTECTED_INVARIANT_BINDING_MISMATCH",ref["id"])
    return value


def derive_conditional_activation(contract: dict[str,Any], artifact_digests: dict[str,str]) -> list[dict[str,Any]]:
    rows=[]
    for criterion in contract["conditional_criteria"]:
        rule=criterion["activation_rule"]; kind=rule["type"]; path=rule.get("path"); present=path in artifact_digests
        if kind=="source_artifact_exists": state="active" if present else "inactive"
        elif kind=="source_artifact_absent": state="inactive" if present else "active"
        else: state="unresolved"
        rows.append({"criterion_ref":criterion["criterion_id"],"state":state,"basis":"candidate_artifact_inventory" if kind!="operator_confirmation" else "operator_confirmation_unavailable","evidence_refs":[artifact_digests[path]] if present else [],"reason_code":"ACTIVATION_PREDICATE_TRUE" if state=="active" else "ACTIVATION_PREDICATE_FALSE" if state=="inactive" else "ACTIVATION_AUTHORITY_UNAVAILABLE"})
    return rows


def _verification_artifacts(artifacts: dict[str,str]) -> dict[str,str]:
    return {path:digest for path,digest in artifacts.items() if path.startswith(("tests/",".github/workflows/")) or PurePosixPath(path).name.lower() in {"tox.ini","pytest.ini","coverage.toml",".coveragerc"}}


def validate_freeze_serialized(raw: bytes, contract_raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.candidate_freeze.v1"); contract=json.loads(contract_raw)
    _uuid(value.get("freeze_id"),"CANDIDATE_FREEZE_ID_INVALID")
    if not _ref_matches(value["contract_ref"],contract,contract_raw,"contract_id"): raise ProvanError("CONTRACT_FREEZE_BINDING_MISMATCH",value["freeze_id"])
    if value["repository_identity"]!=contract["repository_identity"]: raise ProvanError("CANDIDATE_CONTRACT_MISMATCH",value["freeze_id"])
    if value["purpose"]=="acceptance" and value["head"]!=contract["candidate"]["head"]: raise ProvanError("CANDIDATE_CONTRACT_MISMATCH",value["freeze_id"])
    expected=derive_conditional_activation(contract,value["artifact_digests"])
    if value["conditional_activation"]!=expected: raise ProvanError("CONDITIONAL_ACTIVATION_BINDING_MISMATCH",value["freeze_id"])
    artifacts=dict(sorted(value["artifact_digests"].items()))
    dependency={k:v for k,v in artifacts.items() if PurePosixPath(k).name.lower() in {"pyproject.toml","package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","poetry.lock"}}
    if value.get("workspace_digest")!=sha256_bytes(canonical_bytes(artifacts)) or value.get("dependency_digest")!=sha256_bytes(canonical_bytes(dependency)) or value.get("verification_surface_digest")!=sha256_bytes(canonical_bytes(_verification_artifacts(artifacts))):raise ProvanError("CANDIDATE_FREEZE_ANALYSIS_DIGEST_MISMATCH",value["freeze_id"])
    if value.get("protected_invariant_refs")!=contract.get("protected_invariant_refs"):raise ProvanError("CANDIDATE_FREEZE_INVARIANT_SET_MISMATCH",value["freeze_id"])
    expected_refs=[("protected_invariant",r["id"]) for r in contract["protected_invariant_refs"]]+[("closure_requirement",r["id"]) for r in contract["closure_requirement_refs"]]
    actual_refs=[(r.get("kind"),r.get("ref")) for r in value.get("source_check_results",[])]
    if actual_refs!=expected_refs or len(actual_refs)!=len(set(actual_refs)):raise ProvanError("CANDIDATE_FREEZE_SOURCE_CHECK_COVERAGE_MISMATCH",value["freeze_id"])
    for result in value["source_check_results"]:
        if result["status"]=="supports" and result["reason_code"]!="SOURCE_PREDICATE_SATISFIED":raise ProvanError("CANDIDATE_FREEZE_SOURCE_CHECK_RESULT_INVALID",result["ref"])
        if result["status"]=="falsifies" and result["reason_code"]!="SOURCE_PREDICATE_NOT_SATISFIED":raise ProvanError("CANDIDATE_FREEZE_SOURCE_CHECK_RESULT_INVALID",result["ref"])
        if result["status"]=="unable" and result["reason_code"] not in {"FUTURE_CAPABILITY_UNAVAILABLE","CANONICAL_OPERATOR_ACTION_NOT_SUPPLIED","DYNAMIC_PYTHON_EXPORT_NONCOVERAGE","PROTECTED_INVARIANT_UNRESOLVED"}:raise ProvanError("CANDIDATE_FREEZE_SOURCE_CHECK_RESULT_INVALID",result["ref"])
    return value


def effective_status(expires_at: str | None, now: Callable[[],datetime]) -> str:
    if not expires_at:return "active"
    expiry=datetime.fromisoformat(expires_at.replace("Z","+00:00"))
    current=now(); current=current if current.tzinfo else current.replace(tzinfo=timezone.utc)
    return "expired" if current>=expiry else "active"


def validate_settlement_serialized(raw: bytes, contract_raw: bytes, freeze_raw: bytes, *, now: Callable[[],datetime]) -> dict[str,Any]:
    value=_load(raw,"provan.evidence_settlement.v1"); contract=json.loads(contract_raw); freeze=json.loads(freeze_raw)
    if not _ref_matches(value["contract_ref"],contract,contract_raw,"contract_id") or not _ref_matches(value["freeze_ref"],freeze,freeze_raw,"freeze_id"): raise ProvanError("SETTLEMENT_CHAIN_MISMATCH",value["settlement_id"])
    expected=derive_conditional_activation(contract,freeze["artifact_digests"])
    if value["conditional_activation"]!=expected: raise ProvanError("CONDITIONAL_ACTIVATION_BINDING_MISMATCH",value["settlement_id"])
    by_activation={r["criterion_ref"]:r["state"] for r in expected}
    source_results={row["ref"]:row for row in freeze["source_check_results"] if row["kind"]=="closure_requirement"}
    contract_rows=[]
    for contract_class,key in (("mandatory","mandatory_criteria"),("conditional","conditional_criteria"),("not_applicable","non_applicable_criteria")):
        contract_rows.extend((contract_class,row) for row in contract[key])
    expected_ids=[row["criterion_id"] for _,row in contract_rows]
    actual_ids=[row.get("criterion_ref") for row in value["criteria"]]
    if len(actual_ids)!=len(set(actual_ids)) or actual_ids!=expected_ids:
        raise ProvanError("SETTLEMENT_CRITERION_COVERAGE_MISMATCH",value["settlement_id"])
    contract_by_id={row["criterion_id"]:(contract_class,row) for contract_class,row in contract_rows}
    has_future_requirement=False
    has_holding_condition=bool(contract.get("unresolved_questions")) or any(
        contract["risk"][name].get("authority")=="unresolved" or contract["risk"][name].get("value")=="unresolved"
        for name in ("tier","reversibility")
    )
    for row in value["criteria"]:
        contract_class,criterion=contract_by_id[row["criterion_ref"]]
        if row.get("contract_class")!=contract_class or row.get("closure_requirement_ref")!=criterion["closure_requirement_ref"] or row.get("material")!=criterion.get("material",True):
            raise ProvanError("SETTLEMENT_CRITERION_BINDING_MISMATCH",row["criterion_ref"])
        if row.get("required_evidence_class") not in criterion["required_evidence_classes"]:
            raise ProvanError("SETTLEMENT_EVIDENCE_CLASS_MISMATCH",row["criterion_ref"])
        state=row.get("state"); eligible=row.get("eligible_evidence",[])
        for evidence in eligible:
            result=source_results.get(evidence.get("closure_requirement_ref"));core={"source":"provan_source_only_evaluator","candidate_digest":freeze["candidate_digest"],"closure_requirement_ref":evidence.get("closure_requirement_ref"),"predicate_result":result and result.get("status"),"reason_code":result and result.get("reason_code")}
            if evidence.get("evidence_class")!="source_verified" or result is None or evidence.get("candidate_digest")!=freeze["candidate_digest"] or evidence.get("predicate_result")!=result.get("status") or evidence.get("evidence_id")!=sha256_bytes(canonical_bytes(core)):
                raise ProvanError("EVIDENCE_AUTHORITY_PROVENANCE_INVALID",row["criterion_ref"])
        result=source_results.get(criterion["closure_requirement_ref"]["id"])
        expected_eligible=[]
        if result and result.get("status") in {"supports","falsifies"} and "source_verified" in criterion["required_evidence_classes"]:
            core={"source":"provan_source_only_evaluator","candidate_digest":freeze["candidate_digest"],"closure_requirement_ref":criterion["closure_requirement_ref"]["id"],"predicate_result":result["status"],"reason_code":result["reason_code"]}
            expected_eligible=[{"evidence_id":sha256_bytes(canonical_bytes(core)),"evidence_class":"source_verified",**core}]
        if eligible!=expected_eligible:
            raise ProvanError("SETTLEMENT_ELIGIBLE_EVIDENCE_MISMATCH",row["criterion_ref"])
        supports=any(x["predicate_result"]=="supports" for x in expected_eligible); falsifies=any(x["predicate_result"]=="falsifies" for x in expected_eligible)
        expected_state="disputed" if supports and falsifies else "established" if supports else "falsified" if falsifies else "not_established"
        activation=by_activation.get(row["criterion_ref"])
        if contract_class=="not_applicable" or activation=="inactive":expected_state="not_applicable"
        if state!=expected_state: raise ProvanError("EVIDENCE_SETTLEMENT_STATE_INVALID",row["criterion_ref"])
        if state=="not_applicable" and row.get("missing_evidence_as_basis"): raise ProvanError("MISSING_EVIDENCE_NOT_APPLICABLE_FORBIDDEN",row["criterion_ref"])
        applicable=contract_class!="not_applicable" and activation!="inactive"
        if applicable and result and result.get("reason_code")=="FUTURE_CAPABILITY_UNAVAILABLE":has_future_requirement=True
        if activation=="unresolved" or (applicable and expected_state not in {"established"}):has_holding_condition=True
    expected_recommendation="not_eligible" if has_future_requirement else "held" if has_holding_condition else "cleared"
    if value.get("recommendation")!=expected_recommendation:
        raise ProvanError("SETTLEMENT_RECOMMENDATION_MISMATCH",value["settlement_id"])
    if value["effective_status"]!=effective_status(contract.get("expires_at"),now): raise ProvanError("SETTLEMENT_EXPIRY_STATUS_INVALID",value["settlement_id"])
    return value


def validate_owner_decision_serialized(raw: bytes, attestation_raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.owner_decision.v1"); att=json.loads(attestation_raw)
    _uuid(value.get("decision_id"),"OWNER_DECISION_ID_INVALID")
    if not _ref_matches(value["attestation_ref"],att,attestation_raw,"attestation_id"): raise ProvanError("OWNER_DECISION_ATTESTATION_MISMATCH",value["decision_id"])
    recommendation=att["recommendation"]
    if value["provan_recommendation"]!=recommendation or value["decision"] not in DECISIONS[recommendation]: raise ProvanError("OWNER_DECISION_INCOMPATIBLE",value["decision"])
    actor=value.get("actor")
    if not isinstance(actor,dict) or set(actor)!={"actor_label","authority_type","identity_assurance"} or not isinstance(actor.get("actor_label"),str) or not actor["actor_label"].strip() or actor.get("authority_type")!="case_operator" or actor.get("identity_assurance")!="self_asserted_label":
        raise ProvanError("OWNER_DECISION_ACTOR_AUTHORITY_INVALID",value["decision_id"])
    for field in ("accepted_risks","conditions","required_reinspection"):
        rows=value.get(field)
        if not isinstance(rows,list) or any(not isinstance(row,str) or not row.strip() or len(row)>4096 for row in rows) or len(rows)!=len(set(rows)):
            raise ProvanError("OWNER_DECISION_FIELD_INVALID",field)
    allowed_reinspection={row["id"] for row in att.get("reinspection_requirements",[])}
    if not set(value["required_reinspection"]).issubset(allowed_reinspection):raise ProvanError("OWNER_DECISION_REINSPECTION_REF_INVALID",value["decision_id"])
    if value["decision"]=="accept_with_conditions" and not value["conditions"]:raise ProvanError("OWNER_DECISION_CONDITIONS_REQUIRED",value["decision_id"])
    if value["decision"]=="override_accept_risk" and not value["accepted_risks"]:raise ProvanError("OWNER_DECISION_ACCEPTED_RISK_REQUIRED",value["decision_id"])
    if value.get("rationale") is not None and (not isinstance(value["rationale"],str) or not value["rationale"].strip() or len(value["rationale"])>4096):raise ProvanError("OWNER_DECISION_RATIONALE_INVALID",value["decision_id"])
    try:
        created=_parse_timestamp(value["created_at"])
        if created.tzinfo is None:raise ValueError
        if value.get("expires_at"):
            expiry=_parse_timestamp(value["expires_at"])
            if expiry.tzinfo is None or expiry<=created:raise ValueError
    except (KeyError,AttributeError,TypeError,ValueError) as exc:raise ProvanError("OWNER_DECISION_TIMESTAMP_INVALID",value["decision_id"]) from exc
    return value


def validate_attestation_serialized(raw: bytes, contract_raw: bytes, freeze_raw: bytes,
                                    settlement_raw: bytes, *, now: Callable[[],datetime]) -> dict[str,Any]:
    value=_load(raw,"provan.acceptance_attestation.v1");contract=json.loads(contract_raw);freeze=json.loads(freeze_raw);settlement=json.loads(settlement_raw)
    _uuid(value.get("attestation_id"),"ATTESTATION_ID_INVALID")
    validate_settlement_serialized(settlement_raw,contract_raw,freeze_raw,now=now)
    if not _ref_matches(value["contract_ref"],contract,contract_raw,"contract_id") or not _ref_matches(value["freeze_ref"],freeze,freeze_raw,"freeze_id") or not _ref_matches(value["settlement_ref"],settlement,settlement_raw,"settlement_id"):
        raise ProvanError("ATTESTATION_CHAIN_MISMATCH",value["attestation_id"])
    if value["subject"]!={"repository_identity":freeze["repository_identity"],"candidate_digest":freeze["candidate_digest"]}:raise ProvanError("ATTESTATION_SUBJECT_MISMATCH",value["attestation_id"])
    if value["conditional_activation"]!=freeze["conditional_activation"] or value["conditional_activation"]!=settlement["conditional_activation"]:raise ProvanError("CONDITIONAL_ACTIVATION_BINDING_MISMATCH",value["attestation_id"])
    if value["protected_invariant_refs"]!=contract["protected_invariant_refs"]:raise ProvanError("ATTESTATION_PROTECTED_INVARIANT_MISMATCH",value["attestation_id"])
    if value.get("builder_provenance")!=contract.get("provenance"):raise ProvanError("ATTESTATION_BUILDER_PROVENANCE_MISMATCH",value["attestation_id"])
    if value.get("context_provenance")!={"brief_ref":contract["brief_ref"]}:raise ProvanError("ATTESTATION_CONTEXT_PROVENANCE_MISMATCH",value["attestation_id"])
    if value.get("promotion_provenance")!={"preparation_ref":contract["preparation_ref"]}:raise ProvanError("ATTESTATION_PROMOTION_PROVENANCE_MISMATCH",value["attestation_id"])
    expected_source=sorted({e["evidence_id"] for row in settlement["criteria"] for e in row.get("eligible_evidence",[]) if e.get("evidence_class")=="source_verified"})
    expected_imported=sorted({e["evidence_id"] for row in settlement["criteria"] for e in row.get("supporting_ineligible_evidence",[]) if e.get("evidence_class")=="imported_unverified"})
    expected_missing=[row["criterion_ref"] for row in settlement["criteria"] if row["state"]=="not_established"]
    expected_evidence={"source":expected_source,"imported":expected_imported,"operator":[],"model":[],"missing":expected_missing}
    actual_evidence={**value.get("evidence_refs",{}),"source":sorted(value.get("evidence_refs",{}).get("source",[])),"imported":sorted(value.get("evidence_refs",{}).get("imported",[]))}
    if actual_evidence!=expected_evidence:raise ProvanError("ATTESTATION_EVIDENCE_BINDING_MISMATCH",value["attestation_id"])
    if value["recommendation"]!=settlement["recommendation"]:raise ProvanError("ATTESTATION_RECOMMENDATION_MISMATCH",value["attestation_id"])
    if value["expires_at"]!=contract.get("expires_at") or value["effective_status"]!=effective_status(contract.get("expires_at"),now):raise ProvanError("ATTESTATION_EXPIRY_STATUS_INVALID",value["attestation_id"])
    if value["reinspection_requirements"]!=contract["closure_requirement_refs"]:raise ProvanError("ATTESTATION_REINSPECTION_REQUIREMENTS_MISMATCH",value["attestation_id"])
    verifier=value["verifier_state"]
    if verifier["execution"]!="not_run" or verifier["capability"] not in {"unavailable","unqualified"} or verifier["environment"] not in {"unavailable","unqualified"}:raise ProvanError("SESSION11_EXECUTION_STATE_FABRICATED",value["attestation_id"])
    challenge=value["challenge_state"]
    if challenge.get("requirement")!=contract.get("challenge_policy"):raise ProvanError("ATTESTATION_CHALLENGE_POLICY_MISMATCH",value["attestation_id"])
    if challenge.get("pack") is not None or challenge.get("seed") is not None or challenge.get("siblings")!="not_run":raise ProvanError("SESSION11_CHALLENGE_STATE_FABRICATED",value["attestation_id"])
    if value["owner_placeholders"]!={"accepted_risk":"not_decided","conditions":"not_decided"}:raise ProvanError("ATTESTATION_OWNER_DECISION_MUTATION_FORBIDDEN",value["attestation_id"])
    if value["usage"]!={"model_calls":0,"execution_calls":0}:raise ProvanError("ATTESTATION_USAGE_FABRICATED",value["attestation_id"])
    projections=value["projection_refs"]
    _uuid(projections.get("internal"),"ATTESTATION_PROJECTION_ID_INVALID");_uuid(projections.get("client_safe"),"ATTESTATION_PROJECTION_ID_INVALID")
    if projections["internal"]==projections["client_safe"]:raise ProvanError("ATTESTATION_PROJECTION_ID_COLLISION",value["attestation_id"])
    provenance=value.get("provenance",{})
    if provenance.get("package_version") not in {"0.4.0","0.5.0"} or {key:value for key,value in provenance.items() if key!="package_version"}!={"policy_id":"community.acceptance.v1","policy_version":"1"}:raise ProvanError("ATTESTATION_PROVENANCE_INVALID",value["attestation_id"])
    return value


def validate_attestation_projection_serialized(raw: bytes, attestation_raw: bytes, *, projection_kind: str) -> dict[str,Any]:
    value=_load(raw,"provan.artifact_projection.v1");attestation=_load(attestation_raw,"provan.acceptance_attestation.v1")
    if projection_kind not in {"internal","client_safe"} or value.get("projection_kind")!=projection_kind:
        raise ProvanError("ATTESTATION_PROJECTION_KIND_INVALID",projection_kind)
    projection_id=value.get("projection_id");_uuid(projection_id,"ATTESTATION_PROJECTION_ID_INVALID")
    if projection_id!=attestation["projection_refs"][projection_kind]:raise ProvanError("ATTESTATION_PROJECTION_ID_MISMATCH",projection_id)
    expected_ref={"id":attestation["attestation_id"],"sha256":sha256_bytes(attestation_raw)}
    if value.get("attestation_ref")!=expected_ref:raise ProvanError("ATTESTATION_PROJECTION_BINDING_MISMATCH",projection_id)
    expected_sensitivity="LOCAL_EPHEMERAL" if projection_kind=="internal" else "PUBLIC_SAFE"
    if value.get("sensitivity")!=expected_sensitivity:raise ProvanError("ATTESTATION_PROJECTION_SENSITIVITY_INVALID",projection_id)
    payload=value.get("payload")
    if not isinstance(payload,dict) or payload.get("recommendation")!=attestation["recommendation"] or payload.get("effective_status")!=attestation["effective_status"]:
        raise ProvanError("ATTESTATION_PROJECTION_PAYLOAD_INVALID",projection_id)
    if projection_kind=="internal":
        expected={"subject":attestation["subject"],"recommendation":attestation["recommendation"],"effective_status":attestation["effective_status"],"contract_ref":attestation["contract_ref"],"freeze_ref":attestation["freeze_ref"],"settlement_ref":attestation["settlement_ref"],"limitations":["SESSION12_VERIFIER_EXECUTION_UNAVAILABLE","SESSION13_CHALLENGE_EXECUTION_NOT_RUN"]}
        if payload!=expected:raise ProvanError("ATTESTATION_INTERNAL_PROJECTION_MISMATCH",projection_id)
    else:
        expected={"recommendation":attestation["recommendation"],"effective_status":attestation["effective_status"],"evidence_counts":{key:len(attestation["evidence_refs"][key]) for key in ("source","imported","operator","model","missing")},"limitations":["SESSION12_VERIFIER_EXECUTION_UNAVAILABLE","SESSION13_CHALLENGE_EXECUTION_NOT_RUN"]}
        if payload!=expected:raise ProvanError("ATTESTATION_CLIENT_SAFE_PROJECTION_MISMATCH",projection_id)
    return value


def derive_reinspection_overall(items: list[dict[str,Any]], invariants: list[dict[str,Any]]) -> str:
    material=[r for r in items if r.get("material",True)]; inv=[r for r in invariants if r.get("material",True)]
    all_rows=material+inv
    if any(r["status"]=="disputed" for r in all_rows):return "disputed"
    targets=[r for r in material if r["status"]!="not_applicable"]
    invariants_ok=all(r["status"] in {"closed","not_applicable"} for r in inv)
    if targets and all(r["status"]=="closed" for r in targets) and invariants_ok:return "closed"
    if any(r["status"]=="closed" for r in targets):return "partially_closed"
    unresolved=[r for r in targets+inv if r["status"] not in {"closed","not_applicable"}]
    if unresolved and all(r["status"]=="unable_to_establish" for r in unresolved):return "unable_to_establish"
    return "open"


def validate_reinspection_serialized(raw: bytes, *, attestation_raw:bytes|None=None, contract_raw:bytes|None=None,
                                     original_freeze_raw:bytes|None=None, later_freeze_raw:bytes|None=None,
                                     settlement_raw:bytes|None=None, external_receipt_raw:bytes|None=None) -> dict[str,Any]:
    value=_load(raw,"provan.reinspection_record.v1")
    _uuid(value.get("reinspection_id"),"REINSPECTION_ID_INVALID")
    receipt_ref=value.get("external_change_receipt_ref")
    if receipt_ref is None:
        if external_receipt_raw is not None:raise ProvanError("REINSPECTION_EXTERNAL_RECEIPT_BINDING_MISMATCH",value["reinspection_id"])
    else:
        if external_receipt_raw is None:raise ProvanError("REINSPECTION_EXTERNAL_RECEIPT_UNRESOLVED",value["reinspection_id"])
        receipt=validate_external_change_receipt_serialized(external_receipt_raw)
        if not _ref_matches(receipt_ref,receipt,external_receipt_raw,"receipt_id"):raise ProvanError("REINSPECTION_EXTERNAL_RECEIPT_BINDING_MISMATCH",value["reinspection_id"])
    expected=derive_reinspection_overall(value["items"],value["protected_invariant_results"])
    if value["overall_status"]!=expected: raise ProvanError("REINSPECTION_AGGREGATE_STATUS_INVALID",value["reinspection_id"])
    supplied=(attestation_raw,contract_raw,original_freeze_raw,later_freeze_raw,settlement_raw)
    if any(item is not None for item in supplied):
        if not all(item is not None for item in supplied):raise ProvanError("REINSPECTION_VALIDATION_CHAIN_INCOMPLETE",value["reinspection_id"])
        att=json.loads(attestation_raw);contract=json.loads(contract_raw);original=json.loads(original_freeze_raw);later=json.loads(later_freeze_raw);settlement=json.loads(settlement_raw)
        if not _ref_matches(value["original_attestation_ref"],att,attestation_raw,"attestation_id") or not _ref_matches(value["original_contract_ref"],contract,contract_raw,"contract_id") or not _ref_matches(value["original_freeze_ref"],original,original_freeze_raw,"freeze_id") or not _ref_matches(value["later_freeze_ref"],later,later_freeze_raw,"freeze_id"):
            raise ProvanError("REINSPECTION_CHAIN_MISMATCH",value["reinspection_id"])
        expected_criteria={row["criterion_ref"] for row in settlement["criteria"] if row.get("material",True) and row["state"] not in {"established","not_applicable"}}
        actual_criteria={row["criterion_ref"] for row in value["items"] if row.get("material",True)}
        if expected_criteria!=actual_criteria:raise ProvanError("REINSPECTION_MATERIAL_REQUIREMENT_SET_MISMATCH",value["reinspection_id"])
        expected_invariants={row["id"] for row in contract["protected_invariant_refs"]};actual_invariants={row["protected_invariant_ref"]["id"] for row in value["protected_invariant_results"]}
        if expected_invariants!=actual_invariants:raise ProvanError("REINSPECTION_PROTECTED_INVARIANT_SET_MISMATCH",value["reinspection_id"])
        if later.get("purpose")!="reinspection" or later.get("contract_ref")!=value["original_contract_ref"]:raise ProvanError("REINSPECTION_LATER_FREEZE_BINDING_MISMATCH",value["reinspection_id"])
        later_results={(row["kind"],row["ref"]):row for row in later.get("source_check_results",[])}
        expected_items=[]
        for row in settlement["criteria"]:
            if not row.get("material",True) or row["state"] in {"established","not_applicable"}:continue
            outcome=later_results.get(("closure_requirement",row["closure_requirement_ref"]["id"]),{"status":"unable","reason_code":"EVIDENCE_UNAVAILABLE"})
            status={"supports":"closed","falsifies":"open","disputed":"disputed"}.get(outcome["status"],"unable_to_establish")
            expected_items.append({"criterion_ref":row["criterion_ref"],"closure_requirement_ref":row["closure_requirement_ref"],"status":status,"material":True,"reason_code":outcome["reason_code"]})
        if not expected_items:expected_items=[{"criterion_ref":"NO_MATERIAL_OPEN_REQUIREMENT","closure_requirement_ref":{"id":"not-applicable","sha256":"sha256:"+"0"*64},"status":"not_applicable","material":False,"reason_code":"NO_OPEN_REQUIREMENT"}]
        if value["items"]!=expected_items:raise ProvanError("REINSPECTION_ITEM_RESULT_MISMATCH",value["reinspection_id"])
        expected_inv=[]
        for ref in contract["protected_invariant_refs"]:
            outcome=later_results.get(("protected_invariant",ref["id"]),{"status":"unable","reason_code":"EVIDENCE_UNAVAILABLE"})
            status={"supports":"closed","falsifies":"open","disputed":"disputed"}.get(outcome["status"],"unable_to_establish")
            expected_inv.append({"protected_invariant_ref":ref,"status":status,"material":True,"reason_code":outcome["reason_code"]})
        if value["protected_invariant_results"]!=expected_inv:raise ProvanError("REINSPECTION_INVARIANT_RESULT_MISMATCH",value["reinspection_id"])
        if value["overall_status"]!=derive_reinspection_overall(expected_items,expected_inv):raise ProvanError("REINSPECTION_AGGREGATE_STATUS_INVALID",value["reinspection_id"])
    return value


def validate_session12_handoff_serialized(raw:bytes, artifacts:dict[str,bytes])->dict[str,Any]:
    value=_load(raw,"provan.session12_handoff.v1")
    refs=[value["brief"],value["preparation"],*value["seed_dispositions"],value["acceptance_contract"],value["candidate_freeze"],*value["closure_requirements"],*value["verifier_contracts"],*value["receipt_contracts"],*value["protected_invariants"],value["evidence_settlement"],value["attestation"],value["reinspection"],value["layer4_matrix"],value["proof_manifest"],*value["reviewer_receipts"],value["schema_registry"],value["claim_registry"],value["implementation_binding_ref"],value["wheel"]]
    if len({ref["path"] for ref in refs})!=len(refs):raise ProvanError("SESSION12_HANDOFF_DUPLICATE_ARTIFACT_REF","duplicate path")
    for ref in refs:
        path=PurePosixPath(ref["path"])
        if path.is_absolute() or any(part in {"",".",".."} for part in path.parts):raise ProvanError("SESSION12_HANDOFF_ARTIFACT_PATH_UNSAFE",ref["path"])
        artifact=artifacts.get(ref["path"])
        if artifact is None or sha256_bytes(artifact)!=ref["sha256"]:raise ProvanError("SESSION12_HANDOFF_ARTIFACT_UNRESOLVABLE",ref["path"])
    if value["candidate"].get("mode")!="immutable" or not FULL_COMMIT.fullmatch(str(value["candidate"].get("head",""))):raise ProvanError("SESSION12_HANDOFF_CANDIDATE_INVALID","immutable full head required")
    if value["projection_rules"]!={"internal":"LOCAL_NON_PUBLIC","client_safe":"DETERMINISTICALLY_SANITISED","record_locator":"RESOLVE_CANONICAL_CHAIN_NOT_RENDERED_PROSE"}:raise ProvanError("SESSION12_HANDOFF_PROJECTION_RULES_INVALID","projection rules")
    policy=value["evidence_policy"]
    if policy.get("target_access")!="read_only" or policy.get("execution_available") is not False or policy.get("challenge_available") is not False:raise ProvanError("SESSION12_HANDOFF_AUTHORITY_BOUNDARY_INVALID","evidence policy")
    binding=value["implementation_binding"]
    if binding.get("package_version")!="0.4.0" or binding.get("published") is not False or binding.get("maturity")!="QUALIFIED_BOUNDED":raise ProvanError("SESSION12_HANDOFF_IMPLEMENTATION_BINDING_INVALID","implementation")
    bound_artifact=json.loads(artifacts[value["implementation_binding_ref"]["path"]])
    if binding!=bound_artifact:raise ProvanError("SESSION12_HANDOFF_IMPLEMENTATION_BINDING_MISMATCH","implementation")
    if not FULL_COMMIT.fullmatch(str(binding.get("implementation_commit",""))) or not FULL_COMMIT.fullmatch(str(binding.get("implementation_tree",""))) or not SHA.fullmatch(str(binding.get("wheel_sha256",""))):raise ProvanError("SESSION12_HANDOFF_IMPLEMENTATION_BINDING_INVALID","identity")
    if sha256_bytes(artifacts[value["wheel"]["path"]])!=binding["wheel_sha256"]:raise ProvanError("SESSION12_HANDOFF_WHEEL_BINDING_MISMATCH","wheel")
    claim_raw=artifacts[value["claim_registry"]["path"]]
    if sha256_bytes(claim_raw)!=value["claim_registry_digest"] or binding.get("claim_registry_digest")!=value["claim_registry_digest"]:raise ProvanError("SESSION12_HANDOFF_CLAIM_REGISTRY_MISMATCH","claim registry")
    claim_registry=json.loads(claim_raw);claim_ids=[row.get("claim_id") for row in claim_registry.get("claims",[])]
    if claim_ids!=[f"G11-{number:02d}" for number in range(1,88)]:raise ProvanError("SESSION12_HANDOFF_CLAIM_REGISTRY_MISMATCH","claim set")
    schema_registry=json.loads(artifacts[value["schema_registry"]["path"]]);schema_entries=schema_registry.get("entries",[])
    if schema_registry.get("registry_digest")!=sha256_bytes(canonical_bytes(schema_entries)) or binding.get("schema_registry_digest")!=schema_registry.get("registry_digest"):raise ProvanError("SESSION12_HANDOFF_SCHEMA_REGISTRY_MISMATCH","schema registry")
    matrix=json.loads(artifacts[value["layer4_matrix"]["path"]])
    if matrix.get("claim_registry_digest")!=value["claim_registry_digest"]:raise ProvanError("SESSION12_HANDOFF_LAYER4_CLAIM_BINDING_MISMATCH","layer4")
    expected_schema_sets=({"provan.verifier_work_order.v1","provan.verifier_capability_request.v1","provan.verification_result.v1"},{"provan.environment_receipt.v1","provan.command_receipt.v1"})
    for contract_refs,expected_ids,error in ((value["verifier_contracts"],expected_schema_sets[0],"SESSION12_HANDOFF_VERIFIER_CONTRACT_SET_MISMATCH"),(value["receipt_contracts"],expected_schema_sets[1],"SESSION12_HANDOFF_RECEIPT_CONTRACT_SET_MISMATCH")):
        schemas=[]
        try:
            for ref in contract_refs:
                schema=json.loads(artifacts[ref["path"]])
                schema_id=schema.get("$id")
                properties=schema.get("properties")
                if schema.get("$schema")!="https://json-schema.org/draft/2020-12/schema" or schema.get("type")!="object" or schema.get("additionalProperties") is not False or not isinstance(properties,dict) or properties.get("schema_id")!={"const":schema_id} or not isinstance(schema.get("required"),list) or "schema_id" not in schema["required"]:
                    raise ValueError("invalid canonical schema contract")
                schemas.append(schema)
        except (json.JSONDecodeError,KeyError,TypeError,ValueError) as exc:raise ProvanError(error,"invalid schema contract") from exc
        if {schema.get("$id") for schema in schemas}!=expected_ids or len(schemas)!=len(expected_ids):raise ProvanError(error,"typed schema set")
    if len(value["session12_prerequisites"])<5 or not value["limitations"]:raise ProvanError("SESSION12_HANDOFF_SEMANTIC_COMPLETENESS_MISSING","prerequisites")
    manifest=json.loads(artifacts[value["proof_manifest"]["path"]]);entries=manifest.get("entries")
    if not isinstance(entries,list) or not entries:raise ProvanError("SESSION12_HANDOFF_PROOF_MANIFEST_INVALID","entries")
    for entry in entries:
        artifact=artifacts.get(entry.get("path"))
        if set(entry)!={"path","sha256"} or artifact is None or sha256_bytes(artifact)!=entry.get("sha256"):
            raise ProvanError("SESSION12_HANDOFF_PROOF_MANIFEST_UNRESOLVABLE",str(entry.get("path")))
    expected_root=sha256_bytes(canonical_bytes(entries))
    if manifest.get("proof_root")!=expected_root or value["proof_root"]!=expected_root:raise ProvanError("SESSION12_HANDOFF_PROOF_ROOT_MISMATCH",value["proof_root"])
    contract=json.loads(artifacts[value["acceptance_contract"]["path"]])
    expected_closure={row["id"]:row["sha256"] for row in contract.get("closure_requirement_refs",[])}
    actual_closure={row["id"]:row["sha256"] for row in value["closure_requirements"]}
    if actual_closure!=expected_closure:raise ProvanError("SESSION12_HANDOFF_CLOSURE_REQUIREMENT_SET_MISMATCH","closure requirements")
    if contract.get("schema_id")=="provan.acceptance_contract.v1":
        brief_raw=artifacts[value["brief"]["path"]];brief=json.loads(brief_raw);preparation_raw=artifacts[value["preparation"]["path"]];preparation=json.loads(preparation_raw)
        if not _ref_matches(contract["brief_ref"],brief,brief_raw,"brief_id") or not _ref_matches(contract["preparation_ref"],preparation,preparation_raw,"preparation_id"):raise ProvanError("SESSION12_HANDOFF_PREDECESSOR_BINDING_MISMATCH","brief/preparation")
        seed=brief.get("acceptance_seed",{});seed_raw=canonical_bytes(seed)
        if not _ref_matches(contract["seed_ref"],seed,seed_raw,"seed_id") or preparation.get("brief_id")!=brief.get("brief_id") or preparation.get("candidate_digest")!=brief.get("candidate",{}).get("candidate_digest"):raise ProvanError("SESSION12_HANDOFF_PREDECESSOR_BINDING_MISMATCH","seed")
        dispositions=[]
        for ref in value["seed_dispositions"]:
            disp_raw=artifacts[ref["path"]];disp=validate_seed_disposition_serialized(disp_raw);dispositions.append((disp,disp_raw))
        if {ref["id"] for ref in contract["disposition_refs"]}!={disp["disposition_id"] for disp,_ in dispositions}:raise ProvanError("SESSION12_HANDOFF_DISPOSITION_SET_MISMATCH","dispositions")
        for disp,disp_raw in dispositions:
            if not any(_ref_matches(ref,disp,disp_raw,"disposition_id") for ref in contract["disposition_refs"]) or disp.get("preparation_ref")!=contract["preparation_ref"] or disp.get("seed_ref")!=contract["seed_ref"] or disp.get("case_id")!=contract.get("case_id"):raise ProvanError("SESSION12_HANDOFF_DISPOSITION_BINDING_MISMATCH",disp["disposition_id"])
        closure_raw={row["id"]:artifacts[row["path"]] for row in value["closure_requirements"]}
        invariant_raw={row["id"]:artifacts[row["path"]] for row in value["protected_invariants"]}
        predecessor_raw={preparation["preparation_id"]:preparation_raw,brief["brief_id"]:brief_raw,seed["seed_id"]:seed_raw,**{disp["disposition_id"]:disp_raw for disp,disp_raw in dispositions}}
        validate_contract_serialized(artifacts[value["acceptance_contract"]["path"]],closure_raw,invariant_raw,predecessors=predecessor_raw,schema_registry_raw=artifacts[value["schema_registry"]["path"]])
        freeze_raw=artifacts[value["candidate_freeze"]["path"]];freeze=validate_freeze_serialized(freeze_raw,artifacts[value["acceptance_contract"]["path"]])
        settlement_raw=artifacts[value["evidence_settlement"]["path"]];settlement=json.loads(settlement_raw)
        created=datetime.fromisoformat(settlement["created_at"].replace("Z","+00:00"));clock=lambda:created
        validate_settlement_serialized(settlement_raw,artifacts[value["acceptance_contract"]["path"]],freeze_raw,now=clock)
        att_raw=artifacts[value["attestation"]["path"]]
        validate_attestation_serialized(att_raw,artifacts[value["acceptance_contract"]["path"]],freeze_raw,settlement_raw,now=lambda:datetime.fromisoformat(json.loads(att_raw)["created_at"].replace("Z","+00:00")))
        if value["candidate"]!={"repository_identity":freeze["repository_identity"],"base":freeze["base"],"head":freeze["head"],"mode":"immutable","candidate_digest":freeze["candidate_digest"]}:raise ProvanError("SESSION12_HANDOFF_CANDIDATE_BINDING_MISMATCH","candidate")
        if not _ref_matches({"id":json.loads(att_raw)["settlement_ref"]["id"],"sha256":value["evidence_settlement"]["sha256"]},settlement,settlement_raw,"settlement_id"):raise ProvanError("SESSION12_HANDOFF_SETTLEMENT_BINDING_MISMATCH","settlement")
        matrix=json.loads(artifacts[value["layer4_matrix"]["path"]]);claims=matrix.get("claims",[])
        if len(claims)<87 or any(row.get("Status") not in {"READY_FOR_REVIEW","CLOSED"} for row in claims):raise ProvanError("SESSION12_HANDOFF_LAYER4_INCOMPLETE","layer4")
    return value


SEMANTIC_VALIDATORS={
    "provan.seed_disposition.v1":validate_seed_disposition_serialized,
    "provan.acceptance_contract.v1":validate_contract_serialized,
    "provan.closure_requirement.v1":validate_closure_requirement_serialized,
    "provan.protected_invariant.v1":validate_protected_invariant_serialized,
    "provan.candidate_freeze.v1":validate_freeze_serialized,
    "provan.verifier_work_order.v1":validate_verifier_work_order_serialized,
    "provan.verifier_capability_request.v1":validate_verifier_capability_request_serialized,
    "provan.verification_result.v1":validate_verification_result_serialized,
    "provan.environment_receipt.v1":validate_environment_receipt_serialized,
    "provan.command_receipt.v1":validate_command_receipt_serialized,
    "provan.evidence_settlement.v1":validate_settlement_serialized,
    "provan.acceptance_attestation.v1":validate_attestation_serialized,
    "provan.owner_decision.v1":validate_owner_decision_serialized,
    "provan.external_change_receipt.v1":validate_external_change_receipt_serialized,
    "provan.reinspection_record.v1":validate_reinspection_serialized,
    "provan.session12_handoff.v1":validate_session12_handoff_serialized,
}
