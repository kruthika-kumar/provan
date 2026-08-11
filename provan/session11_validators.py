from __future__ import annotations

import ast
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Callable

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError

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


def _load(raw: bytes, expected_schema: str) -> dict[str, Any]:
    try: value=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ProvanError("SESSION11_CANONICAL_JSON_INVALID",str(exc)) from exc
    if not isinstance(value,dict) or value.get("schema_id") != expected_schema: raise ProvanError("SESSION11_SCHEMA_ID_MISMATCH",expected_schema)
    if canonical_bytes(value) != raw: raise ProvanError("SESSION11_CANONICAL_BYTES_INVALID",expected_schema)
    return value


def _ref_matches(ref: dict[str,Any], value: dict[str,Any], raw: bytes, id_key: str) -> bool:
    return ref.get("id") == value.get(id_key) and ref.get("sha256") == sha256_bytes(raw)


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


def validate_contract_serialized(raw: bytes, closures: dict[str,bytes], invariants: dict[str,bytes]) -> dict[str,Any]:
    value=_load(raw,"provan.acceptance_contract.v1")
    if value["candidate"].get("mode") != "immutable" or not FULL_COMMIT.fullmatch(str(value["candidate"].get("head",""))): raise ProvanError("CONTRACT_CANDIDATE_NOT_IMMUTABLE",value["contract_id"])
    budget=value["challenge_policy"].get("challenge_budget",{}); cls=budget.get("class")
    caps=[budget.get("max_instances"),budget.get("max_wall_seconds"),budget.get("max_network_requests")]
    if cls=="not_required" and caps != [0,0,0]: raise ProvanError("CHALLENGE_NOT_REQUIRED_CAP_NONZERO",value["contract_id"])
    if cls=="bounded" and not (isinstance(caps[0],int) and 1<=caps[0]<=32 and isinstance(caps[1],int) and 1<=caps[1]<=3600 and isinstance(caps[2],int) and 0<=caps[2]<=128): raise ProvanError("CHALLENGE_BUDGET_INVALID",value["contract_id"])
    if cls not in {"not_required","bounded"}: raise ProvanError("CHALLENGE_BUDGET_INVALID",value["contract_id"])
    execution=value["execution_policy"]
    if execution.get("target_access")!="read_only" or execution.get("network_policy") not in {"none","allowlisted"}: raise ProvanError("CONTRACT_EXECUTION_POLICY_INVALID",value["contract_id"])
    for name in ("tier","reversibility"):
        row=value["risk"].get(name,{})
        if row.get("authority") not in {"source_verified","owner_confirmed","unresolved"} or not row.get("provenance_refs"): raise ProvanError("RISK_AUTHORITY_INVALID",name)
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


def validate_freeze_serialized(raw: bytes, contract_raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.candidate_freeze.v1"); contract=json.loads(contract_raw)
    if not _ref_matches(value["contract_ref"],contract,contract_raw,"contract_id"): raise ProvanError("CONTRACT_FREEZE_BINDING_MISMATCH",value["freeze_id"])
    if value["repository_identity"]!=contract["repository_identity"]: raise ProvanError("CANDIDATE_CONTRACT_MISMATCH",value["freeze_id"])
    if value["purpose"]=="acceptance" and value["head"]!=contract["candidate"]["head"]: raise ProvanError("CANDIDATE_CONTRACT_MISMATCH",value["freeze_id"])
    expected=derive_conditional_activation(contract,value["artifact_digests"])
    if value["conditional_activation"]!=expected: raise ProvanError("CONDITIONAL_ACTIVATION_BINDING_MISMATCH",value["freeze_id"])
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
    if not _ref_matches(value["attestation_ref"],att,attestation_raw,"attestation_id"): raise ProvanError("OWNER_DECISION_ATTESTATION_MISMATCH",value["decision_id"])
    recommendation=att["recommendation"]
    if value["provan_recommendation"]!=recommendation or value["decision"] not in DECISIONS[recommendation]: raise ProvanError("OWNER_DECISION_INCOMPATIBLE",value["decision"])
    return value


def validate_attestation_serialized(raw: bytes, contract_raw: bytes, freeze_raw: bytes,
                                    settlement_raw: bytes, *, now: Callable[[],datetime]) -> dict[str,Any]:
    value=_load(raw,"provan.acceptance_attestation.v1");contract=json.loads(contract_raw);freeze=json.loads(freeze_raw);settlement=json.loads(settlement_raw)
    validate_settlement_serialized(settlement_raw,contract_raw,freeze_raw,now=now)
    if not _ref_matches(value["contract_ref"],contract,contract_raw,"contract_id") or not _ref_matches(value["freeze_ref"],freeze,freeze_raw,"freeze_id") or not _ref_matches(value["settlement_ref"],settlement,settlement_raw,"settlement_id"):
        raise ProvanError("ATTESTATION_CHAIN_MISMATCH",value["attestation_id"])
    if value["subject"]!={"repository_identity":freeze["repository_identity"],"candidate_digest":freeze["candidate_digest"]}:raise ProvanError("ATTESTATION_SUBJECT_MISMATCH",value["attestation_id"])
    if value["conditional_activation"]!=freeze["conditional_activation"] or value["conditional_activation"]!=settlement["conditional_activation"]:raise ProvanError("CONDITIONAL_ACTIVATION_BINDING_MISMATCH",value["attestation_id"])
    if value["protected_invariant_refs"]!=contract["protected_invariant_refs"]:raise ProvanError("ATTESTATION_PROTECTED_INVARIANT_MISMATCH",value["attestation_id"])
    if value["recommendation"]!=settlement["recommendation"]:raise ProvanError("ATTESTATION_RECOMMENDATION_MISMATCH",value["attestation_id"])
    if value["expires_at"]!=contract.get("expires_at") or value["effective_status"]!=effective_status(contract.get("expires_at"),now):raise ProvanError("ATTESTATION_EXPIRY_STATUS_INVALID",value["attestation_id"])
    if value["reinspection_requirements"]!=contract["closure_requirement_refs"]:raise ProvanError("ATTESTATION_REINSPECTION_REQUIREMENTS_MISMATCH",value["attestation_id"])
    verifier=value["verifier_state"]
    if verifier["execution"]!="not_run" or verifier["capability"] not in {"unavailable","unqualified"} or verifier["environment"] not in {"unavailable","unqualified"}:raise ProvanError("SESSION11_EXECUTION_STATE_FABRICATED",value["attestation_id"])
    challenge=value["challenge_state"]
    if challenge.get("pack") is not None or challenge.get("seed") is not None or challenge.get("siblings")!="not_run":raise ProvanError("SESSION11_CHALLENGE_STATE_FABRICATED",value["attestation_id"])
    if value["owner_placeholders"]!={"accepted_risk":"not_decided","conditions":"not_decided"}:raise ProvanError("ATTESTATION_OWNER_DECISION_MUTATION_FORBIDDEN",value["attestation_id"])
    if value["usage"]!={"model_calls":0,"execution_calls":0}:raise ProvanError("ATTESTATION_USAGE_FABRICATED",value["attestation_id"])
    projections=value["projection_refs"]
    if projections["internal"]==projections["client_safe"]:raise ProvanError("ATTESTATION_PROJECTION_ID_COLLISION",value["attestation_id"])
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
                                     settlement_raw:bytes|None=None) -> dict[str,Any]:
    value=_load(raw,"provan.reinspection_record.v1")
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
    return value


def validate_session12_handoff_serialized(raw:bytes, artifacts:dict[str,bytes])->dict[str,Any]:
    value=_load(raw,"provan.session12_handoff.v1")
    refs=[value["acceptance_contract"],value["candidate_freeze"],*value["closure_requirements"],*value["verifier_contracts"],*value["receipt_contracts"],*value["protected_invariants"],value["attestation"],value["reinspection"],value["layer4_matrix"],value["proof_manifest"],*value["reviewer_receipts"],value["schema_registry"]]
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
    return value
