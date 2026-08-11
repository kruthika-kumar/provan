from __future__ import annotations

import ast
import html
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

import jsonschema

from .canonical import canonical_bytes, sha256_bytes
from .change_brief import (_analyse_local, _git, _runtime_schema_digest,
                           _snapshot_local_target, _target_fingerprint)
from .errors import ProvanError
from .safe_input import read_bounded_file
from .session10_validators import validate_acceptance_preparation_serialized, validate_change_brief_serialized
from .session11_validators import (
    DECISIONS, derive_conditional_activation, derive_reinspection_overall,
    effective_status, validate_attestation_serialized, validate_closure_requirement_serialized,
    validate_attestation_projection_serialized,
    validate_contract_serialized, validate_freeze_serialized,
    validate_external_change_receipt_serialized,
    validate_owner_decision_serialized, validate_protected_invariant_serialized,
    validate_reinspection_serialized, validate_seed_disposition_serialized,
    validate_settlement_serialized,
)
from .state import secure_read, secure_write, state_root

PACKAGE_VERSION="0.4.0"
POLICY_ID="community.acceptance.v1"
POLICY_VERSION="1"
ANALYSIS_VERSION="session11-source-only-v1"
FULL_COMMIT=re.compile(r"[0-9a-f]{40}")
RECORD_SUFFIXES=frozenset({".json",".markdown",".html",".txt"})


def utcnow() -> datetime: return datetime.now(timezone.utc)
def iso(now: Callable[[],datetime]) -> str: return now().astimezone(timezone.utc).isoformat().replace("+00:00","Z")


def _schema(filename: str,value: dict[str,Any]) -> None:
    schema=json.loads((Path(__file__).with_name("schemas")/filename).read_text(encoding="utf-8"));jsonschema.validate(value,schema)


def _ref(value: dict[str,Any],raw: bytes,id_key: str) -> dict[str,str]: return {"id":str(value[id_key]),"sha256":sha256_bytes(raw)}


def _session11_schema_registry_raw() -> bytes:
    rows=[]
    for path in sorted(Path(__file__).with_name("schemas").glob("*.json"),key=lambda value:value.name):
        raw=path.read_bytes();value=json.loads(raw)
        rows.append({"schema_id":value["$id"],"path":f"provan/schemas/{path.name}","sha256":sha256_bytes(raw),"normalized_sha256":sha256_bytes(canonical_bytes(value))})
    return canonical_bytes({"schema_id":"provan.session11_schema_registry.v1","sensitivity":"PUBLIC_SAFE","entries":rows,"registry_digest":sha256_bytes(canonical_bytes(rows))})


def _path(kind: str, identifier: str) -> Path: return Path("outputs/acceptance")/kind/f"{identifier}.json"


def _store(kind: str, identifier: str, value: dict[str,Any], schema_file: str | None = None) -> tuple[dict[str,Any],bytes]:
    if schema_file:_schema(schema_file,value)
    raw=canonical_bytes(value)
    try:secure_write(_path(kind,identifier),raw)
    except FileExistsError:
        if secure_read(_path(kind,identifier))!=raw:raise ProvanError("CANONICAL_ARTIFACT_ID_COLLISION",identifier)
    return value,raw


def _load(kind: str, identifier: str, expected_schema: str | None = None) -> tuple[dict[str,Any],bytes]:
    try:raw=secure_read(_path(kind,identifier))
    except FileNotFoundError as exc:raise ProvanError("CANONICAL_ARTIFACT_NOT_FOUND",identifier) from exc
    try:value=json.loads(raw)
    except json.JSONDecodeError as exc:raise ProvanError("CANONICAL_ARTIFACT_INVALID",identifier) from exc
    if expected_schema and value.get("schema_id")!=expected_schema:raise ProvanError("CANONICAL_ARTIFACT_SCHEMA_MISMATCH",identifier)
    if expected_schema:
        schemas=Path(__file__).with_name("schemas").glob("*.json");matched=False
        for schema_path in schemas:
            schema=json.loads(schema_path.read_text(encoding="utf-8"))
            if schema.get("$id")==expected_schema:jsonschema.validate(value,schema);matched=True;break
        if not matched:raise ProvanError("CANONICAL_ARTIFACT_SCHEMA_UNREGISTERED",expected_schema)
    if canonical_bytes(value)!=raw:raise ProvanError("CANONICAL_ARTIFACT_BYTES_INVALID",identifier)
    return value,raw


def _validate_contract_loaded(contract:dict[str,Any],contract_raw:bytes)->None:
    closures={ref["id"]:_load("closure-requirements",ref["id"],"provan.closure_requirement.v1")[1] for ref in contract["closure_requirement_refs"]}
    invariants={ref["id"]:_load("protected-invariants",ref["id"],"provan.protected_invariant.v1")[1] for ref in contract["protected_invariant_refs"]}
    preparation,preparation_raw,brief,brief_raw=_resolve_preparation(contract["preparation_ref"]["id"])
    seed=brief["acceptance_seed"];seed_raw=canonical_bytes(seed)
    predecessors={preparation["preparation_id"]:preparation_raw,brief["brief_id"]:brief_raw,seed["seed_id"]:seed_raw}
    for ref in contract["disposition_refs"]:
        disposition,disposition_raw=_load("dispositions",ref["id"],"provan.seed_disposition.v1");predecessors[disposition["disposition_id"]]=disposition_raw
    validate_contract_serialized(contract_raw,closures,invariants,predecessors=predecessors,schema_registry_raw=_session11_schema_registry_raw())


def _store_attestation_projections(attestation:dict[str,Any],attestation_raw:bytes)->None:
    limitations=["SESSION12_VERIFIER_EXECUTION_UNAVAILABLE","SESSION13_CHALLENGE_EXECUTION_NOT_RUN"]
    internal={"schema_id":"provan.artifact_projection.v1","sensitivity":"LOCAL_EPHEMERAL","projection_id":attestation["projection_refs"]["internal"],"projection_kind":"internal","attestation_ref":_ref(attestation,attestation_raw,"attestation_id"),"payload":{"subject":attestation["subject"],"recommendation":attestation["recommendation"],"effective_status":attestation["effective_status"],"contract_ref":attestation["contract_ref"],"freeze_ref":attestation["freeze_ref"],"settlement_ref":attestation["settlement_ref"],"limitations":limitations}}
    client_safe={"schema_id":"provan.artifact_projection.v1","sensitivity":"PUBLIC_SAFE","projection_id":attestation["projection_refs"]["client_safe"],"projection_kind":"client_safe","attestation_ref":_ref(attestation,attestation_raw,"attestation_id"),"payload":{"recommendation":attestation["recommendation"],"effective_status":attestation["effective_status"],"evidence_counts":{key:len(attestation["evidence_refs"][key]) for key in ("source","imported","operator","model","missing")},"limitations":limitations}}
    for kind,value in (("internal",internal),("client_safe",client_safe)):
        validate_attestation_projection_serialized(canonical_bytes(value),attestation_raw,projection_kind=kind)
        _store("attestation-projections",value["projection_id"],value,"artifact-projection.v1.json")


def _validate_attestation_projections(attestation:dict[str,Any],attestation_raw:bytes)->None:
    for kind,projection_id in attestation["projection_refs"].items():
        _,raw=_load("attestation-projections",projection_id,"provan.artifact_projection.v1")
        validate_attestation_projection_serialized(raw,attestation_raw,projection_kind=kind)


def _resolve_preparation(preparation_id: str) -> tuple[dict[str,Any],bytes,dict[str,Any],bytes]:
    root=state_root()/"outputs"/"change-brief"; found=[]
    if root.is_dir():
        for child in sorted(root.iterdir(),key=lambda p:p.name):
            if not child.is_dir() or child.is_symlink():continue
            rel=Path("outputs/change-brief")/child.name/"acceptance-preparation.json"
            try:raw=secure_read(rel)
            except FileNotFoundError:continue
            try:value=json.loads(raw)
            except json.JSONDecodeError:continue
            if value.get("preparation_id")==preparation_id:found.append((child.name,value,raw))
    if len(found)!=1:raise ProvanError("ACCEPTANCE_PREPARATION_NOT_FOUND" if not found else "ACCEPTANCE_PREPARATION_DUPLICATE",preparation_id)
    brief_id,preparation,prep_raw=found[0];validate_acceptance_preparation_serialized(prep_raw)
    brief_raw=secure_read(Path("outputs/change-brief")/brief_id/"change-brief.json");validate_change_brief_serialized(brief_raw);brief=json.loads(brief_raw)
    if brief["brief_id"]!=preparation["brief_id"] or brief["case_id"]!=preparation["case_id"] or brief["candidate"]["candidate_digest"]!=preparation["candidate_digest"]:raise ProvanError("PREPARATION_BRIEF_BINDING_MISMATCH",preparation_id)
    return preparation,prep_raw,brief,brief_raw


def _item_id(seed_digest: str,kind: str,source_ref: str,value: Any) -> str:
    return sha256_bytes(canonical_bytes({"seed":seed_digest,"kind":kind,"source_ref":source_ref,"value":value}))


def disposition_items(preparation_id: str) -> dict[str,Any]:
    preparation,_,brief,_=_resolve_preparation(preparation_id);seed=brief["acceptance_seed"];seed_digest=sha256_bytes(canonical_bytes(seed));items=[]
    for index,value in enumerate(brief["claims"].get("source_attributed_product_intent",[])):
        items.append({"item_id":_item_id(seed_digest,"intended_outcome",f"brief:intent:{index}",value),"kind":"intended_outcome","source_ref":f"brief:intent:{index}","original_value":value})
    journeys=brief.get("context_request",{}).get("journey_digests",[])
    for index,value in enumerate(journeys):items.append({"item_id":_item_id(seed_digest,"journey",f"context:journey:{index}",value),"kind":"journey","source_ref":f"context:journey:{index}","original_value":value})
    for index,value in enumerate(brief.get("promotion_decision",{}).get("applied_triggers",[])):
        items.append({"item_id":_item_id(seed_digest,"criterion",f"promotion:trigger:{index}",value),"kind":"criterion","source_ref":f"promotion:trigger:{index}","original_value":value})
    for index,value in enumerate(brief.get("context_bundle",{}).get("records",[])):
        items.append({"item_id":_item_id(seed_digest,"context_use",f"context:record:{index}",value),"kind":"context_use","source_ref":f"context:record:{index}","original_value":value})
    for index,value in enumerate(seed.get("unresolved_questions",[])):
        items.append({"item_id":_item_id(seed_digest,"unresolved_question",f"seed:unresolved:{index}",value),"kind":"unresolved_question","source_ref":f"seed:unresolved:{index}","original_value":value})
    if not items:items.append({"item_id":_item_id(seed_digest,"unresolved_question","seed:empty","INTENDED_OUTCOME_UNRESOLVED"),"kind":"unresolved_question","source_ref":"seed:empty","original_value":"INTENDED_OUTCOME_UNRESOLVED"})
    return {"preparation_id":preparation_id,"case_id":preparation["case_id"],"seed_digest":seed_digest,"items":items}


def _closure_from_spec(criterion_id: str,spec: dict[str,Any],invariant_refs:dict[str,dict[str,str]],now: Callable[[],datetime]) -> tuple[dict[str,Any],bytes]:
    protected_ids=list(spec.get("protected_invariant_ids",[]));check=dict(spec["check"])
    if check.get("type")=="protected_invariant_satisfied":
        invariant_id=check.pop("protected_invariant_id",None)
        if invariant_id not in invariant_refs:raise ProvanError("PROTECTED_INVARIANT_UNRESOLVED",str(invariant_id))
        check["protected_invariant_ref"]=invariant_refs[invariant_id]
        if invariant_id not in protected_ids:protected_ids.append(invariant_id)
    if any(item not in invariant_refs for item in protected_ids):raise ProvanError("PROTECTED_INVARIANT_UNRESOLVED",criterion_id)
    value={"schema_id":"provan.closure_requirement.v1","artifact_id":str(uuid.uuid4()),"closure_requirement_id":str(uuid.uuid4()),"version":1,"criterion_ref":criterion_id,"required_evidence_class":spec.get("required_evidence_class","source_verified"),"check_mode":spec.get("check_mode","source_only"),"check":check,"subject_refs":spec.get("subject_refs",[check.get("path",criterion_id)]),"protected_invariant_refs":[invariant_refs[item] for item in protected_ids],"limitations":spec.get("limitations",[]),"summary":spec.get("summary")}
    validate_closure_requirement_serialized(canonical_bytes(value));return _store("closure-requirements",value["closure_requirement_id"],value,"closure-requirement.v1.json")


def create_contract(preparation_id: str,dispositions: dict[str,Any],actor_label: str,*,supersedes: str|None=None,now:Callable[[],datetime]=utcnow) -> dict[str,Any]:
    if not actor_label or len(actor_label)>128:raise ProvanError("ACTOR_LABEL_INVALID","actor label must contain 1..128 characters")
    preparation,prep_raw,brief,brief_raw=_resolve_preparation(preparation_id);surface=disposition_items(preparation_id);expected={r["item_id"]:r for r in surface["items"]};rows=dispositions.get("items",[])
    if len(rows)!=len(expected) or {r.get("item_id") for r in rows}!=set(expected):raise ProvanError("SEED_DISPOSITIONS_INCOMPLETE","every exact seed item requires one disposition")
    if len({r["item_id"] for r in rows})!=len(rows):raise ProvanError("SEED_DISPOSITION_DUPLICATE",preparation_id)
    timestamp=iso(now);actor={"actor_label":actor_label,"authority_type":"case_operator","authority_scope":"case_intent_and_meaning","identity_assurance":"self_asserted_label"};normalized=[];criteria=[];unresolved=[];intent=[];journeys=[]
    for row in rows:
        source=expected[row["item_id"]];action=row.get("action")
        if action not in {"confirm","reject","edit","unresolved"}:raise ProvanError("SEED_DISPOSITION_ACTION_INVALID",str(action))
        if action=="edit" and "edited_value" not in row:raise ProvanError("SEED_EDIT_VALUE_MISSING",row["item_id"])
        current=row.get("edited_value") if action=="edit" else source["original_value"]
        item={"item_id":row["item_id"],"kind":source["kind"],"source_ref":source["source_ref"],"original_value":source["original_value"],"action":action,"edited_value":row.get("edited_value"),"rationale":row.get("rationale"),"actor":actor,"acted_at":timestamp};normalized.append(item)
        if action=="unresolved" or source["kind"]=="unresolved_question" and action!="reject":unresolved.append(str(current))
        if action in {"confirm","edit"} and source["kind"]=="intended_outcome":intent.append(str(current))
        if action in {"confirm","edit"} and source["kind"]=="journey":journeys.append(current)
        if action in {"confirm","edit"} and source["kind"]=="criterion":
            spec=row.get("criterion")
            if not isinstance(spec,dict):raise ProvanError("CONTRACT_CRITERION_INCOMPLETE",row["item_id"])
            criteria.append(spec)
    terms=dispositions.get("contract_terms",{})
    if not intent:intent=[str(terms.get("intended_outcome") or "INTENDED_OUTCOME_UNRESOLVED")];unresolved.append("INTENDED_OUTCOME_UNRESOLVED")
    if not criteria:
        for spec in terms.get("criteria",[]):criteria.append(spec)
    if not criteria:raise ProvanError("CONTRACT_CRITERIA_MISSING",preparation_id)
    disposition={"schema_id":"provan.seed_disposition.v1","disposition_id":str(uuid.uuid4()),"preparation_ref":_ref(preparation,prep_raw,"preparation_id"),"seed_ref":_ref(brief["acceptance_seed"],canonical_bytes(brief["acceptance_seed"]),"seed_id"),"case_id":brief["case_id"],"actor":actor,"items":normalized,"created_at":timestamp};validate_seed_disposition_serialized(canonical_bytes(disposition));disp,disp_raw=_store("dispositions",disposition["disposition_id"],disposition,"seed-disposition.v1.json")
    invariant_values=[]
    for spec in terms.get("protected_invariants",[]):
        inv={"schema_id":"provan.protected_invariant.v1","artifact_id":str(uuid.uuid4()),"protected_invariant_id":str(spec["protected_invariant_id"]),"version":int(spec.get("version",1)),"statement":str(spec["statement"]),"scope":str(spec.get("scope","candidate")),"authority":spec.get("authority",{"class":"source_verified","source_refs":[]}),"source_refs":spec.get("source_refs",[]),"required_evidence_class":spec.get("required_evidence_class","source_verified"),"check_mode":spec.get("check_mode","source_only"),"check":spec["check"],"prohibited_actions":spec.get("prohibited_actions",["target_mutation","target_execution","remediation"]),"closure_requirement_refs":[],"limitations":spec.get("limitations",[]),"sensitivity":spec.get("sensitivity","PUBLIC_SAFE")};validate_protected_invariant_serialized(canonical_bytes(inv));invariant_values.append(_store("protected-invariants",inv["protected_invariant_id"],inv,"protected-invariant.v1.json"))
    invariant_refs={value["protected_invariant_id"]:_ref(value,raw,"protected_invariant_id") for value,raw in invariant_values}
    closure_values=[];mandatory=[];conditional=[];non_applicable=[]
    for index,spec in enumerate(criteria):
        cid=str(spec.get("criterion_id") or f"criterion-{index+1}");closure,closure_raw=_closure_from_spec(cid,spec["closure_requirement"],invariant_refs,now);closure_values.append((closure,closure_raw));row={"criterion_id":cid,"statement":str(spec.get("statement") or cid),"required_evidence_classes":spec.get("required_evidence_classes",[closure["required_evidence_class"]]),"closure_requirement_ref":_ref(closure,closure_raw,"closure_requirement_id"),"material":bool(spec.get("material",True)),"challenge_requirement":spec.get("challenge_requirement","not_required")}
        cls=spec.get("class","mandatory")
        if cls=="conditional":row["activation_rule"]=spec.get("activation_rule",{"type":"operator_confirmation"});row["activation_provenance"]=spec.get("activation_provenance",{"authority":"unresolved","source_refs":[]});conditional.append(row)
        elif cls=="not_applicable":row["not_applicable_provenance"]=spec.get("not_applicable_provenance",{"authority":"owner_confirmed","source_refs":[disp["disposition_id"]]});non_applicable.append(row)
        elif cls=="mandatory":mandatory.append(row)
        else:raise ProvanError("CONTRACT_CRITERION_CLASS_INVALID",str(cls))
    parent=None;version=1
    if supersedes:
        old,old_raw=_load("contracts",supersedes,"provan.acceptance_contract.v1");parent=_ref(old,old_raw,"contract_id");version=old["version"]+1
        if old["case_id"]!=brief["case_id"]:raise ProvanError("CONTRACT_SUPERSESSION_CASE_MISMATCH",supersedes)
    budget=terms.get("challenge_budget",{"class":"not_required","max_instances":0,"max_wall_seconds":0,"max_network_requests":0})
    risk=terms.get("risk",{"tier":{"value":"unresolved","authority":"unresolved","provenance_refs":[disp["disposition_id"]]},"reversibility":{"value":"unresolved","authority":"unresolved","provenance_refs":[disp["disposition_id"]]}})
    risk=json.loads(json.dumps(risk))
    for name in ("tier","reversibility"):
        if risk.get(name,{}).get("authority")=="owner_confirmed":risk[name]["provenance_refs"]=[disp["disposition_id"]]
    schema_registry_raw=_session11_schema_registry_raw();schema_registry=json.loads(schema_registry_raw)
    contract={"schema_id":"provan.acceptance_contract.v1","contract_id":str(uuid.uuid4()),"version":version,"supersedes":parent,"case_id":brief["case_id"],"preparation_ref":_ref(preparation,prep_raw,"preparation_id"),"seed_ref":_ref(brief["acceptance_seed"],canonical_bytes(brief["acceptance_seed"]),"seed_id"),"brief_ref":_ref(brief,brief_raw,"brief_id"),"candidate":brief["candidate"],"repository_identity":brief["candidate"]["repository_identity"],"disposition_refs":[_ref(disp,disp_raw,"disposition_id")],"intended_outcome":"\n".join(intent),"target_user":terms.get("target_user"),"journeys":journeys,"mandatory_criteria":mandatory,"conditional_criteria":conditional,"non_applicable_criteria":non_applicable,"unresolved_questions":sorted(set(unresolved)),"protected_invariant_refs":[_ref(v,r,"protected_invariant_id") for v,r in invariant_values],"closure_requirement_refs":[_ref(v,r,"closure_requirement_id") for v,r in closure_values],"allowed_evidence_classes":terms.get("allowed_evidence_classes",["source_verified","owner_confirmed","trusted_imported_receipt"]),"execution_policy":{"source_only_allowed":True,"future_verifier_requirements":terms.get("future_verifier_requirements",[]),"network_policy":terms.get("network_policy","none"),"target_access":"read_only","prohibited_actions":["target_mutation","target_execution","remediation","deployment"]},"challenge_policy":{"criteria_requiring_challenge":[r["criterion_id"] for r in mandatory+conditional if r["challenge_requirement"]=="required_future"],"challenge_budget":budget,"prohibited_actions":["challenge_generation","challenge_execution","pack_creation","seed_creation","sibling_creation"]},"risk":risk,"operator_authority":actor,"decision_policy":{"policy_id":"community.owner-decision-compatibility.v1","allowed":{k:sorted(v) for k,v in DECISIONS.items()}},"conditions":terms.get("conditions",[]),"expires_at":terms.get("expires_at"),"reinspection_triggers":terms.get("reinspection_triggers",["candidate_changed","expiry_reached"]),"provenance":{"package_version":PACKAGE_VERSION,"policy_id":POLICY_ID,"policy_version":POLICY_VERSION,"schema_registry_digest":schema_registry["registry_digest"]},"created_at":timestamp}
    closure_map={v["closure_requirement_id"]:r for v,r in closure_values};inv_map={v["protected_invariant_id"]:r for v,r in invariant_values};predecessors={preparation["preparation_id"]:prep_raw,brief["brief_id"]:brief_raw,brief["acceptance_seed"]["seed_id"]:canonical_bytes(brief["acceptance_seed"]),disp["disposition_id"]:disp_raw};validate_contract_serialized(canonical_bytes(contract),closure_map,inv_map,predecessors=predecessors,schema_registry_raw=schema_registry_raw);return _store("contracts",contract["contract_id"],contract,"acceptance-contract.v1.json")[0]


def _json_pointer(value: Any,pointer: str) -> Any:
    current=value
    if pointer=="":return current
    for token in pointer.split("/")[1:]:
        token=token.replace("~1","/").replace("~0","~")
        if isinstance(current,list):current=current[int(token)]
        elif isinstance(current,dict) and token in current:current=current[token]
        else:raise KeyError(pointer)
    return current


def _read_blob(repo: Path,head: str,path: str) -> bytes:
    pure=PurePosixPath(path)
    if pure.is_absolute() or any(part in {"",".",".."} for part in pure.parts):raise ProvanError("CLOSURE_SOURCE_PATH_UNSAFE",path)
    if _git(repo,["cat-file","-t",f"{head}:{path}"]).decode("utf-8","strict").strip()!="blob":raise ProvanError("CLOSURE_SOURCE_ARTIFACT_NOT_REGULAR",path)
    return _git(repo,["show",f"{head}:{path}"])


def _bounded_json_depth(value:Any,depth:int=0)->int:
    if depth>64:raise ProvanError("CLOSURE_STRUCTURED_DOCUMENT_TOO_DEEP","JSON nesting exceeds 64")
    if isinstance(value,dict):
        for child in value.values():_bounded_json_depth(child,depth+1)
    elif isinstance(value,list):
        for child in value:_bounded_json_depth(child,depth+1)
    return depth


def _evaluate_check(repo:Path,head:str,check:dict[str,Any]) -> dict[str,Any]:
    kind=check["type"]
    try:
        if kind=="artifact_exists":_read_blob(repo,head,check["path"]);result=True
        elif kind=="canonical_field_equals":
            raw=_read_blob(repo,head,check["path"])
            if len(raw)>1024*1024:raise ProvanError("CLOSURE_STRUCTURED_DOCUMENT_TOO_LARGE",check["path"])
            document=json.loads(raw.decode("utf-8"));_bounded_json_depth(document);result=_json_pointer(document,check["json_pointer"])==check["expected_value"]
        elif kind=="python_public_export_exists":
            raw=_read_blob(repo,head,check["path"])
            if len(raw)>1024*1024:raise ProvanError("CLOSURE_PYTHON_SOURCE_TOO_LARGE",check["path"])
            tree=ast.parse(raw.decode("utf-8"));symbol=check["symbol"];defined={n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))};exports=None
            for node in tree.body:
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="__all__" for t in node.targets):
                    try:exports=set(ast.literal_eval(node.value))
                    except Exception:return {"status":"unable","reason_code":"DYNAMIC_PYTHON_EXPORT_NONCOVERAGE"}
            result=symbol in (exports if exports is not None else defined)
        else:return {"status":"unable","reason_code":"PROTECTED_INVARIANT_REQUIRES_RESOLUTION"}
        return {"status":"supports" if result else "falsifies","reason_code":"SOURCE_PREDICATE_SATISFIED" if result else "SOURCE_PREDICATE_NOT_SATISFIED"}
    except (KeyError,ValueError,UnicodeDecodeError,json.JSONDecodeError,ProvanError):return {"status":"falsifies","reason_code":"SOURCE_PREDICATE_NOT_SATISFIED"}


def _make_freeze(contract:dict[str,Any],contract_raw:bytes,repo_source:str,*,purpose:str,head_override:str|None,now:Callable[[],datetime]) -> dict[str,Any]:
    if "://" in repo_source:raise ProvanError("SESSION11_REMOTE_FREEZE_REQUIRES_LOCAL_SOURCE","Session 11 freeze requires a local source checkout")
    repo=Path(repo_source).resolve();head=head_override or contract["candidate"]["head"]
    if not FULL_COMMIT.fullmatch(head):raise ProvanError("CANDIDATE_FULL_COMMIT_REQUIRED",head)
    before=_target_fingerprint(repo);snapshot,scratch,identity,initial_excluded=_snapshot_local_target(repo,False)
    try:
        if identity!=contract["repository_identity"]:
            code="REINSPECTION_REPOSITORY_MISMATCH" if purpose=="reinspection" else "CANDIDATE_CONTRACT_MISMATCH"
            raise ProvanError(code,"repository identity")
        candidate,analysis=_analyse_local(scratch,base=contract["candidate"].get("base"),head=head,working_tree=False)
        candidate_core={**candidate,"repository_identity":identity};candidate_core.pop("candidate_digest",None)
        candidate={**candidate_core,"candidate_digest":sha256_bytes(canonical_bytes(candidate_core))}
        if purpose=="acceptance" and candidate["candidate_digest"]!=contract["candidate"]["candidate_digest"]:raise ProvanError("CANDIDATE_CONTRACT_MISMATCH","candidate digest")
        closures={ref["id"]:_load("closure-requirements",ref["id"],"provan.closure_requirement.v1") for ref in contract["closure_requirement_refs"]};invariants={ref["id"]:_load("protected-invariants",ref["id"],"provan.protected_invariant.v1") for ref in contract["protected_invariant_refs"]}
        artifacts={}
        for row in analysis["changed_files"]:
            digest=row.get("static_details",{}).get("content_digest")
            if digest:artifacts[row["path"]]=digest
        results=[];invariant_outcomes={}
        for iid,(inv,_) in invariants.items():
            outcome=_evaluate_check(scratch,head,inv["check"]) if inv["check_mode"]=="source_only" else {"status":"unable","reason_code":"FUTURE_CAPABILITY_UNAVAILABLE"}
            invariant_outcomes[iid]=outcome;results.append({"kind":"protected_invariant","ref":iid,**outcome})
        for cid,(closure,_) in closures.items():
            check=closure["check"];path=check.get("path")
            if path:
                try:artifacts[path]=sha256_bytes(_read_blob(scratch,head,path))
                except ProvanError:pass
            if closure["check_mode"]=="source_only" and check["type"]=="protected_invariant_satisfied":outcome=invariant_outcomes.get(check["protected_invariant_ref"]["id"],{"status":"unable","reason_code":"PROTECTED_INVARIANT_UNRESOLVED"})
            else:outcome=_evaluate_check(scratch,head,check) if closure["check_mode"]=="source_only" else {"status":"unable","reason_code":"FUTURE_CAPABILITY_UNAVAILABLE" if closure["check_mode"] in {"verifier_runtime","challenge"} else "CANONICAL_OPERATOR_ACTION_NOT_SUPPLIED"}
            results.append({"kind":"closure_requirement","ref":cid,**outcome})
        analysis["excluded_sensitive_surfaces"]=initial_excluded+analysis.get("excluded_sensitive_surfaces",[])
    finally:
        snapshot.cleanup()
    if _target_fingerprint(repo)!=before:raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED","target changed during scratch-only freeze")
    dependency={k:v for k,v in artifacts.items() if Path(k).name.lower() in {"pyproject.toml","package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","poetry.lock"}}
    verification={path:digest for path,digest in artifacts.items() if path.startswith(("tests/",".github/workflows/")) or PurePosixPath(path).name.lower() in {"tox.ini","pytest.ini","coverage.toml",".coveragerc"}}
    freeze={"schema_id":"provan.candidate_freeze.v1","freeze_id":str(uuid.uuid4()),"purpose":purpose,"contract_ref":_ref(contract,contract_raw,"contract_id"),"repository_identity":candidate["repository_identity"],"base":contract["candidate"].get("base"),"head":head,"candidate_digest":candidate["candidate_digest"],"artifact_digests":dict(sorted(artifacts.items())),"dependency_digest":sha256_bytes(canonical_bytes(dependency)),"workspace_digest":sha256_bytes(canonical_bytes(dict(sorted(artifacts.items())))),"verification_surface_digest":sha256_bytes(canonical_bytes(verification)),"protected_invariant_refs":contract["protected_invariant_refs"],"conditional_activation":derive_conditional_activation(contract,artifacts),"source_check_results":results,"analysis_version":ANALYSIS_VERSION,"limitations":sorted(set(analysis.get("limitations",[]))),"created_at":iso(now)}
    validate_freeze_serialized(canonical_bytes(freeze),contract_raw);return _store("freezes",freeze["freeze_id"],freeze,"candidate-freeze.v1.json")[0]


def freeze_contract(contract_id:str,repo_source:str,*,now:Callable[[],datetime]=utcnow)->dict[str,Any]:
    contract,raw=_load("contracts",contract_id,"provan.acceptance_contract.v1");_validate_contract_loaded(contract,raw);return _make_freeze(contract,raw,repo_source,purpose="acceptance",head_override=None,now=now)


def _evidence_from_source(freeze:dict[str,Any]) -> list[dict[str,Any]]:
    rows=[]
    for result in freeze["source_check_results"]:
        if result["kind"]!="closure_requirement":continue
        core={"source":"provan_source_only_evaluator","candidate_digest":freeze["candidate_digest"],"closure_requirement_ref":result["ref"],"predicate_result":result["status"],"reason_code":result["reason_code"]}
        rows.append({"evidence_id":sha256_bytes(canonical_bytes(core)),"evidence_class":"source_verified",**core})
    return rows


def derive_evidence_state(eligible_evidence:list[dict[str,Any]]) -> str:
    """Settle already-qualified current evidence without conferring authority."""
    supports=any(row.get("predicate_result")=="supports" for row in eligible_evidence)
    falsifies=any(row.get("predicate_result")=="falsifies" for row in eligible_evidence)
    if supports and falsifies:return "disputed"
    if supports:return "established"
    if falsifies:return "falsified"
    return "not_established"


def attest(freeze_id:str,evidence_inputs:list[tuple[str,bytes]],*,now:Callable[[],datetime]=utcnow)->dict[str,Any]:
    freeze,freeze_raw=_load("freezes",freeze_id,"provan.candidate_freeze.v1");contract,contract_raw=_load("contracts",freeze["contract_ref"]["id"],"provan.acceptance_contract.v1");_validate_contract_loaded(contract,contract_raw);validate_freeze_serialized(freeze_raw,contract_raw)
    source=_evidence_from_source(freeze);imported=[]
    for name,raw in evidence_inputs:
        try:claimed=json.loads(raw)
        except json.JSONDecodeError:claimed={"format":"unparsed"}
        core={"source_name":Path(name).name,"sha256":sha256_bytes(raw),"claimed_schema":claimed.get("schema_id") if isinstance(claimed,dict) else None,"claimed_state":claimed.get("state") if isinstance(claimed,dict) else None}
        imported.append({"evidence_id":sha256_bytes(canonical_bytes(core)),"evidence_class":"imported_unverified","predicate_result":"supporting_only","provenance":core})
    source_by={r["closure_requirement_ref"]:r for r in source};activation={r["criterion_ref"]:r["state"] for r in freeze["conditional_activation"]};criteria=[];requires_future=False;held=False
    all_contract=[]
    for cls,key in (("mandatory","mandatory_criteria"),("conditional","conditional_criteria"),("not_applicable","non_applicable_criteria")):
        for row in contract[key]:all_contract.append((cls,row))
    for cls,row in all_contract:
        cref=row["closure_requirement_ref"]["id"];e=source_by.get(cref);eligible=[]
        if e and e["predicate_result"] in {"supports","falsifies"} and "source_verified" in row["required_evidence_classes"]:eligible=[e]
        state=derive_evidence_state(eligible)
        if cls=="not_applicable" or activation.get(row["criterion_id"])=="inactive":state="not_applicable"
        if activation.get(row["criterion_id"])=="unresolved":held=True
        closure,_=_load("closure-requirements",cref,"provan.closure_requirement.v1")
        if closure["check_mode"] in {"verifier_runtime","challenge"} and cls!="not_applicable" and activation.get(row["criterion_id"])!="inactive":requires_future=True
        if state in {"falsified","disputed"}:held=True
        criteria.append({"criterion_ref":row["criterion_id"],"contract_class":cls,"required_evidence_class":closure["required_evidence_class"],"considered_evidence":[x["evidence_id"] for x in source+imported],"eligible_evidence":eligible,"supporting_ineligible_evidence":imported,"state":state,"reason_codes":["ELIGIBLE_EVIDENCE_"+state.upper()],"closure_requirement_ref":row["closure_requirement_ref"],"missing_evidence":[] if state in {"established","falsified","disputed","not_applicable"} else [closure["required_evidence_class"]],"missing_evidence_as_basis":False,"material":row.get("material",True)})
    unresolved_risk=any(contract["risk"][name].get("authority")=="unresolved" or contract["risk"][name].get("value")=="unresolved" for name in ("tier","reversibility"))
    recommendation="not_eligible" if requires_future else "held" if held or unresolved_risk or contract.get("unresolved_questions") or any(r["state"] not in {"established","not_applicable"} for r in criteria if r["contract_class"]!="not_applicable") else "cleared"
    settlement={"schema_id":"provan.evidence_settlement.v1","settlement_id":str(uuid.uuid4()),"contract_ref":_ref(contract,contract_raw,"contract_id"),"freeze_ref":_ref(freeze,freeze_raw,"freeze_id"),"conditional_activation":freeze["conditional_activation"],"criteria":criteria,"recommendation":recommendation,"effective_status":effective_status(contract.get("expires_at"),now),"created_at":iso(now)};validate_settlement_serialized(canonical_bytes(settlement),contract_raw,freeze_raw,now=now);settlement,settlement_raw=_store("settlements",settlement["settlement_id"],settlement,"evidence-settlement.v1.json")
    work_orders=[]
    for row in criteria:
        closure,_=_load("closure-requirements",row["closure_requirement_ref"]["id"],"provan.closure_requirement.v1")
        if closure["check_mode"] in {"verifier_runtime","challenge"}:
            wo={"schema_id":"provan.verifier_work_order.v1","work_order_id":str(uuid.uuid4()),"contract_ref":_ref(contract,contract_raw,"contract_id"),"freeze_ref":_ref(freeze,freeze_raw,"freeze_id"),"criterion_refs":[row["criterion_ref"]],"protected_invariant_refs":closure["protected_invariant_refs"],"required_evidence_class":closure["required_evidence_class"],"requested_capabilities":[closure["check_mode"]],"target_policy":"read_only","network_policy":contract["execution_policy"]["network_policy"],"allowed_tool_classes":[],"prohibited_actions":contract["execution_policy"]["prohibited_actions"],"environment_requirements":contract["execution_policy"]["future_verifier_requirements"],"completion_requirements":[row["closure_requirement_ref"]],"remediation_allowed":False};work_orders.append(_store("work-orders",wo["work_order_id"],wo,"verifier-work-order.v1.json")[0])
    projection_ids={"internal":str(uuid.uuid4()),"client_safe":str(uuid.uuid4())}
    eligible_source=sorted({e["evidence_id"] for row in criteria for e in row["eligible_evidence"] if e["evidence_class"]=="source_verified"})
    attestation={"schema_id":"provan.acceptance_attestation.v1","attestation_id":str(uuid.uuid4()),"subject":{"repository_identity":freeze["repository_identity"],"candidate_digest":freeze["candidate_digest"]},"freeze_ref":_ref(freeze,freeze_raw,"freeze_id"),"contract_ref":_ref(contract,contract_raw,"contract_id"),"builder_provenance":contract["provenance"],"verifier_state":{"capability":"unavailable","execution":"not_run","environment":"unqualified","work_order_refs":[w["work_order_id"] for w in work_orders]},"context_provenance":{"brief_ref":contract["brief_ref"]},"promotion_provenance":{"preparation_ref":contract["preparation_ref"]},"protected_invariant_refs":contract["protected_invariant_refs"],"evidence_refs":{"source":eligible_source,"imported":[r["evidence_id"] for r in imported],"operator":[],"model":[],"missing":[r["criterion_ref"] for r in criteria if r["state"]=="not_established"]},"settlement_ref":_ref(settlement,settlement_raw,"settlement_id"),"conditional_activation":freeze["conditional_activation"],"challenge_state":{"requirement":contract["challenge_policy"],"state":"not_run","pack":None,"seed":None,"siblings":"not_run"},"recommendation":recommendation,"owner_placeholders":{"accepted_risk":"not_decided","conditions":"not_decided"},"expires_at":contract.get("expires_at"),"effective_status":settlement["effective_status"],"reinspection_requirements":contract["closure_requirement_refs"],"usage":{"model_calls":0,"execution_calls":0},"provenance":{"package_version":PACKAGE_VERSION,"policy_id":POLICY_ID,"policy_version":POLICY_VERSION},"projection_refs":projection_ids,"created_at":iso(now)}
    validate_attestation_serialized(canonical_bytes(attestation),contract_raw,freeze_raw,settlement_raw,now=now)
    attestation,attestation_raw=_store("attestations",attestation["attestation_id"],attestation,"acceptance-attestation.v1.json")
    _store_attestation_projections(attestation,attestation_raw)
    return attestation


def decide(attestation_id:str,decision_input:dict[str,Any],actor_label:str,*,now:Callable[[],datetime]=utcnow)->dict[str,Any]:
    att,att_raw=_load("attestations",attestation_id,"provan.acceptance_attestation.v1");value={"schema_id":"provan.owner_decision.v1","decision_id":str(uuid.uuid4()),"attestation_ref":_ref(att,att_raw,"attestation_id"),"provan_recommendation":att["recommendation"],"decision":decision_input["decision"],"actor":{"actor_label":actor_label,"authority_type":"case_operator","identity_assurance":"self_asserted_label"},"rationale":decision_input.get("rationale"),"accepted_risks":decision_input.get("accepted_risks",[]),"conditions":decision_input.get("conditions",[]),"expires_at":decision_input.get("expires_at"),"required_reinspection":decision_input.get("required_reinspection",[]),"created_at":iso(now)};validate_owner_decision_serialized(canonical_bytes(value),att_raw);return _store("decisions",value["decision_id"],value,"owner-decision.v1.json")[0]


def _record_data(att:dict[str,Any],att_raw:bytes,settlement:dict[str,Any],decision:dict[str,Any]|None,decision_raw:bytes|None,record_id:str,*,now:Callable[[],datetime])->dict[str,Any]:
    open_rows=[r for r in settlement["criteria"] if r["state"] not in {"established","not_applicable"}]
    return {"record_id":record_id,"record_contract":"provan.acceptance_record.v1","record_version":1,"attestation_ref":_ref(att,att_raw,"attestation_id"),"decision_ref":_ref(decision,decision_raw,"decision_id") if decision and decision_raw else None,"subject":att["subject"],"recommendation":att["recommendation"],"owner_decision":decision and decision["decision"],"accepted_risks":decision.get("accepted_risks",[]) if decision else [],"conditions":decision.get("conditions",[]) if decision else [],"decision_expires_at":decision.get("expires_at") if decision else None,"required_reinspection":decision.get("required_reinspection",[]) if decision else [],"effective_status":effective_status(att.get("expires_at"),now),"priority_open_items":open_rows[:3],"additional_open_count":max(0,len(open_rows)-3),"criteria":settlement["criteria"],"limitations":["SESSION12_VERIFIER_EXECUTION_UNAVAILABLE","SESSION13_CHALLENGE_EXECUTION_NOT_RUN"],"conflict_of_interest":"Internal Provan dogfood may use explicit founder/operator confirmation; recommendation remains evidence-derived."}


def render_record(attestation_id:str,decision_id:str|None,format_name:str,*,now:Callable[[],datetime]=utcnow)->tuple[str,str]:
    att,att_raw=_load("attestations",attestation_id,"provan.acceptance_attestation.v1");settlement,settlement_raw=_load("settlements",att["settlement_ref"]["id"],"provan.evidence_settlement.v1");decision=decision_raw=None
    if decision_id:decision,decision_raw=_load("decisions",decision_id,"provan.owner_decision.v1");validate_owner_decision_serialized(decision_raw,att_raw)
    contract,contract_raw=_load("contracts",att["contract_ref"]["id"],"provan.acceptance_contract.v1");_validate_contract_loaded(contract,contract_raw);freeze,freeze_raw=_load("freezes",att["freeze_ref"]["id"],"provan.candidate_freeze.v1");validate_freeze_serialized(freeze_raw,contract_raw);validate_settlement_serialized(settlement_raw,contract_raw,freeze_raw,now=lambda:datetime.fromisoformat(settlement["created_at"].replace("Z","+00:00")));validate_attestation_serialized(att_raw,contract_raw,freeze_raw,settlement_raw,now=lambda:datetime.fromisoformat(att["created_at"].replace("Z","+00:00")));_validate_attestation_projections(att,att_raw)
    core={"attestation_sha256":sha256_bytes(att_raw),"decision_sha256":sha256_bytes(decision_raw) if decision_raw else None,"record_contract":"provan.acceptance_record.v1","record_version":1};record_id=sha256_bytes(canonical_bytes(core));data=_record_data(att,att_raw,settlement,decision,decision_raw,record_id,now=now)
    terminal=f"Acceptance Record {record_id}\nRecommendation: {data['recommendation']}\nOwner decision: {data['owner_decision'] or 'not supplied'}\nAccepted risks: {json.dumps(data['accepted_risks'],sort_keys=True)}\nConditions: {json.dumps(data['conditions'],sort_keys=True)}\nDecision expiry: {data['decision_expires_at'] or 'none'}\nRequired Reinspection: {json.dumps(data['required_reinspection'],sort_keys=True)}\nEffective status: {data['effective_status']}\nOpen items: {len([r for r in data['criteria'] if r['state'] not in {'established','not_applicable'}])}"
    markdown=f"# Acceptance Record\n\n- Record: `{record_id}`\n- Recommendation: `{data['recommendation']}`\n- Owner decision: `{data['owner_decision'] or 'not supplied'}`\n- Effective status: `{data['effective_status']}`\n\n## Priority open items\n\n"+"\n".join(f"- `{r['criterion_ref']}` — `{r['state']}`; closure `{r['closure_requirement_ref']['id']}`" for r in data["priority_open_items"])+(f"\n- Plus {data['additional_open_count']} additional open item(s)." if data["additional_open_count"] else "")
    markdown += "\n\n## Owner conditions and Reinspection\n\n"+f"- Accepted risks: `{json.dumps(data['accepted_risks'],sort_keys=True)}`\n- Conditions: `{json.dumps(data['conditions'],sort_keys=True)}`\n- Decision expiry: `{data['decision_expires_at'] or 'none'}`\n- Required Reinspection: `{json.dumps(data['required_reinspection'],sort_keys=True)}`"
    rendered={"json":canonical_bytes(data).decode("utf-8"),"terminal":terminal+"\n","markdown":markdown+"\n"};rendered["html"]="<!doctype html><meta charset=utf-8><title>Acceptance Record</title><pre>"+html.escape(markdown)+"</pre>"
    views={}
    for name,text in rendered.items():
        digest=sha256_bytes(text.encode())
        views[name]={"path":f"{name}.txt" if name=="terminal" else f"record.{name}","sha256":digest,"projection_id":sha256_bytes(canonical_bytes({"record_id":record_id,"format":name,"sha256":digest}))}
    bundle={"record_id":record_id,"record_contract":"provan.acceptance_record.v1","record_version":1,"authoritative_chain":{"attestation_ref":_ref(att,att_raw,"attestation_id"),"settlement_ref":_ref(settlement,settlement_raw,"settlement_id"),"decision_ref":_ref(decision,decision_raw,"decision_id") if decision and decision_raw else None},"views":views}
    root=Path("outputs/acceptance/records")/record_id.removeprefix("sha256:")
    for name,text in rendered.items():
        rel=root/views[name]["path"]
        try:secure_write(rel,text.encode(),allowed_suffixes=RECORD_SUFFIXES)
        except FileExistsError:
            if secure_read(rel,allowed_suffixes=RECORD_SUFFIXES)!=text.encode():raise ProvanError("RECORD_PROJECTION_TAMPERED",name)
    try:secure_write(root/"bundle.json",canonical_bytes(bundle))
    except FileExistsError:
        if secure_read(root/"bundle.json")!=canonical_bytes(bundle):raise ProvanError("RECORD_BUNDLE_TAMPERED",record_id)
    if format_name not in rendered:raise ProvanError("RECORD_FORMAT_UNSUPPORTED",format_name)
    return record_id,rendered[format_name]


def _load_record_bundle(record_id:str)->tuple[dict[str,Any],Path]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}",record_id):raise ProvanError("RECORD_ID_INVALID",record_id)
    root=Path("outputs/acceptance/records")/record_id.removeprefix("sha256:");raw=secure_read(root/"bundle.json");bundle=json.loads(raw)
    if bundle.get("record_id")!=record_id:raise ProvanError("RECORD_BUNDLE_ID_MISMATCH",record_id)
    for name,view in bundle["views"].items():
        try:data=secure_read(root/view["path"],allowed_suffixes=RECORD_SUFFIXES)
        except FileNotFoundError as exc:raise ProvanError("RECORD_PROJECTION_ORPHANED",view["path"]) from exc
        if sha256_bytes(data)!=view["sha256"]:raise ProvanError("RECORD_PROJECTION_TAMPERED",view["path"])
        if view.get("projection_id")!=sha256_bytes(canonical_bytes({"record_id":record_id,"format":name,"sha256":view["sha256"]})):raise ProvanError("RECORD_PROJECTION_ID_MISMATCH",view["path"])
    return bundle,root


def reinspect(record_id:str,repo_source:str,later_head:str,external_receipt:dict[str,Any]|None,*,now:Callable[[],datetime]=utcnow)->dict[str,Any]:
    bundle,_=_load_record_bundle(record_id);chain=bundle["authoritative_chain"];att,att_raw=_load("attestations",chain["attestation_ref"]["id"],"provan.acceptance_attestation.v1");settlement,settlement_raw=_load("settlements",chain["settlement_ref"]["id"],"provan.evidence_settlement.v1");contract,contract_raw=_load("contracts",att["contract_ref"]["id"],"provan.acceptance_contract.v1");original,original_raw=_load("freezes",att["freeze_ref"]["id"],"provan.candidate_freeze.v1")
    if any((chain["attestation_ref"]["sha256"]!=sha256_bytes(att_raw),chain["settlement_ref"]["sha256"]!=sha256_bytes(settlement_raw),att["contract_ref"]["sha256"]!=sha256_bytes(contract_raw),att["freeze_ref"]["sha256"]!=sha256_bytes(original_raw))):raise ProvanError("RECORD_AUTHORITATIVE_CHAIN_MISMATCH",record_id)
    decision_raw=None
    if chain.get("decision_ref"):
        decision,decision_raw=_load("decisions",chain["decision_ref"]["id"],"provan.owner_decision.v1")
        if chain["decision_ref"]["sha256"]!=sha256_bytes(decision_raw):raise ProvanError("RECORD_AUTHORITATIVE_CHAIN_MISMATCH",record_id)
        validate_owner_decision_serialized(decision_raw,att_raw)
    identity_core={"attestation_sha256":sha256_bytes(att_raw),"decision_sha256":sha256_bytes(decision_raw) if decision_raw else None,"record_contract":"provan.acceptance_record.v1","record_version":1}
    if record_id!=sha256_bytes(canonical_bytes(identity_core)):raise ProvanError("RECORD_ID_BINDING_MISMATCH",record_id)
    _validate_contract_loaded(contract,contract_raw);validate_freeze_serialized(original_raw,contract_raw);validate_settlement_serialized(settlement_raw,contract_raw,original_raw,now=lambda:datetime.fromisoformat(settlement["created_at"].replace("Z","+00:00")));validate_attestation_serialized(att_raw,contract_raw,original_raw,settlement_raw,now=lambda:datetime.fromisoformat(att["created_at"].replace("Z","+00:00")));_validate_attestation_projections(att,att_raw)
    if "://" in repo_source:raise ProvanError("SESSION11_REMOTE_REINSPECTION_REQUIRES_LOCAL_SOURCE",repo_source)
    repo=Path(repo_source).resolve()
    identity_context,_,identity,_=_snapshot_local_target(repo,False)
    identity_context.cleanup()
    if identity!=original["repository_identity"]:raise ProvanError("REINSPECTION_REPOSITORY_MISMATCH",identity)
    if later_head==original["head"]:raise ProvanError("REINSPECTION_NOT_LATER_CANDIDATE",later_head)
    if not FULL_COMMIT.fullmatch(later_head):raise ProvanError("CANDIDATE_FULL_COMMIT_REQUIRED",later_head)
    try:_git(repo,["merge-base","--is-ancestor",original["head"],later_head])
    except ProvanError as exc:raise ProvanError("REINSPECTION_LINEAGE_MISMATCH",later_head) from exc
    later=_make_freeze(contract,contract_raw,repo_source,purpose="reinspection",head_override=later_head,now=now);later_raw=canonical_bytes(later);results={r["ref"]:r for r in later["source_check_results"]};items=[]
    for row in settlement["criteria"]:
        if not row.get("material",True) or row["state"] in {"established","not_applicable"}:continue
        outcome=results.get(row["closure_requirement_ref"]["id"],{"status":"unable"});status="closed" if outcome["status"]=="supports" else "open" if outcome["status"]=="falsifies" else "disputed" if outcome["status"]=="disputed" else "unable_to_establish"
        items.append({"criterion_ref":row["criterion_ref"],"closure_requirement_ref":row["closure_requirement_ref"],"status":status,"material":True,"reason_code":outcome.get("reason_code","EVIDENCE_UNAVAILABLE")})
    inv_results=[]
    for ref in contract["protected_invariant_refs"]:
        outcome=results.get(ref["id"],{"status":"unable"});status="closed" if outcome["status"]=="supports" else "open" if outcome["status"]=="falsifies" else "disputed" if outcome["status"]=="disputed" else "unable_to_establish";inv_results.append({"protected_invariant_ref":ref,"status":status,"material":True,"reason_code":outcome.get("reason_code","EVIDENCE_UNAVAILABLE")})
    if not items:items=[{"criterion_ref":"NO_MATERIAL_OPEN_REQUIREMENT","closure_requirement_ref":{"id":"not-applicable","sha256":"sha256:"+"0"*64},"status":"not_applicable","material":False,"reason_code":"NO_OPEN_REQUIREMENT"}]
    receipt_ref=None
    receipt_raw=None
    if external_receipt:
        _schema("external-change-receipt.v1.json",external_receipt);receipt_raw=canonical_bytes(external_receipt);validate_external_change_receipt_serialized(receipt_raw);stored,receipt_raw=_store("external-change-receipts",external_receipt["receipt_id"],external_receipt,"external-change-receipt.v1.json");receipt_ref=_ref(stored,receipt_raw,"receipt_id")
    value={"schema_id":"provan.reinspection_record.v1","reinspection_id":str(uuid.uuid4()),"record_id":record_id,"original_attestation_ref":_ref(att,att_raw,"attestation_id"),"original_contract_ref":_ref(contract,contract_raw,"contract_id"),"original_freeze_ref":_ref(original,original_raw,"freeze_id"),"later_freeze_ref":_ref(later,later_raw,"freeze_id"),"external_change_receipt_ref":receipt_ref,"items":items,"protected_invariant_results":inv_results,"overall_status":derive_reinspection_overall(items,inv_results),"created_at":iso(now)};validate_reinspection_serialized(canonical_bytes(value),attestation_raw=att_raw,contract_raw=contract_raw,original_freeze_raw=original_raw,later_freeze_raw=later_raw,settlement_raw=settlement_raw,external_receipt_raw=receipt_raw);return _store("reinspections",value["reinspection_id"],value,"reinspection-record.v1.json")[0]
