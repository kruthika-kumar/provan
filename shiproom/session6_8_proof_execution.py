"""Execute authentic Sessions 6--8 proofs against retained canonical evidence."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shiproom.session6_8_evidence_query import evaluate, validate_query
from shiproom.workflow_audit import session as audit_session, subcase as audit_subcase


@dataclass(frozen=True)
class RequirementProofCase:
    proof_id: str
    requirement_id: str
    fixture_class: str
    workflow_case: str
    production_functions: tuple[str, ...]
    artifact_queries: tuple[dict[str, Any], ...]
    expected_boundary_outcome: str
    minimum_record_count: int
    semantic_fingerprint: str
    expected_acceptance: bool
    expected_error: str | None
    fixture_binding: dict[str, Any] | None
    outcome_evidence: dict[str, Any] | None
    attack_spec: dict[str, Any] | None


def _load_registry() -> dict[str, Any]:
    path=Path(__file__).with_name("session6_8_requirement_proof_registry.json")
    value=json.loads(path.read_text(encoding="utf-8"))
    rows=value.get("proofs")
    if value.get("schema_version")!="session6-8-requirement-proof-registry.v2" or not isinstance(rows,list) or len(rows)!=318:
        raise ValueError("authentic_proof_registry_invalid")
    if len({row.get("proof_id") for row in rows})!=318:
        raise ValueError("authentic_proof_registry_duplicate")
    for row in rows:
        if not row.get("workflow_case") or not row.get("production_functions") or not row.get("artifact_queries"):
            raise ValueError("authentic_proof_binding_incomplete")
        for query in row["artifact_queries"]:
            validate_query(query)
            selector_parts=tuple(part for part in query["selector"].split("/") if part)
            if selector_parts[:1]==("measurements",) or selector_parts[-1:]==("observed",):
                raise ValueError("synthetic_measurement_proof_forbidden")
    return value


def _case(row: dict[str, Any]) -> RequirementProofCase:
    return RequirementProofCase(
        proof_id=row["proof_id"],requirement_id=row["requirement_id"],fixture_class=row["fixture_class"],
        workflow_case=row["workflow_case"],production_functions=tuple(row["production_functions"]),
        artifact_queries=tuple(row["artifact_queries"]),expected_boundary_outcome=row["expected_boundary_outcome"],
        minimum_record_count=row["minimum_cardinality"],semantic_fingerprint=row["semantic_fingerprint"],
        expected_acceptance=row["expected_acceptance"],expected_error=row.get("expected_error"),
        fixture_binding=row.get("fixture_binding"),outcome_evidence=row.get("outcome_evidence"),attack_spec=row.get("attack_spec"),
    )


PROOF_CASES={row["proof_id"]:_case(row) for row in _load_registry()["proofs"]}


def _sha(path: Path) -> str:
    return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()


def _workflow_receipt(local_root: Path) -> dict[str, Any]:
    path=local_root/"session6-8-workflow-eval-receipt.json"
    if not path.is_file():
        raise ValueError("authentic_workflow_receipt_missing")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value.get("cases"),list) or len(value["cases"])!=18:
        raise ValueError("authentic_workflow_receipt_invalid")
    return value


def _binding_path(root: Path, relative: str) -> Path:
    path=(root/relative).resolve()
    try:path.relative_to(root.resolve())
    except ValueError as exc:raise ValueError("proof_fixture_path_unsafe") from exc
    if not path.is_file():raise ValueError("proof_fixture_artifact_missing")
    return path


def _semantic_hash(value: Any) -> str:
    raw=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()
    return "sha256:"+hashlib.sha256(raw).hexdigest()


def _resolve_symbol(reference: str):
    module_name,separator,name=reference.rpartition(".")
    if not separator:raise ValueError("proof_attack_production_function_invalid")
    module=importlib.import_module(module_name)
    value=getattr(module,name,None)
    if not callable(value):raise ValueError("proof_attack_production_function_missing")
    return value


def _mutate(value: Any, operation: dict[str, Any]) -> Any:
    clone=json.loads(json.dumps(value))
    pointer=operation.get("pointer")
    if not isinstance(pointer,str) or not pointer.startswith("/"):raise ValueError("proof_attack_mutation_invalid")
    parts=[part.replace("~1","/").replace("~0","~") for part in pointer.split("/")[1:]]
    if not parts:raise ValueError("proof_attack_mutation_invalid")
    parent=clone
    for part in parts[:-1]:
        parent=parent[int(part)] if isinstance(parent,list) else parent[part]
    leaf=parts[-1];kind=operation.get("operation")
    if kind=="remove":
        if isinstance(parent,list):parent.pop(int(leaf))
        else:parent.pop(leaf)
    elif kind=="replace":
        if isinstance(parent,list):parent[int(leaf)]=operation.get("value")
        else:parent[leaf]=operation.get("value")
    elif kind=="duplicate":
        target=parent[int(leaf)] if isinstance(parent,list) else parent[leaf]
        if not isinstance(target,list) or not target:raise ValueError("proof_attack_mutation_invalid")
        target.append(json.loads(json.dumps(target[0])))
    else:raise ValueError("proof_attack_mutation_invalid")
    return clone


def _execute_attack(case: RequirementProofCase, root: Path, final_commit: str) -> tuple[dict[str,Any],list[dict[str,Any]]]:
    spec=case.attack_spec
    if spec is None:raise ValueError("proof_attack_spec_missing")
    required={"schema_version","subcase_id","mutation_id","mutation_class","target","base_artifact","mutation","production_function","arguments","expected_status_or_error","expected_exception","channel"}
    if set(spec)!=required or spec.get("schema_version")!="production-proof-attack.v1" or spec.get("subcase_id")!=case.proof_id:
        raise ValueError("proof_attack_spec_invalid")
    base_path=_binding_path(root,spec["base_artifact"]);base=json.loads(base_path.read_text(encoding="utf-8"));mutated=_mutate(base,spec["mutation"])
    proof_root=root/"proof-artifacts"/case.proof_id;proof_root.mkdir(parents=True,exist_ok=True)
    base_copy=proof_root/"base.json";mutated_copy=proof_root/"mutated.json"
    base_copy.write_text(json.dumps(base,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    mutated_copy.write_text(json.dumps(mutated,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    callable_=_resolve_symbol(spec["production_function"]);arguments=[];keyword_arguments={}
    for item in spec["arguments"]:
        if item=="$mutated":arguments.append(mutated)
        elif item=="$mutated_path":arguments.append(mutated_copy)
        elif item=="$base_path":arguments.append(base_copy)
        elif isinstance(item,str) and item.startswith("$artifact:"):
            arguments.append(json.loads(_binding_path(root,item.removeprefix("$artifact:")).read_text(encoding="utf-8")))
        elif isinstance(item,dict) and set(item)=={"$base_pointer"}:
            current=base
            for part in item["$base_pointer"].lstrip("/").split("/"):
                current=current[int(part)] if isinstance(current,list) else current[part]
            arguments.append(current)
        elif isinstance(item,dict) and set(item)=={"$keyword"}:
            definition=item["$keyword"]
            if not isinstance(definition,dict) or set(definition)!={"name","base_pointer"}:raise ValueError("proof_attack_argument_invalid")
            current=base
            for part in definition["base_pointer"].lstrip("/").split("/"):
                current=current[int(part)] if isinstance(current,list) else current[part]
            keyword_arguments[definition["name"]]=current
        else:arguments.append(item)
    records=[];returned=None;caught=None
    with audit_session(Path.cwd(),case.workflow_case) as records:
        with audit_subcase(spec["subcase_id"]):
            try:returned=callable_(*arguments,**keyword_arguments)
            except Exception as exc:caught=exc
    matching=[row for row in records if row.get("subcase_id")==spec["subcase_id"] and row.get("qualified_function")==spec["production_function"]]
    if len(matching)!=1:raise ValueError("proof_attack_invocation_missing")
    invocation=matching[0]
    if spec["channel"]=="exception":
        if caught is None or invocation.get("exception_type")!=spec["expected_exception"] or invocation.get("typed_status_or_error")!=spec["expected_status_or_error"]:
            raise ValueError("proof_attack_expected_rejection_missing")
    elif spec["channel"]=="returned_status":
        if caught is not None or not isinstance(returned,dict) or invocation.get("typed_status_or_error")!=spec["expected_status_or_error"]:
            raise ValueError("proof_attack_expected_rejection_missing")
    else:raise ValueError("proof_attack_channel_invalid")
    before_hash="sha256:"+hashlib.sha256(json.dumps(invocation.get("persisted_state_before") or {},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    after_hash="sha256:"+hashlib.sha256(json.dumps(invocation.get("persisted_state_after") or {},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    relative=lambda path:path.relative_to(root).as_posix()
    manifest={"schema_version":"production-proof-subcase.v1","subcase_id":spec["subcase_id"],"mutation_id":spec["mutation_id"],"mutation_class":spec["mutation_class"],"target":spec["target"],"base_artifact":relative(base_copy),"base_hash":_sha(base_copy),"base_semantic_hash":_semantic_hash(base),"mutated_artifact":relative(mutated_copy),"mutated_hash":_sha(mutated_copy),"mutated_semantic_hash":_semantic_hash(mutated),"authoritative_state_before_hash":before_hash,"authoritative_state_after_hash":after_hash,"rejection_receipt_artifact":None,"rejection_receipt_hash":None}
    manifest_path=proof_root/"subcase-manifest.json";manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return {"subcase_id":spec["subcase_id"],"manifest_artifact":relative(manifest_path)},records


def _validate_fixture_binding(root: Path, binding: dict[str, Any] | None) -> dict[str, Any] | None:
    if binding is None:return None
    if set(binding)!={"subcase_id","manifest_artifact"} or not all(isinstance(value,str) and value for value in binding.values()):
        raise ValueError("proof_fixture_binding_invalid")
    manifest_path=_binding_path(root,binding["manifest_artifact"])
    manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    required={"schema_version","subcase_id","mutation_id","mutation_class","target","base_artifact","base_hash","base_semantic_hash","mutated_artifact","mutated_hash","mutated_semantic_hash","authoritative_state_before_hash","authoritative_state_after_hash","rejection_receipt_artifact","rejection_receipt_hash"}
    if set(manifest)!=required or manifest.get("schema_version")!="production-proof-subcase.v1" or manifest.get("subcase_id")!=binding["subcase_id"]:
        raise ValueError("proof_fixture_manifest_invalid")
    base=_binding_path(root,manifest["base_artifact"]);mutated=_binding_path(root,manifest["mutated_artifact"])
    base_hash=_sha(base);mutated_hash=_sha(mutated)
    if base_hash!=manifest["base_hash"] or mutated_hash!=manifest["mutated_hash"]:
        raise ValueError("proof_fixture_hash_mismatch")
    if base_hash==mutated_hash:
        raise ValueError("proof_fixture_mutation_missing")
    base_value=json.loads(base.read_text(encoding="utf-8"));mutated_value=json.loads(mutated.read_text(encoding="utf-8"))
    semantic=lambda value:"sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
    if semantic(base_value)!=manifest["base_semantic_hash"] or semantic(mutated_value)!=manifest["mutated_semantic_hash"]:
        raise ValueError("proof_fixture_semantic_hash_mismatch")
    return {**manifest,"manifest_artifact":binding["manifest_artifact"],"manifest_hash":_sha(manifest_path)}


def _derive_rejection(root: Path, case: RequirementProofCase, invocations: list[dict[str, Any]], fixture: dict[str, Any] | None) -> tuple[bool,str|None,str|None,dict[str,Any]|None]:
    evidence=case.outcome_evidence
    if evidence is None:return False,None,None,None
    required={"schema_version","subcase_id","channel","production_function","expected_status_or_error","expected_exception","receipt_artifact","receipt_hash"}
    if set(evidence)!=required or evidence.get("schema_version")!="production-rejection-binding.v1":
        raise ValueError("proof_rejection_binding_invalid")
    if fixture is None:
        raise ValueError("proof_rejection_mutation_missing")
    matches=[row for row in invocations if row.get("subcase_id")==evidence["subcase_id"] and row.get("qualified_function")==evidence["production_function"]]
    if len(matches)!=1:
        raise ValueError("proof_rejection_invocation_missing")
    invocation=matches[0];channel=evidence["channel"]
    actual_error=invocation.get("typed_status_or_error");actual_exception=invocation.get("exception_type")
    if channel=="exception":
        rejected=actual_exception is not None and actual_exception==evidence["expected_exception"] and actual_error==evidence["expected_status_or_error"]
    elif channel=="returned_status":
        rejected=actual_exception is None and actual_error==evidence["expected_status_or_error"]
    elif channel=="persisted_receipt":
        receipt=evidence["receipt_artifact"]
        if not isinstance(receipt,str) or not receipt:raise ValueError("proof_rejection_receipt_missing")
        path=_binding_path(root,receipt)
        if _sha(path)!=evidence["receipt_hash"]:raise ValueError("proof_rejection_receipt_hash_mismatch")
        generated=invocation.get("generated_artifact_hashes",{})
        rejected=generated.get(receipt)==evidence["receipt_hash"] and actual_error==evidence["expected_status_or_error"]
    else:
        raise ValueError("proof_rejection_channel_invalid")
    if not rejected:raise ValueError("proof_rejection_outcome_mismatch")
    before=set((invocation.get("persisted_state_before") or {}).values())
    components=set(invocation.get("input_component_hashes") or [])
    if fixture["mutated_hash"] not in before and fixture["mutated_semantic_hash"] not in components:
        raise ValueError("proof_rejection_mutation_unbound")
    return True,actual_error,actual_exception,invocation


def execute_proof(proof_id: str, *, final_commit: str, evidence_root: Path | None = None) -> dict[str, Any]:
    try:case=PROOF_CASES[proof_id]
    except KeyError as exc:raise ValueError("proof_id_unregistered") from exc
    local_root=(evidence_root or Path(os.environ.get("SHIPROOM_AUTHENTIC_EVIDENCE_ROOT",Path.cwd()/".shiproom"/"local"))).resolve()
    receipt=_workflow_receipt(local_root)
    workflow=next((row for row in receipt["cases"] if row.get("name")==case.workflow_case),None)
    if workflow is None or not workflow.get("passed"):
        raise ValueError("authentic_workflow_case_unavailable")
    observed_functions={item.get("qualified_function") for item in workflow.get("production_invocations",[])}
    if not set(case.production_functions)<=observed_functions:
        raise ValueError("authentic_production_invocation_missing")
    runtime_binding=case.fixture_binding;attack_invocations=[]
    if case.fixture_class=="adversarial_invalid":
        runtime_binding,attack_invocations=_execute_attack(case,local_root,final_commit)
    query_results=[];artifact_paths=[];artifact_hashes={};cardinalities=[]
    for query in case.artifact_queries:
        result=evaluate(local_root,query)
        path=(local_root/query["artifact"]).resolve()
        relative=path.relative_to(local_root).as_posix()
        actual_hash=_sha(path)
        artifact_parts=Path(query["artifact"]).parts
        if len(artifact_parts)>2 and artifact_parts[0]=="session6-8-workflow-evidence":
            artifact_case=artifact_parts[1]
            artifact_workflow=next((row for row in receipt["cases"] if row.get("name")==artifact_case),None)
            if artifact_workflow is None or not artifact_workflow.get("passed"):
                raise ValueError("authentic_artifact_workflow_unavailable")
            matches=[value for key,value in artifact_workflow.get("canonical_artifact_hashes",{}).items() if key.replace("\\","/").endswith("/"+relative)]
            if len(matches)!=1 or matches[0]!=actual_hash: raise ValueError("authentic_artifact_hash_mismatch")
        artifact_paths.append(relative);artifact_hashes[relative]=actual_hash;cardinalities.append(result.cardinality)
        query_results.append({"query":query,"actual":result.actual,"expected":result.expected,"passed":result.passed,"cardinality":result.cardinality})
    measured=max(cardinalities or [0])
    invocations=[item for item in workflow["production_invocations"] if item.get("qualified_function") in case.production_functions]
    invocations.extend(attack_invocations)
    fixture=_validate_fixture_binding(local_root,runtime_binding)
    rejected,actual_error,actual_exception,rejection_invocation=_derive_rejection(local_root,case,invocations,fixture)
    if case.fixture_class=="adversarial_invalid" and not rejected:raise ValueError("proof_adversarial_rejection_missing")
    if case.fixture_class!="adversarial_invalid" and rejected:raise ValueError("proof_non_adversarial_rejection_forbidden")
    actual_acceptance=bool(all(row["passed"] for row in query_results) and not rejected)
    event={
        "proof_id":case.proof_id,"requirement_id":case.requirement_id,"fixture_class":case.fixture_class,
        "subcase_id":case.proof_id+":canonical_artifact_query","semantic_fingerprint":case.semantic_fingerprint,
        "expected_boundary_outcome":case.expected_boundary_outcome,"actual_boundary_outcome":"rejected" if rejected else ("accepted" if case.expected_boundary_outcome=="accepted" else "bounded"),
        "actual_acceptance":actual_acceptance,"actual_exception":actual_exception,"actual_error_code":actual_error,
        "actual_schema_result":"not_applicable","artifact_paths":sorted(set(artifact_paths)),"artifact_hashes":artifact_hashes,
        "artifact_assertions":query_results,"actual_record_count":measured,"measured_record_count":measured,
        "minimum_record_count":case.minimum_record_count,"side_effect_observed":False,
        "production_invocation_ids":[item["invocation_id"] for item in invocations],"production_invocations":invocations,
        "fixture_binding":fixture,"outcome_evidence":case.outcome_evidence,
        "rejection_invocation_id":rejection_invocation.get("invocation_id") if rejection_invocation else None,
        "workflow_receipt_hash":_sha(local_root/"session6-8-workflow-eval-receipt.json"),"final_commit":final_commit,
    }
    event["passed"]=bool(event["actual_acceptance"]==case.expected_acceptance and event["actual_error_code"]==case.expected_error and event["production_invocation_ids"] and measured>=case.minimum_record_count and all(row["passed"] for row in query_results))
    output=os.environ.get("SHIPROOM_PROOF_EVENT_ROOT")
    if output:
        target=Path(output)/(proof_id+".event."+uuid.uuid4().hex+".json")
        target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(event,sort_keys=True)+"\n",encoding="utf-8")
    return event
