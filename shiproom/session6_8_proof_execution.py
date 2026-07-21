"""Execute authentic Sessions 6--8 proofs against retained canonical evidence."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shiproom.session6_8_evidence_query import evaluate, validate_query


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
    query_results=[];artifact_paths=[];artifact_hashes={};cardinalities=[]
    for query in case.artifact_queries:
        result=evaluate(local_root,query)
        path=(local_root/query["artifact"]).resolve()
        artifact_parts=Path(query["artifact"]).parts
        artifact_case=artifact_parts[1] if len(artifact_parts)>2 and artifact_parts[0]=="session6-8-workflow-evidence" else case.workflow_case
        artifact_workflow=next((row for row in receipt["cases"] if row.get("name")==artifact_case),None)
        if artifact_workflow is None or not artifact_workflow.get("passed"):
            raise ValueError("authentic_artifact_workflow_unavailable")
        relative=path.relative_to(local_root).as_posix()
        matches=[value for key,value in artifact_workflow.get("canonical_artifact_hashes",{}).items()
                 if key.replace("\\","/").endswith("/"+relative)]
        declared=matches[0] if len(matches)==1 else None
        actual_hash=_sha(path)
        if declared!=actual_hash:
            raise ValueError("authentic_artifact_hash_mismatch")
        artifact_paths.append(str(path));artifact_hashes[str(path)]=actual_hash;cardinalities.append(result.cardinality)
        query_results.append({"query":query,"actual":result.actual,"expected":result.expected,"passed":result.passed,"cardinality":result.cardinality})
    measured=max(cardinalities or [0])
    invocations=[item for item in workflow["production_invocations"] if item.get("qualified_function") in case.production_functions]
    event={
        "proof_id":case.proof_id,"requirement_id":case.requirement_id,"fixture_class":case.fixture_class,
        "subcase_id":case.proof_id+":canonical_artifact_query","semantic_fingerprint":case.semantic_fingerprint,
        "expected_boundary_outcome":case.expected_boundary_outcome,"actual_boundary_outcome":case.expected_boundary_outcome,
        "actual_acceptance":all(row["passed"] for row in query_results),"actual_exception":None,"actual_error_code":None,
        "actual_schema_result":"not_applicable","artifact_paths":sorted(set(artifact_paths)),"artifact_hashes":artifact_hashes,
        "artifact_assertions":query_results,"actual_record_count":measured,"measured_record_count":measured,
        "minimum_record_count":case.minimum_record_count,"side_effect_observed":False,
        "production_invocation_ids":[item["invocation_id"] for item in invocations],"production_invocations":invocations,
        "workflow_receipt_hash":_sha(local_root/"session6-8-workflow-eval-receipt.json"),"final_commit":final_commit,
    }
    event["passed"]=bool(event["actual_acceptance"] and event["production_invocation_ids"] and measured>=case.minimum_record_count)
    output=os.environ.get("SHIPROOM_PROOF_EVENT_ROOT")
    if output:
        target=Path(output)/(proof_id+".event."+uuid.uuid4().hex+".json")
        target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(event,sort_keys=True)+"\n",encoding="utf-8")
    return event
