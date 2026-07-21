"""Build closeout maps from frozen authentic requirement and proof registries."""
from __future__ import annotations

import json
from pathlib import Path

from shiproom.session6_8_semantics import validate_requirement_inventory


ROOT=Path(__file__).resolve().parents[1]
VALIDATION=ROOT/"docs"/"validation"


def _dump(value: object) -> str:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n"


def main() -> int:
    inventory=validate_requirement_inventory(json.loads((VALIDATION/"session6-8-requirement-inventory.json").read_text(encoding="utf-8")))
    registry=json.loads((VALIDATION/"session6-8-requirement-proof-registry.json").read_text(encoding="utf-8"))
    rows=registry.get("proofs")
    if registry.get("schema_version")!="session6-8-requirement-proof-registry.v2" or not isinstance(rows,list) or len(rows)!=318:
        raise SystemExit("authentic_proof_registry_invalid")
    by_requirement={row["requirement_id"]:[] for row in inventory["requirements"]}
    for row in rows:
        if row["requirement_id"] not in by_requirement:raise SystemExit("authentic_proof_requirement_unregistered")
        by_requirement[row["requirement_id"]].append(row)
    completion=[];execution=[];proofs=[];claims=[]
    for requirement in inventory["requirements"]:
        rid=requirement["requirement_id"]; selected=by_requirement[rid]
        by_class={row["fixture_class"]:row for row in selected}
        if set(by_class)!={"valid","near_valid","adversarial_invalid"}:raise SystemExit("authentic_proof_classes_incomplete:"+rid)
        proof_ids=[by_class[name]["proof_id"] for name in ("valid","near_valid","adversarial_invalid")]
        implementation=sorted({function for row in selected for function in row["production_functions"]})
        artifacts=sorted({artifact for row in selected for artifact in row["canonical_artifacts"]})
        completion.append({"requirement_id":rid,"phase":requirement["session"],"current_state":"pending_authentic_execution","known_gap":"authentic proof execution required","implementation_symbols":implementation,"production_boundary":requirement["owning_production_entrypoint"],"positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],"canonical_artifacts":artifacts,"status":"pending_authentic_execution"})
        execution.append({"requirement_id":rid,"production_boundaries":implementation,"proof_ids":proof_ids,"canonical_artifacts":artifacts,"status":"pending_authentic_execution"})
        for row in selected:
            proofs.append({"proof_id":row["proof_id"],"requirement_id":rid,"domain":requirement["session"],"invariant":requirement["normative_behavior"],"fixture_class":row["fixture_class"],"workflow_case":row["workflow_case"],"production_functions":row["production_functions"],"artifact_queries":row["artifact_queries"],"semantic_fingerprint":row["semantic_fingerprint"],"expected_boundary_outcome":row["expected_boundary_outcome"],"canonical_artifacts":row["canonical_artifacts"],"minimum_record_count":row["minimum_cardinality"],"test_id":f"tests/test_session6_8_proof_execution.py::test_requirement_proof[{row['proof_id']}]","status":"pending_authentic_execution"})
        claims.append({"claim_id":"claim_"+rid.lower(),"requirement_ids":[rid],"approved_semantic_hash":requirement["approved_semantic_hash"],"implementation_symbols":implementation,"positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],"artifact_queries":by_class["valid"]["artifact_queries"],"minimum_record_counts":requirement["minimum_cardinalities"],"production_invocation_receipts":implementation,"contract_parity_receipts":[],"security_receipts":[],"installed_wheel_receipts":[],"status":"pending_authentic_execution"})
    values={
        "session6-8-completion-map.json":{"schema_version":"shiproom.session6-8-completion-map.v5","requirements":completion},
        "session6-8-execution-map.json":{"schema_version":"shiproom.session6-8-execution-map.v5","requirements":execution},
        "session6-8-proof-manifest.json":{"schema_version":"shiproom.session6-8-proof-manifest.v6","proofs":proofs},
        "session6-8-claim-registry.json":{"schema_version":"shiproom.session6-8-claim-registry.v5","claims":claims},
    }
    for name,value in values.items():(VALIDATION/name).write_text(_dump(value),encoding="utf-8")
    print(json.dumps({"requirements":106,"proofs":318,"claims":106,"status":"pending_authentic_execution"}))
    return 0


if __name__=="__main__":raise SystemExit(main())
