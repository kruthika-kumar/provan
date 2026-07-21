from __future__ import annotations

import json
from pathlib import Path

from scripts.build_session6_8_requirement_evidence_matrix import build


ROOT=Path(__file__).resolve().parents[1]


def test_requirement_evidence_matrix_has_one_measured_row_per_claim(tmp_path:Path):
    registry=json.loads((ROOT/"docs/validation/session6-8-claim-registry.json").read_text(encoding="utf-8"))
    resolved=[]
    for claim in registry["claims"]:
        ids=claim["positive_proof_ids"]+claim["near_valid_proof_ids"]+claim["adversarial_proof_ids"]
        resolved.append({"claim_id":claim["claim_id"],"requirement_id":claim["requirement_ids"][0],"production_invocation_ids":["inv_measured"],"measured_evidence":[{"proof_id":pid,"artifact_hash":"sha256:"+"a"*64,"selector":claim["artifact_assertions"][0]["selector"],"measured_value":1,"measured_cardinality":1} for pid in ids]})
    receipt={"final_commit":"f"*40,"claims":resolved}
    receipt_path=tmp_path/"claims.json";receipt_path.write_text(json.dumps(receipt),encoding="utf-8")
    output_json=tmp_path/"matrix.json";output_md=tmp_path/"matrix.md"
    value=build(claims_path=receipt_path,registry_path=ROOT/"docs/validation/session6-8-claim-registry.json",output_json=output_json,output_markdown=output_md)
    assert value["requirement_count"]==len(value["rows"])==106
    assert all(row["production_invocations"]==["inv_measured"] for row in value["rows"])
    assert len([line for line in output_md.read_text(encoding="utf-8").splitlines() if line.startswith("| `")])==106
