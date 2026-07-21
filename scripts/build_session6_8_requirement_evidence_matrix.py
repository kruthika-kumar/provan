"""Render the 106-row matrix from independently measured claim evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build(*, claims_path: Path, registry_path: Path, output_json: Path, output_markdown: Path) -> dict:
    resolution=json.loads(claims_path.read_text(encoding="utf-8"))
    registry=json.loads(registry_path.read_text(encoding="utf-8"))["claims"]
    by_claim={row["claim_id"]:row for row in resolution["claims"]}
    rows=[]
    for claim in registry:
        resolved=by_claim.get(claim["claim_id"])
        if resolved is None or resolved.get("requirement_id")!=claim["requirement_ids"][0]:
            raise ValueError("evidence_matrix_claim_missing")
        proofs={item["proof_id"]:item for item in resolved["measured_evidence"]}
        ordered=[claim["positive_proof_ids"][0],claim["near_valid_proof_ids"][0],claim["adversarial_proof_ids"][0]]
        if set(proofs)!=set(ordered):raise ValueError("evidence_matrix_proof_binding_invalid")
        rows.append({
            "requirement_id":resolved["requirement_id"],
            "implementation_symbols":claim["implementation_symbols"],
            "valid_proof":proofs[ordered[0]],
            "near_valid_proof":proofs[ordered[1]],
            "adversarial_proof":proofs[ordered[2]],
            "measured_artifact_assertions":resolved.get("evidence_assertions",resolved["measured_evidence"]),
            "measured_cardinalities":{item["proof_id"]:item["measured_cardinality"] for item in proofs.values()},
            "production_invocations":resolved["production_invocation_ids"],
            "claim_status":"resolved",
        })
    if len(rows)!=106:raise ValueError("evidence_matrix_cardinality_invalid")
    result={"schema_version":"session6-8-requirement-evidence-matrix.v1","final_commit":resolution["final_commit"],"requirement_count":106,"rows":rows}
    output_json.parent.mkdir(parents=True,exist_ok=True);output_json.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    lines=["# Sessions 6–8 Requirement Evidence Matrix","",f"Final evidence commit: `{resolution['final_commit']}`","", "| Requirement | Valid | Near-valid | Adversarial | Claim |", "|---|---|---|---|---|"]
    for row in rows:lines.append(f"| `{row['requirement_id']}` | `{row['valid_proof']['proof_id']}` | `{row['near_valid_proof']['proof_id']}` | `{row['adversarial_proof']['proof_id']}` | resolved |")
    output_markdown.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return result


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--claims",type=Path,required=True);parser.add_argument("--registry",type=Path,required=True);parser.add_argument("--output-json",type=Path,required=True);parser.add_argument("--output-markdown",type=Path,required=True);args=parser.parse_args()
    result=build(claims_path=args.claims,registry_path=args.registry,output_json=args.output_json,output_markdown=args.output_markdown);print(json.dumps({"requirements":result["requirement_count"]},sort_keys=True));return 0


if __name__=="__main__":raise SystemExit(main())
