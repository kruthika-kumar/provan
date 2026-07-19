"""Non-vacuous registry consistency check for the Sessions 6--8 closeout inputs."""
from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    root=Path(__file__).resolve().parents[1]; validation=root/"docs"/"validation"
    completion=json.loads((validation/"session6-8-completion-map.json").read_text(encoding="utf-8"))["requirements"]
    proofs=json.loads((validation/"session6-8-proof-manifest.json").read_text(encoding="utf-8"))["proofs"]
    claims=json.loads((validation/"session6-8-claim-registry.json").read_text(encoding="utf-8"))["claims"]
    requirement_ids={item["requirement_id"] for item in completion}; proof_ids={item["proof_id"] for item in proofs}
    if len(requirement_ids)!=len(completion) or any(item["status"]=="planned" for item in completion): raise SystemExit("completion map is incomplete")
    if {item["requirement_id"] for item in proofs} != requirement_ids: raise SystemExit("proof requirements are not exhaustive")
    covered={rid for claim in claims for rid in claim["requirement_ids"]}
    if covered != requirement_ids or any(not claim["requirement_ids"] for claim in claims): raise SystemExit("claim requirements are not exhaustive")
    for claim in claims:
        for field in ("positive_proof_ids","near_valid_proof_ids","adversarial_proof_ids"):
            if not claim[field] or not set(claim[field]) <= proof_ids: raise SystemExit("claim proof binding invalid")
    print(json.dumps({"requirements":len(requirement_ids),"proofs":len(proofs),"claims":len(claims),"status":"registry_consistent"}))
    return 0
if __name__=="__main__": raise SystemExit(main())
