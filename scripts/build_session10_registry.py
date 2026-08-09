from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCHEMA_ROOT=ROOT/"provan"/"schemas"
OUTPUT=ROOT/"artifacts"/"session10"/"schema_registry.v1.public.json"
SESSION10_NAMES={
    "provan.change_brief.v1","provan.affected_entity.v1","provan.affected_relationship.v1","provan.context_record.v1",
    "provan.case_context_bundle.v1","provan.context_request.v1","provan.context_provider_result.v1","provan.promotion_decision.v1",
    "provan.acceptance_seed.v1","provan.change_topology.v1","provan.model_usage_receipt.v1","provan.session_handoff.v1",
    "provan.error.v1","provan.acceptance_preparation.v1","provan.model_input_envelope.v1","provan.session10_proof_registry.v1",
    "provan.session10_layer4_matrix.v1","provan.session10_reviewer_receipt.v1",
    "provan.repository_analysis_cache_fragment.v1","provan.change_brief_export_manifest.v1",
    "provan.session10_implementation_binding.v1","provan.session10_real_use_evidence.v1",
    "provan.change_brief_manifest.v1","provan.change_brief_public_projection.v1",
    "provan.session10_runtime_invariant_evidence.v1","provan.session10_handoff_finalization.v1","provan.session10_generic_absence_receipt.v1","provan.session10_authentic_comparator.v1",
    "provan.session10_consequential_range_dogfood_ledger.v1","provan.session10_proof_manifest.v1","provan.session10_closeout.v1",
}


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()


def main()->int:
    rows=[]
    for path in sorted(SCHEMA_ROOT.glob("*.json")):
        value=json.loads(path.read_text(encoding="utf-8"));schema_id=value.get("$id")
        if schema_id in SESSION10_NAMES:
            rows.append({"schema_id":schema_id,"path":path.relative_to(ROOT).as_posix(),"sha256":digest(path.read_bytes()),"normalized_sha256":digest(canonical(value))})
    if {row["schema_id"] for row in rows}!=SESSION10_NAMES:raise SystemExit("SESSION10_SCHEMA_SET_INCOMPLETE")
    value={"schema_id":"provan.session10_schema_registry.v1","sensitivity":"PUBLIC_SAFE","entries":rows,"registry_digest":digest(canonical(rows))}
    OUTPUT.parent.mkdir(parents=True,exist_ok=True);OUTPUT.write_bytes(canonical(value));print(value["registry_digest"]);return 0
if __name__=="__main__":raise SystemExit(main())
