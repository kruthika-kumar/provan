"""Freeze the exact 4 x 11 Sessions 6--8 security surface."""
from __future__ import annotations
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OPERATIONS=("model","project_command","network_socket","http_browser","sql","warehouse_bi","tracing_service","external_eval","github_publish","deployment","out_of_root_write")
DOMAINS={
 "remediation_roadmaps":("shiproom.remediation_roadmaps.closure_verify","remediation-closure-evidence.v1"),
 "review_organisation":("shiproom.review_organisation.assert_submission_path","harness-execution-receipt.v1"),
 "contestability":("shiproom.contestability.validate_action_contract","contestation-action.v1"),
 "management_artifacts":("shiproom.management_artifacts.compiler.validate_recommendation_policy","release-recommendation-policy.v1"),
}
def main():
    records=[]
    for domain,(entry,contract) in DOMAINS.items():
        for operation in OPERATIONS:
            reachable=operation=="out_of_root_write" and domain in {"remediation_roadmaps","review_organisation"}
            records.append({"domain":domain,"operation":operation,"classification":"reachable_guarded" if reachable else "unreachable_by_design","production_entrypoint":entry,"production_gate":entry,"closed_contract":contract,"adapter_or_side_effect_surface":operation,"proof_ids":["proof_shared_zero_prohibited_operations_valid","proof_shared_zero_prohibited_operations_near_valid","proof_shared_zero_prohibited_operations_adversarial_invalid"]})
    encoded=json.dumps(records,sort_keys=True,separators=(",",":")).encode();value={"schema_version":"session6-8-security-surface-registry.v2","row_count":44,"approved_semantic_hash":"sha256:"+hashlib.sha256(encoded).hexdigest(),"records":records}
    path=ROOT/"docs/validation/session6-8-security-surface-registry.json";path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
