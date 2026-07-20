"""Freeze the production-facing Sessions 6--8 security surface."""
from __future__ import annotations
import json
from pathlib import Path
from shiproom.workflow_trust import PROHIBITED_PRIVATE_ALPHA_OPERATIONS

ROOT=Path(__file__).resolve().parents[1]
DOMAINS={"review_organisation":"shiproom.review_organisation.guard_prohibited_operation","remediation":"shiproom.remediation_roadmaps.guard_prohibited_operation","contestation":"shiproom.contestability.guard_prohibited_operation","management":"shiproom.management_artifacts.compiler.guard_prohibited_operation"}

def main():
    records=[]
    for domain,gate in DOMAINS.items():
        for operation in sorted(PROHIBITED_PRIVATE_ALPHA_OPERATIONS):
            records.append({"domain":domain,"operation":operation,"classification":"reachable_guarded","production_entrypoint":gate,"production_gate":gate,"closed_contract":"private-alpha-operation-policy.v1","adapter_or_side_effect_surface":operation,"proof_ids":["proof_shared_zero_external_operations_valid","proof_shared_zero_external_operations_near_valid","proof_shared_zero_external_operations_adversarial_invalid"]})
    path=ROOT/"docs/validation/session6-8-security-surface-registry.json"; path.write_text(json.dumps({"schema_version":"session6-8-security-surface-registry.v1","records":records},sort_keys=True,indent=2)+"\n")

if __name__=="__main__": main()
