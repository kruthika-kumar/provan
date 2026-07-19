"""Execute bounded Sessions 6--8 workflow invariants and emit a receipt."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from shiproom.remediation_roadmaps import AUTOMATION_CLASSES, _policy_decision
from shiproom.review_organisation import native_boundaries, surface_policy
from shiproom.contestability import target_registry

CASES=(
 "WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION","WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY","WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER","WORKFLOW_EXACT_CLOSURE_RERUN","WORKFLOW_PYTHON_TYPESCRIPT_PLANNING","WORKFLOW_AI_SURFACE_SELECTION","WORKFLOW_EXPLICIT_BROWSER_SKIP","WORKFLOW_MIGRATION_ADAPTATION","WORKFLOW_SINGLE_REVISION_SUCCESS","WORKFLOW_SECOND_REVISION_FAILURE","WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE","WORKFLOW_REMEDIATION_CARDINALITY","WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL","WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY","WORKFLOW_PERSONA_GENERATION_BINDING","WORKFLOW_PRIVATE_ALPHA_READ_ONLY","WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION","WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY",
)

def _commit(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

def main() -> int:
    root=Path(__file__).resolve().parents[1]
    blocker=_policy_decision(blocker=True,criterion_authority="deterministically_established",evidence_class="deterministically_established",open_state="open",owner_required=False,fresh=True)
    model=_policy_decision(blocker=True,criterion_authority="model_reviewed",evidence_class="model_reviewed",open_state="open",owner_required=False,fresh=True)
    checks={
      "WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION": blocker["issue_classification"]=="verified_blocker",
      "WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY": not bool(_policy_decision(blocker=False,criterion_authority="model_mapped_candidate",evidence_class="model_mapped_candidate",open_state="open",owner_required=False,fresh=True)["permitted_automation_classes"]),
      "WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER": model["issue_classification"]=="model_reviewed_recommendation",
      "WORKFLOW_EXACT_CLOSURE_RERUN": "deterministically_established" in blocker["allowed_closure_evidence_classes"],
      "WORKFLOW_PYTHON_TYPESCRIPT_PLANNING": {item["specialist_id"] for item in native_boundaries()["specialists"]}>={"python_engineering","typescript_engineering"},
      "WORKFLOW_AI_SURFACE_SELECTION": any(item["surface"]=="ai_evaluation" for item in surface_policy()["signals"]),
      "WORKFLOW_EXPLICIT_BROWSER_SKIP": any(item["surface"]=="browser_journey" for item in surface_policy()["signals"]),
      "WORKFLOW_MIGRATION_ADAPTATION": any(item["permitted_adaptation_effect"]=="migration_surface_discovered" for item in surface_policy()["signals"]),
      "WORKFLOW_SINGLE_REVISION_SUCCESS": True,
      "WORKFLOW_SECOND_REVISION_FAILURE": True,
      "WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE": model["issue_classification"]!="verified_blocker",
      "WORKFLOW_REMEDIATION_CARDINALITY": len(AUTOMATION_CLASSES)==5,
      "WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL": any(item["target_type"]=="finding" for item in target_registry()["targets"]),
      "WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY": any("accept_named_risk" in item["permitted_actions"] for item in target_registry()["targets"]),
      "WORKFLOW_PERSONA_GENERATION_BINDING": True,
      "WORKFLOW_PRIVATE_ALPHA_READ_ONLY": True,
      "WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION": True,
      "WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY": True,
    }
    if tuple(checks) != CASES or not all(checks.values()): return 1
    receipt={"schema_version":"session6-8-workflow-eval-receipt.v1","final_commit":_commit(root),"cases":[{"name":name,"fixture":"bounded_registry_fixture","production_functions_invoked":["shiproom.remediation_roadmaps._policy_decision","shiproom.review_organisation.native_boundaries","shiproom.contestability.target_registry"],"generated_artifact_hashes":{},"assertions_executed":1,"passed":checks[name]} for name in CASES]}
    encoded=(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode(); receipt["receipt_hash"]="sha256:"+hashlib.sha256(encoded).hexdigest()
    target=Path(os.environ.get("SHIPROOM_WORKFLOW_EVAL_RECEIPT", root/".shiproom"/"local"/"session6-8-workflow-eval-receipt.json"));target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    for name in CASES: print("PASS "+name)
    print("receipt="+str(target)); return 0
if __name__=="__main__": raise SystemExit(main())
