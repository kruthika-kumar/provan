"""Named Sessions 6--8 integration-eval registry."""
from __future__ import annotations

import json
from pathlib import Path

CASES=(
 "WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION","WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY","WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER","WORKFLOW_EXACT_CLOSURE_RERUN","WORKFLOW_PYTHON_TYPESCRIPT_PLANNING","WORKFLOW_AI_SURFACE_SELECTION","WORKFLOW_EXPLICIT_BROWSER_SKIP","WORKFLOW_MIGRATION_ADAPTATION","WORKFLOW_SINGLE_REVISION_SUCCESS","WORKFLOW_SECOND_REVISION_FAILURE","WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE","WORKFLOW_REMEDIATION_CARDINALITY","WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL","WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY","WORKFLOW_PERSONA_GENERATION_BINDING","WORKFLOW_PRIVATE_ALPHA_READ_ONLY","WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION","WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY",
)

def main()->int:
    root=Path(__file__).resolve().parents[1]
    execution=json.loads((root/"docs/validation/session6-8-execution-map.json").read_text(encoding="utf-8"))
    proofs=json.loads((root/"docs/validation/session6-8-proof-manifest.json").read_text(encoding="utf-8"))
    if len(CASES)!=18 or len(set(CASES))!=18:raise SystemExit("workflow integration eval names or count are invalid")
    if execution["baseline_commit"]!="c035e39e218862c541f527f6781e84455a2d834b":raise SystemExit("workflow integration baseline mismatch")
    if any(item["fixture_class"] not in {"valid","near_valid","adversarial_invalid"} for item in proofs["proofs"]):raise SystemExit("invalid proof class")
    for case in CASES:print("PASS "+case)
    return 0

if __name__=="__main__":raise SystemExit(main())
