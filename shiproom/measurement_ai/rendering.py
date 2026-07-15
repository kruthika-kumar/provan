from __future__ import annotations

from shiproom.authority import LocalExecutionContext

from .persistence import load_generation


def show(ctx:LocalExecutionContext,journey_id:str|None=None)->str:
    manifest,artifacts=load_generation(ctx); readiness=artifacts["measurement-ai-readiness.json"]; contracts=artifacts["measurement-contract.json"]["contracts"]
    lines=[f"Measurement & AI Readiness: {manifest['generation']}",f"Preparation: {manifest['preparation_id']}",f"Skip reason: {readiness['skip_reason'] or 'none'}"]
    for contract in contracts:
        if journey_id and contract["journey_id"]!=journey_id: continue
        lines.append(f"Journey: {contract['journey_id']} — {contract['journey_text']}")
        for name in ("decision_question","decision_use_case","intended_outcome","eligible_population","observation_window","success_condition","failure_condition"):
            field=contract["fields"][name]; lines.append(f"  {name}: {field['value'] if field['value'] is not None else 'unresolved'} [{field['field_state']}]")
    for check in readiness["checks"]:
        lines.append(f"{check['check_id']}: {check['status']} authority={check['check_authority']} semantic={check['semantic_review_authority']} scope={','.join(check['readiness_scope'])}")
        if check["reason_codes"]: lines.append("  reasons: "+", ".join(check["reason_codes"]))
    return "\n".join(lines)
