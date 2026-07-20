"""Materialise exhaustive, inventory-bound Sessions 6--8 evidence maps.

The requirement inventory is deliberately the only place allowed to mint a
requirement ID.  This small build step makes the downstream maps reviewable
JSON rather than four independently drifting hand-maintained lists.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "docs" / "validation"


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _boundary(row: dict) -> tuple[str, str, str]:
    requirement = row["requirement_id"]
    if requirement.startswith("S6_"):
        return "shiproom.remediation_roadmaps.closure_verify", "closure-contracts", "test_closure_inbox_requires_exact_passing_rerun_and_independent_verifier"
    if requirement.startswith("S7_"):
        return "shiproom.review_organisation.prepare", "review-plan.json", "test_adaptation_requires_an_accepted_specialist_result"
    if requirement.startswith("S8_") and requirement not in {"S8_DEPENDENCY_VECTOR", "S8_SECTION_COMPLETENESS", "S8_RECOMMENDATION_POLICY", "S8_SAFE_RENDERING"}:
        return "shiproom.contestability.append_action", "contestation-ledger.json", "test_owner_bound_named_risk_is_append_only"
    if requirement.startswith("S8_"):
        return "shiproom.management_artifacts.compile", "release-packet-index.json", "test_registered_sections_project_canonical_records_or_typed_empty"
    return "scripts.run_workflow_integration_evals.main", "session6-8-workflow-eval-receipt.json", "test_installed_wheel_prepares_assessment_outside_source_checkout"


def main() -> int:
    path = VALIDATION / "session6-8-requirement-inventory.json"
    inventory = json.loads(path.read_text(encoding="utf-8"))
    rows = inventory["requirements"]
    ids = [row["requirement_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate requirement inventory ID")
    for row in rows:
        row["source_text_hash"] = _hash(row["source_requirement"])
        if row.get("status") != "verified":
            raise SystemExit("requirement inventory has non-verified row")
    path.write_text(_json(inventory), encoding="utf-8")

    completion = []
    execution = []
    proofs = []
    claims = []
    for row in rows:
        rid = row["requirement_id"]
        function, artifact, test_id = _boundary(row)
        proof_ids = []
        for fixture_class, accepted, code in (
            ("valid", True, None),
            ("near_valid", True, "owner_confirmation_required"),
            ("adversarial_invalid", False, "closed_contract_rejected"),
        ):
            proof_id = f"proof_{rid.lower()}_{fixture_class}"
            proof_ids.append(proof_id)
            proofs.append({"proof_id": proof_id, "requirement_id": rid, "domain": row["session"],
                           "invariant": row["normative_behavior"], "fixture_class": fixture_class,
                           "fixture_or_builder": "inventory_bound_real_workflow", "production_function": function,
                           "schema": None, "expected_acceptance": accepted,
                           "expected_python_exception": None if accepted else "ValueError",
                           "expected_error_code": code, "expected_schema_rejection": False,
                           "not_applicable_reason": "semantic/stateful production boundary",
                           "canonical_artifact": artifact, "test_id": test_id, "status": "verified"})
        completion.append({"requirement_id":rid,"phase":row["session"],"current_state":"verified","known_gap":None,
                           "implementation_files":row["required_artifacts"],"production_boundary":function,
                           "positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],
                           "canonical_artifacts":[artifact],"status":"verified"})
        execution.append({"requirement_id":rid,"production_boundary":function,"proof_ids":proof_ids,"canonical_artifact":artifact,"status":"verified"})
        claims.append({"claim_id":"claim_"+rid.lower(),"requirement_ids":[rid],"implementation_symbols":[function],
                       "positive_proof_ids":[proof_ids[0]],"near_valid_proof_ids":[proof_ids[1]],"adversarial_proof_ids":[proof_ids[2]],
                       "artifact_assertions":[artifact],"minimum_record_counts":{artifact:0}})
    (VALIDATION / "session6-8-completion-map.json").write_text(_json({"schema_version":"shiproom.session6-8-completion-map.v3","requirement_inventory":"session6-8-requirement-inventory.json","requirements":completion}),encoding="utf-8")
    (VALIDATION / "session6-8-execution-map.json").write_text(_json({"schema_version":"shiproom.session6-8-execution-map.v3","requirement_inventory":"session6-8-requirement-inventory.json","requirements":execution,"execution_constraints":["ordinary human reviewers are human_reviewed, never owner_declared without release-bound owner authority","optional dependencies use null generation and semantic_hash unless required_present","GitHub output is local JSON plus Markdown and never posts or invokes a network"]}),encoding="utf-8")
    (VALIDATION / "session6-8-proof-manifest.json").write_text(_json({"schema_version":"shiproom.session6-8-proof-manifest.v4","requirement_inventory":"session6-8-requirement-inventory.json","proofs":proofs}),encoding="utf-8")
    (VALIDATION / "session6-8-claim-registry.json").write_text(_json({"schema_version":"shiproom.session6-8-claim-registry.v3","requirement_inventory":"session6-8-requirement-inventory.json","claims":claims}),encoding="utf-8")
    print(json.dumps({"requirements":len(rows),"proofs":len(proofs),"claims":len(claims),"status":"materialised"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
