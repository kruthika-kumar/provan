"""Discover and freeze the complete Sessions 6--8 contract inventory."""
from __future__ import annotations

import json
from pathlib import Path


ROOT=Path(__file__).resolve().parents[1]
INVENTORY=ROOT/"docs/validation/session6-8-contract-inventory.json"
REGISTRY=ROOT/"docs/validation/session6-8-contract-registry.json"

CANONICAL={
 "remediation_source_packet":("remediation-source-packet.v1","S6_PLANNER_COMPILER_AUTHORITY"),
 "remediation_work_orders":("remediation-work-orders.v1","S6_OPTIONAL_PLANNER_LIFECYCLE"),
 "remediation_active_pointer":("active-remediation-preparation.v1","SHARED_POINTER_LATE_FAILURE"),
 "remediation_current_pointer":("current-remediation-generation.v1","SHARED_POINTER_LATE_FAILURE"),
 "remediation_generation_manifest":("remediation-generation-manifest.v1","S6_PACKET_FILE_INTEGRITY"),
 "remediation_index":("remediation-index.v1","S6_REMEDIATION_CARDINALITY"),
 "remediation_plan":("remediation-plan.v1","S6_REMEDIATION_CARDINALITY"),
 "remediation_overlay":("remediation-overlay.v1","S6_REMEDIATION_CARDINALITY"),
 "remediation_packet":("remediation-packet.v1","S6_REMEDIATION_CARDINALITY"),
 "remediation_closure_contract":("remediation-closure-contract.v1","S6_CLOSURE_CONTRACT_COMPLETENESS"),
 "review_current_pointer":("current-review-plan.v1","S7_POINTER_LAST_PUBLICATION"),
 "review_generation_manifest":("review-plan-generation-manifest.v1","S7_POINTER_LAST_PUBLICATION"),
 "review_plan_events":("plan-events.v1","S7_TRIGGER_SPECIFIC_EVIDENCE"),
 "review_revision_ledger":("revision-ledger.v1","S7_REVISION_REQUEST"),
 "review_accepted_results":("accepted-specialist-results.v1","S7_CORRECTED_RESULT_ACCEPTANCE"),
 "review_execution_summary_initial":("execution-summary.v1:initial","S7_PYTHON_SELECTION"),
 "review_execution_summary_adapted":("execution-summary.v1:adapted","S7_MIGRATION_ADAPTATION"),
 "review_specialist_work_order":("specialist-work-order.v1","S7_NATIVE_WORK_ORDER_INTEGRITY"),
 "review_submission_validation":("specialist-submission-validation.v1","S7_CORRECTED_RESULT_ACCEPTANCE"),
 "contestation_current_pointer":("current-contestation-generation.v1","S8_CONTEST_APPEND_SEQUENCE"),
 "contestation_generation_manifest":("contestation-generation-manifest.v1","S8_CONTEST_PREVIOUS_HASH"),
 "contestation_ledger":("contestation-ledger.v1","S8_CONTEST_PREVIOUS_HASH"),
 "contestation_effects":("contestation-effects.v1","S8_OWNER_DECISION_BUDGET"),
 "management_current_pointer":("current-management-generation.v1","SHARED_POINTER_LATE_FAILURE"),
 "management_executive_release_brief":("executive-release-brief.v1","S8_EXECUTIVE_SECTION_COMPLETENESS"),
 "management_product_release_review":("product-release-review.v1","S8_PRODUCT_MATRIX_COMPLETENESS"),
 "management_engineering_release_assessment":("engineering-release-assessment.v1","S8_ENGINEERING_SECTION_COMPLETENESS"),
 "management_measurement_ai_readiness":("measurement-ai-readiness-report.v1","S8_MEASUREMENT_AI_PASSTHROUGH"),
 "management_remediation_overview":("remediation-overview.v1","S8_REMEDIATION_OVERVIEW_COMPLETENESS"),
 "management_release_packet_index":("release-packet-index.v1","S8_ARTIFACT_FILE_SET"),
 "management_release_recommendation_view":("release-recommendation-view.v1","S8_RECOMMENDATION_POLICY"),
 "management_github_payload":("github-summary-payload.v1","S8_SAFE_MARKDOWN"),
}

PRESENTATION={
 "management_html_reports":"management-generation/*.html",
 "management_github_markdown":"management-generation/github-summary.md",
}

LEGACY_REQUIREMENT_MAP={
 "S6_AUTHORITY_POLICY":"S6_ISSUE_AUTHORITY_POLICY","S6_CLOSURE_INBOX":"S6_CLOSURE_EXACT_RERUN",
 "S6_EXACT_CLOSURE_RERUN":"S6_CLOSURE_EXACT_RERUN","S6_OPTIONAL_PLANNER":"S6_OPTIONAL_PLANNER_LIFECYCLE",
 "S6_VERIFIER_INDEPENDENCE":"S6_CLOSURE_VERIFIER_INDEPENDENCE","S7_ADAPTATION":"S7_MIGRATION_ADAPTATION",
 "S7_HARNESS_HONESTY":"S7_HARNESS_DECLARATION_HONESTY","S7_NATIVE_BOUNDARIES":"S7_NATIVE_BOUNDARY_REUSE",
 "S7_PACKAGE_COMPLETENESS":"S7_CODEX_PACKAGE_COMPLETENESS","S7_REVISION_LIFECYCLE":"S7_CORRECTED_RESULT_ACCEPTANCE",
 "S7_TYPED_SELECTION":"S7_TYPED_SURFACE_POLICY","S7_WORK_ORDER_INTEGRITY":"S7_NATIVE_WORK_ORDER_INTEGRITY",
 "S8_CONTESTABILITY":"S8_CONTEST_TARGET_REGISTRY","S8_MANAGEMENT_VECTOR":"S8_MANAGEMENT_DEPENDENCY_STATES",
 "S8_SECTION_COMPLETENESS":"S8_EXECUTIVE_SECTION_COMPLETENESS","S8_TARGET_RESOLUTION":"S8_CONTEST_TARGET_REGISTRY",
}


def _dump(path:Path,value:object)->None:
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8")


def build()->tuple[dict,dict]:
 old_inventory=json.loads(INVENTORY.read_text(encoding="utf-8"))["contracts"]
 old_registry={row["contract_name"]:row for row in json.loads(REGISTRY.read_text(encoding="utf-8"))["contracts"]}
 package_rows=[]
 for row in old_inventory:
  if row["contract_id"] in CANONICAL or row["contract_id"] in PRESENTATION:continue
  enriched={**row,"discovery_sources":["packaged_json_resource","python_contract_identifier"]}
  package_rows.append(enriched)
 canonical_rows=[{"contract_id":cid,"path":path,"classification":"canonical_persisted","parity_required":True,"exclusion_reason":None,"discovery_sources":["python_contract_identifier","golden_workflow_output"]} for cid,(path,_) in CANONICAL.items()]
 presentation_rows=[{"contract_id":cid,"path":path,"classification":"presentation_only","parity_required":False,"exclusion_reason":"Deterministic presentation bytes are validated by management rendering and wheel lifecycles; they are not externally authored semantic contracts.","discovery_sources":["golden_workflow_output"]} for cid,path in PRESENTATION.items()]
 inventory={"schema_version":"shiproom.session6-8-contract-inventory.v2","contracts":sorted(package_rows+canonical_rows+presentation_rows,key=lambda row:row["contract_id"])}
 registry=[]
 for row in inventory["contracts"]:
  if not row["parity_required"]:continue
  cid=row["contract_id"]
  if cid in old_registry:
   prior=old_registry[cid]
   registry.append({**prior,"requirement_ids":[LEGACY_REQUIREMENT_MAP.get(item,item) for item in prior["requirement_ids"]]});continue
  requirement=CANONICAL[cid][1]
  registry.append({"contract_name":cid,"schema":CANONICAL[cid][0],"realistic_builder":"scripts.run_session6_8_contract_parity._baselines","production_validator_or_loader":"shiproom.session6_8_contract_validation.validate_canonical_contract","stateful_fixture_builder":"golden_workflow_generation_and_loader","structural_mutations":["top_level_extra"],"semantic_mutations":["contract_specific_binding_tamper"],"integration_test_ids":["test_replayable_contract_parity"],"requirement_ids":[requirement]})
 registry_value={"schema_version":"shiproom.session6-8-contract-registry.v2","contracts":sorted(registry,key=lambda row:row["contract_name"])}
 _dump(INVENTORY,inventory);_dump(REGISTRY,registry_value);return inventory,registry_value


if __name__=="__main__":
 inventory,registry=build();print(json.dumps({"discovered":len(inventory["contracts"]),"parity_required":len(registry["contracts"])}))
