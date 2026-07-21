"""Bind all 18 workflow assertions to concrete retained production artifacts."""
from __future__ import annotations
import json
from pathlib import Path
from shiproom.session6_8_semantics import workflow_semantic_hash

ROOT=Path(__file__).resolve().parents[1];PATH=ROOT/"docs/validation/session6-8-workflow-contracts.json"
def a(artifact,pointer,comparator,expected):return (artifact,pointer,comparator,expected)
C={
"WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION":[a("remediation-packet.json","/issue_authority","equals","deterministically_established"),a("remediation-packet.json","/verification_contract_id","not_equals",None),a("remediation-overlay.json","/nodes","count_equals",1)],
"WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY":[a("remediation-packet.json","/automation_eligibility","equals","roadmap_only"),a("remediation-packet.json","/automation_eligibility","not_equals","bounded_fix_available"),a("remediation-packet.json","/source_issue_id","equals","finding_workflow")],
"WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER":[a("remediation-packet.json","/issue_authority","equals","model_reviewed"),a("remediation-packet.json","/issue_classification","not_equals","verified_blocker"),a("remediation-packet.json","/allowed_closure_evidence_classes","count_equals",0)],
"WORKFLOW_EXACT_CLOSURE_RERUN":[a("closure-outcomes.json","/wrong_check/status","equals","unsatisfied"),a("closure-outcomes.json","/failed_rerun/status","equals","unsatisfied"),a("closure-outcomes.json","/self_verifier_rejected","equals",True),a("closure-outcomes.json","/stale_commit/status","equals","stale"),a("closure-outcomes.json","/valid/status","equals","satisfied_candidate"),a("source-finding.json","/state","equals","OPEN")],
"WORKFLOW_PYTHON_TYPESCRIPT_PLANNING":[a("python-review-plan.json","/input_vector/language_framework_signals/python","equals",True),a("python-review-plan.json","/plan_id","not_equals_reference",{"artifact":"typescript-review-plan.json","selector":"/plan_id"}),a("python-generation-manifest.json","/semantic_bundle_hash","not_equals_reference",{"artifact":"typescript-generation-manifest.json","selector":"/semantic_bundle_hash"}),a("python-review-plan.json","/input_vector/language_framework_signals","not_equals_reference",{"artifact":"typescript-review-plan.json","selector":"/input_vector/language_framework_signals"})],
"WORKFLOW_AI_SURFACE_SELECTION":[a("ai-specialist.json","/state","equals","selected")],
"WORKFLOW_EXPLICIT_BROWSER_SKIP":[a("browser-specialist.json","/state","equals","skipped"),a("browser-specialist.json","/applicability_authority","equals","explicitly_not_applicable")],
"WORKFLOW_MIGRATION_ADAPTATION":[a("before-manifest.json","/semantic_bundle_hash","not_equals_reference",{"artifact":"successor-manifest.json","selector":"/semantic_bundle_hash"}),a("plan-events.json","/migration/trigger","equals","migration_surface_discovered"),a("plan-events.json","/migration/replacement_work_order_ids","count_at_least",1),a("accepted-result.json","/status","equals","accepted"),a("before-execution-summary.json","","not_equals_reference",{"artifact":"after-execution-summary.json","selector":""})],
"WORKFLOW_SINGLE_REVISION_SUCCESS":[a("first-submission.json","/status","equals","revision_required"),a("revision-ledger.json","/entries","count_at_least",1),a("second-submission.json","/status","equals","accepted"),a("accepted-results.json","/results","count_at_least",1)],
"WORKFLOW_SECOND_REVISION_FAILURE":[a("revision-outcomes.json","/second_failed_closed","equals",True),a("revision-ledger.json","/entries","count_at_least",1),a("revision-outcomes.json","/third_rejected","equals",True),a("revision-outcomes.json","/failed_not_adaptable","equals",True),a("revision-outcomes.json","/plan_usable","equals",True)],
"WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE":[a("submission-outcome.json","/reason","equals","AUTHORITY_UPGRADE"),a("accepted-results.json","/results","count_equals",0)],
"WORKFLOW_REMEDIATION_CARDINALITY":[a("preparation.json","/actionable_issue_count","equals",3),a("remediation-plan.json","/packets","count_equals",3),a("closure-contracts.json","","count_equals",3),a("remediation-overlay.json","/nodes","count_equals",3),a("remediation-plan.json","/packets","unique",True)],
"WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL":[a("source-finding.json","/state","equals","OPEN"),a("contestation-ledger.json","/actions/0/submitted_evidence","not_equals",None)],
"WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY":[a("contestation-effects.json","/named_risk_effects","count_equals",4),a("source-findings.json","/0/state","equals","OPEN"),a("source-findings.json","/0/evidence_class","equals","deterministically_established"),a("source-findings.json","/0/blocker","equals",True)],
"WORKFLOW_PERSONA_GENERATION_BINDING":[a("artifacts/release-packet-index.json","/artifact_dependency_vector","equals_reference",{"artifact":"artifacts/executive-release-brief.json","selector":"/artifact_dependency_vector"}),a("rendered/executive-release-brief.html","","text_absent",["<script","<iframe","http://","https://"]),a("artifacts/github-summary-payload.json","/artifact_dependency_vector","equals_reference",{"artifact":"artifacts/executive-release-brief.json","selector":"/artifact_dependency_vector"}),a("artifacts/executive-release-brief.json","/section_records","count_at_least",1)],
"WORKFLOW_PRIVATE_ALPHA_READ_ONLY":[a("repository-state.json","/before_status","equals_reference",{"artifact":"repository-state.json","selector":"/after_status"}),a("repository-state.json","/source_unchanged","equals",True),a("remediation-manifest.json","/release_commit","not_equals",None),a("review-manifest.json","/generation","not_equals",None)],
"WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION":[a("historical-remediation-receipt.json","/allowlisted_files","set_equals",["route.txt"]),a("historical-remediation-receipt.json","/exact_rerun_passed","equals",True),a("historical-remediation-receipt.json","/merge_performed","equals",False),a("historical-remediation-receipt.json","/cleanup_completed","equals",True),a("historical-remediation-receipt.json","/source_repository_unchanged","equals",True)],
"WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY":[a("codex-execution-package.json","/schema_version","equals","codex-execution-package.v1"),a("manual-submission.json","/status","equals","accepted"),a("codex-submission.json","/status","equals","idempotent_replay"),a("manual-submission.json","/result_id","equals_reference",{"artifact":"codex-submission.json","selector":"/result_ids/0"}),a("accepted-results.json","/results","count_at_least",1),a("manual-receipt.json","/execution_receipt","not_equals_reference",{"artifact":"codex-receipt.json","selector":"/execution_receipt"})],
}
def main():
 value=json.loads(PATH.read_text(encoding="utf-8"))
 for contract in value["cases"]:
  specs=C[contract["case_name"]];ids=contract["required_assertion_ids"]
  if len(specs)!=len(ids):raise SystemExit("workflow_assertion_mapping_invalid:"+contract["case_name"])
  rows=[]
  for assertion_id,(artifact,pointer,operator,expected) in zip(ids,specs):
   if isinstance(expected,dict) and "artifact" in expected:expected={**expected,"artifact":"session6-8-workflow-evidence/"+contract["case_name"]+"/"+expected["artifact"]}
   rows.append({"assertion_id":assertion_id,"assertion_type":"artifact_query","artifact_path":".shiproom/local/session6-8-workflow-evidence/"+contract["case_name"]+"/"+artifact,"json_pointer":pointer,"comparator":operator,"expected_value":expected,"named_assertion_function":None})
  contract["assertions"]=rows;contract["approved_semantic_hash"]=workflow_semantic_hash(contract)
 PATH.write_text(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 print(json.dumps({"workflows":18,"assertions":sum(len(row["assertions"]) for row in value["cases"])}))
if __name__=="__main__":main()
