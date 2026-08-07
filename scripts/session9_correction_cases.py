from __future__ import annotations

import uuid
from typing import Any

from provan.canonical import canonical_bytes, sha256_bytes
from provan.validators import (
    CORRECTION_CLAIMS,
    validate_access_warning_audit_semantics,
    validate_correction_layer4_semantics,
    validate_doctor_semantics,
    validate_external_publication_state_semantics,
    validate_inspection_write_result_semantics,
    validate_mirror_attestation_semantics,
    validate_private_projection_semantics,
    validate_reviewer_receipt_semantics,
    validate_state_link_proof_semantics,
    validate_telemetry_status_semantics,
)


def _doctor(broken: bool = False) -> dict[str, Any]:
    identifiers=["python","installed_version","packaged_schemas","git_local_operation","provan_home","state_outputs","state_pending","state_output_probe","source_only_inspection","extension_registry_metadata","telemetry_enabled","telemetry_transport","qualified_execution_sandbox","network_policy"]
    optional={"telemetry_enabled","telemetry_transport","qualified_execution_sandbox","network_policy"}
    checks=[]
    for identifier in identifiers:
        status="NOT_CONFIGURED" if identifier in optional - {"network_policy"} else "NOT_APPLICABLE" if identifier=="network_policy" else "READY"
        if broken and identifier=="git_local_operation": status="BLOCKED"
        checks.append({"id":identifier,"status":status,"detail":"fixture","required":identifier not in optional})
    return {"schema_id":"provan.doctor_report.v1","product_version":"0.2.0","status":"READY_WITH_LIMITATIONS","checks":checks,"limitations":["qualified_execution_sandbox_not_configured"]}


def _review(count: int = 40, limitation: bool = False) -> dict[str, Any]:
    return {"schema_id":"provan.session9_correction_reviewer_receipt.v1","reviewer_mode":"read-only","reviewer_harness":"fixture","reviewer_model_or_runtime":"identity unavailable","reviewed_repository":"provan","reviewed_commit":"0"*40,"reviewed_tree":"1"*40,"reviewed_pre_review_proof_root":"sha256:"+"0"*64,"review_started_at":"2026-01-01T00:00:00Z","review_finished_at":"2026-01-01T00:01:00Z","scope":[],"findings":[],"verdict":"GO","open_p0_count":0,"open_p1_count":0,"open_p2_count":0,"claim_dispositions":[{"claim_id":f"G9-{i:02d}","result":"ACCEPTED"} for i in range(1,count+1)],"independence_limitations":["model identity not independently attestable"] if limitation else []}


def _projection(private: bool = False, drift: str = "EXACT_EXPECTED_HEAD") -> dict[str, Any]:
    aggregate={"validator":"PASS","all_and_only_authorized":True,"authorized_usable_count":7,"classification_totals":{"PRIVATE_EVAL_CASE":4,"PRIVATE_INCIDENT_REGRESSION":3},"typed_exclusion_count":7,"typed_exclusion_reason_totals":{"NOT_PRIVATE_USABLE_ASSET":6,"QUARANTINED_NON_EXECUTABLE_INCIDENT_EVIDENCE":1},"customer_content_validation":"PASS","community_runtime_dependency":"ABSENT","headline_claims_authorized":False,"session2_status":"CLOSED_PARTIAL"}
    if private: aggregate["private_case"]="C:/"+"hidden"
    return {"schema_id":"provan.private_repository_projection.v1","sensitivity":"PUBLIC_SAFE","repository_role":"EVALUATION","repository_name":"provan-"+"evals","visibility":"PRIVATE","commit":"0"*40,"tree":"1"*40,"branch":"main","clean":True,"drift_status":drift,"aggregate_results":aggregate}


def _crosswalk() -> dict[str, Any]:
    ids=[f"G9-{i:02d}" for i in range(1,41)]
    return {"invariants":[{"invariant":"forty claims","proof_family":"C9F","claim_ids":ids}],"claims":[{"claim_id":claim,"proof_families":["C9F"]} for claim in ids]}


def _registry() -> dict[str,Any]:
    digest="sha256:"+"0"*64
    return {"entries":[{"proof_id":f"session9.correction.C9F.{kind}","fixture_class":kind,"test_id":"test","production_function":"production","python_validator":"validator","schema_result":"PASS","python_result":"REJECT:LAYER4_CLAIM_SET_INCOMPLETE" if kind=="adversarial" else "PASS","artifact_locations":["fixture"],"artifact_hashes":[digest],"transcript_hash":digest} for kind in ("valid","near-valid","adversarial")]}


def _matrix(shared: bool = False) -> dict[str, Any]:
    rows=[]
    for index,wording in enumerate(CORRECTION_CLAIMS,1):
        family="C9F"
        rows.append({"Claim":f"G9-{index:02d} — {wording}","Implemented in":"fixture","Positive proof":f"session9.correction.{family}.valid","Near-valid proof":f"session9.correction.{family}.near-valid","Negative proof":f"session9.correction.{family}.adversarial","Python result":"PASS; REJECT:LAYER4_CLAIM_SET_INCOMPLETE","Schema result":"PASS","Artifact evidence":"sha256:"+"0"*64,"Reviewer result":"ACCEPTED","Status":"CLOSED"})
    return {"schema_id":"provan.layer4_claim_matrix_correction.v2","sensitivity":"PUBLIC_SAFE","claims":rows}


def contract_fixture(family: str, fixture_class: str) -> tuple[str,dict[str,Any]]:
    adversarial=fixture_class=="adversarial"
    if family=="C9A":
        rid=str(uuid.uuid5(uuid.NAMESPACE_URL,f"{family}-{fixture_class}")); path="../outside/receipt.json" if adversarial else f"outputs/repository-inspection-{rid}.json"
        return "inspection-write-result.v1.json",{"schema_id":"provan.inspection_write_result.v1","receipt_id":rid,"receipt_sha256":"sha256:"+"0"*64,"public_relative_path":path}
    if family=="C9B": return "doctor-report.v1.json",_doctor(adversarial)
    if family=="C9C": return "telemetry-status-policy.v1.json",{"schema_id":"provan.telemetry_status.v1","enabled":False,"transport":"NOT_CONFIGURED","identifier_policy":"per_envelope_pseudonymous_non_persistent","installation_identity_collected":adversarial,"cross_run_correlation":"UNSUPPORTED","timed_rotation":"NOT_APPLICABLE","recurring_installation_usage_measurement":"UNSUPPORTED"}
    if family=="C9D":
        value=_review(40,fixture_class=="near-valid")
        if adversarial: value["claim_dispositions"][-1]["claim_id"]="G9-39"
        return "reviewer-receipt-correction.v1.json",value
    if family=="C9E": return "private-repository-projection.v1.json",_projection(adversarial,"AUTHORIZED_ADDITIVE_CORRECTION_FROM_EXPECTED_HEAD" if fixture_class=="near-valid" else "EXACT_EXPECTED_HEAD")
    if family=="C9F":
        value=_matrix(fixture_class=="near-valid")
        if adversarial: value["claims"][-1]["Claim"]=value["claims"][-2]["Claim"]
        return "layer4-claim-matrix-correction.v2.json",value
    if family=="C9G": return "access-warning-audit.v1.json",{"schema_id":"provan.access_warning_audit.v1","sensitivity":"PUBLIC_SAFE","records":[{"classification":"REQUIRED_AUTHORITY" if adversarial else "OPTIONAL_NONAUTHORITATIVE","accessible":not adversarial,"description":"fixture"}],"unclassified_stderr_count":0}
    if family=="C9H": return "state-link-proof.v1.json",{"schema_id":"provan.state_link_proof.v1","child":"pending" if fixture_class=="near-valid" else "outputs","link_rejected":not adversarial,"error":"PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN" if not adversarial else "NONE","outside_before_sha256":"sha256:"+"0"*64,"outside_after_sha256":"sha256:"+"0"*64}
    if family=="C9I" and fixture_class=="near-valid": return "external-mirror-attestation.v1.json",{"schema_id":"provan.external_mirror_attestation.v1","status":"FAILED","canonical_file_sha256":"sha256:"+"0"*64,"retention_limitation":"bounded","typed_failure":"MIRROR_WORKFLOW_UNAVAILABLE"}
    state={"release_created":False,"package_published":False,"tag_created":False}; digest="sha256:"+"0"*64 if adversarial else sha256_bytes(canonical_bytes(state))
    return "external-publication-receipt.v1.json",{"schema_id":"provan.external_publication_receipt.v1","publication_state":state,"publication_state_sha256":digest,"collected_at":"2026-01-01T00:00:00Z","limitations":[]}


def evaluate_fixture(family: str, fixture_class: str) -> None:
    adversarial=fixture_class=="adversarial"
    _, value=contract_fixture(family,fixture_class)
    if family=="C9A":
        validate_inspection_write_result_semantics(value); return
    if family=="C9B": validate_doctor_semantics(value); return
    if family=="C9C": validate_telemetry_status_semantics(value); return
    if family=="C9D": validate_reviewer_receipt_semantics(value); return
    if family=="C9E": validate_private_projection_semantics(value); return
    if family=="C9F":
        validate_correction_layer4_semantics(value,_crosswalk(),[_registry()],{f"G9-{i:02d}":["C9F"] for i in range(1,41)}); return
    if family=="C9G":
        validate_access_warning_audit_semantics(value); return
    if family=="C9H":
        validate_state_link_proof_semantics(value); return
    if family=="C9I":
        if fixture_class=="near-valid":
            validate_mirror_attestation_semantics(value); return
        validate_external_publication_state_semantics(value); return
    raise AssertionError(family)
