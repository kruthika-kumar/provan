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
    return {"verdict":"GO","open_p0_count":0,"open_p1_count":0,"open_p2_count":0,"reviewed_pre_review_proof_root":"sha256:"+"0"*64,"claim_dispositions":[{"claim_id":f"G9-{i:02d}","result":"ACCEPTED"} for i in range(1,count+1)],"independence_limitations":["model identity not independently attestable"] if limitation else []}


def _projection(private: bool = False, drift: str = "EXACT_EXPECTED_HEAD") -> dict[str, Any]:
    aggregate={"usable_asset_count":7}
    if private: aggregate["private_case"]="C:/"+"hidden"
    return {"schema_id":"provan.private_repository_projection.v1","sensitivity":"PUBLIC_SAFE","repository_role":"EVALUATION","repository_name":"provan-"+"evals","visibility":"PRIVATE","commit":"0"*40,"tree":"1"*40,"branch":"main","clean":True,"drift_status":drift,"aggregate_results":aggregate}


def _crosswalk() -> dict[str, Any]:
    return {"claims":[{"claim_id":f"G9-{i:02d}","proof_families":["C9F"]} for i in range(1,41)]}


def _matrix(shared: bool = False) -> dict[str, Any]:
    rows=[]
    for index,wording in enumerate(CORRECTION_CLAIMS,1):
        family="C9F"
        rows.append({"Claim":f"G9-{index:02d} — {wording}","Implemented in":"fixture","Positive proof":f"session9.correction.{family}.valid","Near-valid proof":f"session9.correction.{family}.near-valid","Negative proof":f"session9.correction.{family}.adversarial","Python result":"PASS","Schema result":"PASS","Artifact evidence":"sha256-bound fixture","Reviewer result":"ACCEPTED","Status":"CLOSED"})
    return {"claims":rows,"shared":shared}


def evaluate_fixture(family: str, fixture_class: str) -> None:
    adversarial=fixture_class=="adversarial"
    if family=="C9A":
        rid=str(uuid.uuid4()); relative="C:/"+"Users/person/receipt.json" if adversarial else f"outputs/repository-inspection-{rid}.json"
        validate_inspection_write_result_semantics({"receipt_id":rid,"receipt_sha256":"sha256:"+"0"*64,"public_relative_path":relative}); return
    if family=="C9B": validate_doctor_semantics(_doctor(adversarial)); return
    if family=="C9C":
        value={"identifier_policy":"per_envelope_pseudonymous_non_persistent","installation_identity_collected":adversarial,"cross_run_correlation":"UNSUPPORTED","timed_rotation":"NOT_APPLICABLE","recurring_installation_usage_measurement":"UNSUPPORTED"}
        validate_telemetry_status_semantics(value); return
    if family=="C9D": validate_reviewer_receipt_semantics(_review(39 if adversarial else 40,fixture_class=="near-valid")); return
    if family=="C9E": validate_private_projection_semantics(_projection(adversarial,"AUTHORISED_NEWER_LINEAGE" if fixture_class=="near-valid" else "EXACT_EXPECTED_HEAD")); return
    if family=="C9F":
        value=_matrix(fixture_class=="near-valid");
        if adversarial: value["claims"].pop()
        validate_correction_layer4_semantics(value,_crosswalk()); return
    if family=="C9G":
        classification="REQUIRED_AUTHORITY" if adversarial else "OPTIONAL_NONAUTHORITATIVE"
        validate_access_warning_audit_semantics({"records":[{"classification":classification,"accessible":not adversarial,"description":"fixture"}],"unclassified_stderr_count":0}); return
    if family=="C9H":
        validate_state_link_proof_semantics({"child":"pending" if fixture_class=="near-valid" else "outputs","link_rejected":not adversarial,"error":"PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN" if not adversarial else "NONE","outside_before_sha256":"sha256:"+"0"*64,"outside_after_sha256":"sha256:"+"0"*64}); return
    if family=="C9I":
        if fixture_class=="near-valid":
            validate_mirror_attestation_semantics({"status":"FAILED","canonical_file_sha256":"sha256:"+"0"*64,"retention_limitation":"bounded","typed_failure":"MIRROR_WORKFLOW_UNAVAILABLE"}); return
        state={"release_created":False,"package_published":False,"tag_created":False}
        digest="sha256:"+"0"*64 if adversarial else sha256_bytes(canonical_bytes(state))
        validate_external_publication_state_semantics({"publication_state":state,"publication_state_sha256":digest}); return
    raise AssertionError(family)
