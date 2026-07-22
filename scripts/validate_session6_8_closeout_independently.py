"""Independently reconstruct Sessions 6--8 closure from bundle bytes only.

The validator deliberately uses only the Python standard library.  It neither
imports nor trusts the proof, workflow, parity, security, wheel, claim, or
closeout generators whose outputs it checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


class CloseoutValidationError(ValueError):
    pass


REQ_FIELDS=("requirement_id","normative_behavior","forbidden_substitutions","required_artifacts","minimum_cardinalities","near_valid_behavior","adversarial_behavior","adversarial_error_code","owning_production_entrypoint")
WORKFLOW_FIELDS=("preconditions","required_production_functions","assertions","required_artifacts","minimum_record_counts","forbidden_substitutions")


def _sha(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _canonical(value:Any)->bytes:return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()


def _safe(root:Path,relative:str)->Path:
    if not isinstance(relative,str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise CloseoutValidationError("closeout_bundle_path_invalid")
    candidate=(root/relative).resolve()
    try:candidate.relative_to(root.resolve())
    except ValueError as exc:raise CloseoutValidationError("closeout_bundle_path_invalid") from exc
    return candidate


def _load(path:Path)->dict:
    try:value=json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:raise CloseoutValidationError("closeout_json_invalid") from exc
    if not isinstance(value,dict):raise CloseoutValidationError("closeout_object_invalid")
    return value


def _load_any(path:Path)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:raise CloseoutValidationError("closeout_json_invalid") from exc


def _validate_production_rejection(bundle:Path,row:dict,registered:dict)->None:
    if row.get("fixture_class")!="adversarial_invalid":
        if row.get("rejection_invocation_id") is not None or row.get("outcome_evidence") is not None:raise CloseoutValidationError("closeout_proof_spurious_rejection")
        if row.get("fixture_class")=="near_valid":
            binding=row.get("fixture_binding")
            if not isinstance(binding,dict):raise CloseoutValidationError("closeout_proof_near_binding_missing")
            manifest=_load(_safe(bundle,binding.get("manifest_artifact")));base=_safe(bundle,manifest.get("base_artifact"));bounded=_safe(bundle,manifest.get("mutated_artifact"))
            if manifest.get("mutation_class")!="bounded_production_state" or _sha(base.read_bytes())!=manifest.get("base_hash") or _sha(bounded.read_bytes())!=manifest.get("mutated_hash") or manifest.get("base_semantic_hash")==manifest.get("mutated_semantic_hash"):raise CloseoutValidationError("closeout_proof_near_binding_invalid")
            baselines=[item for item in row.get("production_invocations",[]) if item.get("invocation_id")==manifest.get("baseline_invocation_id")]
            if len(baselines)!=1 or baselines[0].get("exception_type") is not None:raise CloseoutValidationError("closeout_proof_near_invocation_missing")
        return
    outcome=row.get("outcome_evidence");binding=row.get("fixture_binding")
    if outcome!=registered.get("outcome_evidence") or not isinstance(binding,dict):raise CloseoutValidationError("closeout_proof_rejection_binding_missing")
    matches=[item for item in row.get("production_invocations",[]) if item.get("invocation_id")==row.get("rejection_invocation_id") and item.get("subcase_id")==outcome.get("subcase_id") and item.get("qualified_function")==outcome.get("production_function")]
    if len(matches)!=1:raise CloseoutValidationError("closeout_proof_rejection_invocation_missing")
    invocation=matches[0]
    if outcome.get("channel")=="exception":
        if invocation.get("exception_type")!=outcome.get("expected_exception") or invocation.get("typed_status_or_error")!=outcome.get("expected_status_or_error"):raise CloseoutValidationError("closeout_proof_rejection_status_mismatch")
    elif outcome.get("channel")=="returned_status":
        if invocation.get("exception_type") is not None or invocation.get("typed_status_or_error")!=outcome.get("expected_status_or_error"):raise CloseoutValidationError("closeout_proof_rejection_status_mismatch")
    else:raise CloseoutValidationError("closeout_proof_rejection_channel_invalid")
    manifest_path=_safe(bundle,binding.get("manifest_artifact"));manifest=_load(manifest_path)
    if manifest.get("subcase_id")!=outcome.get("subcase_id"):raise CloseoutValidationError("closeout_proof_mutation_binding_mismatch")
    base=_safe(bundle,manifest.get("base_artifact"));mutated=_safe(bundle,manifest.get("mutated_artifact"))
    if not base.is_file() or not mutated.is_file() or _sha(base.read_bytes())!=manifest.get("base_hash") or _sha(mutated.read_bytes())!=manifest.get("mutated_hash") or manifest.get("base_hash")==manifest.get("mutated_hash"):raise CloseoutValidationError("closeout_proof_mutation_hash_invalid")
    if _sha(_canonical(_load_any(base)))!=manifest.get("base_semantic_hash") or _sha(_canonical(_load_any(mutated)))!=manifest.get("mutated_semantic_hash"):raise CloseoutValidationError("closeout_proof_mutation_semantics_invalid")
    if manifest.get("mutated_semantic_hash") not in set(invocation.get("input_component_hashes",[])):raise CloseoutValidationError("closeout_proof_mutation_invocation_unbound")
    baselines=[item for item in row.get("production_invocations",[]) if item.get("invocation_id")==manifest.get("baseline_invocation_id") and item.get("subcase_id")==outcome.get("subcase_id")+":baseline" and item.get("qualified_function")==outcome.get("production_function")]
    if len(baselines)!=1 or baselines[0].get("exception_type") is not None or manifest.get("base_semantic_hash") not in set(baselines[0].get("input_component_hashes",[])):raise CloseoutValidationError("closeout_proof_valid_baseline_missing")


def _pointer(value:Any,pointer:str)->Any:
    if pointer=="":return value
    if not isinstance(pointer,str) or not pointer.startswith("/"):raise CloseoutValidationError("closeout_selector_invalid")
    current=value
    for raw in pointer[1:].split("/"):
        token=raw.replace("~1","/").replace("~0","~")
        if isinstance(current,list):
            try:current=current[int(token)]
            except (ValueError,IndexError) as exc:raise CloseoutValidationError("closeout_selector_unresolved") from exc
        elif isinstance(current,dict) and token in current:current=current[token]
        else:raise CloseoutValidationError("closeout_selector_unresolved")
    return current


def _count(value:Any)->int:
    if value is None:return 0
    if isinstance(value,bool):return 1
    if isinstance(value,(list,dict)):return len(value)
    if isinstance(value,str):return 1
    if isinstance(value,int):return 1
    return 1


def _query(bundle:Path,query:dict)->tuple[bool,Any,int]:
    required={"artifact","selector","operator","expected"}
    if not isinstance(query,dict) or set(query)!=required:raise CloseoutValidationError("closeout_query_shape_invalid")
    path=_safe(bundle,query["artifact"])
    if not path.is_file() or path.is_symlink():raise CloseoutValidationError("closeout_proof_artifact_mismatch")
    op=query["operator"];expected=query["expected"]
    if op in {"text_contains","text_absent"}:
        actual=path.read_text(encoding="utf-8")
    else:actual=_pointer(_load_any(path),query["selector"])
    if op=="equals":passed=actual==expected
    elif op=="not_equals":passed=actual!=expected
    elif op=="count_equals":passed=_count(actual)==expected
    elif op=="count_at_least":passed=_count(actual)>=expected
    elif op=="set_equals":passed=isinstance(actual,list) and set(actual)==set(expected)
    elif op=="ordered_equals":passed=actual==expected
    elif op=="unique":passed=isinstance(actual,list) and len(actual)==len({_canonical(item) for item in actual})
    elif op=="text_contains":passed=isinstance(expected,str) and expected in actual
    elif op=="text_absent":passed=isinstance(expected,list) and all(item.lower() not in actual.lower() for item in expected)
    elif op in {"equals_reference","not_equals_reference","count_equals_reference","flattened_field_set_equals_reference"}:
        reference=_pointer(_load_any(_safe(bundle,expected["artifact"])),expected["selector"])
        if op=="equals_reference":passed=actual==reference
        elif op=="not_equals_reference":passed=actual!=reference
        elif op=="count_equals_reference":passed=_count(actual)==_count(reference)
        else:
            actual_field=expected["actual_field"];reference_field=expected["reference_field"]
            flattened={item for row in actual for item in row.get(actual_field,[])} if isinstance(actual,list) else set()
            expected_set={row.get(reference_field) for row in reference} if isinstance(reference,list) else set()
            passed=flattened==expected_set
    else:raise CloseoutValidationError("closeout_query_operator_invalid")
    return passed,actual,_count(actual)


def _semantic_hash(row:dict)->str:return _sha(_canonical({key:row[key] for key in REQ_FIELDS}))
def _workflow_hash(row:dict)->str:return _sha(_canonical({key:row[key] for key in WORKFLOW_FIELDS}))


def validate_bundle(bundle:Path,*,expected_commit:str,expected_receipt_hash:str)->dict:
    bundle=bundle.resolve();manifest=_load(bundle/"session6-8-evidence-bundle-manifest.json")
    if manifest.get("final_evidence_commit")!=expected_commit:raise CloseoutValidationError("closeout_final_commit_mismatch")
    body={**manifest,"manifest_hash":""}
    if manifest.get("manifest_hash")!=_sha(_canonical(body)):raise CloseoutValidationError("closeout_bundle_manifest_hash_mismatch")
    listed=set()
    for row in manifest.get("files",[]):
        relative=row.get("relative_path")
        if relative in listed:raise CloseoutValidationError("closeout_bundle_path_invalid")
        path=_safe(bundle,relative);listed.add(relative)
        if not path.is_file() or path.is_symlink() or _sha(path.read_bytes())!=row.get("sha256") or path.stat().st_size!=row.get("size_bytes") or row.get("final_evidence_commit")!=expected_commit:
            raise CloseoutValidationError("closeout_bundle_file_hash_mismatch")
    actual={path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}-{"session6-8-evidence-bundle-manifest.json"}
    if listed!=actual:raise CloseoutValidationError("closeout_bundle_file_set_mismatch")

    report_path=bundle/"session6-8-final-closeout-report.json";receipt_path=bundle/"session6-8-final-closeout-receipt.json"
    report=_load(report_path);receipt=_load(receipt_path)
    if _sha(receipt_path.read_bytes())!=expected_receipt_hash:raise CloseoutValidationError("closeout_detached_receipt_hash_mismatch")
    if receipt.get("report_hash")!=_sha(report_path.read_bytes()):raise CloseoutValidationError("closeout_report_hash_mismatch")
    if receipt.get("receipt_hash")!=_sha(_canonical({key:value for key,value in receipt.items() if key!="receipt_hash"})):raise CloseoutValidationError("closeout_receipt_hash_mismatch")
    if report.get("final_commit")!=expected_commit or receipt.get("final_commit")!=expected_commit:raise CloseoutValidationError("closeout_report_commit_mismatch")
    if report.get("report_self_hash")!=_sha(_canonical({**report,"report_self_hash":""})):raise CloseoutValidationError("closeout_report_self_hash_mismatch")

    inventory_path=bundle/"session6-8-requirement-inventory.json";inventory=_load(inventory_path);requirements=inventory.get("requirements",[])
    if inventory.get("expected_requirement_count")!=106 or len(requirements)!=106 or len({row.get("requirement_id") for row in requirements})!=106:raise CloseoutValidationError("closeout_requirement_cardinality_invalid")
    if any(row.get("approved_semantic_hash")!=_semantic_hash(row) for row in requirements):raise CloseoutValidationError("closeout_requirement_semantics_tampered")
    rids={row["requirement_id"] for row in requirements};requirements_by={row["requirement_id"]:row for row in requirements}
    completion={row.get("requirement_id") for row in _load(bundle/"session6-8-completion-map.json").get("requirements",[])}
    execution={row.get("requirement_id") for row in _load(bundle/"session6-8-execution-map.json").get("requirements",[])}
    proof_manifest=_load(bundle/"session6-8-proof-manifest.json").get("proofs",[]);proof_registry=_load(bundle/"session6-8-requirement-proof-registry.json").get("proofs",[])
    claims=_load(bundle/"session6-8-claim-registry.json").get("claims",[])
    if rids!=completion or rids!=execution or rids!={row.get("requirement_id") for row in proof_manifest} or {(rid,) for rid in rids}!={tuple(row.get("requirement_ids",[])) for row in claims} or len(claims)!=106:raise CloseoutValidationError("closeout_requirement_coverage_mismatch")
    if len(proof_manifest)!=318 or len(proof_registry)!=318 or len({row.get("proof_id") for row in proof_registry})!=318:raise CloseoutValidationError("closeout_proof_registry_cardinality_invalid")
    manifest_by={row["proof_id"]:row for row in proof_manifest};registry_by={row["proof_id"]:row for row in proof_registry}
    if set(manifest_by)!=set(registry_by):raise CloseoutValidationError("closeout_proof_registry_mismatch")
    for rid in rids:
        if {row.get("fixture_class") for row in proof_registry if row.get("requirement_id")==rid}!={"valid","near_valid","adversarial_invalid"}:raise CloseoutValidationError("closeout_proof_fixture_class_reuse")
    fingerprints=[]
    for row in proof_registry:
        raw={"workflow_case":row["workflow_case"],"production_functions":row["production_functions"],"queries":row["artifact_queries"],"expected_boundary_outcome":row["expected_boundary_outcome"]}
        fingerprint=_sha(_canonical(raw));fingerprints.append(fingerprint)
        if row.get("semantic_fingerprint")!=fingerprint:raise CloseoutValidationError("closeout_proof_fingerprint_tampered")
        if row.get("independent_requirement_assertion")!=requirements_by[row["requirement_id"]]["normative_behavior"]:raise CloseoutValidationError("closeout_proof_requirement_substitution")
    audit=_load(bundle/"session6-8-proof-fingerprint-audit.json")
    if len(set(fingerprints))!=318 or audit.get("unjustified_duplicate_count")!=0 or audit.get("unique_fingerprint_count")!=318:raise CloseoutValidationError("closeout_proof_fingerprint_duplicate")

    workflows=_load(bundle/"session6-8-workflow-contracts.json").get("cases",[])
    if len(workflows)!=18 or any(row.get("approved_semantic_hash")!=_workflow_hash(row) for row in workflows):raise CloseoutValidationError("closeout_workflow_semantics_tampered")
    junit=ET.parse(bundle/"final-session6-8-junit.xml").getroot()
    if any(child.tag in {"failure","error"} for case in junit.iter("testcase") for child in case):raise CloseoutValidationError("closeout_junit_not_clean")
    skipped={case.attrib.get("name","") for case in junit.iter("testcase") if any(child.tag=="skipped" for child in case)}
    authoritative_test_names={row["test_id"].rsplit("::",1)[-1] for row in proof_manifest}
    if any(any(name.endswith(test_name) for name in skipped) for test_name in authoritative_test_names):raise CloseoutValidationError("closeout_authoritative_proof_skipped")
    behavioral=_load(bundle/"behavioral-eval-receipt.json");workflow_receipt=_load(bundle/"session6-8-workflow-eval-receipt.json")
    if behavioral.get("final_commit")!=expected_commit or len(behavioral.get("cases",[]))!=35 or not all(row.get("passed") for row in behavioral["cases"]):raise CloseoutValidationError("closeout_behavioral_evidence_incomplete")
    if workflow_receipt.get("final_commit")!=expected_commit or len(workflow_receipt.get("cases",[]))!=18:raise CloseoutValidationError("closeout_workflow_evidence_incomplete")
    cases={row["name"]:row for row in workflow_receipt["cases"]}
    for contract in workflows:
        case=cases.get(contract["case_name"])
        if case is None:raise CloseoutValidationError("closeout_workflow_case_missing")
        observed={row.get("qualified_function") for row in case.get("production_invocations",[])}
        if not set(contract["required_production_functions"]).issubset(observed):raise CloseoutValidationError("closeout_workflow_invocation_missing")
        for assertion in contract["assertions"]:
            relative=assertion["artifact_path"].replace("\\","/")
            prefix=".shiproom/local/"
            if not relative.startswith(prefix):raise CloseoutValidationError("closeout_workflow_assertion_failed")
            query={"artifact":relative[len(prefix):],"selector":assertion["json_pointer"],"operator":assertion["comparator"],"expected":assertion["expected_value"]}
            if not _query(bundle,query)[0]:raise CloseoutValidationError("closeout_workflow_assertion_failed")

    proof_receipt=_load(bundle/"session6-8-proof-execution-receipt.json");proof_rows=proof_receipt.get("proofs",[])
    if proof_receipt.get("final_commit")!=expected_commit or len(proof_rows)!=318 or len({row.get("proof_id") for row in proof_rows})!=318:raise CloseoutValidationError("closeout_proof_execution_incomplete")
    expected_rejection_audit={"adversarial_proof_count":106,"matching_production_rejection_count":106,"selector_or_value_derived_error_count":0,"missing_controlled_mutation_count":0,"unjustified_valid_near_duplicate_count":0,"unjustified_valid_adversarial_duplicate_count":0,"unexpected_adversarial_acceptance_count":0}
    if proof_receipt.get("rejection_audit")!=expected_rejection_audit:raise CloseoutValidationError("closeout_proof_rejection_audit_invalid")
    measured_by={}
    for row in proof_rows:
        expected=manifest_by.get(row.get("proof_id"));registered=registry_by.get(row.get("proof_id"))
        if expected is None or registered is None or row.get("requirement_id")!=expected["requirement_id"] or row.get("fixture_class")!=expected["fixture_class"]:raise CloseoutValidationError("closeout_proof_binding_invalid")
        if row.get("actual_acceptance")!=expected["expected_acceptance"]:raise CloseoutValidationError("closeout_proof_outcome_invalid")
        if row.get("actual_exception")!=expected.get("expected_python_exception") or row.get("actual_error_code")!=expected.get("expected_error_code"):raise CloseoutValidationError("closeout_proof_rejection_mismatch")
        if row.get("semantic_fingerprint")!=registered.get("semantic_fingerprint"):raise CloseoutValidationError("closeout_proof_receipt_fingerprint_mismatch")
        ids=set(row.get("production_invocation_ids",[]));invocations=row.get("production_invocations",[])
        if not ids or ids!={item.get("invocation_id") for item in invocations}:raise CloseoutValidationError("closeout_proof_invocation_missing")
        if not set(registered["production_functions"]).issubset({item.get("qualified_function") for item in invocations}):raise CloseoutValidationError("closeout_proof_invocation_missing")
        _validate_production_rejection(bundle,row,registered)
        counts=[]
        for assertion in row.get("artifact_assertions",[]):
            passed,actual,count=_query(bundle,assertion["query"]);relative=assertion["query"]["artifact"]
            path=_safe(bundle,relative)
            if not passed or actual!=assertion.get("actual") or count!=assertion.get("cardinality") or row.get("artifact_hashes",{}).get(relative)!=_sha(path.read_bytes()):
                direct_error={"session6-8-contract-parity-report.json":"closeout_parity_incomplete","session6-8-security-receipt.json":"closeout_security_cardinality_invalid","session6-8-installed-wheel-receipt.json":"closeout_wheel_lifecycle_incomplete"}.get(relative)
                raise CloseoutValidationError(direct_error or "closeout_proof_artifact_mismatch")
            counts.append(count)
        if not counts or row.get("actual_record_count")!=max(counts):raise CloseoutValidationError("closeout_proof_configured_minimum_substitution")
        if row["expected_acceptance"] and row["actual_record_count"]<row.get("minimum_record_count",1):raise CloseoutValidationError("closeout_proof_cardinality_invalid")
        measured_by[row["proof_id"]]=row

    parity=_load(bundle/"session6-8-contract-parity-report.json")
    if parity.get("final_commit")!=expected_commit or len(parity.get("accepted_baselines",[]))!=parity.get("contract_count") or len(parity.get("mutation_receipts",[]))!=2*parity.get("contract_count",0):raise CloseoutValidationError("closeout_parity_incomplete")
    for row in parity["mutation_receipts"]:
        valid=bundle/"parity-fixtures"/Path(row["valid_fixture_path"]).name;mutated=bundle/"parity-fixtures"/Path(row["mutated_fixture_path"]).name
        if not valid.is_file() or _sha(valid.read_bytes())!=row["valid_fixture_hash"]:raise CloseoutValidationError("closeout_parity_baseline_invalid")
        if not mutated.is_file() or _sha(mutated.read_bytes())!=row["mutated_fixture_hash"]:raise CloseoutValidationError("closeout_parity_mutation_invalid")
        if row.get("actual_python_result")!="rejected" or row.get("unexpected_pass"):raise CloseoutValidationError("closeout_parity_unexpected_pass")
    security_registry=_load(bundle/"session6-8-security-surface-registry.json").get("records",[]);security=_load(bundle/"session6-8-security-receipt.json")
    if security.get("final_commit")!=expected_commit or len(security_registry)!=44 or len(security.get("records",[]))!=44:raise CloseoutValidationError("closeout_security_cardinality_invalid")
    for row in security["records"]:
        raw=bundle/"security-evidence"/Path(row["raw_evidence_path"]).name
        if not raw.is_file() or _sha(raw.read_bytes())!=row["raw_evidence_hash"]:raise CloseoutValidationError("closeout_security_raw_evidence_invalid")
        evidence=_load(raw)
        if evidence.get("adapter_spy",{}).get("calls")!=[] or evidence.get("before_state")!=evidence.get("after_state"):raise CloseoutValidationError("closeout_security_side_effect")
        state_hash=_sha(json.dumps(evidence.get("before_state"),sort_keys=True,default=str).encode())
        if row.get("before_hash")!=state_hash or row.get("after_hash")!=state_hash or row.get("underlying_adapter_called") or row.get("side_effect_observed"):raise CloseoutValidationError("closeout_security_side_effect")

    wheel=_load(bundle/"session6-8-installed-wheel-receipt.json")
    if wheel.get("final_commit")!=expected_commit or len(wheel.get("commands",[]))<20 or not wheel.get("source_checkout_not_on_sys_path"):raise CloseoutValidationError("closeout_wheel_lifecycle_incomplete")
    for index,row in enumerate(wheel["commands"]):
        for stream in ("stdout","stderr"):
            raw=bundle/"wheel-logs"/f"{index:02d}.{stream}.txt"
            if not raw.is_file() or _sha(raw.read_bytes())!=row[stream+"_hash"]:raise CloseoutValidationError("closeout_wheel_log_invalid")
        if row.get("exit_code")!=0:raise CloseoutValidationError("closeout_wheel_command_failed")
    for row in wheel.get("artifacts",[]):
        artifact=bundle/"canonical-artifacts/wheel"/row["relative_path"]
        if not artifact.is_file() or _sha(artifact.read_bytes())!=row["sha256"]:raise CloseoutValidationError("closeout_wheel_artifact_invalid")
    wheel_file=bundle/"final-session6-8.whl"
    if not wheel_file.is_file() or _sha(wheel_file.read_bytes())!=wheel.get("wheel_sha256"):raise CloseoutValidationError("closeout_bundled_wheel_invalid")
    if not (bundle/"independent-validator-entrypoint.py").is_file():raise CloseoutValidationError("closeout_validator_source_missing")

    tamper=_load(bundle/"session6-8-tamper-receipt.json");attacks=tamper.get("attacks",[])
    if tamper.get("final_commit")!=expected_commit or tamper.get("attack_count")!=31 or len(attacks)!=31 or len({row.get("attack_id") for row in attacks})!=31:raise CloseoutValidationError("closeout_tamper_evidence_incomplete")
    if any(not row.get("expected_error") or row.get("actual_error")!=row.get("expected_error") for row in attacks):raise CloseoutValidationError("closeout_tamper_rejection_mismatch")

    if len(claims)!=len({row.get("claim_id") for row in claims}):raise CloseoutValidationError("closeout_claim_duplicate")
    resolution=_load(bundle/"session6-8-claim-resolution-receipt.json")
    if resolution.get("final_commit")!=expected_commit or resolution.get("claim_count")!=106 or resolution.get("resolved_claim_count")!=106:raise CloseoutValidationError("closeout_claim_resolution_incomplete")
    resolved={row.get("requirement_id"):row for row in resolution.get("claims",[])}
    if set(resolved)!=rids or len(resolved)!=106:raise CloseoutValidationError("closeout_claim_resolution_binding_invalid")
    for claim in claims:
        rid=claim["requirement_ids"][0]
        if claim.get("approved_semantic_hash")!=requirements_by[rid]["approved_semantic_hash"]:raise CloseoutValidationError("closeout_claim_semantics_mismatch")
        expected_ids=set(claim["positive_proof_ids"]+claim["near_valid_proof_ids"]+claim["adversarial_proof_ids"]);actual=resolved[rid]
        if set(actual.get("proof_ids",[]))!=expected_ids:raise CloseoutValidationError("closeout_claim_proof_substitution")
        if {row.get("proof_id") for row in actual.get("measured_evidence",[])}!=expected_ids:raise CloseoutValidationError("closeout_claim_measured_evidence_incomplete")
        for proof_id in expected_ids:
            if proof_id not in measured_by:raise CloseoutValidationError("closeout_claim_proof_substitution")

    matrix=_load(bundle/"session6-8-requirement-evidence-matrix.json");matrix_rows=matrix.get("rows",[])
    if matrix.get("final_commit")!=expected_commit or matrix.get("requirement_count")!=106 or len(matrix_rows)!=106 or {row.get("requirement_id") for row in matrix_rows}!=rids:raise CloseoutValidationError("closeout_evidence_matrix_incomplete")
    if any(row.get("claim_status")!="resolved" or not row.get("production_invocations") for row in matrix_rows):raise CloseoutValidationError("closeout_evidence_matrix_invalid")

    inputs=report.get("inputs",{})
    input_files={"requirement_inventory_hash":"session6-8-requirement-inventory.json","completion_map_hash":"session6-8-completion-map.json","execution_map_hash":"session6-8-execution-map.json","proof_manifest_hash":"session6-8-proof-manifest.json","requirement_proof_registry_hash":"session6-8-requirement-proof-registry.json","proof_fingerprint_audit_hash":"session6-8-proof-fingerprint-audit.json","claim_registry_hash":"session6-8-claim-registry.json","contract_inventory_hash":"session6-8-contract-inventory.json","workflow_contracts_hash":"session6-8-workflow-contracts.json","security_surface_registry_hash":"session6-8-security-surface-registry.json","junit_hash":"final-session6-8-junit.xml","workflow_receipt_hash":"session6-8-workflow-eval-receipt.json","behavioral_receipt_hash":"behavioral-eval-receipt.json","security_receipt_hash":"session6-8-security-receipt.json","contract_parity_report_hash":"session6-8-contract-parity-report.json","wheel_receipt_hash":"session6-8-installed-wheel-receipt.json","proof_execution_receipt_hash":"session6-8-proof-execution-receipt.json","workflow_validation_hash":"session6-8-workflow-validation.json"}
    if any(inputs.get(key)!=_sha((bundle/name).read_bytes()) for key,name in input_files.items()):raise CloseoutValidationError("closeout_report_input_hash_mismatch")
    if report.get("claim_resolution_hash")!=_sha((bundle/"session6-8-claim-resolution-receipt.json").read_bytes()) or report.get("requirement_evidence_matrix_hash")!=_sha((bundle/"session6-8-requirement-evidence-matrix.json").read_bytes()):raise CloseoutValidationError("closeout_report_input_hash_mismatch")
    if report.get("resolved") is not True:raise CloseoutValidationError("closeout_report_not_resolved")
    return {"status":"verified","final_commit":expected_commit,"requirement_count":106,"claim_count":106,"proof_count":318,"workflow_count":18,"security_count":44,"parity_mutation_count":len(parity["mutation_receipts"]),"wheel_command_count":len(wheel["commands"]),"bundle_manifest_hash":manifest["manifest_hash"]}


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--expected-commit",required=True);parser.add_argument("--expected-receipt-hash",required=True);parser.add_argument("--require-installed-wheel",action="store_true");args=parser.parse_args()
    if args.require_installed_wheel:
        try:
            import shiproom
            Path(shiproom.__file__).resolve().relative_to(Path(sys.prefix).resolve())
        except Exception:print("closeout_external_wheel_origin_invalid");return 2
    try:result=validate_bundle(args.bundle,expected_commit=args.expected_commit,expected_receipt_hash=args.expected_receipt_hash)
    except CloseoutValidationError as exc:print(str(exc));return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=="__main__":raise SystemExit(main())
