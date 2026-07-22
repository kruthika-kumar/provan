"""Run isolated post-bundle tamper attacks against the independent validator."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
    from scripts.validate_session6_8_closeout_independently import CloseoutValidationError, validate_bundle
except ModuleNotFoundError:
    from validate_session6_8_closeout_independently import CloseoutValidationError, validate_bundle


def _sha(raw: bytes) -> str: return "sha256:"+hashlib.sha256(raw).hexdigest()
def _write(path: Path, value: dict) -> None: path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8")


def _refresh(root: Path) -> None:
    path=root/"session6-8-evidence-bundle-manifest.json";manifest=json.loads(path.read_text())
    for row in manifest["files"]:
        item=root/row["relative_path"];row["sha256"]=_sha(item.read_bytes());row["size_bytes"]=item.stat().st_size
    manifest["manifest_hash"]=""
    manifest["manifest_hash"]=_sha(json.dumps(manifest,sort_keys=True,separators=(",",":")).encode())
    _write(path,manifest)


ATTACKS=(
 ("modified_report","closeout_report_hash_mismatch"),("modified_receipt","closeout_receipt_hash_mismatch"),
 ("modified_manifest","closeout_bundle_manifest_hash_mismatch"),("unlisted_file","closeout_bundle_file_set_mismatch"),
 ("requirement_removed","closeout_requirement_cardinality_invalid"),("requirement_semantics","closeout_requirement_semantics_tampered"),
 ("completion_removed","closeout_requirement_coverage_mismatch"),("workflow_semantics","closeout_workflow_semantics_tampered"),
 ("junit_failure","closeout_junit_not_clean"),("authoritative_proof_skipped","closeout_authoritative_proof_skipped"),("behavioral_removed","closeout_behavioral_evidence_incomplete"),
 ("workflow_removed","closeout_workflow_evidence_incomplete"),("workflow_invocation_removed","closeout_workflow_invocation_missing"),
 ("workflow_assertion_changed","closeout_workflow_assertion_failed"),("proof_removed","closeout_proof_execution_incomplete"),
 ("proof_binding_changed","closeout_proof_binding_invalid"),("proof_outcome_changed","closeout_proof_outcome_invalid"),
 ("parity_mutations_removed","closeout_parity_incomplete"),("parity_fixture_changed","closeout_parity_mutation_invalid"),
 ("security_removed","closeout_security_cardinality_invalid"),("security_raw_changed","closeout_security_raw_evidence_invalid"),
 ("wheel_commands_removed","closeout_wheel_lifecycle_incomplete"),("claim_resolution_changed","closeout_claim_resolution_incomplete"),
 ("proof_registry_substitution","closeout_proof_fingerprint_tampered"),("proof_fixture_class_reuse","closeout_proof_fixture_class_reuse"),
 ("proof_invocation_removed","closeout_proof_invocation_missing"),("proof_selector_changed","closeout_selector_unresolved"),
 ("proof_rejection_invocation_removed","closeout_proof_rejection_invocation_missing"),("proof_rejection_status_changed","closeout_proof_rejection_status_mismatch"),
 ("proof_mutation_artifact_changed","closeout_proof_mutation_hash_invalid"),("proof_mutation_input_unbound","closeout_proof_mutation_invocation_unbound"),
 ("proof_configured_minimum","closeout_proof_configured_minimum_substitution"),("claim_duplicate","closeout_claim_duplicate"),
 ("claim_proof_substitution","closeout_claim_proof_substitution"),("evidence_matrix_removed","closeout_evidence_matrix_incomplete"),
)


def _mutate(root: Path, attack: str) -> str | None:
    receipt_hash=_sha((root/"session6-8-final-closeout-receipt.json").read_bytes())
    def value(name):return json.loads((root/name).read_text())
    if attack=="modified_report":
        row=value("session6-8-final-closeout-report.json");row["resolved"]=False;_write(root/"session6-8-final-closeout-report.json",row)
    elif attack=="modified_receipt":
        row=value("session6-8-final-closeout-receipt.json");row["receipt_hash"]="sha256:"+"0"*64;_write(root/"session6-8-final-closeout-receipt.json",row);receipt_hash=_sha((root/"session6-8-final-closeout-receipt.json").read_bytes())
    elif attack=="modified_manifest":
        row=value("session6-8-evidence-bundle-manifest.json");row["manifest_hash"]="sha256:"+"0"*64;_write(root/"session6-8-evidence-bundle-manifest.json",row);return receipt_hash
    elif attack=="unlisted_file":(root/"unlisted.json").write_text("{}")
    elif attack=="requirement_removed":row=value("session6-8-requirement-inventory.json");row["requirements"].pop();_write(root/"session6-8-requirement-inventory.json",row)
    elif attack=="requirement_semantics":row=value("session6-8-requirement-inventory.json");row["requirements"][0]["normative_behavior"]+=" weakened";_write(root/"session6-8-requirement-inventory.json",row)
    elif attack=="completion_removed":row=value("session6-8-completion-map.json");row["requirements"].pop();_write(root/"session6-8-completion-map.json",row)
    elif attack=="workflow_semantics":row=value("session6-8-workflow-contracts.json");row["cases"][0]["preconditions"].append("weakened");_write(root/"session6-8-workflow-contracts.json",row)
    elif attack=="junit_failure":(root/"final-session6-8-junit.xml").write_text('<testsuite><testcase name="x"><failure/></testcase></testsuite>')
    elif attack=="authoritative_proof_skipped":
        path=root/"final-session6-8-junit.xml";tree=ET.parse(path);case=next(item for item in tree.getroot().iter("testcase") if item.attrib.get("name","").startswith("test_requirement_proof["));ET.SubElement(case,"skipped");tree.write(path,encoding="utf-8",xml_declaration=True)
    elif attack=="behavioral_removed":row=value("behavioral-eval-receipt.json");row["cases"].pop();_write(root/"behavioral-eval-receipt.json",row)
    elif attack=="workflow_removed":row=value("session6-8-workflow-eval-receipt.json");row["cases"].pop();_write(root/"session6-8-workflow-eval-receipt.json",row)
    elif attack=="workflow_invocation_removed":row=value("session6-8-workflow-eval-receipt.json");row["cases"][0]["production_invocations"]=[];_write(root/"session6-8-workflow-eval-receipt.json",row)
    elif attack=="workflow_assertion_changed":row=value("session6-8-workflow-evidence/WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION/remediation-packet.json");row["issue_authority"]="not_inspected";_write(root/"session6-8-workflow-evidence/WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION/remediation-packet.json",row)
    elif attack=="proof_removed":row=value("session6-8-proof-execution-receipt.json");row["proofs"].pop();_write(root/"session6-8-proof-execution-receipt.json",row)
    elif attack=="proof_binding_changed":row=value("session6-8-proof-execution-receipt.json");row["proofs"][0]["requirement_id"]="wrong";_write(root/"session6-8-proof-execution-receipt.json",row)
    elif attack=="proof_outcome_changed":row=value("session6-8-proof-execution-receipt.json");row["proofs"][0]["actual_acceptance"]=False;_write(root/"session6-8-proof-execution-receipt.json",row)
    elif attack=="parity_mutations_removed":row=value("session6-8-contract-parity-report.json");row["mutation_receipts"]=[];_write(root/"session6-8-contract-parity-report.json",row)
    elif attack=="parity_fixture_changed":
        row=value("session6-8-contract-parity-report.json")["mutation_receipts"][0];path=root/"parity-fixtures"/Path(row["mutated_fixture_path"]).name;path.write_text("{}")
    elif attack=="security_removed":row=value("session6-8-security-receipt.json");row["records"].pop();_write(root/"session6-8-security-receipt.json",row)
    elif attack=="security_raw_changed":row=value("session6-8-security-receipt.json")["records"][0];path=root/"security-evidence"/Path(row["raw_evidence_path"]).name;path.write_text("{}")
    elif attack=="wheel_commands_removed":row=value("session6-8-installed-wheel-receipt.json");row["commands"]=[];_write(root/"session6-8-installed-wheel-receipt.json",row)
    elif attack=="claim_resolution_changed":row=value("session6-8-claim-resolution-receipt.json");row["resolved_claim_count"]=105;_write(root/"session6-8-claim-resolution-receipt.json",row)
    elif attack=="proof_registry_substitution":row=value("session6-8-requirement-proof-registry.json");row["proofs"][0]["artifact_queries"][0]["selector"]="/substituted";_write(root/"session6-8-requirement-proof-registry.json",row)
    elif attack=="proof_fixture_class_reuse":row=value("session6-8-requirement-proof-registry.json");row["proofs"][1]["fixture_class"]="valid";_write(root/"session6-8-requirement-proof-registry.json",row)
    elif attack=="proof_invocation_removed":row=value("session6-8-proof-execution-receipt.json");row["proofs"][0]["production_invocations"]=[];_write(root/"session6-8-proof-execution-receipt.json",row)
    elif attack in {"proof_rejection_invocation_removed","proof_rejection_status_changed","proof_mutation_input_unbound"}:
        receipt=value("session6-8-proof-execution-receipt.json");proof=next(item for item in receipt["proofs"] if item["fixture_class"]=="adversarial_invalid")
        invocation=next(item for item in proof["production_invocations"] if item["invocation_id"]==proof["rejection_invocation_id"])
        if attack=="proof_rejection_invocation_removed":proof["production_invocations"].remove(invocation)
        elif attack=="proof_rejection_status_changed":invocation["typed_status_or_error"]="valid_schema_version"
        else:invocation["input_component_hashes"]=[]
        _write(root/"session6-8-proof-execution-receipt.json",receipt)
    elif attack=="proof_mutation_artifact_changed":
        receipt=value("session6-8-proof-execution-receipt.json");proof=next(item for item in receipt["proofs"] if item["fixture_class"]=="adversarial_invalid");manifest=value(proof["fixture_binding"]["manifest_artifact"]);path=root/manifest["mutated_artifact"];path.write_text("{}\n",encoding="utf-8")
    elif attack=="proof_selector_changed":
        receipt=value("session6-8-proof-execution-receipt.json");proof=receipt["proofs"][0];proof["artifact_assertions"][0]["query"]["selector"]="/changed";_write(root/"session6-8-proof-execution-receipt.json",receipt)
    elif attack=="proof_configured_minimum":row=value("session6-8-proof-execution-receipt.json");row["proofs"][0]["actual_record_count"]=row["proofs"][0]["minimum_record_count"]+7;_write(root/"session6-8-proof-execution-receipt.json",row)
    elif attack=="claim_duplicate":row=value("session6-8-claim-registry.json");row["claims"][1]["claim_id"]=row["claims"][0]["claim_id"];_write(root/"session6-8-claim-registry.json",row)
    elif attack=="claim_proof_substitution":row=value("session6-8-claim-resolution-receipt.json");row["claims"][0]["proof_ids"][0]=row["claims"][1]["proof_ids"][0];_write(root/"session6-8-claim-resolution-receipt.json",row)
    elif attack=="evidence_matrix_removed":row=value("session6-8-requirement-evidence-matrix.json");row["rows"].pop();_write(root/"session6-8-requirement-evidence-matrix.json",row)
    _refresh(root);return receipt_hash


def run(bundle: Path, *, expected_commit: str) -> dict:
    source_manifest=json.loads((bundle/"session6-8-evidence-bundle-manifest.json").read_text(encoding="utf-8"))
    rows=[]
    for attack,expected in ATTACKS:
        with tempfile.TemporaryDirectory() as raw:
            target=Path(raw)/"bundle";shutil.copytree(bundle,target)
            receipt_hash=_mutate(target,attack)
            try:validate_bundle(target,expected_commit=expected_commit,expected_receipt_hash=receipt_hash,require_tamper_evidence=False);actual=None
            except CloseoutValidationError as exc:actual=str(exc)
            rows.append({"attack_id":attack,"expected_error":expected,"actual_error":actual,"passed":actual==expected})
    return {"schema_version":"session6-8-tamper-receipt.v1","final_commit":expected_commit,"source_bundle_manifest_hash":source_manifest["manifest_hash"],"attack_count":len(rows),"attacks":rows,"passed":all(row["passed"] for row in rows)}


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--expected-commit",required=True);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();result=run(args.bundle,expected_commit=args.expected_commit);_write(args.output,result);print(json.dumps({"attack_count":len(result["attacks"]),"passed":result["passed"]}));return 0 if result["passed"] else 2


if __name__=="__main__":raise SystemExit(main())
