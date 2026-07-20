"""Run isolated post-bundle tamper attacks against the independent validator."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
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
 ("junit_failure","closeout_junit_not_clean"),("behavioral_removed","closeout_behavioral_evidence_incomplete"),
 ("workflow_removed","closeout_workflow_evidence_incomplete"),("workflow_invocation_removed","closeout_workflow_invocation_missing"),
 ("workflow_assertion_changed","closeout_workflow_assertion_failed"),("proof_removed","closeout_proof_execution_incomplete"),
 ("proof_binding_changed","closeout_proof_binding_invalid"),("proof_outcome_changed","closeout_proof_outcome_invalid"),
 ("parity_mutations_removed","closeout_parity_incomplete"),("parity_fixture_changed","closeout_parity_mutation_invalid"),
 ("security_removed","closeout_security_cardinality_invalid"),("security_raw_changed","closeout_security_raw_evidence_invalid"),
 ("wheel_commands_removed","closeout_wheel_lifecycle_incomplete"),("claim_resolution_changed","closeout_claim_resolution_incomplete"),
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
    elif attack=="behavioral_removed":row=value("behavioral-eval-receipt.json");row["cases"].pop();_write(root/"behavioral-eval-receipt.json",row)
    elif attack=="workflow_removed":row=value("session6-8-workflow-eval-receipt.json");row["cases"].pop();_write(root/"session6-8-workflow-eval-receipt.json",row)
    elif attack=="workflow_invocation_removed":row=value("session6-8-workflow-eval-receipt.json");row["cases"][0]["production_invocations"]=[];_write(root/"session6-8-workflow-eval-receipt.json",row)
    elif attack=="workflow_assertion_changed":row=value("canonical-artifacts/workflow-evidence/WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION.json");row["assertions"]["deterministic_issue_authority"]=False;_write(root/"canonical-artifacts/workflow-evidence/WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION.json",row)
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
    _refresh(root);return receipt_hash


def run(bundle: Path, *, expected_commit: str) -> dict:
    rows=[]
    for attack,expected in ATTACKS:
        with tempfile.TemporaryDirectory() as raw:
            target=Path(raw)/"bundle";shutil.copytree(bundle,target)
            receipt_hash=_mutate(target,attack)
            try:validate_bundle(target,expected_commit=expected_commit,expected_receipt_hash=receipt_hash);actual=None
            except CloseoutValidationError as exc:actual=str(exc)
            rows.append({"attack_id":attack,"expected_error":expected,"actual_error":actual,"passed":actual==expected})
    return {"schema_version":"session6-8-tamper-receipt.v1","attack_count":len(rows),"attacks":rows,"passed":all(row["passed"] for row in rows)}


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--expected-commit",required=True);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();result=run(args.bundle,expected_commit=args.expected_commit);_write(args.output,result);print(json.dumps({"attack_count":len(result["attacks"]),"passed":result["passed"]}));return 0 if result["passed"] else 2


if __name__=="__main__":raise SystemExit(main())
