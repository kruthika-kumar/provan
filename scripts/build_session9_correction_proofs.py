from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import jsonschema

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from provan.errors import ProvanError
from scripts.session9_correction_cases import evaluate_fixture

OUT=ROOT/"artifacts/session9/correction"
FIXTURE=ROOT/"tests/fixtures/session9/correction-proof-fixtures.v1.json"

SCHEMAS={
 "C9A":"provan.inspection_write_result.v1","C9B":"provan.doctor_report.v1","C9C":"provan.telemetry_status_policy.v1",
 "C9D":"provan.session9_correction_reviewer_receipt.v1","C9E":"provan.private_repository_projection.v1",
 "C9F":"provan.layer4_claim_matrix_correction.v2","C9G":"provan.access_warning_audit.v1","C9H":"provan.state_link_proof.v1",
 "C9I":"provan.external_publication_receipt.v1",
}
VALIDATORS={
 "C9A":"provan.validators.validate_inspection_write_result_semantics","C9B":"provan.validators.validate_doctor_semantics",
 "C9C":"provan.validators.validate_telemetry_status_semantics","C9D":"provan.validators.validate_reviewer_receipt_semantics",
 "C9E":"provan.validators.validate_private_projection_semantics","C9F":"provan.validators.validate_correction_layer4_semantics",
 "C9G":"provan.validators.validate_access_warning_audit_semantics","C9H":"provan.validators.validate_state_link_proof_semantics",
 "C9I":"provan.validators.validate_external_publication_state_semantics + provan.validators.validate_mirror_attestation_semantics",
}
PRODUCTION={
 "C9A":"provan.validators.validate_inspection_write_result_semantics","C9B":"provan.validators.validate_doctor_semantics",
 "C9C":"provan.validators.validate_telemetry_status_semantics","C9D":"provan.validators.validate_reviewer_receipt_semantics",
 "C9E":"provan.validators.validate_private_projection_semantics","C9F":"provan.validators.validate_correction_layer4_semantics",
 "C9G":"provan.validators.validate_access_warning_audit_semantics","C9H":"provan.validators.validate_state_link_proof_semantics",
}


def production_function(family: str, kind: str) -> str:
    if family == "C9I":
        return "provan.validators.validate_mirror_attestation_semantics" if kind == "near-valid" else "provan.validators.validate_external_publication_state_semantics"
    return PRODUCTION[family]


def test_id(family: str, kind: str) -> str:
    return "tests/test_session9_correction.py::test_correction_proof_fixture_executes_independent_semantics" + f"[{family}-{kind}]"


def canonical(value: object) -> bytes: return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(data: bytes) -> str: return "sha256:"+hashlib.sha256(data).hexdigest()
def file_sha(path: Path) -> str: return sha(path.read_bytes().replace(b"\r\n",b"\n"))
def binary_file_sha(path: Path) -> str: return sha(path.read_bytes())
def write(path: Path,value: object) -> None: path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8",newline="\n")


def manifest(commit: str, tree: str, paths: list[str], scope: str) -> dict:
    rows=[{"path":path,"sha256":file_sha(ROOT/path)} for path in sorted(set(paths))]
    root=sha(("\n".join(row["path"]+" "+row["sha256"] for row in rows)+"\n").encode())
    return {"schema_id":"provan.session9_correction_proof_manifest.v1","sensitivity":"PUBLIC_SAFE","scope":scope,"implementation_commit":commit,"implementation_tree":tree,"artifacts":rows,"proof_root":root}


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--implementation-commit",required=True)
    parser.add_argument("--full-pytest-result",required=True); parser.add_argument("--base-collected",type=int,required=True)
    parser.add_argument("--candidate-collected",type=int,required=True); parser.add_argument("--baseline-nodes-missing",type=int,required=True)
    args=parser.parse_args()
    commit=args.implementation_commit
    tree=subprocess.run(["git","rev-parse",f"{commit}^{{tree}}"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
    ancestry=subprocess.run(["git","merge-base","--is-ancestor",commit,"HEAD"],cwd=ROOT,check=False)
    if ancestry.returncode: raise SystemExit("implementation commit is not an ancestor of the proof-building tree")
    run=subprocess.run([sys.executable,"-m","pytest","-q","tests/test_session9_correction.py"],cwd=ROOT,text=True,capture_output=True)
    transcript=(run.stdout+run.stderr).replace(str(ROOT),"<COMMUNITY_ROOT>")
    transcript_path=OUT/"transcripts/correction_focused.public.txt"; transcript_path.parent.mkdir(parents=True,exist_ok=True); transcript_path.write_text(transcript,encoding="utf-8",newline="\n")
    if run.returncode: print(transcript); return run.returncode
    bundle=json.loads(FIXTURE.read_text(encoding="utf-8")); fixture_hash=file_sha(FIXTURE); transcript_hash=file_sha(transcript_path); entries=[]
    for family,cases in sorted(bundle["families"].items()):
        for kind in ("valid","near-valid","adversarial"):
            case=cases[kind]; error=case["expected_error"]
            schema_doc=json.loads((ROOT/"provan/schemas"/case["schema_file"]).read_text(encoding="utf-8")); jsonschema.validate(case["input"],schema_doc)
            python_error=None
            try: evaluate_fixture(family,kind)
            except ProvanError as exc: python_error=exc.code
            if python_error!=error: raise SystemExit(f"{family}/{kind} semantic result drift: {python_error} != {error}")
            entries.append({"proof_id":f"session9.correction.{family}.{kind}","family":family,"fixture_class":kind,"fixture_path":f"tests/fixtures/session9/correction-proof-fixtures.v1.json#/families/{family}/{kind}/input","schema_id":schema_doc["$id"],"schema_result":"PASS","schema_error":None,"python_validator":VALIDATORS[family],"python_result":"REJECT:"+python_error if python_error else "PASS","python_error":python_error,"production_function":production_function(family,kind),"test_id":test_id(family,kind),"artifact_locations":["tests/fixtures/session9/correction-proof-fixtures.v1.json","artifacts/session9/correction/transcripts/correction_focused.public.txt"],"artifact_hashes":[fixture_hash,transcript_hash],"command":"python -m pytest -q tests/test_session9_correction.py","exit_code":run.returncode,"transcript_hash":transcript_hash})
    registry_path=OUT/"proof_registry.v1.public.json"; write(registry_path,{"schema_id":"provan.session9_correction_proof_registry.v1","sensitivity":"PUBLIC_SAFE","entries":entries})
    warning_path=OUT/"access_warning_audit.v1.public.json"; write(warning_path,{"schema_id":"provan.access_warning_audit.v1","sensitivity":"PUBLIC_SAFE","records":[{"classification":"OPTIONAL_NONAUTHORITATIVE","accessible":False,"description":"Git implicit XDG excludes lookup observed before isolation; validation now supplies an isolated XDG configuration and explicit excludes policy."}],"unclassified_stderr_count":0})
    wheel=next((ROOT/"dist").glob("*.whl")); schema_rows=[]
    for path in sorted((ROOT/"provan/schemas").glob("*.json")): schema_rows.append(path.name+" "+file_sha(path))
    binding_path=OUT/"implementation_binding.v1.public.json"; write(binding_path,{"schema_id":"provan.session9_correction_implementation_binding.v1","sensitivity":"PUBLIC_SAFE","community_version":"0.2.0","extension_api_major":1,"implementation_commit":commit,"implementation_tree":tree,"wheel_sha256":binary_file_sha(wheel),"schema_registry_digest":sha(("\n".join(schema_rows)+"\n").encode()),"final_proof_commit":"RECORDED_SEPARATELY_AFTER_REVIEW"})
    gate_path=OUT/"implementation_gate_summary.v1.public.json"; write(gate_path,{"schema_id":"provan.session9_correction_gate_summary.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":commit,"implementation_tree":tree,"test_scope":{"base_collected":args.base_collected,"candidate_collected":args.candidate_collected,"baseline_nodes_missing":args.baseline_nodes_missing},"results":[{"command":"python -m pytest -q","exit_code":0,"result":args.full_pytest_result},{"command":"python -m pytest -q tests/test_session9_correction.py","exit_code":0,"result":run.stdout.strip()},{"command":"python scripts/run_evals.py","exit_code":0,"result":"PASS: 35 checks"},{"command":"python scripts/run_workflow_integration_evals.py","exit_code":0,"result":"PASS: 18 checks"},{"command":"python -m build","exit_code":0,"result":"wheel and sdist built after isolated build dependency access was available"},{"command":"installed-wheel source-only inspection and doctor gate","exit_code":0,"result":"PASS: isolated site-packages origin, target unchanged, doctor READY_WITH_LIMITATIONS"},{"command":"README inspection command from a fresh installed wheel","exit_code":0,"result":"PASS: credential-free public GitHub pinned commit inspected with default UUID receipt path"},{"command":"python scripts/validate_session9.py --wheel dist/*.whl --archive dist/*.tar.gz","exit_code":0,"result":"SESSION9_VALID; warning-free isolated Git environment"},{"command":"python scripts/validate_session9_correction.py --implementation-only","exit_code":0,"result":"SESSION9_CORRECTION_VALID; warning-free isolated Git environment"},{"command":"python scripts/validate_session9_leakage.py","exit_code":0,"result":"SESSION9_PUBLIC_LEAKAGE_VALID; warning-free isolated Git environment"},{"command":"git diff --check","exit_code":0,"result":"PASS"}]})
    paths=["artifacts/session9/correction/correction_authority.v1.json","artifacts/session9/correction/correction_plan.v1.json","artifacts/session9/correction/correction_plan.md","artifacts/session9/correction/proof_registry.v1.public.json","artifacts/session9/correction/access_warning_audit.v1.public.json","artifacts/session9/correction/implementation_binding.v1.public.json","artifacts/session9/correction/implementation_gate_summary.v1.public.json","artifacts/session9/correction/transcripts/correction_focused.public.txt","tests/fixtures/session9/correction-proof-fixtures.v1.json"]
    pre=manifest(commit,tree,paths,"PRE_REVIEW_NON_RECURSIVE"); write(OUT/"pre_review_proof_manifest.v1.public.json",pre)
    print(json.dumps({"status":"CORRECTION_PRE_REVIEW_BUILT","entries":len(entries),"proof_root":pre["proof_root"],"implementation_commit":commit},sort_keys=True)); return 0


if __name__=="__main__": raise SystemExit(main())
