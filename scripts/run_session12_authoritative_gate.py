from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from uuid import uuid4

ROOT=Path(__file__).parents[1]
sys.path.insert(0,str(ROOT))
from provan.canonical import canonical_bytes,sha256_bytes
from provan.session12_validators import validate_validation_summary_serialized


def _linked_or_reparse(path: Path) -> bool:
    stat = path.lstat()
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)


def quarantine_local_test_outputs(repo: Path, transcripts: Path) -> tuple[int, bytes]:
    local = repo / ".shiproom" / "local"
    local.parent.mkdir(parents=True, exist_ok=True)
    if not local.exists():
        local.mkdir()
        return 0, b"LOCAL_TEST_BYPRODUCTS_QUARANTINED:0\n"
    if _linked_or_reparse(local) or local.resolve() != local.absolute():
        raise SystemExit("SESSION12_LOCAL_TEST_OUTPUT_PATH_UNSAFE")
    files = sum(1 for path in local.rglob("*") if path.is_file())
    if files:
        destination_root = transcripts / "local-byproducts"
        destination_root.mkdir(parents=True, exist_ok=True)
        destination = destination_root / ("authoritative-gate-" + uuid4().hex)
        if destination.exists():
            raise SystemExit("SESSION12_LOCAL_TEST_OUTPUT_DESTINATION_EXISTS")
        local.replace(destination)
        local.mkdir()
    return files, f"LOCAL_TEST_BYPRODUCTS_QUARANTINED:{files}\n".encode("ascii")


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument("--binding",type=Path,required=True);parser.add_argument("--wheel",type=Path,required=True);parser.add_argument("--transcript-root",type=Path,required=True);args=parser.parse_args();binding_raw=args.binding.read_bytes();binding=json.loads(binding_raw);wheel=args.wheel.resolve();transcripts=args.transcript_root.resolve();repo=ROOT.resolve()
    if transcripts==repo or repo in transcripts.parents or transcripts in repo.parents:raise SystemExit("SESSION12_GATE_TRANSCRIPT_SEPARATION_INVALID")
    if subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.strip()!=binding["implementation_commit"]:raise SystemExit("SESSION12_GATE_IMPLEMENTATION_COMMIT_MISMATCH")
    if subprocess.run(["git","show","-s","--format=%T","HEAD"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",check=True).stdout.strip()!=binding["implementation_tree"]:raise SystemExit("SESSION12_GATE_IMPLEMENTATION_TREE_MISMATCH")
    if sha256_bytes(wheel.read_bytes())!=binding["wheel_sha256"]:raise SystemExit("SESSION12_GATE_WHEEL_MISMATCH")
    transcripts.mkdir(parents=True,exist_ok=True)
    commands=[
        ("full_pytest",[sys.executable,"-m","pytest","-q"],["python","-m","pytest","-q"]),
        ("evals",[sys.executable,"scripts/run_evals.py"],["python","scripts/run_evals.py"]),
        ("workflow_integrations",[sys.executable,"scripts/run_workflow_integration_evals.py"],["python","scripts/run_workflow_integration_evals.py"]),
        ("session9_correction",[sys.executable,"scripts/validate_session9_correction.py","--implementation-only"],["python","scripts/validate_session9_correction.py","--implementation-only"]),
        ("session10_successor",[sys.executable,"scripts/validate_session10_successor.py"],["python","scripts/validate_session10_successor.py"]),
        ("session11_final",[sys.executable,"scripts/validate_session11.py","--phase","final","--successor"],["python","scripts/validate_session11.py","--phase","final","--successor"]),
        ("session12_implementation",[sys.executable,"scripts/validate_session12.py","--phase","implementation"],["python","scripts/validate_session12.py","--phase","implementation"]),
        ("session12_leakage",[sys.executable,"scripts/validate_session12_leakage.py"],["python","scripts/validate_session12_leakage.py"]),
        ("authoritative_wheel_fresh_install",[sys.executable,"scripts/fresh_install_gate.py","--wheel",str(wheel)],["python","scripts/fresh_install_gate.py","--wheel","dist/provan_assurance-0.5.0-py3-none-any.whl"]),
        ("diff_check",["git","diff","--check"],["git","diff","--check"]),
    ]
    checks=[]
    env=dict(os.environ);env.update({"PYTHONUTF8":"1","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_TERMINAL_PROMPT":"0","GIT_OPTIONAL_LOCKS":"0"})
    baseline_zip=transcripts/"baseline.zip";subprocess.run(["git","archive","--format=zip","-o",str(baseline_zip),"6c1006c7fe546805aaefd0bc2b47a40317c19c88"],cwd=ROOT,check=True,env=env);baseline_root=transcripts/"baseline-tree";baseline_root.mkdir(exist_ok=True)
    with zipfile.ZipFile(baseline_zip) as archive:archive.extractall(baseline_root)
    base_collect=subprocess.run([sys.executable,"-m","pytest","--collect-only","-q"],cwd=baseline_root,capture_output=True,env=env);current_collect=subprocess.run([sys.executable,"-m","pytest","--collect-only","-q"],cwd=ROOT,capture_output=True,env=env)
    base_nodes={line.strip() for line in base_collect.stdout.decode("utf-8","strict").splitlines() if "::" in line};current_nodes={line.strip() for line in current_collect.stdout.decode("utf-8","strict").splitlines() if "::" in line}
    collection_raw=current_collect.stdout+b"\n--- BASELINE COUNT ---\n"+str(len(base_nodes)).encode()+b"\n--- CURRENT COUNT ---\n"+str(len(current_nodes)).encode()+b"\n"
    (transcripts/"node_inventory.txt").write_bytes(collection_raw)
    if base_collect.returncode!=0 or current_collect.returncode!=0 or not base_nodes or not base_nodes.issubset(current_nodes):raise SystemExit("SESSION12_TEST_NODE_INVENTORY_REGRESSION")
    checks.append({"label":"test_node_inventory","command":["python","-m","pytest","--collect-only","-q"],"exit_code":0,"transcript_sha256":sha256_bytes(collection_raw)})
    for label,command,public_command in commands:
        if label == "session12_leakage":
            _, quarantine_raw = quarantine_local_test_outputs(repo, transcripts)
            (transcripts / "local_test_byproducts_quarantine.txt").write_bytes(quarantine_raw)
            checks.append({"label":"local_test_byproducts_quarantine","command":["internal","quarantine-local-test-byproducts"],"exit_code":0,"transcript_sha256":sha256_bytes(quarantine_raw)})
        result=subprocess.run(command,cwd=ROOT,capture_output=True,env=env);raw=result.stdout+b"\n--- STDERR ---\n"+result.stderr;(transcripts/(label+".txt")).write_bytes(raw)
        if result.returncode!=0:raise SystemExit("SESSION12_AUTHORITATIVE_GATE_FAILED:"+label)
        checks.append({"label":label,"command":public_command,"exit_code":0,"transcript_sha256":sha256_bytes(raw)})
    value={"schema_id":"provan.session12_validation_summary.v1","implementation_binding":binding,"authoritative_full_gate":"SUCCESS","target_mutation_detected":False,"execution_available":False,"challenge_available":False,"session13_implemented":False,"checks":checks};raw=canonical_bytes(value);validate_validation_summary_serialized(raw,binding_raw);target=ROOT/"artifacts/session12/proofs/validation_summary.v1.public.json";target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);print("SESSION12_AUTHORITATIVE_GATE_SUCCESS",sha256_bytes(raw));return 0


if __name__=="__main__":raise SystemExit(main())
