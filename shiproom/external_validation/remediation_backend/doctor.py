#!/usr/bin/env python3
"""Root-staged remediation doctor using the production lifecycle interface."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
_STAGED_MODULE_DIRECTORY = str(Path(__file__).resolve().parent)
if _STAGED_MODULE_DIRECTORY not in sys.path: sys.path.insert(0, _STAGED_MODULE_DIRECTORY)
try:
    from .bootstrap import require_staged_script
    from .control import Control, ControlError, canonical
    from .contracts import validate_release_authorization
    from .lifecycle import execute_patient_command, function_ids, git_artifacts, materialize_fixture, prepare_fixture_source, seal_and_finalize
    from .release_helper import require_openat2
except ImportError:
    from bootstrap import require_staged_script
    from control import Control, ControlError, canonical
    from contracts import validate_release_authorization
    from lifecycle import execute_patient_command, function_ids, git_artifacts, materialize_fixture, prepare_fixture_source, seal_and_finalize
    from release_helper import require_openat2

ROOT = Path("/var/lib/shiproom-remediation")
MOUNT = Path("/mnt/shiproom-remediation")
RUN = Path("/run/shiproom-remediation-docker")


def digest(value: object) -> str: return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
def sha(path: Path) -> str: return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def invocation(argv: list[str], *, timeout: int = 180, environment: dict[str, str] | None = None) -> dict[str, object]:
    try: result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc: return {"command": argv, "exit_code": None, "stdout": "", "stderr": str(exc), "error": type(exc).__name__}
    return {"command": argv, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def write_root_owned(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022: raise RuntimeError("doctor_supervisor_directory_untrusted")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try: os.fchown(fd, 0, 0); os.fchmod(fd, 0o400); os.write(fd, data); os.fsync(fd)
    finally: os.close(fd)


def allocated_tree(db: Path, attempt: str, allocation_result: dict[str, object]) -> Path:
    lines = str(allocation_result["stdout"]).strip().splitlines()
    if len(lines) != 1: raise RuntimeError("doctor_allocation_output_invalid")
    tree = Path(lines[0]); control = Control(db)
    try: authority = control.allocation(attempt)["worktree_authority_json"]
    finally: control.close()
    if tree != Path(str(authority["canonical_path"])) or not tree.is_dir(): raise RuntimeError("doctor_allocation_authority_mismatch")
    return tree


def _state_value(path: Path, key: str) -> str:
    import base64
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate, _, encoded = line.partition("\t")
        if candidate == key: return base64.b64decode(encoded).decode("utf-8")
    raise RuntimeError("doctor_backend_state_missing:" + key)


def _authorization(control: Control, attempt: str, source: dict[str, str], receipt_id: str, manifest_path: Path, artifacts: dict[str, Path]) -> Path:
    allocation = control.allocation(attempt); authority = allocation["worktree_authority_json"]
    records = [{"kind": name, "canonical_path": str(path), "sha256": sha(path)} for name, path in sorted(artifacts.items())]
    indexed = {row["kind"]: row["sha256"] for row in records}
    document = {"schema_id": "remediation_release_authorization.v1", "schema_version": "1", "authorization_id": "authorization_" + secrets.token_hex(16), "backend_instance_id": control.instance_id(), "attempt_id": attempt, "project_id": allocation["project_id"], "allocation_record_id": attempt, "capacity_reservation_id": str(allocation["project_id"]), "worktree_authority": authority, "source_snapshot_hash": source["source_snapshot_hash"], "sealed_artifact_manifest_hash": sha(manifest_path), "receipt_id": receipt_id, "patch_hash": indexed["patch.bin"], "changed_file_manifest_hash": indexed["changed-manifest.json"], "untracked_file_manifest_hash": indexed["untracked-manifest.bin"], "test_result_hashes": [value for key, value in indexed.items() if key.startswith("command-") and key.endswith(".json")], "log_hashes": [value for key, value in indexed.items() if key.startswith("command-") and key.endswith("stdout.bin")], "artifact_records": records, "supervisor_package_hash": sha(Path(__file__).with_name("lifecycle.py")), "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    validate_release_authorization(document)
    path = ROOT / "supervisor-owned" / "authorizations" / (document["authorization_id"] + ".json"); write_root_owned(path, canonical(document)); control.authorize_release(document, str(path)); return path


def real_git_remediation_fixture(db: Path, runner_image: str, shiproom_commit: str, tree_hash: str) -> dict[str, object]:
    if db.resolve() != (ROOT / "control.sqlite3").resolve() or not MOUNT.is_mount() or not RUN.is_dir(): return {"name": "real_git_remediation_fixture", "ok": False, "reason": "doctor_paths_not_qualified"}
    allocation_script = Path(__file__).with_name("quota-worktree.sh"); require_staged_script(allocation_script)
    qualification_run = "qualification_" + secrets.token_hex(16); attempt = "doctor-git-" + secrets.token_hex(8)
    source_root = ROOT / "supervisor-owned" / "doctor-sources" / qualification_run
    try:
        control = Control(db)
        try: control.start_qualification(qualification_run, shiproom_commit, tree_hash.removeprefix("sha256:"))
        finally: control.close()
        source = prepare_fixture_source(source_root)
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SHIPROOM_QUALIFICATION_RUN_ID": qualification_run}
        allocate = invocation([str(allocation_script), "allocate", attempt, str(32 * 1024 * 1024), "2048", source["source_snapshot_hash"]], environment=environment)
        if allocate["exit_code"] != 0:
            raise RuntimeError("doctor_production_allocation_failed:" + str(allocate["stderr"]))
        tree = allocated_tree(db, attempt, allocate); materialize_fixture(source_root=source_root, worktree=tree, source=source)
        # The host materializer creates Git metadata as root; the untrusted
        # patient gets ownership only of its dedicated, quota-controlled tree.
        for candidate in [tree, *tree.rglob("*")]: os.chown(candidate, 65533, 65533, follow_symlinks=False)
        docker, socket = _state_value(ROOT / "backend.state", "DOCKER_CLI"), Path(_state_value(ROOT / "backend.state", "RUN")) / "docker.sock"
        before_target, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, command=["python3", "target_test.py"], label="target_before")
        before_protected, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, command=["python3", "protected_test.py"], label="protected_before")
        repair, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, command=["python3", "-c", "p='calculator.py';s=open(p).read();open(p,'w').write(s.replace('return a - b','return a + b'))"], label="controlled_repair")
        after_target, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, command=["python3", "target_test.py"], label="target_after")
        after_protected, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, command=["python3", "protected_test.py"], label="protected_after")
        if before_target["exit_code"] == 0 or before_protected["exit_code"] != 0 or repair["exit_code"] != 0 or after_target["exit_code"] != 0 or after_protected["exit_code"] != 0: raise RuntimeError("doctor_real_checks_invalid")
        artifacts, git_evidence = git_artifacts(source_root=source_root, worktree=tree, artifact_root=ROOT / "supervisor-owned" / "doctor-artifacts" / attempt)
        receipt_id, receipt_path, manifest_path, receipt = seal_and_finalize(attempt=attempt, source=source, artifacts=artifacts, command_results=[before_target, before_protected, repair, after_target, after_protected], receipt_root=ROOT / "supervisor-owned", journal_root=ROOT / "supervisor-owned" / "journals", runner_image_digest=runner_image, container=container, shiproom_commit=shiproom_commit, package_tree_hash=tree_hash)
        control = Control(db)
        try: authorization = _authorization(control, attempt, source, receipt_id, manifest_path, artifacts)
        finally: control.close()
        released = invocation([str(allocation_script), "release", attempt, str(authorization)], timeout=180)
        control = Control(db)
        try: allocation = control.allocation(attempt); status = control.effective_status()
        finally: control.close()
        ok = released["exit_code"] == 0 and allocation["terminal_status"] == "RELEASED_RETIRED" and status["effective_state"] == "READY" and subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip() == source["commit"]
        control = Control(db)
        try: control.finish_qualification(qualification_run, ok)
        finally: control.close()
        return {"name": "real_git_remediation_fixture", "ok": ok, "qualification_run_id": qualification_run, "attempt_id": attempt, "source": source, "git_evidence": git_evidence, "receipt_id": receipt_id, "receipt_hash": sha(receipt_path), "authorization_hash": sha(authorization), "release": released, "postcondition": {"terminal_status": allocation["terminal_status"], "effective_state": status["effective_state"], "tree_absent": not tree.exists()}, "function_ids": function_ids()}
    except Exception as exc:
        try:
            control = Control(db); control.finish_qualification(qualification_run, False); control.close()
        except Exception:
            pass
        return {"name": "real_git_remediation_fixture", "ok": False, "attempt_id": attempt, "qualification_run_id": qualification_run, "error": type(exc).__name__ + ":" + str(exc), "function_ids": function_ids()}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--db", type=Path, required=True); parser.add_argument("--out", type=Path, required=True); parser.add_argument("--profile", choices=("detection", "remediation", "all"), default="all"); parser.add_argument("--run-remediation-fixture", action="store_true"); parser.add_argument("--runner-image", default=os.environ.get("SHIPROOM_REMEDIATION_RUNNER_IMAGE")); parser.add_argument("--shiproom-commit", default=os.environ.get("SHIPROOM_REMEDIATION_COMMIT", "")); parser.add_argument("--package-tree-hash", default=os.environ.get("SHIPROOM_REMEDIATION_TREE", "")); args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit("doctor_root_required")
    require_staged_script(Path(__file__))
    checks = [{"name": "linux", "ok": sys.platform.startswith("linux"), "platform": platform.platform()}, {"name": "docker_binary", "ok": shutil.which("dockerd") is not None}, {"name": "xfs_tools", "ok": shutil.which("xfs_quota") is not None and shutil.which("mkfs.xfs") is not None}, {"name": "openat2", "ok": _openat2()}]
    try:
        control = Control(args.db); backend = control.instance_id(); control.assert_ready(); active = control.active_capacity_id(); control.close(); readiness = {"name": "control_ready", "ok": bool(active), "backend_instance_id": backend, "active_capacity_id": active}
    except Exception as exc: backend = None; readiness = {"name": "control_ready", "ok": False, "error": str(exc)}
    remediation: list[dict[str, object]] = []
    if args.profile in ("remediation", "all"):
        if not args.run_remediation_fixture: remediation.append({"name": "real_git_remediation_fixture", "ok": False, "reason": "not_requested"})
        elif not args.runner_image or "@sha256:" not in args.runner_image or len(args.shiproom_commit) != 40 or len(args.package_tree_hash) != 40: remediation.append({"name": "real_git_remediation_fixture", "ok": False, "reason": "real_runner_or_clean_commit_authority_missing"})
        else: remediation.append(real_git_remediation_fixture(args.db, args.runner_image, args.shiproom_commit, "sha256:" + args.package_tree_hash))
    detection_ok = all(bool(row.get("ok")) for row in checks + [readiness]); remediation_ok = detection_ok and bool(remediation) and all(bool(row.get("ok")) for row in remediation)
    report = {"schema_id": "remediation_doctor_report.v2", "schema_version": "2", "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "backend_instance_id": backend, "proof_classification": {"privileged_runtime": remediation, "static_contract": checks + [readiness], "non_privileged_semantic_adversarial": "recorded by focused control tests"}, "detection_profile": {"status": "QUALIFIED" if detection_ok else "BLOCKED", "checks": checks + [readiness]}, "remediation_profile": {"status": "QUALIFIED" if remediation_ok else "BLOCKED", "checks": remediation}, "overall_status": "QUALIFIED" if remediation_ok else ("PARTIALLY_QUALIFIED" if detection_ok else "FAILED")}; report["report_hash"] = digest(report)
    args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(canonical(report)); os.chmod(args.out, 0o600); print(json.dumps({"detection_profile": report["detection_profile"]["status"], "remediation_profile": report["remediation_profile"]["status"], "overall_status": report["overall_status"], "report_hash": report["report_hash"]}, sort_keys=True)); return 0


def _openat2() -> bool:
    try: require_openat2(); return True
    except Exception: return False


if __name__ == "__main__": raise SystemExit(main())
