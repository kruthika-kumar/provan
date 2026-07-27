#!/usr/bin/env python3
"""Root-staged remediation doctor using the production lifecycle interface."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
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
    from .lifecycle import execute_patient_command, function_ids, git_artifacts, issue_release_authorization, materialize_fixture, prepare_fixture_source, seal_and_finalize
    from .release_helper import require_openat2
except ImportError:
    from bootstrap import require_staged_script
    from control import Control, ControlError, canonical
    from lifecycle import execute_patient_command, function_ids, git_artifacts, issue_release_authorization, materialize_fixture, prepare_fixture_source, seal_and_finalize
    from release_helper import require_openat2

ROOT = Path("/var/lib/shiproom-remediation")
MOUNT = Path("/mnt/shiproom-remediation")
RUN = Path("/run/shiproom-remediation-docker")
REQUIRED_RUNTIME_PROOFS = (
    "real_git_remediation_fixture",
    "real_overlapping_quota_fixture",
    "real_authorization_tamper_fixture",
    "real_residual_reference_fixture",
)


def digest(value: object) -> str: return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
def sha(path: Path) -> str: return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def invocation(argv: list[str], *, timeout: int = 180, environment: dict[str, str] | None = None) -> dict[str, object]:
    try: result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc: return {"command": argv, "exit_code": None, "stdout": "", "stderr": str(exc), "error": type(exc).__name__}
    return {"command": argv, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


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


def _runtime_paths() -> tuple[str, Path]:
    """Load only the already-recorded custom-daemon authority."""
    state = ROOT / "backend.state"
    return _state_value(state, "DOCKER_CLI"), Path(_state_value(state, "RUN")) / "docker.sock"


def _patient_ownership(tree: Path) -> None:
    """Give the patient its one disposable quota surface and nothing else."""
    for candidate in [tree, *tree.rglob("*")]:
        os.chown(candidate, 65533, 65533, follow_symlinks=False)


def _fresh_capacity_record(staged_directory: Path) -> dict[str, object]:
    """Invoke the production XFS capacity measurement—not a doctor copy."""
    lib = staged_directory / "lib.sh"
    require_staged_script(lib)
    result = subprocess.run(
        ["/usr/bin/bash", "-c", 'source "$1"; capacity_record_from_xfs', "doctor-capacity", str(lib)],
        text=True, capture_output=True, timeout=60, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if result.returncode != 0:
        raise RuntimeError("doctor_capacity_measurement_failed:" + result.stderr[-800:])
    try:
        record = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("doctor_capacity_measurement_invalid") from exc
    if not isinstance(record, dict):
        raise RuntimeError("doctor_capacity_measurement_invalid")
    return record


def _release_attempt(*, control: Control, allocation_script: Path, attempt: str,
                     source: dict[str, str], artifacts: dict[str, Path],
                     commands: list[dict[str, Any]], container: dict[str, Any],
                     shiproom_commit: str, package_tree_hash: str) -> tuple[Path, str, Path, dict[str, object]]:
    """Use the normal finalizer, authorization issuer, and release command."""
    receipt_id, receipt_path, manifest_path, _ = seal_and_finalize(
        attempt=attempt, source=source, artifacts=artifacts, command_results=commands,
        receipt_root=ROOT / "supervisor-owned", journal_root=ROOT / "supervisor-owned" / "journals",
        runner_image_digest=str(container["runner_image_digest"]), container=container,
        shiproom_commit=shiproom_commit, package_tree_hash=package_tree_hash,
    )
    authorization = issue_release_authorization(
        control=control, attempt=attempt, source=source, receipt_id=receipt_id,
        manifest_path=manifest_path, artifacts=artifacts,
        authorization_root=ROOT / "supervisor-owned" / "authorizations",
    )
    released = invocation([str(allocation_script), "release", attempt, str(authorization)], timeout=180)
    return authorization, receipt_id, receipt_path, released


def _daemon_residual_absence(docker: str, socket: Path) -> dict[str, object]:
    result = invocation([docker, "--host", "unix://" + str(socket), "ps", "-aq"], timeout=30)
    return {"name": "custom_daemon_residual_absence", "ok": result["exit_code"] == 0 and not str(result["stdout"]).strip(), "docker_ps": result}


def _release_primitives() -> tuple[Any, Any]:
    """Load Linux-only production release functions only when a probe needs them.

    Stage-0 behavioral tests intentionally import the doctor on Windows where
    ``fcntl`` is unavailable; importing the release transaction there would
    make a non-privileged static gate depend on Linux runtime facilities.
    """
    try:
        from .release import rehash_records as rehash, residual_proof as residual
    except ImportError:
        from release import rehash_records as rehash, residual_proof as residual
    return rehash, residual


def real_git_remediation_fixture(db: Path, runner_image: str, shiproom_commit: str, source_tree: str, package_tree_hash: str, runner_ref: str | None = None) -> dict[str, object]:
    if db.resolve() != (ROOT / "control.sqlite3").resolve() or not MOUNT.is_mount() or not RUN.is_dir(): return {"name": "real_git_remediation_fixture", "ok": False, "reason": "doctor_paths_not_qualified"}
    allocation_script = Path(__file__).with_name("quota-worktree.sh"); require_staged_script(allocation_script)
    qualification_run = "qualification_" + secrets.token_hex(16); attempt = "doctor-git-" + secrets.token_hex(8)
    source_root = ROOT / "supervisor-owned" / "doctor-sources" / qualification_run
    try:
        control = Control(db)
        try: control.start_qualification(qualification_run, shiproom_commit, source_tree)
        finally: control.close()
        source = prepare_fixture_source(source_root)
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SHIPROOM_QUALIFICATION_RUN_ID": qualification_run}
        allocate = invocation([str(allocation_script), "allocate", attempt, str(32 * 1024 * 1024), "2048", source["source_snapshot_hash"]], environment=environment)
        if allocate["exit_code"] != 0:
            raise RuntimeError("doctor_production_allocation_failed:" + str(allocate["stderr"]))
        tree = allocated_tree(db, attempt, allocate); materialize_fixture(source_root=source_root, worktree=tree, source=source)
        # The host materializer creates Git metadata as root; the untrusted
        # patient gets ownership only of its dedicated, quota-controlled tree.
        _patient_ownership(tree)
        docker, socket = _runtime_paths()
        before_target, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "target_test.py"], label="target_before")
        before_protected, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "protected_test.py"], label="protected_before")
        repair, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "-c", "p='calculator.py';s=open(p).read();open(p,'w').write(s.replace('return a - b','return a + b'))"], label="controlled_repair")
        after_target, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "target_test.py"], label="target_after")
        after_protected, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "protected_test.py"], label="protected_after")
        if before_target["exit_code"] == 0 or before_protected["exit_code"] != 0 or repair["exit_code"] != 0 or after_target["exit_code"] != 0 or after_protected["exit_code"] != 0: raise RuntimeError("doctor_real_checks_invalid")
        artifacts, git_evidence = git_artifacts(source_root=source_root, worktree=tree, artifact_root=ROOT / "supervisor-owned" / "doctor-artifacts" / attempt)
        receipt_id, receipt_path, manifest_path, receipt = seal_and_finalize(attempt=attempt, source=source, artifacts=artifacts, command_results=[before_target, before_protected, repair, after_target, after_protected], receipt_root=ROOT / "supervisor-owned", journal_root=ROOT / "supervisor-owned" / "journals", runner_image_digest=runner_image, container=container, shiproom_commit=shiproom_commit, package_tree_hash=package_tree_hash)
        control = Control(db)
        try: authorization = issue_release_authorization(control=control, attempt=attempt, source=source, receipt_id=receipt_id, manifest_path=manifest_path, artifacts=artifacts, authorization_root=ROOT / "supervisor-owned" / "authorizations")
        finally: control.close()
        released = invocation([str(allocation_script), "release", attempt, str(authorization)], timeout=180)
        control = Control(db)
        try: allocation = control.allocation(attempt); status = control.effective_status()
        finally: control.close()
        ok = released["exit_code"] == 0 and allocation["terminal_status"] == "RELEASED_RETIRED" and status["effective_state"] == "READY" and subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip() == source["commit"]
        control = Control(db)
        try: control.finish_qualification(qualification_run, ok)
        finally: control.close()
        return {"name": "real_git_remediation_fixture", "ok": ok, "qualification_run_id": qualification_run, "attempt_id": attempt, "source": source, "git_evidence": git_evidence, "receipt_id": receipt_id, "receipt_hash": sha(receipt_path), "authorization_hash": sha(authorization), "authorization_path": str(authorization), "release": released, "postcondition": {"terminal_status": allocation["terminal_status"], "effective_state": status["effective_state"], "tree_absent": not tree.exists()}, "function_ids": function_ids()}
    except Exception as exc:
        try:
            control = Control(db)
            # This is a production lifecycle failure, not a test-only cleanup
            # opportunity.  Preserve its worktree/capacity reservation and
            # create an immutable global block for an explicit recovery flow.
            try:
                control.allocation_phase(attempt, "INCIDENT", control.allocation(attempt).get("worktree_authority_json", {}))
                control.incident("doctor_attempt_failure", "RECOVERY_REQUIRED", {"attempt_id": attempt, "qualification_run_id": qualification_run, "error": type(exc).__name__ + ":" + str(exc)}, qualification_run_id=qualification_run)
            except Exception:
                pass
            control.finish_qualification(qualification_run, False); control.close()
        except Exception:
            pass
        return {"name": "real_git_remediation_fixture", "ok": False, "attempt_id": attempt, "qualification_run_id": qualification_run, "error": type(exc).__name__ + ":" + str(exc), "function_ids": function_ids()}


def real_overlapping_quota_fixture(db: Path, runner_image: str, shiproom_commit: str,
                                   source_tree: str, package_tree_hash: str,
                                   runner_ref: str | None = None) -> dict[str, object]:
    """Exercise two genuinely overlapping production quota lifecycles.

    This deliberately allocates through the normal project-ID/capacity
    authority, executes through the normal container path, finalizes through
    the normal v2/journal path, and retires through the normal release path.
    No doctor-owned project counter or test-only release shortcut exists.
    """
    allocation_script = Path(__file__).with_name("quota-worktree.sh")
    if db.resolve() != (ROOT / "control.sqlite3").resolve() or not MOUNT.is_mount():
        return {"name": "real_overlapping_quota_fixture", "ok": False, "reason": "doctor_paths_not_qualified"}
    require_staged_script(allocation_script)
    qualification_run = "qualification_" + secrets.token_hex(16)
    attempts = ["doctor-quota-" + secrets.token_hex(8), "doctor-quota-" + secrets.token_hex(8)]
    source_root = ROOT / "supervisor-owned" / "doctor-sources" / qualification_run
    trees: list[Path] = []
    try:
        control = Control(db)
        try:
            control.start_qualification(qualification_run, shiproom_commit, source_tree)
        finally:
            control.close()
        source = prepare_fixture_source(source_root)
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SHIPROOM_QUALIFICATION_RUN_ID": qualification_run}
        allocations = [
            invocation([str(allocation_script), "allocate", attempt, str(32 * 1024 * 1024), "2048", source["source_snapshot_hash"]], environment=environment)
            for attempt in attempts
        ]
        if any(row["exit_code"] != 0 for row in allocations):
            raise RuntimeError("doctor_overlapping_allocation_failed")
        trees = [allocated_tree(db, attempt, row) for attempt, row in zip(attempts, allocations)]
        if trees[0] == trees[1] or not all(tree.is_dir() for tree in trees):
            raise RuntimeError("doctor_overlapping_tree_authority_invalid")
        # The third request is within the per-worktree policy but must be
        # refused by aggregate admission while the two live reservations are
        # held.  It never receives a project ID or creates a worktree.
        overcommit = invocation([str(allocation_script), "allocate", "doctor-overcommit-" + secrets.token_hex(6), str(4 * 1024 * 1024 * 1024), "2048", source["source_snapshot_hash"]], environment=environment)
        if overcommit["exit_code"] == 0:
            raise RuntimeError("doctor_aggregate_admission_not_enforced")
        for tree in trees:
            materialize_fixture(source_root=source_root, worktree=tree, source=source)
            _patient_ownership(tree)
        docker, socket = _runtime_paths()
        commands: list[list[dict[str, Any]]] = [[], []]
        containers: list[dict[str, Any]] = []
        for index, tree in enumerate(trees):
            passed, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "protected_test.py"], label=f"quota_{index}_protected")
            forbidden, _ = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "-c", f"import os,sys;sys.exit(0 if not os.path.exists('/mnt/shiproom-remediation/worktrees/{attempts[1-index]}') else 1)"], label=f"quota_{index}_cross_mount_denied")
            if passed["exit_code"] != 0 or forbidden["exit_code"] != 0:
                raise RuntimeError("doctor_cross_attempt_isolation_failed")
            commands[index].extend([passed, forbidden]); containers.append(container)
        control = Control(db)
        try:
            active = [control.allocation(attempt) for attempt in attempts]
            if active[0]["project_id"] == active[1]["project_id"] or active[0]["capacity_id"] != active[1]["capacity_id"]:
                raise RuntimeError("doctor_quota_identity_not_independent")
            # A freshly measured successor must be refused while either live
            # production reservation exists; this is the cross-lineage gate.
            refused_record = _fresh_capacity_record(Path(__file__).parent)
            try:
                control.install_capacity(refused_record, qualification_run_id=qualification_run)
            except ControlError as exc:
                if str(exc) != "capacity_replacement_nonterminal_projects":
                    raise
            else:
                raise RuntimeError("doctor_capacity_replacement_not_refused")
            artifacts_a, git_a = git_artifacts(source_root=source_root, worktree=trees[0], artifact_root=ROOT / "supervisor-owned" / "doctor-artifacts" / attempts[0])
            auth_a, receipt_a, receipt_path_a, release_a = _release_attempt(control=control, allocation_script=allocation_script, attempt=attempts[0], source=source, artifacts=artifacts_a, commands=commands[0], container=containers[0], shiproom_commit=shiproom_commit, package_tree_hash=package_tree_hash)
            still_live = control.allocation(attempts[1])
            if release_a["exit_code"] != 0 or still_live["terminal_status"] is not None or still_live["status"] != "ACTIVE":
                raise RuntimeError("doctor_release_a_affected_b")
            artifacts_b, git_b = git_artifacts(source_root=source_root, worktree=trees[1], artifact_root=ROOT / "supervisor-owned" / "doctor-artifacts" / attempts[1])
            auth_b, receipt_b, receipt_path_b, release_b = _release_attempt(control=control, allocation_script=allocation_script, attempt=attempts[1], source=source, artifacts=artifacts_b, commands=commands[1], container=containers[1], shiproom_commit=shiproom_commit, package_tree_hash=package_tree_hash)
            if release_b["exit_code"] != 0:
                raise RuntimeError("doctor_release_b_failed")
        finally:
            control.close()
        control = Control(db)
        try:
            terminal = [control.allocation(attempt) for attempt in attempts]
            if any(row["terminal_status"] != "RELEASED_RETIRED" for row in terminal):
                raise RuntimeError("doctor_quota_retirement_failed")
            successor = _fresh_capacity_record(Path(__file__).parent)
            predecessor = control.active_capacity_id()
            if successor.get("predecessor_capacity_id") != predecessor:
                raise RuntimeError("doctor_capacity_measurement_lineage_invalid")
            successor_id = control.install_capacity(successor, qualification_run_id=qualification_run)
            status = control.effective_status()
            control.finish_qualification(qualification_run, status["effective_state"] == "READY")
        finally:
            control.close()
        residual = _daemon_residual_absence(docker, socket)
        ok = (status["effective_state"] == "READY" and all(not tree.exists() for tree in trees)
              and residual["ok"] and successor_id == successor["capacity_id"])
        return {
            "name": "real_overlapping_quota_fixture", "ok": ok,
            "qualification_run_id": qualification_run, "attempt_ids": attempts,
            "project_ids": [row["project_id"] for row in terminal],
            "capacity_predecessor_refusal": "capacity_replacement_nonterminal_projects",
            "aggregate_admission": {"ok": True, "attempt": overcommit["command"][2], "result": overcommit},
            "active_capacity_id": successor_id, "source": source,
            "receipts": [receipt_a, receipt_b],
            "receipt_hashes": [sha(receipt_path_a), sha(receipt_path_b)],
            "authorization_hashes": [sha(auth_a), sha(auth_b)],
            "git_evidence": [git_a, git_b], "residual": residual,
            "function_ids": function_ids(),
        }
    except Exception as exc:
        try:
            control = Control(db)
            try:
                control.incident("doctor_attempt_failure", "RECOVERY_REQUIRED", {"attempt_ids": attempts, "qualification_run_id": qualification_run, "error": type(exc).__name__ + ":" + str(exc)}, qualification_run_id=qualification_run)
                control.finish_qualification(qualification_run, False)
            except Exception:
                pass
            finally:
                control.close()
        except Exception:
            pass
        return {"name": "real_overlapping_quota_fixture", "ok": False, "qualification_run_id": qualification_run, "attempt_ids": attempts, "error": type(exc).__name__ + ":" + str(exc), "function_ids": function_ids()}


def real_authorization_tamper_fixture(authorization_path: Path) -> dict[str, object]:
    """Run the production release rehasher against genuine sealed evidence.

    The canonical authorization and sealed artifacts remain immutable; the
    adversarial bytes are isolated in a root-owned doctor directory.  This
    demonstrates that neither a modified authorization assertion nor modified
    evidence bytes can reach a release transaction.
    """
    try:
        rehash, _ = _release_primitives()
        document = json.loads(authorization_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise RuntimeError("doctor_authorization_invalid")
        original = dict(document)
        original_records = list(document["artifact_records"])
        tamper_root = ROOT / "supervisor-owned" / "doctor-adversarial" / ("tamper-" + secrets.token_hex(12))
        tamper_root.mkdir(parents=True, mode=0o700)
        artifact = tamper_root / "changed-bytes.bin"
        artifact.write_bytes(b"tampered\n")
        os.chown(artifact, 0, 0); os.chmod(artifact, 0o400)
        changed = dict(original)
        changed["patch_hash"] = "sha256:" + ("0" * 32) * 2
        assertion_rejected = False
        try:
            rehash(changed, ROOT / "supervisor-owned")
        except Exception:
            assertion_rejected = True
        artifact_changed = dict(original)
        records = [dict(row) for row in original_records]
        records[0]["canonical_path"] = str(artifact)
        artifact_changed["artifact_records"] = records
        artifact_rejected = False
        try:
            rehash(artifact_changed, ROOT / "supervisor-owned")
        except Exception:
            artifact_rejected = True
        shutil.rmtree(tamper_root)
        return {"name": "real_authorization_tamper_fixture", "ok": assertion_rejected and artifact_rejected, "canonical_authorization_hash": sha(authorization_path), "assertion_rejected": assertion_rejected, "artifact_rejected": artifact_rejected, "function_ids": function_ids()}
    except Exception as exc:
        return {"name": "real_authorization_tamper_fixture", "ok": False, "error": type(exc).__name__ + ":" + str(exc), "function_ids": function_ids()}


def real_residual_reference_fixture(db: Path, runner_image: str, shiproom_commit: str,
                                    source_tree: str, package_tree_hash: str,
                                    runner_ref: str | None = None) -> dict[str, object]:
    """Prove a real host cwd/fd reference blocks release before deletion."""
    allocation_script = Path(__file__).with_name("quota-worktree.sh")
    qualification_run = "qualification_" + secrets.token_hex(16)
    attempt = "doctor-residual-" + secrets.token_hex(8)
    source_root = ROOT / "supervisor-owned" / "doctor-sources" / qualification_run
    held: subprocess.Popen[bytes] | None = None
    try:
        _, residual = _release_primitives()
        control = Control(db)
        try:
            control.start_qualification(qualification_run, shiproom_commit, source_tree)
        finally:
            control.close()
        source = prepare_fixture_source(source_root)
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SHIPROOM_QUALIFICATION_RUN_ID": qualification_run}
        allocation_result = invocation([str(allocation_script), "allocate", attempt, str(32 * 1024 * 1024), "2048", source["source_snapshot_hash"]], environment=environment)
        if allocation_result["exit_code"] != 0:
            raise RuntimeError("doctor_residual_allocation_failed:" + str(allocation_result["stderr"])[-800:])
        tree = allocated_tree(db, attempt, allocation_result)
        materialize_fixture(source_root=source_root, worktree=tree, source=source)
        _patient_ownership(tree)
        control = Control(db)
        try:
            authority = control.allocation(attempt)["worktree_authority_json"]
            aliases = ROOT / "supervisor-owned" / "release-aliases" / (attempt + ".json")
            aliases.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            aliases.write_bytes(canonical(control.registered_worktree_paths()))
            os.chown(aliases, 0, 0); os.chmod(aliases, 0o400)
        finally:
            control.close()
        docker, socket = _runtime_paths()
        held = subprocess.Popen(["/usr/bin/python3", "-c", "import os,time; fd=os.open('.',os.O_RDONLY); time.sleep(60)"], cwd=tree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rejected = False
        try:
            residual(Path(__file__).with_name("residual.py"), tree, authority, socket, aliases)
        except Exception:
            rejected = True
        finally:
            held.terminate()
            try: held.wait(timeout=10)
            except subprocess.TimeoutExpired: held.kill(); held.wait(timeout=10)
            held = None
        if not rejected:
            raise RuntimeError("doctor_residual_reference_not_rejected")
        command, container = execute_patient_command(docker=docker, socket=socket, tree=tree, runner_image=runner_image, runner_ref=runner_ref, command=["python3", "protected_test.py"], label="residual_after_cleanup")
        if command["exit_code"] != 0:
            raise RuntimeError("doctor_residual_fixture_patient_failed")
        artifacts, git_evidence = git_artifacts(source_root=source_root, worktree=tree, artifact_root=ROOT / "supervisor-owned" / "doctor-artifacts" / attempt)
        control = Control(db)
        try:
            authorization, receipt_id, receipt_path, released = _release_attempt(control=control, allocation_script=allocation_script, attempt=attempt, source=source, artifacts=artifacts, commands=[command], container=container, shiproom_commit=shiproom_commit, package_tree_hash=package_tree_hash)
            allocation = control.allocation(attempt); status = control.effective_status()
            ok = released["exit_code"] == 0 and allocation["terminal_status"] == "RELEASED_RETIRED" and status["effective_state"] == "READY"
            control.finish_qualification(qualification_run, ok)
        finally:
            control.close()
        return {"name": "real_residual_reference_fixture", "ok": ok, "qualification_run_id": qualification_run, "attempt_id": attempt, "residual_reference_rejected": rejected, "receipt_id": receipt_id, "receipt_hash": sha(receipt_path), "authorization_hash": sha(authorization), "git_evidence": git_evidence, "function_ids": function_ids()}
    except Exception as exc:
        if held is not None and held.poll() is None:
            held.kill(); held.wait(timeout=10)
        try:
            control = Control(db)
            try:
                control.incident("doctor_attempt_failure", "RECOVERY_REQUIRED", {"attempt_id": attempt, "qualification_run_id": qualification_run, "error": type(exc).__name__ + ":" + str(exc)}, qualification_run_id=qualification_run)
                control.finish_qualification(qualification_run, False)
            except Exception:
                pass
            finally:
                control.close()
        except Exception:
            pass
        return {"name": "real_residual_reference_fixture", "ok": False, "qualification_run_id": qualification_run, "attempt_id": attempt, "error": type(exc).__name__ + ":" + str(exc), "function_ids": function_ids()}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--db", type=Path, required=True); parser.add_argument("--out", type=Path, required=True); parser.add_argument("--profile", choices=("detection", "remediation", "all"), default="all"); parser.add_argument("--run-remediation-fixture", action="store_true"); parser.add_argument("--runner-image", default=os.environ.get("SHIPROOM_REMEDIATION_RUNNER_IMAGE")); parser.add_argument("--runner-image-ref", default=os.environ.get("SHIPROOM_REMEDIATION_RUNNER_REF")); parser.add_argument("--shiproom-commit", default=os.environ.get("SHIPROOM_REMEDIATION_COMMIT", "")); parser.add_argument("--source-tree", default=os.environ.get("SHIPROOM_REMEDIATION_SOURCE_TREE", "")); parser.add_argument("--package-tree-hash", default=os.environ.get("SHIPROOM_REMEDIATION_PACKAGE_TREE_HASH", "")); args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit("doctor_root_required")
    require_staged_script(Path(__file__))
    checks = [{"name": "linux", "ok": sys.platform.startswith("linux"), "platform": platform.platform()}, {"name": "docker_binary", "ok": shutil.which("dockerd") is not None}, {"name": "xfs_tools", "ok": shutil.which("xfs_quota") is not None and shutil.which("mkfs.xfs") is not None}, {"name": "openat2", "ok": _openat2()}]
    try:
        control = Control(args.db); backend = control.instance_id(); control.assert_ready(); active = control.active_capacity_id(); control.close(); readiness = {"name": "control_ready", "ok": bool(active), "backend_instance_id": backend, "active_capacity_id": active}
    except Exception as exc: backend = None; readiness = {"name": "control_ready", "ok": False, "error": str(exc)}
    remediation: list[dict[str, object]] = []
    if args.profile in ("remediation", "all"):
        if not args.run_remediation_fixture: remediation.append({"name": "real_git_remediation_fixture", "ok": False, "reason": "not_requested"})
        elif not args.runner_image or "@sha256:" not in args.runner_image or not args.runner_image_ref or len(args.shiproom_commit) != 40 or len(args.source_tree) != 40 or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.package_tree_hash): remediation.append({"name": "real_git_remediation_fixture", "ok": False, "reason": "real_runner_or_clean_commit_authority_missing"})
        else:
            primary = real_git_remediation_fixture(args.db, args.runner_image, args.shiproom_commit, args.source_tree, args.package_tree_hash, args.runner_image_ref)
            remediation.append(primary)
            remediation.append(real_overlapping_quota_fixture(args.db, args.runner_image, args.shiproom_commit, args.source_tree, args.package_tree_hash, args.runner_image_ref))
            if primary.get("ok") and isinstance(primary.get("authorization_path"), str):
                remediation.append(real_authorization_tamper_fixture(Path(str(primary["authorization_path"]))))
            else:
                remediation.append({"name": "real_authorization_tamper_fixture", "ok": False, "reason": "primary_fixture_missing_authorization"})
            remediation.append(real_residual_reference_fixture(args.db, args.runner_image, args.shiproom_commit, args.source_tree, args.package_tree_hash, args.runner_image_ref))
    detection_ok = all(bool(row.get("ok")) for row in checks + [readiness]); remediation_ok = detection_ok and {str(row.get("name")) for row in remediation} == set(REQUIRED_RUNTIME_PROOFS) and all(bool(row.get("ok")) for row in remediation)
    report = {"schema_id": "remediation_doctor_report.v2", "schema_version": "2", "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "backend_instance_id": backend, "proof_classification": {"privileged_runtime": remediation, "static_contract": checks + [readiness], "non_privileged_semantic_adversarial": "recorded by focused control tests"}, "detection_profile": {"status": "QUALIFIED" if detection_ok else "BLOCKED", "checks": checks + [readiness]}, "remediation_profile": {"status": "QUALIFIED" if remediation_ok else "BLOCKED", "checks": remediation}, "overall_status": "QUALIFIED" if remediation_ok else ("PARTIALLY_QUALIFIED" if detection_ok else "FAILED")}; report["report_hash"] = digest(report)
    args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(canonical(report)); os.chmod(args.out, 0o600); print(json.dumps({"detection_profile": report["detection_profile"]["status"], "remediation_profile": report["remediation_profile"]["status"], "overall_status": report["overall_status"], "report_hash": report["report_hash"]}, sort_keys=True)); return 0


def _openat2() -> bool:
    try: require_openat2(); return True
    except Exception: return False


if __name__ == "__main__": raise SystemExit(main())
