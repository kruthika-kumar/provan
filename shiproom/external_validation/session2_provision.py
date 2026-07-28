"""Root-only Session 2 external-root provisioning receipt.

This module is intentionally limited to the newly approved evidence root and
the already-qualified custom daemon.  It creates no patient clone, source
worktree, case, mutation, or model request.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
from typing import Any

from .identity import canonical_json
from .session2_storage import prepare_external_namespace
from .trusted_attestation import TRUSTED_ROOT, load_trusted_attestation


EXPECTED_ROOT = Path("/var/lib/shiproom-external-validation")
CUSTOM_SOCKET = Path("/run/shiproom-remediation-docker/docker.sock")
CONFIG = Path("/etc/shiproom-external-validation.conf")
PATIENT_UID = "65533:65533"


class ProvisionError(RuntimeError):
    def __init__(self, code: str, *, evidence: dict[str, Any] | None = None):
        self.code, self.evidence = code, evidence
        super().__init__(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def _stat(path: Path, *, directory: bool = False) -> dict[str, int]:
    value = os.lstat(path)
    if (directory and not stat.S_ISDIR(value.st_mode)) or (not directory and not stat.S_ISREG(value.st_mode)) or stat.S_ISLNK(value.st_mode):
        raise ProvisionError("session2_provision_path_type_invalid")
    if value.st_uid != 0 or value.st_gid != 0 or value.st_mode & 0o022:
        raise ProvisionError("session2_provision_path_authority_invalid")
    return {"mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid, "inode": value.st_ino, "device": value.st_dev}


def _mount(path: Path) -> dict[str, str]:
    completed = _run(["findmnt", "-T", str(path), "-no", "TARGET,SOURCE,FSTYPE,OPTIONS"])
    if completed.returncode != 0:
        raise ProvisionError("session2_provision_mount_unavailable")
    parts = completed.stdout.decode("utf-8", "strict").strip().split(None, 3)
    if len(parts) != 4 or parts[2] not in {"ext4", "xfs"}:
        raise ProvisionError("session2_provision_mount_invalid")
    return {"target": parts[0], "source": parts[1], "fstype": parts[2], "options": parts[3]}


def _git(repo: Path, argument: str) -> str:
    completed = _run(["git", "-c", "safe.directory=" + str(repo), "show", argument], timeout=30)
    if completed.returncode != 0:
        raise ProvisionError("session2_provision_session1_git_binding_invalid")
    return _sha(completed.stdout)


def _session1_attestations() -> list[dict[str, str]]:
    root = TRUSTED_ROOT
    if not root.is_dir():
        raise ProvisionError("session2_provision_session1_attestation_missing")
    entries: list[dict[str, str]] = []
    for path in sorted(root.glob("*.json")):
        identifier = path.stem
        loaded = load_trusted_attestation(identifier, trusted_root=root)
        entries.append({"attestation_id": identifier, "sha256": "sha256:" + identifier, "schema_id": str(loaded.document.get("schema_id"))})
    if not entries:
        raise ProvisionError("session2_provision_session1_attestation_missing")
    return entries


def _docker_canary(root: Path, image: str) -> dict[str, Any]:
    """Prove a real patient container cannot see or write the evidence root."""
    docker = "/usr/bin/docker"
    if not CUSTOM_SOCKET.is_socket():
        raise ProvisionError("session2_provision_custom_socket_missing")
    inspect_image = _run([docker, "--host", "unix://" + str(CUSTOM_SOCKET), "image", "inspect", image])
    if inspect_image.returncode != 0:
        raise ProvisionError("session2_provision_canary_image_missing")
    image_data = json.loads(inspect_image.stdout)[0]
    image_id = image_data.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise ProvisionError("session2_provision_canary_image_identity_invalid")
    name = "session2-provision-" + secrets.token_hex(12)
    patient_command = ["-c", "test ! -e /var/lib/shiproom-external-validation && test ! -r /var/lib/shiproom-external-validation && test ! -w /var/lib/shiproom-external-validation"]
    command = [docker, "--host", "unix://" + str(CUSTOM_SOCKET), "create", "--name", name, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", PATIENT_UID, "--pids-limit", "32", "--memory", "64m", "--memory-swap", "64m", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1m", "--entrypoint", "/bin/sh", image, *patient_command]
    created = False
    try:
        result = _run(command)
        if result.returncode != 0:
            raise ProvisionError("session2_provision_canary_create_failed")
        created = True
        identifier = result.stdout.decode("utf-8", "strict").strip()
        inspect = _run([docker, "--host", "unix://" + str(CUSTOM_SOCKET), "inspect", identifier])
        if inspect.returncode != 0:
            raise ProvisionError("session2_provision_canary_inspect_failed")
        data = json.loads(inspect.stdout)[0]
        mounts = data.get("Mounts")
        if not isinstance(mounts, list) or any(str(root) in json.dumps(item, sort_keys=True) for item in mounts):
            raise ProvisionError("session2_provision_evidence_root_mounted")
        started = _utc()
        executed = _run([docker, "--host", "unix://" + str(CUSTOM_SOCKET), "start", "-a", identifier])
        completed = _utc()
        evidence = {"supervisor_run_id": "provision-canary-" + identifier[:12], "container_id": identifier, "container_image_id": image_id, "command": patient_command, "started_at": started, "completed_at": completed, "exit_code": executed.returncode, "stdout": {"bytes": len(executed.stdout), "sha256": _sha(executed.stdout)}, "stderr": {"bytes": len(executed.stderr), "sha256": _sha(executed.stderr)}, "network_policy": "none", "read_only_root": True, "patient_uid": PATIENT_UID, "mounts": mounts}
        if executed.returncode != 0:
            raise ProvisionError("session2_provision_patient_access_denial_failed", evidence=evidence)
        return evidence
    finally:
        if created:
            removed = _run([docker, "--host", "unix://" + str(CUSTOM_SOCKET), "rm", "-f", name])
            if removed.returncode != 0:
                raise ProvisionError("session2_provision_canary_cleanup_failed")


def _seal_provisioning_event(directory: Path, value: dict[str, Any]) -> tuple[Path, str]:
    raw = canonical_json(value); identifier = _sha(raw)[7:]; final = directory / (identifier + ".json")
    if final.exists():
        if final.read_bytes() != raw: raise ProvisionError("session2_provision_event_collision")
        return final, "sha256:" + identifier
    temporary = final.with_name("." + final.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
    try:
        os.write(fd, raw); os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
    finally: os.close(fd)
    os.replace(temporary, final)
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)
    _stat(final)
    return final, "sha256:" + identifier


def provision(repository: Path, *, image: str, implementation_commit: str, implementation_tree: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ProvisionError("session2_provision_root_required")
    configured = os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT")
    if configured != str(EXPECTED_ROOT):
        raise ProvisionError("session2_provision_environment_authority_invalid")
    root = Path(configured)
    if root.resolve() != EXPECTED_ROOT or not root.is_dir():
        raise ProvisionError("session2_provision_root_invalid")
    parents = {str(path): _stat(path, directory=True) for path in (Path("/var"), Path("/var/lib"), root)}
    if parents[str(root)]["mode"] != 0o700:
        raise ProvisionError("session2_provision_root_mode_invalid")
    namespace = prepare_external_namespace(repository, newly_authorized_for_session2=True)
    session2 = root / "session2"
    probe = session2 / "provisioning" / (".write-" + secrets.token_hex(16))
    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
    try:
        os.write(fd, b"supervisor-write-check"); os.fsync(fd)
    finally:
        os.close(fd)
    _stat(probe); probe.unlink()
    config_before = None if not CONFIG.exists() else _sha(CONFIG.read_bytes())
    mount = _mount(root)
    repo = repository.resolve()
    if str(repo).startswith("/mnt/c/") is False:
        raise ProvisionError("session2_provision_public_repository_location_invalid")
    if root == repo or root in repo.parents or repo in root.parents:
        raise ProvisionError("session2_provision_git_overlap")
    patient_roots = [Path("/mnt/shiproom-remediation"), Path("/run/shiproom-remediation-docker"), Path("/var/lib/shiproom-remediation")]
    if any(root == item or root in item.parents or item in root.parents for item in patient_roots):
        raise ProvisionError("session2_provision_patient_overlap")
    try:
        canary = _docker_canary(root, image)
    except ProvisionError as exc:
        failure = {"schema_id": "external_validation.session2_root_provisioning_incident.v1", "schema_version": "1", "created_at": _utc(), "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "code": exc.code, "canary_evidence": exc.evidence, "resolved": False}
        final, digest = _seal_provisioning_event(session2 / "provisioning", failure)
        raise ProvisionError(exc.code + ":" + digest, evidence={"incident_path": str(final), "incident_hash": digest}) from exc
    config_after = None if not CONFIG.exists() else _sha(CONFIG.read_bytes())
    if config_after != config_before:
        raise ProvisionError("session2_provision_config_changed")
    session1_commit = "d5b99293b62e907f21226ee05d541c9559f33bc8"
    document: dict[str, Any] = {"schema_id": "external_validation.session2_root_provisioning_receipt.v1", "schema_version": "1", "receipt_id": "", "created_at": _utc(), "external_root": str(root), "external_root_origin": "NEWLY_AUTHORIZED_FOR_SESSION2", "environment_variable": "SHIPROOM_EXTERNAL_VALIDATION_ROOT", "environment_value": configured, "filesystem": mount, "parent_authority": parents, "namespace": namespace, "config_before": config_before, "config_after": config_after, "git_repository": str(repo), "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "session1": {"closeout_commit": session1_commit, "status_authority_hash": _git(repo, session1_commit + ":external_validation/status/session1-status-authority.v1.json"), "proof_bundle_hash": _git(repo, session1_commit + ":external_validation/proofs/session1/session1_closeout_manifest.v1.json"), "root_attestations": _session1_attestations()}, "patient_root_overlap": False, "patient_canary": canary, "evaluated_model_call_count": 0, "shiproom_evaluated_output_count": 0, "comparator_evaluated_output_count": 0}
    content = dict(document); content.pop("receipt_id")
    document["receipt_id"] = "sha256:" + sha256(canonical_json(content)).hexdigest()
    final, digest = _seal_provisioning_event(session2 / "provisioning", document)
    return {"receipt_id": document["receipt_id"], "path": str(final), "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--image", required=True); parser.add_argument("--implementation-commit", required=True); parser.add_argument("--implementation-tree", required=True)
    args = parser.parse_args(); print(json.dumps(provision(args.repository, image=args.image, implementation_commit=args.implementation_commit, implementation_tree=args.implementation_tree), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
