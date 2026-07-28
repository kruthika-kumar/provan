"""Build a dependency-authoritative Session 2 runner image from a lockfile.

Dependency acquisition is a supervisor build operation, not patient execution:
the resulting image is pinned by its local immutable Docker config ID, while
every fetched distribution is constrained by a committed lockfile hash.  A
patient container still runs with ``--network=none`` and only the read-only
snapshot/release mounts supplied by :mod:`runner_v2`.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
from typing import Any

from .identity import canonical_json
from .runner_v2 import immutable_image_config_digest
from .session2_lockfile import export_uv_requirements, requirements_manifest_hash


EXPECTED_ROOT = Path("/var/lib/shiproom-external-validation")
SOCKET = Path("/run/shiproom-remediation-docker/docker.sock")
BUILD_ROOT = Path("/mnt/shiproom-remediation/session2-supervisor/environment-builds")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class EnvironmentBuildError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise EnvironmentBuildError(code)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _root(repository: Path) -> Path:
    if os.geteuid() != 0 or os.name != "posix" or platform.system() != "Linux":
        _fail("session2_environment_linux_root_required")
    if os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT") != str(EXPECTED_ROOT):
        _fail("session2_environment_root_authority_invalid")
    if not EXPECTED_ROOT.is_dir() or EXPECTED_ROOT.is_symlink() or EXPECTED_ROOT.stat().st_uid != 0 or stat.S_IMODE(EXPECTED_ROOT.stat().st_mode) != 0o700:
        _fail("session2_environment_root_authority_invalid")
    # Provisioning has already created this namespace.  Re-running namespace
    # creation after it contains evidence would be an authority violation.
    session2 = EXPECTED_ROOT / "session2"
    if not session2.is_dir() or session2.is_symlink() or session2.stat().st_uid != 0 or session2.stat().st_mode & 0o022:
        _fail("session2_environment_namespace_invalid")
    target = EXPECTED_ROOT / "session2" / "receipts" / "environments"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = target.lstat()
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        _fail("session2_environment_receipt_store_invalid")
    return target


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})


def _write_once(directory: Path, suffix: str, raw: bytes) -> tuple[Path, str]:
    digest = _sha(raw); path = directory / (digest[7:] + suffix)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != raw:
            _fail("session2_environment_receipt_collision")
    else:
        try:
            os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400); os.write(descriptor, raw); os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(parent)
        finally: os.close(parent)
    return path, digest


def _dockerfile(base_digest: str) -> bytes:
    """Use the locally verified immutable config ID, never a mutable tag."""
    immutable_image_config_digest(base_digest)
    return ("FROM " + base_digest + "\nUSER root\nCOPY requirements.txt /tmp/requirements.txt\n"
            "RUN /usr/local/bin/python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt\n"
            "USER 65532:65532\n").encode("ascii")


def _inspect_image(base_ref: str) -> str:
    if not SOCKET.is_socket():
        _fail("session2_environment_custom_socket_missing")
    result = _run(["/usr/bin/docker", "--host", "unix://" + str(SOCKET), "image", "inspect", base_ref], timeout=30)
    if result.returncode != 0:
        _fail("session2_environment_base_image_missing")
    try:
        identity = json.loads(result.stdout)[0]["Id"]
        return immutable_image_config_digest(identity)
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EnvironmentBuildError("session2_environment_base_image_invalid") from exc


def build_environment(repository: Path, *, snapshot: Path, project_name: str, implementation_commit: str, implementation_tree: str, base_image_ref: str = "shiproom-session1-runner:03fe9026acb7", extras: set[str] = frozenset(), additional_packages: set[str] = frozenset()) -> dict[str, Any]:
    """Build exactly one image from a sealed snapshot's ``uv.lock``.

    The public caller provides no package specifiers: all install authority is
    derived from the snapshot's lockfile and package-group selection.
    """
    if not _GIT_SHA.fullmatch(implementation_commit) or not _GIT_SHA.fullmatch(implementation_tree):
        _fail("session2_environment_implementation_authority_invalid")
    receipts = _root(repository)
    if not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink():
        _fail("session2_environment_snapshot_invalid")
    lock = snapshot / "uv.lock"
    if not lock.is_file() or lock.is_symlink():
        _fail("session2_environment_lock_missing")
    lock_bytes = lock.read_bytes()
    export = export_uv_requirements(lock_bytes, project_name=project_name, extras=set(extras), groups=set(), additional_packages=set(additional_packages))
    base_digest = _inspect_image(base_image_ref)
    build_identity = sha256(canonical_json({"project": project_name, "lock": _sha(lock_bytes), "requirements": export.manifest["requirements_sha256"], "base": base_digest})).hexdigest()
    context = BUILD_ROOT / build_identity
    if context.exists():
        _fail("session2_environment_build_context_exists")
    BUILD_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BUILD_ROOT.is_symlink() or BUILD_ROOT.stat().st_uid != 0 or BUILD_ROOT.stat().st_mode & 0o022:
        _fail("session2_environment_build_root_invalid")
    context.mkdir(mode=0o700)
    try:
        dockerfile = _dockerfile(base_digest)
        (context / "Dockerfile").write_bytes(dockerfile)
        (context / "requirements.txt").write_bytes(export.requirements)
        for item in context.iterdir():
            os.chown(item, 0, 0); os.chmod(item, 0o400)
        tag = "shiproom-session2-" + build_identity[:24]
        started = _utc()
        result = _run(["/usr/bin/docker", "--host", "unix://" + str(SOCKET), "build", "--pull=false", "--network=default", "--tag", tag, str(context)], timeout=1800)
        completed = _utc()
        stdout, stderr = result.stdout, result.stderr
        logs = receipts / "logs"; logs.mkdir(mode=0o700, exist_ok=True)
        stdout_path, stdout_hash = _write_once(logs, ".environment-build.stdout", stdout)
        stderr_path, stderr_hash = _write_once(logs, ".environment-build.stderr", stderr)
        if result.returncode != 0:
            failure = {"schema_id": "external_validation.session2_environment_build_failure.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "build_identity": build_identity, "started_at": started, "completed_at": completed, "exit_code": result.returncode, "stdout_hash": stdout_hash, "stderr_hash": stderr_hash, "lock_hash": _sha(lock_bytes), "requirements_manifest_hash": requirements_manifest_hash(export)}
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_build_failed:" + digest)
        image_digest = _inspect_image(tag)
        receipt = {"schema_id": "external_validation.session2_environment_build_receipt.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "build_identity": build_identity, "base_image_ref": base_image_ref, "base_image_digest": base_digest, "image_ref": tag, "runner_image_digest": image_digest, "project_name": project_name, "lock_hash": _sha(lock_bytes), "requirements_manifest": export.manifest, "requirements_manifest_hash": requirements_manifest_hash(export), "dockerfile_hash": _sha(dockerfile), "started_at": started, "completed_at": completed, "exit_code": result.returncode, "stdout": {"opaque_id": stdout_path.name, "bytes": len(stdout), "sha256": stdout_hash}, "stderr": {"opaque_id": stderr_path.name, "bytes": len(stderr), "sha256": stderr_hash}, "network_during_build": "supervisor_dependency_acquisition_only", "patient_network_policy": "none"}
        path, digest = _write_once(receipts, ".environment-build.json", canonical_json(receipt))
        return {"receipt_path": str(path), "receipt_hash": digest, "image_ref": tag, "runner_image_digest": image_digest, "requirements_manifest_hash": receipt["requirements_manifest_hash"]}
    finally:
        # Context contains public dependency metadata only.  It is never an
        # evidence authority and must not outlive the deterministic build.
        if context.exists():
            shutil.rmtree(context)


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--snapshot", type=Path, required=True); parser.add_argument("--project", required=True); parser.add_argument("--implementation-commit", required=True); parser.add_argument("--implementation-tree", required=True); parser.add_argument("--extra", action="append", default=[]); parser.add_argument("--additional-package", action="append", default=[])
    args = parser.parse_args()
    try:
        print(json.dumps(build_environment(args.repository, snapshot=args.snapshot, project_name=args.project, implementation_commit=args.implementation_commit, implementation_tree=args.implementation_tree, extras=set(args.extra), additional_packages=set(args.additional_package)), sort_keys=True))
    except EnvironmentBuildError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
