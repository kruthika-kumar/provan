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
import tomllib
from typing import Any
from urllib.request import Request, urlopen

from .identity import canonical_json
from .runner_v2 import immutable_image_config_digest
from .session2_lockfile import LockfileError, export_uv_requirements, requirements_manifest_hash
from .session2_requirements import (
    RequirementsAuthorityError,
    export_hash_pinned_requirements,
    pinned_requirement_records,
    requirements_authority_hash,
)


EXPECTED_ROOT = Path("/var/lib/shiproom-external-validation")
SOCKET = Path("/run/shiproom-remediation-docker/docker.sock")
BUILD_ROOT = Path("/mnt/shiproom-remediation/session2-supervisor/environment-builds")
# Session 2 qualification is bound to the reviewed glibc runner.  The former
# Session 1 musl image cannot be an implicit fallback: its wheel platform can
# reject otherwise reproducible locked dependencies.
DEFAULT_BASE_IMAGE_REF = "shiproom-session2-glibc:a4ccb7f"
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECLARED_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


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
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
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
    return ("FROM " + base_digest + "\nUSER root\nCOPY requirements.txt /tmp/requirements.txt\nCOPY wheelhouse /wheelhouse\n"
            "RUN /usr/local/bin/python -m pip install --no-index --find-links=/wheelhouse --no-cache-dir --require-hashes -r /tmp/requirements.txt\n"
            "USER 65532:65532\n").encode("ascii")


def _wheel_score(url: str, platform_tag: str) -> int:
    """Accept only a wheel that can execute on the declared CPython target."""
    name = url.rsplit("/", 1)[-1].lower()
    if platform_tag not in {"manylinux_2_17_x86_64", "musllinux_1_2_x86_64"}:
        _fail("session2_environment_platform_invalid")
    if not name.endswith(".whl") or ("none-any" not in name and platform_tag not in name):
        return -1
    if "cp312-cp312" in name:
        return 30
    if "cp312-abi3" in name or "cp311-abi3" in name or "cp310-abi3" in name or "cp39-abi3" in name:
        return 20
    if "py3-none-any" in name or "py2.py3-none-any" in name:
        return 10
    return -1


def _select_wheels(manifest: dict[str, Any], *, platform_tag: str) -> list[dict[str, str]]:
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages:
        _fail("session2_environment_requirements_manifest_invalid")
    selected: list[dict[str, str]] = []
    for package in packages:
        artifacts = package.get("artifacts") if isinstance(package, dict) else None
        if not isinstance(artifacts, list):
            _fail("session2_environment_requirements_manifest_invalid")
        compatible = [item for item in artifacts if isinstance(item, dict) and isinstance(item.get("url"), str) and isinstance(item.get("sha256"), str) and _wheel_score(item["url"], platform_tag) >= 0]
        if not compatible:
            _fail("session2_environment_wheel_unavailable")
        winner = max(compatible, key=lambda item: (_wheel_score(item["url"], platform_tag), item["url"]))
        selected.append({"name": str(package.get("name")), "version": str(package.get("version")), "url": winner["url"], "sha256": winner["sha256"]})
    return selected


def _select_hash_pinned_wheel(
    record: dict[str, object], files: list[dict[str, object]], *, platform_tag: str,
) -> dict[str, str]:
    """Select only a PyPI wheel whose digest was frozen in requirements.

    The PyPI version metadata is discovery data, never dependency authority:
    the exact project/version/hash tuple remains the committed requirements
    file and the downloaded bytes are verified again below.
    """
    name, version, hashes = record.get("name"), record.get("version"), record.get("hashes")
    if (not isinstance(name, str) or not isinstance(version, str)
            or not isinstance(hashes, list) or not hashes):
        _fail("session2_environment_requirements_manifest_invalid")
    allowed = {str(value).removeprefix("--hash=") for value in hashes}
    compatible: list[dict[str, str]] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        digest = item.get("digests", {}).get("sha256") if isinstance(item.get("digests"), dict) else None
        if not isinstance(url, str) or not url.startswith("https://files.pythonhosted.org/") or not isinstance(digest, str):
            continue
        candidate_digest = "sha256:" + digest
        if candidate_digest not in allowed or _wheel_score(url, platform_tag) < 0:
            continue
        compatible.append({"name": name, "version": version, "url": url, "sha256": candidate_digest})
    if not compatible:
        _fail("session2_environment_wheel_unavailable:" + name)
    return max(compatible, key=lambda item: (_wheel_score(item["url"], platform_tag), item["url"]))


def _select_requirements_wheels(records: list[dict[str, object]], responses: dict[str, list[dict[str, object]]], *, platform_tag: str) -> list[dict[str, str]]:
    """Pure selection helper, deliberately testable without network access."""
    selected: list[dict[str, str]] = []
    for record in records:
        name = record.get("name")
        if not isinstance(name, str) or name not in responses:
            _fail("session2_environment_pypi_metadata_missing")
        selected.append(_select_hash_pinned_wheel(record, responses[name], platform_tag=platform_tag))
    return selected


def _unsupported_packages(manifest: dict[str, Any], *, platform_tag: str) -> list[str]:
    packages = manifest.get("packages")
    if not isinstance(packages, list):
        _fail("session2_environment_requirements_manifest_invalid")
    result: list[str] = []
    for package in packages:
        artifacts = package.get("artifacts") if isinstance(package, dict) else None
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(artifacts, list):
            _fail("session2_environment_requirements_manifest_invalid")
        if not any(isinstance(item, dict) and isinstance(item.get("url"), str) and _wheel_score(item["url"], platform_tag) >= 0 for item in artifacts):
            result.append(package["name"])
    return sorted(result)


def _download_wheelhouse(context: Path, manifest: dict[str, Any], *, platform_tag: str) -> list[dict[str, str]]:
    wheelhouse = context / "wheelhouse"; wheelhouse.mkdir(mode=0o700)
    downloaded: list[dict[str, str]] = []
    for item in _select_wheels(manifest, platform_tag=platform_tag):
        filename = item["url"].rsplit("/", 1)[-1]
        if not filename or "/" in filename or filename.startswith("."):
            _fail("session2_environment_wheel_filename_invalid")
        destination = wheelhouse / filename
        request = Request(item["url"], headers={"User-Agent": "shiproom-session2-lock-fetch/1"})
        try:
            with urlopen(request, timeout=90) as source:
                payload = source.read()
        except OSError as exc:
            raise EnvironmentBuildError("session2_environment_wheel_download_failed") from exc
        if _sha(payload) != item["sha256"]:
            _fail("session2_environment_wheel_hash_mismatch")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o400)
        try:
            os.write(descriptor, payload); os.fsync(descriptor); os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        downloaded.append({**item, "bytes": str(len(payload))})
    return downloaded


def _download_requirements_wheelhouse(context: Path, records: list[dict[str, object]], *, platform_tag: str) -> list[dict[str, str]]:
    """Fetch host-side wheels selected by a frozen hash-pinned requirement file."""
    metadata: dict[str, list[dict[str, object]]] = {}
    for record in records:
        name, version = record.get("name"), record.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            _fail("session2_environment_requirements_manifest_invalid")
        request = Request("https://pypi.org/pypi/" + name + "/" + version + "/json", headers={"User-Agent": "shiproom-session2-requirements-fetch/1"})
        try:
            with urlopen(request, timeout=30) as source:
                response = json.loads(source.read().decode("utf-8", "strict"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnvironmentBuildError("session2_environment_pypi_metadata_failed") from exc
        files = response.get("urls") if isinstance(response, dict) else None
        if not isinstance(files, list):
            _fail("session2_environment_pypi_metadata_invalid")
        metadata[name] = files
    selected = _select_requirements_wheels(records, metadata, platform_tag=platform_tag)
    wheelhouse = context / "wheelhouse"; wheelhouse.mkdir(mode=0o700)
    downloaded: list[dict[str, str]] = []
    for item in selected:
        filename = item["url"].rsplit("/", 1)[-1]
        if not filename or "/" in filename or filename.startswith("."):
            _fail("session2_environment_wheel_filename_invalid")
        destination = wheelhouse / filename
        try:
            with urlopen(Request(item["url"], headers={"User-Agent": "shiproom-session2-requirements-fetch/1"}), timeout=90) as source:
                payload = source.read()
        except OSError as exc:
            raise EnvironmentBuildError("session2_environment_wheel_download_failed") from exc
        if _sha(payload) != item["sha256"]:
            _fail("session2_environment_wheel_hash_mismatch")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o400)
        try:
            os.write(descriptor, payload); os.fsync(descriptor); os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        downloaded.append({**item, "bytes": str(len(payload))})
    return downloaded


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


def _runtime_platform(base_ref: str) -> str:
    """Probe the immutable base under no-network/no-mount restrictions."""
    result = _run(["/usr/bin/docker", "--host", "unix://" + str(SOCKET), "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", "65532:65532", "--pids-limit", "16", "--memory", "64m", "--memory-swap", "64m", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1m", "--entrypoint", "/bin/sh", base_ref, "-c", "test -r /etc/os-release && cat /etc/os-release"], timeout=30)
    if result.returncode != 0:
        _fail("session2_environment_runtime_probe_failed")
    lines = set(result.stdout.decode("utf-8", "strict").splitlines())
    if "ID=alpine" in lines:
        return "musllinux_1_2_x86_64"
    if any(line in {"ID=debian", "ID=ubuntu"} for line in lines):
        return "manylinux_2_17_x86_64"
    _fail("session2_environment_runtime_platform_unsupported")


def _declared_test_packages(snapshot: Path, packages: set[str]) -> None:
    """Reject a command-specific package unless patient metadata declares it.

    The exact bytes remain pinned by ``uv.lock``; this guard prevents a caller
    from injecting an otherwise-lock-resolvable package merely because it
    happens to occur somewhere in the lock graph.  It intentionally supports
    a minimal test-runner subset when a broad development group also contains
    a prohibited VCS dependency.
    """
    if not packages:
        return
    metadata = snapshot / "pyproject.toml"
    if not metadata.is_file() or metadata.is_symlink():
        _fail("session2_environment_project_metadata_missing")
    try:
        document = tomllib.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EnvironmentBuildError("session2_environment_project_metadata_invalid") from exc
    declared: set[str] = set()
    groups = document.get("dependency-groups", {})
    optional = document.get("project", {}).get("optional-dependencies", {}) if isinstance(document.get("project"), dict) else {}
    values: list[object] = []
    if isinstance(groups, dict):
        values.extend(item for group in groups.values() if isinstance(group, list) for item in group)
    if isinstance(optional, dict):
        values.extend(item for group in optional.values() if isinstance(group, list) for item in group)
    for value in values:
        if isinstance(value, str):
            match = _DECLARED_REQUIREMENT.match(value)
            if match:
                declared.add(match.group(1).lower().replace("_", "-"))
    requested = {item.lower().replace("_", "-") for item in packages}
    if not requested.issubset(declared):
        _fail("session2_environment_additional_package_undeclared")


def _normalized_package_names(packages: set[str]) -> set[str]:
    """Return the canonical package keys used by ``uv.lock``.

    Declaration validation is case-insensitive by Python packaging convention.
    The exact same normalized keys must be passed to the lock exporter; doing
    otherwise makes a valid declared package (for example ``PyJWT``) appear
    absent solely because a caller used its display spelling.
    """
    return {item.lower().replace("_", "-") for item in packages}


def _authoritative_python_project_name(snapshot: Path, requested_project_name: str | None) -> str:
    """Derive the lockfile root from sealed project metadata, never a label.

    An earlier qualification invocation accidentally supplied a case label as
    ``project_name``.  That made a valid lockfile look malformed.  The caller
    may retain a project-name assertion for ergonomics, but the snapshot's
    committed ``[project].name`` is the only dependency-root authority.
    """
    metadata = snapshot / "pyproject.toml"
    if not metadata.is_file() or metadata.is_symlink():
        _fail("session2_environment_project_metadata_missing")
    try:
        document = tomllib.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EnvironmentBuildError("session2_environment_project_metadata_invalid") from exc
    project = document.get("project")
    name = project.get("name") if isinstance(project, dict) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        _fail("session2_environment_project_name_missing")
    if requested_project_name is not None and requested_project_name != name:
        _fail("session2_environment_project_name_assertion_mismatch")
    return name


def build_environment(repository: Path, *, snapshot: Path, project_name: str | None = None, implementation_commit: str, implementation_tree: str, materialization_hash: str, base_image_ref: str = DEFAULT_BASE_IMAGE_REF, extras: set[str] = frozenset(), groups: set[str] = frozenset(), additional_packages: set[str] = frozenset(), requirements_authority_path: str | None = None) -> dict[str, Any]:
    """Build exactly one image from a sealed dependency authority.

    All install authority is derived from the snapshot's lockfile.  A narrow
    test-runner package is permitted only when patient metadata declares it.
    """
    if not _GIT_SHA.fullmatch(implementation_commit) or not _GIT_SHA.fullmatch(implementation_tree) or not _HASH.fullmatch(materialization_hash):
        _fail("session2_environment_implementation_authority_invalid")
    receipts = _root(repository)
    if not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink():
        _fail("session2_environment_snapshot_invalid")
    _declared_test_packages(snapshot, additional_packages)
    additional_packages = _normalized_package_names(additional_packages)
    if requirements_authority_path is not None and (extras or groups or additional_packages):
        # A requirements authority is complete as committed.  Injecting a
        # group or an extra would be an unrecorded dependency-resolution step.
        _fail("session2_environment_requirements_authority_augmented")
    if requirements_authority_path is not None:
        # A hash-pinned requirements file can be the complete dependency
        # authority for repositories that do not expose a PEP 621 project at
        # their checkout root (for example a Django monorepo).  Do not invent
        # a caller project label in that mode: its authority is the committed
        # requirements path and bytes, recorded below.
        if project_name is not None:
            _fail("session2_environment_requirements_project_assertion_forbidden")
        if (not isinstance(requirements_authority_path, str) or not requirements_authority_path
                or requirements_authority_path.startswith("/") or ".." in requirements_authority_path.split("/")):
            _fail("session2_environment_requirements_authority_path_invalid")
        authority_file = snapshot / requirements_authority_path
        if not authority_file.is_file() or authority_file.is_symlink():
            _fail("session2_environment_requirements_authority_missing")
        authority_bytes = authority_file.read_bytes()
        try:
            requirements, authority_manifest = export_hash_pinned_requirements(authority_bytes, source_path=requirements_authority_path)
            requirement_records = pinned_requirement_records(authority_bytes, source_path=requirements_authority_path)
        except RequirementsAuthorityError as exc:
            failure = {"schema_id": "external_validation.session2_environment_build_failure.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "materialization_hash": materialization_hash, "failure_stage": "REQUIREMENTS_AUTHORITY", "failure_code": str(exc), "project_name": project_name, "requirements_authority_path": requirements_authority_path, "patient_network_policy": "none"}
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_requirements_authority_invalid:" + digest) from exc
        authority_kind = "hash_pinned_requirements"
        project_name = "requirements-authority"
        authority_hash = requirements_authority_hash(authority_manifest)
        dependency_manifest: dict[str, Any] = authority_manifest
        lock_hash: str | None = None
        selected_groups: list[str] = []
    else:
        project_name = _authoritative_python_project_name(snapshot, project_name)
        lock = snapshot / "uv.lock"
        if not lock.is_file() or lock.is_symlink():
        # A missing authority lock is a real qualification outcome.  Seal it
        # before returning so the candidate-screen record cannot be a manual
        # assertion about an otherwise unobserved snapshot.
            failure = {
            "schema_id": "external_validation.session2_environment_build_failure.v1",
            "schema_version": "1",
            "implementation_commit": implementation_commit,
            "implementation_tree": implementation_tree,
            "materialization_hash": materialization_hash,
            "failure_stage": "LOCKFILE_AUTHORITY",
            "failure_code": "session2_environment_lock_missing",
            "project_name": project_name,
            "dependency_groups": sorted(groups),
            "patient_network_policy": "none",
        }
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_lock_missing:" + digest)
        lock_bytes = lock.read_bytes()
        if any(not isinstance(group, str) or not group or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", group) for group in groups):
            _fail("session2_environment_group_invalid")
    # Test and executable-check dependencies are authority inputs.  They are
    # deliberately not inferred from a command line and become part of both
    # the build identity and the sealed environment receipt.
        selected_groups = sorted(groups)
        try:
            export = export_uv_requirements(lock_bytes, project_name=project_name, extras=set(extras), groups=set(selected_groups), additional_packages=set(additional_packages))
        except LockfileError as exc:
            failure = {"schema_id": "external_validation.session2_environment_build_failure.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "materialization_hash": materialization_hash, "failure_stage": "LOCKFILE_EXPORT", "failure_code": str(exc), "project_name": project_name, "dependency_groups": selected_groups, "lock_hash": _sha(lock_bytes), "patient_network_policy": "none"}
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_lock_export_failed:" + digest) from exc
        authority_kind = "uv_lock"
        requirements = export.requirements
        dependency_manifest = export.manifest
        authority_hash = requirements_manifest_hash(export)
        lock_hash = _sha(lock_bytes)
        requirement_records = []
    base_digest = _inspect_image(base_image_ref)
    platform_tag = _runtime_platform(base_digest)
    if authority_kind == "uv_lock":
        unsupported = _unsupported_packages(dependency_manifest, platform_tag=platform_tag)
        if unsupported:
            failure = {"schema_id": "external_validation.session2_environment_build_failure.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "materialization_hash": materialization_hash, "failure_stage": "LOCKED_WHEEL_COMPATIBILITY", "base_image_ref": base_image_ref, "base_image_digest": base_digest, "wheel_platform_tag": platform_tag, "project_name": project_name, "dependency_groups": selected_groups, "lock_hash": lock_hash, "requirements_manifest_hash": authority_hash, "unsupported_packages": unsupported, "patient_network_policy": "none"}
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_wheel_unavailable:" + digest)
    build_identity = sha256(canonical_json({"project": project_name, "authority_kind": authority_kind, "authority_hash": authority_hash, "base": base_digest, "groups": selected_groups})).hexdigest()
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
        (context / "requirements.txt").write_bytes(requirements)
        try:
            downloads = (_download_wheelhouse(context, dependency_manifest, platform_tag=platform_tag)
                         if authority_kind == "uv_lock"
                         else _download_requirements_wheelhouse(context, requirement_records, platform_tag=platform_tag))
        except EnvironmentBuildError as exc:
            failure = {
                "schema_id": "external_validation.session2_environment_build_failure.v1",
                "schema_version": "1",
                "implementation_commit": implementation_commit,
                "implementation_tree": implementation_tree,
                "materialization_hash": materialization_hash,
                "build_identity": build_identity,
                "failure_stage": "LOCKED_WHEEL_COMPATIBILITY",
                "failure_code": str(exc),
                "base_image_ref": base_image_ref,
                "base_image_digest": base_digest,
                "wheel_platform_tag": platform_tag,
                "project_name": project_name,
                "dependency_authority_kind": authority_kind,
                "dependency_authority_hash": authority_hash,
                "dependency_authority_manifest": dependency_manifest,
                "lock_hash": lock_hash,
                "patient_network_policy": "none",
            }
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError(str(exc) + ":" + digest) from exc
        for item in context.iterdir():
            os.chown(item, 0, 0); os.chmod(item, 0o400)
        tag = "shiproom-session2-" + build_identity[:24]
        started = _utc()
        result = _run(["/usr/bin/docker", "--host", "unix://" + str(SOCKET), "build", "--pull=false", "--network=none", "--tag", tag, str(context)], timeout=1800)
        completed = _utc()
        stdout, stderr = result.stdout, result.stderr
        logs = receipts / "logs"; logs.mkdir(mode=0o700, exist_ok=True)
        stdout_path, stdout_hash = _write_once(logs, ".environment-build.stdout", stdout)
        stderr_path, stderr_hash = _write_once(logs, ".environment-build.stderr", stderr)
        if result.returncode != 0:
            failure = {"schema_id": "external_validation.session2_environment_build_failure.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "materialization_hash": materialization_hash, "build_identity": build_identity, "dependency_groups": selected_groups, "started_at": started, "completed_at": completed, "exit_code": result.returncode, "stdout_hash": stdout_hash, "stderr_hash": stderr_hash, "dependency_authority_kind": authority_kind, "dependency_authority_hash": authority_hash, "lock_hash": lock_hash}
            _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
            raise EnvironmentBuildError("session2_environment_build_failed:" + digest)
        image_digest = _inspect_image(tag)
        receipt = {"schema_id": "external_validation.session2_environment_build_receipt.v1", "schema_version": "1", "implementation_commit": implementation_commit, "implementation_tree": implementation_tree, "materialization_hash": materialization_hash, "build_identity": build_identity, "base_image_ref": base_image_ref, "base_image_digest": base_digest, "wheel_platform_tag": platform_tag, "image_ref": tag, "runner_image_digest": image_digest, "project_name": project_name, "dependency_groups": selected_groups, "dependency_authority_kind": authority_kind, "dependency_authority_hash": authority_hash, "dependency_authority_manifest": dependency_manifest, "lock_hash": lock_hash, "dependency_downloads": downloads, "dockerfile_hash": _sha(dockerfile), "started_at": started, "completed_at": completed, "exit_code": result.returncode, "stdout": {"opaque_id": stdout_path.name, "bytes": len(stdout), "sha256": stdout_hash}, "stderr": {"opaque_id": stderr_path.name, "bytes": len(stderr), "sha256": stderr_hash}, "network_during_build": "none", "dependency_acquisition_network": "host_supervisor_hash_checked", "patient_network_policy": "none"}
        path, digest = _write_once(receipts, ".environment-build.json", canonical_json(receipt))
        return {"receipt_path": str(path), "receipt_hash": digest, "image_ref": tag, "runner_image_digest": image_digest, "dependency_authority_hash": authority_hash}
    finally:
        # Context contains public dependency metadata only.  It is never an
        # evidence authority and must not outlive the deterministic build.
        if context.exists():
            shutil.rmtree(context)


def node_runtime_unqualified(repository: Path, *, snapshot: Path, project_name: str | None = None,
                             implementation_commit: str, implementation_tree: str,
                             materialization_hash: str, yarn_authority_path: str) -> None:
    """Seal the absence of a qualified Node/Yarn runner without mislabelling it.

    Node packages are not Python lockfiles.  Until a separately qualified
    immutable Node image and lockfile installer exist, a Yarn-locked frontend
    is an honest Linux-path capability failure, not a missing dependency
    authority or an invented test result.
    """
    if (not _GIT_SHA.fullmatch(implementation_commit) or not _GIT_SHA.fullmatch(implementation_tree)
            or not _HASH.fullmatch(materialization_hash) or not snapshot.is_absolute()
            or not isinstance(yarn_authority_path, str) or not yarn_authority_path
            or yarn_authority_path.startswith("/") or ".." in yarn_authority_path.split("/")):
        _fail("session2_environment_node_probe_input_invalid")
    receipts = _root(repository)
    lock = snapshot / yarn_authority_path
    package = lock.parent / "package.json"
    if not lock.is_file() or lock.is_symlink() or not package.is_file() or package.is_symlink():
        _fail("session2_environment_node_authority_missing")
    lock_bytes = lock.read_bytes()
    try:
        package_value = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvironmentBuildError("session2_environment_node_package_invalid") from exc
    yarn = lock.name == "yarn.lock"
    npm = lock.name == "package-lock.json"
    if (not isinstance(package_value, dict)
            or (yarn and (not lock_bytes.startswith(b"# THIS IS AN AUTOGENERATED FILE") or b"yarn lockfile v1" not in lock_bytes[:256]))
            or (npm and not lock_bytes.lstrip().startswith(b"{"))
            or not (yarn or npm)):
        _fail("session2_environment_node_authority_invalid")
    sealed_project_name = package_value.get("name")
    if sealed_project_name is None:
        # A frontend lockfile can be an application-local authority rather
        # than a publishable package.  Its absence of an npm package name
        # must not conceal an otherwise valid Node-runner capability gap.
        if project_name is not None:
            _fail("session2_environment_project_name_assertion_mismatch")
        sealed_project_name = "node-authority"
    elif not isinstance(sealed_project_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@/-]*", sealed_project_name):
        # The package identity is not executable authority here.  Keep an
        # unusual application-local name out of an asserted provenance field
        # while still sealing the exact package.json and lock bytes.
        if project_name is not None:
            _fail("session2_environment_project_name_assertion_mismatch")
        sealed_project_name = "node-authority"
    if project_name is not None and project_name != sealed_project_name:
        _fail("session2_environment_project_name_assertion_mismatch")
    failure = {
        "schema_id": "external_validation.session2_environment_build_failure.v1",
        "schema_version": "1", "implementation_commit": implementation_commit,
        "implementation_tree": implementation_tree, "materialization_hash": materialization_hash,
        "failure_stage": "NODE_RUNTIME_CAPABILITY", "failure_code": "session2_environment_node_runner_unqualified",
        "project_name": sealed_project_name, "node_package_json_hash": _sha(package.read_bytes()),
        "node_lock_kind": "yarn_v1" if yarn else "npm_package_lock", "node_lock_hash": _sha(lock_bytes), "node_authority_path": yarn_authority_path,
        "patient_network_policy": "none",
    }
    _, digest = _write_once(receipts, ".environment-build-failure.json", canonical_json(failure))
    raise EnvironmentBuildError("session2_environment_node_runner_unqualified:" + digest)


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--snapshot", type=Path, required=True); parser.add_argument("--project", help="Optional assertion; the sealed project metadata is authoritative."); parser.add_argument("--implementation-commit", required=True); parser.add_argument("--implementation-tree", required=True); parser.add_argument("--materialization-hash", required=True); parser.add_argument("--extra", action="append", default=[]); parser.add_argument("--group", action="append", default=[]); parser.add_argument("--additional-package", action="append", default=[]); parser.add_argument("--requirements-authority-path"); parser.add_argument("--node-yarn-authority-path"); parser.add_argument("--base-image-ref", default=DEFAULT_BASE_IMAGE_REF)
    args = parser.parse_args()
    try:
        if args.node_yarn_authority_path is not None:
            if args.requirements_authority_path is not None or args.extra or args.group or args.additional_package:
                _fail("session2_environment_node_probe_input_invalid")
            node_runtime_unqualified(args.repository, snapshot=args.snapshot, project_name=args.project, implementation_commit=args.implementation_commit, implementation_tree=args.implementation_tree, materialization_hash=args.materialization_hash, yarn_authority_path=args.node_yarn_authority_path)
        print(json.dumps(build_environment(args.repository, snapshot=args.snapshot, project_name=args.project, implementation_commit=args.implementation_commit, implementation_tree=args.implementation_tree, materialization_hash=args.materialization_hash, base_image_ref=args.base_image_ref, extras=set(args.extra), groups=set(args.group), additional_packages=set(args.additional_package), requirements_authority_path=args.requirements_authority_path), sort_keys=True))
    except EnvironmentBuildError as exc:
        print(str(exc)); return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
