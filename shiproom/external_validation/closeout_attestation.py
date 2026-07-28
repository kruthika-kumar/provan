"""Root-staged creator for the final Session 1 status attestation.

The module is deliberately limited to Git/closeout validation and the status
attestation directory.  It never touches remediation runtime state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
from pathlib import Path

from . import status
from .trusted_attestation import TRUSTED_ROOT, TrustedAttestationError, load_trusted_attestation


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-c", "core.autocrlf=true", "-c", "safe.directory=" + str(root), *args], cwd=root, text=True, capture_output=True, check=False, timeout=20)
    if result.returncode:
        raise RuntimeError("closeout_attestation_git_invalid")
    return result.stdout.strip()


def _secure_directory(path: Path) -> None:
    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        if not current.exists():
            current.mkdir(mode=0o755)
        item = os.lstat(current)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_gid != 0 or item.st_mode & 0o022:
            raise RuntimeError("status_attestation_parent_untrusted")


def _write_attestation(document: dict[str, object]) -> tuple[Path, str]:
    _secure_directory(TRUSTED_ROOT)
    raw = _canonical(document)
    identifier = _hash(raw)
    target = TRUSTED_ROOT / (identifier + ".json")
    if target.exists():
        item = os.lstat(target)
        if not stat.S_ISREG(item.st_mode) or target.read_bytes() != raw:
            raise RuntimeError("status_attestation_existing_object_conflict")
        return target, identifier
    temporary = TRUSTED_ROOT / (".attestation-" + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
    try:
        os.write(fd, raw); os.fsync(fd); os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
    finally:
        os.close(fd)
    os.replace(temporary, target)
    directory_fd = os.open(TRUSTED_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target, identifier


def _self_test() -> None:
    """Run root-only ownership/mode/link checks in one removable subtree."""
    _secure_directory(TRUSTED_ROOT)
    root = TRUSTED_ROOT / (".selftest-" + secrets.token_hex(12))
    root.mkdir(mode=0o700)
    try:
        raw = b'{"schema_id":"test"}'
        identifier = _hash(raw)
        valid = root / (identifier + ".json")
        valid.write_bytes(raw); os.chown(valid, 0, 0); os.chmod(valid, 0o400)
        assert load_trusted_attestation(identifier, trusted_root=root).raw_bytes == raw
        untrusted = root / ("0" * 64 + ".json")
        untrusted.write_bytes(raw); os.chown(untrusted, 65534, 65534); os.chmod(untrusted, 0o400)
        try:
            load_trusted_attestation("0" * 64, trusted_root=root)
            raise RuntimeError("status_attestation_selftest_owner")
        except TrustedAttestationError as exc:
            if str(exc) not in {"status_attestation_owner_invalid", "status_attestation_id_mismatch"}:
                raise
        os.unlink(untrusted)
        link = root / ("1" * 64 + ".json")
        os.symlink(valid.name, link)
        try:
            load_trusted_attestation("1" * 64, trusted_root=root)
            raise RuntimeError("status_attestation_selftest_symlink")
        except TrustedAttestationError:
            pass
        os.unlink(link)
        hard = root / ("2" * 64 + ".json")
        os.link(valid, hard)
        try:
            load_trusted_attestation("2" * 64, trusted_root=root)
            raise RuntimeError("status_attestation_selftest_hardlink")
        except TrustedAttestationError as exc:
            if str(exc) != "status_attestation_hardlink_rejected":
                raise
        os.unlink(hard)
        os.unlink(valid)
    finally:
        if root.exists():
            for child in root.iterdir():
                child.unlink()
            root.rmdir()


def create(repository: Path, commit_a: str, commit_b: str) -> dict[str, str]:
    if os.geteuid() != 0:
        raise RuntimeError("status_attestation_root_required")
    repository = repository.resolve()
    commit_a_tree = _git(repository, "rev-parse", commit_a + "^{tree}")
    commit_b_tree = _git(repository, "rev-parse", commit_b + "^{tree}")
    if _git(repository, "merge-base", "--is-ancestor", commit_a, commit_b) != "":
        raise RuntimeError("status_attestation_implementation_not_ancestor")
    authority = repository / "external_validation/status/session1-status-authority.v1.json"
    authority_data = json.loads(authority.read_text(encoding="utf-8"))
    chain = repository / authority_data["current_chain"]["path"]
    proof = repository / "external_validation/proofs/session1/control_plane_repair_proof_manifest.json"
    manifest = repository / "external_validation/proofs/session1/session1_closeout_manifest.v1.json"
    document: dict[str, object] = {
        "schema_id": "external_validation.status_attestation.v2", "schema_version": "2",
        "implementation_commit": commit_a, "implementation_tree": commit_a_tree,
        "commit_b": commit_b, "commit_b_tree": commit_b_tree,
        "control_plane_proof_manifest_hash": status._committed_content_hash(repository, proof),
        "status_authority_hash": status._committed_content_hash(repository, authority),
        "status_chain_hash": status._committed_content_hash(repository, chain),
        "closeout_manifest_path": "external_validation/proofs/session1/session1_closeout_manifest.v1.json",
        "closeout_manifest_hash": status._committed_content_hash(repository, manifest),
    }
    _self_test()
    target, identifier = _write_attestation(document)
    resolved = status.resolve_status_authority(authority, repository_root=repository, attestation_id=identifier)
    expected = {"detection": "QUALIFIED", "remediation": "QUALIFIED", "overall": "QUALIFIED"}
    if resolved["profiles"] != expected:
        raise RuntimeError("status_attestation_authorized_resolution_invalid")
    item = os.lstat(target)
    if item.st_uid != 0 or item.st_gid != 0 or stat.S_IMODE(item.st_mode) != 0o400 or item.st_nlink != 1:
        raise RuntimeError("status_attestation_final_file_invalid")
    return {"path": str(target), "attestation_id": identifier, "sha256": "sha256:" + identifier, "profiles": json.dumps(resolved["profiles"], sort_keys=True)}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--commit-a", required=True); parser.add_argument("--commit-b", required=True)
    args = parser.parse_args(); print(json.dumps(create(args.repository, args.commit_a, args.commit_b), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
