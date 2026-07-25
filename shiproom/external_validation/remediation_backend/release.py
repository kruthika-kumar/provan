#!/usr/bin/env python3
"""Root-only supervisor release transaction for one remediation worktree."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import fcntl
from contextlib import contextmanager
from pathlib import Path

os.environ["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin"

try:
    from .control import Control, ControlError, canonical, digest
    from .contracts import ContractError, validate_release_authorization
    from .release_helper import mount_id
    from .bootstrap import require_staged_script
except ImportError:
    from control import Control, ControlError, canonical, digest
    from contracts import ContractError, validate_release_authorization
    from release_helper import mount_id
    from bootstrap import require_staged_script


class ReleaseError(RuntimeError):
    pass


LOCK = Path("/run/lock/shiproom-remediation.backend.lock")


@contextmanager
def backend_lock():
    """Hold the fixed, non-removable backend lock for the entire release."""
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    inherited = False
    try:
        candidate = os.fstat(9)
        on_disk = LOCK.stat()
        inherited = candidate.st_dev == on_disk.st_dev and candidate.st_ino == on_disk.st_ino
    except OSError:
        inherited = False
    item = os.fdopen(9, "a+", encoding="ascii", closefd=False) if inherited else LOCK.open("a+", encoding="ascii")
    try:
        os.chmod(LOCK, 0o600)
        fcntl.flock(item.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(item.fileno(), fcntl.LOCK_UN)
        if not inherited:
            item.close()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def root_regular(path: Path, root: Path) -> None:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ReleaseError("authorization_outside_supervisor_root") from exc
    value = resolved.stat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        raise ReleaseError("authorization_not_root_owned_immutable")


def load_authorization(path: Path, authorization_root: Path) -> dict[str, object]:
    root_regular(path, authorization_root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("authorization_json_invalid") from exc
    validate_release_authorization(value)
    return value


def rehash_records(document: dict[str, object], supervisor_root: Path) -> None:
    expected = {
        str(document["sealed_artifact_manifest_hash"]), str(document["patch_hash"]),
        str(document["changed_file_manifest_hash"]), str(document["untracked_file_manifest_hash"]),
        *[str(x) for x in document["test_result_hashes"]], *[str(x) for x in document["log_hashes"]],
    }
    actual: set[str] = set()
    for item in document["artifact_records"]:
        record = dict(item)
        path = Path(str(record["canonical_path"]))
        root_regular(path, supervisor_root)
        value = sha256(path)
        if value != record["sha256"]:
            raise ReleaseError("authorization_artifact_rehash_mismatch")
        actual.add(value)
    if not expected.issubset(actual):
        raise ReleaseError("authorization_artifact_record_incomplete")


def run(command: list[str]) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30, check=False)
    if result.returncode:
        raise ReleaseError("release_command_failed:" + " ".join(command[:3]))


def residual_proof(script: Path, tree: Path, authority: dict[str, object], socket: Path, aliases: Path) -> None:
    run(["/usr/bin/python3", str(script), "--root", str(tree), "--device", str(authority["device"]), "--inode", str(authority["inode"]), "--mount-id", str(authority["mount_id"]), "--socket", str(socket), "--aliases-json", str(aliases)])


def trusted_binary(name: str) -> str:
    path = next((Path(prefix)/name for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin") if (Path(prefix)/name).is_file()), None)
    if path is None: raise ReleaseError("trusted_binary_missing:"+name)
    item=path.stat()
    if item.st_uid!=0 or item.st_mode&0o022: raise ReleaseError("trusted_binary_untrusted:"+name)
    return str(path)
def project_clear(mount: Path, tree: Path, project: int) -> None:
    quota=trusted_binary("xfs_quota")
    run([quota, "-x", "-c", f"project -C -p {tree} {project}", str(mount)])
    # A second assignment of the retired ID must fail on a real qualified XFS
    # backend; doctor proves this command's project-specific evidence.
    report = subprocess.run([quota, "-x", "-d", str(project), "-c", "quota -p -nN", str(mount)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30, check=False)
    if report.returncode == 0 and any(line.split()[:1] == [str(project)] for line in report.stdout.splitlines()):
        raise ReleaseError("project_clear_unverified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--authorization-root", type=Path, required=True)
    parser.add_argument("--supervisor-root", type=Path, required=True)
    parser.add_argument("--mount", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ReleaseError("release_root_required")
    require_staged_script(Path(__file__))
    document = load_authorization(args.authorization, args.authorization_root)
    with backend_lock():
      control = Control(args.db)
      try:
        control.assert_ready()
        indexed = control.authorization(str(document["authorization_id"]))
        if indexed["attempt_id"] != document["attempt_id"] or indexed["content_hash"] != digest(document) or Path(str(indexed["artifact_path"])).resolve() != args.authorization.resolve():
            raise ReleaseError("authorization_index_mismatch")
        allocation = control.allocation(str(document["attempt_id"]))
        authority = dict(document["worktree_authority"])
        for key in ("attempt_id", "project_id", "worktree_hash"):
            if key == "worktree_hash":
                if authority["path_hash"] != allocation[key]: raise ReleaseError("worktree_authority_mismatch")
            elif authority[key] != allocation[key]: raise ReleaseError("worktree_authority_mismatch")
        tree = Path(str(authority["canonical_path"]))
        st = tree.stat(follow_symlinks=False)
        if st.st_dev != authority["device"] or st.st_ino != authority["inode"] or st.st_uid != authority["uid"] or st.st_gid != authority["gid"]:
            raise ReleaseError("worktree_authority_changed")
        fd = os.open(tree, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if mount_id(fd) != authority["mount_id"]:
                raise ReleaseError("worktree_mount_changed")
        finally:
            os.close(fd)
        rehash_records(document, args.supervisor_root)
        attempt = str(document["attempt_id"]); project = int(document["project_id"])
        # Revoke the untrusted UID only after all evidence was sealed and
        # independently rehashed.  A root-owned 0700 tree prevents a patient
        # from racing the residual sweep or destructive helper.
        os.chown(tree, 0, 0); os.chmod(tree, 0o700)
        aliases = args.supervisor_root / "release-aliases" / (attempt + ".json")
        aliases.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        aliases.write_bytes(canonical(control.registered_worktree_paths()))
        os.chown(aliases, 0, 0); os.chmod(aliases, 0o400)
        residual = Path(__file__).with_name("residual.py")
        if not residual.is_file(): raise ReleaseError("residual_helper_missing")
        residual_proof(residual, tree, authority, args.socket, aliases)
        control.release_phase(attempt, "RESIDUAL_ABSENCE_VERIFIED", {"authorization_id": document["authorization_id"], "rehash": True, "aliases_hash": sha256(aliases)})
        control.release_phase(attempt, "WORKTREE_CONTENT_DELETE_STARTED")
        if args.helper.resolve() != Path(__file__).with_name("release_helper.py").resolve(): raise ReleaseError("release_helper_path_untrusted")
        # Recheck directly before descriptor-relative deletion.  This remains
        # under the same fixed lock and RELEASING lifecycle transaction.
        residual_proof(residual, tree, authority, args.socket, aliases)
        run(["/usr/bin/python3", str(args.helper), "delete-contents", "--root", str(tree), "--expected-device", str(st.st_dev), "--expected-inode", str(st.st_ino), "--expected-mount-id", str(authority["mount_id"])])
        control.release_phase(attempt, "WORKTREE_EMPTY_VERIFIED")
        control.release_phase(attempt, "PROJECT_CLEAR_STARTED")
        project_clear(args.mount, tree, project)
        control.release_phase(attempt, "PROJECT_CLEARED_VERIFIED")
        control.release_phase(attempt, "WORKTREE_ROOT_DELETE_STARTED")
        run(["/usr/bin/python3", str(args.helper), "delete-root", "--root", str(tree), "--expected-device", str(st.st_dev), "--expected-inode", str(st.st_ino), "--expected-mount-id", str(authority["mount_id"])])
        if tree.exists():
            raise ReleaseError("worktree_absence_unverified")
        control.release_phase(attempt, "WORKTREE_ABSENT_VERIFIED")
        control.release_phase(attempt, "REGISTRY_REMOVAL_PREPARED")
        control.commit_release(attempt)
      except Exception as exc:
        try:
            control.incident("RELEASE_UNCERTAIN", "QUOTA_STATE_UNCERTAIN", {"error": str(exc), "authorization": str(args.authorization)})
        except Exception:
            pass
        raise
      finally:
        control.close()
    print("release_committed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, ControlError, ContractError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"release_error:{exc}", file=sys.stderr)
        raise SystemExit(2)
