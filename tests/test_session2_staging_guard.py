"""Regression tests for the WSL-unmounted supervisor-staging incident."""
from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from shiproom.external_validation import session2_materialize as materialize
from shiproom.external_validation import session2_fresh_case as fresh_case
from shiproom.external_validation import session2_staging_guard as guard


def _state(path: Path, *, image: Path, mount: Path, loop: str = "/dev/loop7") -> None:
    values = {
        "IMAGE": str(image), "MOUNT": str(mount), "RUN": "/run/shiproom-remediation-docker",
        "LOOP": loop, "DATA_PROJECT": "10000", "DATA_BYTES": "8589934592", "DATA_INODES": "200000",
    }
    path.write_text("".join(key + "\t" + base64.b64encode(value.encode()).decode() + "\n" for key, value in values.items()), encoding="ascii")


def _qualified(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    root = tmp_path / "root"; root.mkdir(); image = root / "shiproom-remediation.xfs"; image.write_bytes(b"x")
    state = root / "backend.state"; mount = tmp_path / "mount"; mount.mkdir(); _state(state, image=image, mount=mount)
    monkeypatch.setattr(guard, "ROOT", root); monkeypatch.setattr(guard, "IMAGE", image)
    monkeypatch.setattr(guard, "STATE", state); monkeypatch.setattr(guard, "MOUNT", mount)
    monkeypatch.setattr(guard, "SUPERVISOR_ROOT", mount / "session2-supervisor")
    monkeypatch.setattr(guard, "_linux_root", lambda: True)
    monkeypatch.setattr(guard, "_state", lambda: {"IMAGE": str(image), "MOUNT": str(mount), "RUN": "/run/shiproom-remediation-docker", "LOOP": "/dev/loop7", "DATA_PROJECT": "10000", "DATA_BYTES": "8589934592", "DATA_INODES": "200000"})
    monkeypatch.setattr(guard.os.path, "ismount", lambda _: True)
    def run(*argv: str) -> str:
        if argv[0].endswith("findmnt"): return "/dev/loop7 xfs rw,noatime,prjquota\n"
        if argv[0].endswith("losetup"): return str(image) + "\n"
        if argv[0].endswith("xfs_info"): return "naming   =version 2 bsize=4096 ascii-ci=0, ftype=1\n"
        if argv[0].endswith("xfs_quota"):
            # Exact 12-field numeric form exercised by the qualified backend
            # command shim for ``quota -p -nNv -b -i <project>``.
            return "/dev/loop7 0 0 8388608 0 - 0 0 200000 0 - " + str(mount).replace(" ", "\\040") + "\n"
        raise AssertionError(argv)
    return mount, run


def test_verified_xfs_identity_is_required_before_supervisor_staging_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    mount, run = _qualified(monkeypatch, tmp_path)
    result = guard.require_supervisor_staging(mount / "session2-supervisor" / "mirrors", run=run)
    assert result["loop"] == "/dev/loop7"
    assert result["data_bytes"] == "8589934592"


def test_ext4_or_unmounted_directory_is_never_treated_as_staging(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _mount, run = _qualified(monkeypatch, tmp_path)
    def ext4(*argv: str) -> str:
        if argv[0].endswith("findmnt"): return "/dev/loop7 ext4 rw,noatime\n"
        return run(*argv)
    with pytest.raises(guard.StagingGuardError, match="session2_staging_guard_mount_invalid"):
        guard.verify_supervisor_staging(run=ext4)
    monkeypatch.setattr(guard.os.path, "ismount", lambda _: False)
    with pytest.raises(guard.StagingGuardError, match="session2_staging_guard_mount_invalid"):
        guard.verify_supervisor_staging(run=run)


def test_wrong_loop_image_or_quota_evidence_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _mount, run = _qualified(monkeypatch, tmp_path)
    def wrong_loop(*argv: str) -> str:
        if argv[0].endswith("losetup"): return "/wrong/image\n"
        return run(*argv)
    with pytest.raises(guard.StagingGuardError, match="session2_staging_guard_loop_identity_invalid"):
        guard.verify_supervisor_staging(run=wrong_loop)
    def no_quota(*argv: str) -> str:
        if argv[0].endswith("xfs_quota"): return ""
        return run(*argv)
    with pytest.raises(guard.StagingGuardError, match="session2_staging_guard_quota_invalid"):
        guard.verify_supervisor_staging(run=no_quota)
    def wrong_limit(*argv: str) -> str:
        if argv[0].endswith("xfs_quota"):
            return "/dev/loop7 0 0 1024 0 - 0 0 200000 0 - " + str(_mount).replace(" ", "\\040") + "\n"
        return run(*argv)
    with pytest.raises(guard.StagingGuardError, match="session2_staging_guard_quota_invalid"):
        guard.verify_supervisor_staging(run=wrong_limit)


def test_active_materialization_under_supervisor_staging_is_rejected_before_any_write(tmp_path: Path):
    for destination in (
        Path("/mnt/shiproom-remediation/session2-supervisor/materializations/claim/buggy"),
        Path("/mnt/shiproom-remediation/session2-supervisor/snapshots/claim/fixed"),
    ):
        with pytest.raises(materialize.MaterializationError, match="session2_materialization_direct_supervisor_staging_forbidden"):
            materialize.seal_materialization(
                tmp_path, candidate_id="fixture", mirror=tmp_path / "missing", commit_sha="a" * 40,
                destination=destination, source_object_receipt_hashes=["sha256:" + "a" * 64, "sha256:" + "b" * 64],
                mirror_receipt_hash="sha256:" + "c" * 64,
            )
    assert not (tmp_path / "missing").exists()


def test_materialization_requires_an_allocator_bound_quota_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    mount = tmp_path / "qualified-mount"; tree = mount / "worktrees" / "successor"; tree.mkdir(parents=True)
    value = tree.stat()
    authority = {"canonical_path": str(tree), "device": value.st_dev, "inode": value.st_ino,
                 "uid": value.st_uid, "gid": value.st_gid}
    class Control:
        def __init__(self, _path: Path): pass
        def assert_ready(self): pass
        def allocation(self, attempt: str):
            assert attempt == "successor"
            return {"attempt_id": attempt, "status": "ACTIVE", "phase": "REGISTRY_COMMITTED",
                    "worktree_authority_json": authority}
        def close(self): pass
    monkeypatch.setattr(materialize, "MOUNT", mount); monkeypatch.setattr(materialize, "Control", Control)
    assert materialize._allocation_bound_destination(tree / "snapshots" / "buggy", "successor") == authority
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_quota_worktree_authority_required"):
        materialize._allocation_bound_destination(tree / "snapshots" / "buggy", None)
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_quota_worktree_authority_invalid"):
        materialize._allocation_bound_destination(mount / "worktrees" / "other" / "buggy", "successor")
    class Inactive(Control):
        def allocation(self, attempt: str):
            value = super().allocation(attempt); value["status"] = "RELEASED_RETIRED"; return value
    monkeypatch.setattr(materialize, "Control", Inactive)
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_quota_worktree_authority_invalid"):
        materialize._allocation_bound_destination(tree / "snapshots" / "buggy", "successor")


def test_public_materializer_rejects_any_caller_selected_path_before_export(tmp_path: Path):
    for destination in (tmp_path / "elsewhere", Path("/mnt/another-tree/case")):
        with pytest.raises(materialize.MaterializationError, match="session2_materialization_quota_worktree_authority_required|session2_materialization_quota_worktree_authority_invalid"):
            materialize.seal_materialization(
                tmp_path, candidate_id="fixture", mirror=tmp_path / "missing", commit_sha="a" * 40,
                destination=destination, source_object_receipt_hashes=["sha256:" + "a" * 64, "sha256:" + "b" * 64],
                mirror_receipt_hash="sha256:" + "c" * 64, allocation_attempt="successor",
            )


def test_descriptor_preparation_rejects_traversal_and_symlinked_ancestors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    tree = tmp_path / "worktree"; tree.mkdir(); item = tree.stat()
    authority = {"canonical_path": str(tree), "device": item.st_dev, "inode": item.st_ino,
                 "uid": item.st_uid, "gid": item.st_gid}
    for destination in (tree / ".." / "outside", tree / "sub" / ".." / "outside"):
        with pytest.raises(materialize.MaterializationError, match="session2_materialization_destination_invalid"):
            with materialize._prepared_allocation_destination(destination, authority):
                pass
    linked = tree / "linked"
    try:
        linked.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("Windows test runner lacks the symlink/dirfd capabilities required for this Linux-only assertion")
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_destination_ancestor_unsafe"):
        with materialize._prepared_allocation_destination(linked / "outside", authority):
            pass


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires Linux root dirfd and ownership semantics")
def test_linux_descriptor_path_allows_twins_but_rejects_patient_and_symlink_ancestors(tmp_path: Path):
    tree = tmp_path / "worktree"; tree.mkdir(mode=0o700); value = tree.stat()
    authority = {"canonical_path": str(tree), "device": value.st_dev, "inode": value.st_ino,
                 "uid": value.st_uid, "gid": value.st_gid}
    for name in ("buggy", "fixed"):
        with materialize._prepared_allocation_destination(tree / "source-materializations" / "claim" / name, authority) as (safe, _relative):
            safe.mkdir(mode=0o700)
    assert (tree / "source-materializations" / "claim" / "buggy").is_dir()
    assert (tree / "source-materializations" / "claim" / "fixed").is_dir()
    patient = tree / "patient"; patient.mkdir(mode=0o700); os.chown(patient, 65533, 65533)
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_destination_ancestor_unsafe"):
        with materialize._prepared_allocation_destination(patient / "bad", authority):
            pass
    link = tree / "link"; link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_destination_ancestor_unsafe"):
        with materialize._prepared_allocation_destination(link / "bad", authority):
            pass


def test_fresh_compiler_rejects_worktree_prefix_without_sealed_allocation_binding(tmp_path: Path):
    snapshot = tmp_path / "worktrees" / "residue"; snapshot.mkdir(parents=True)
    with pytest.raises(fresh_case.FreshQualificationError, match="session2_fresh_license_snapshot_authority_missing"):
        fresh_case._allocation_bound_snapshot({}, snapshot)
