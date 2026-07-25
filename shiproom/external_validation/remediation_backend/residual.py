#!/usr/bin/env python3
"""Fail-closed residual-reference proof for a releasing remediation tree.

This is intentionally a read-only helper.  It runs while the Python release
driver owns the fixed backend lock and the worktree has been revoked from the
patient principal.  An unreadable proc entry or an unavailable custom Docker
daemon is uncertainty, not evidence of absence.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

try:
    from .bootstrap import require_staged_script
    from .release_helper import mount_id as fd_mount_id
except ImportError:
    from bootstrap import require_staged_script
    from release_helper import mount_id as fd_mount_id


class ResidualBlocked(RuntimeError):
    pass


def _under_root(candidate: Path, root: Path, device: int) -> bool:
    """Test a live proc target against the registered root without trusting a string.

    ``samefile`` identifies the root itself.  For descendants we resolve the
    proc target and require both the expected filesystem and a canonical
    relative relationship to the registered root.  Any resolution error is
    handled by the caller as containment uncertainty.
    """
    value = candidate.stat()
    if value.st_dev != device:
        return False
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return True


def _proc_references(root: Path, device: int) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        pid = entry.name
        for name in ("cwd", "root", "exe"):
            candidate = entry / name
            try:
                target = os.readlink(candidate)
                # Deleted-but-open targets cannot be resolved after unlink.
                # This is read-only conservative evidence, not deletion path
                # authority: a canonical root-prefixed proc target is enough
                # to fail closed until the owning process is gone.
                textual_hit = target.removesuffix(" (deleted)") == str(root) or target.removesuffix(" (deleted)").startswith(str(root) + "/")
                if textual_hit or _under_root(candidate, root, device):
                    hits.append({"pid": int(pid), "kind": name, "target": target})
            except FileNotFoundError:
                continue  # Process exited between enumeration and inspection.
            except PermissionError as exc:
                raise ResidualBlocked("residual_proc_unreadable:" + pid) from exc
            except OSError:
                continue
        fds = entry / "fd"
        try:
            entries = list(fds.iterdir())
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise ResidualBlocked("residual_fd_unreadable:" + pid) from exc
        for fd in entries:
            try:
                target = os.readlink(fd)
                textual_hit = target.removesuffix(" (deleted)") == str(root) or target.removesuffix(" (deleted)").startswith(str(root) + "/")
                if textual_hit or _under_root(fd, root, device):
                    hits.append({"pid": int(pid), "kind": "fd", "fd": fd.name, "target": target})
            except FileNotFoundError:
                continue
            except PermissionError as exc:
                raise ResidualBlocked("residual_fd_unreadable:" + pid) from exc
            except OSError:
                continue
        maps = entry / "map_files"
        try:
            mappings = list(maps.iterdir())
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise ResidualBlocked("residual_map_files_unreadable:" + pid) from exc
        for mapping in mappings:
            try:
                target = os.readlink(mapping)
                textual_hit = target.removesuffix(" (deleted)") == str(root) or target.removesuffix(" (deleted)").startswith(str(root) + "/")
                if textual_hit or _under_root(mapping, root, device):
                    hits.append({"pid": int(pid), "kind": "map_file", "range": mapping.name, "target": target})
            except FileNotFoundError:
                continue
            except PermissionError as exc:
                raise ResidualBlocked("residual_map_files_unreadable:" + pid) from exc
            except OSError:
                continue
    return hits


def _mount_references(root: Path) -> list[str]:
    # Mountinfo escapes whitespace and backslashes.  The worktree authority
    # path is controlled and must not contain those characters; reject it if
    # it ever does rather than implement a lossy decoder.
    if any(ch.isspace() or ch == "\\" for ch in str(root)):
        raise ResidualBlocked("residual_root_path_unsupported")
    hits: list[str] = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise ResidualBlocked("residual_mountinfo_malformed")
        mountpoint = Path(fields[4])
        try:
            mountpoint.relative_to(root)
        except ValueError:
            continue
        hits.append(line)
    return hits


def _docker_references(socket: Path, root: Path) -> list[dict[str, object]]:
    docker = Path("/usr/bin/docker")
    if not docker.is_file():
        raise ResidualBlocked("residual_docker_missing")
    identity = docker.stat()
    if identity.st_uid != 0 or identity.st_mode & 0o022:
        raise ResidualBlocked("residual_docker_untrusted")
    try:
        socket_mode = socket.stat().st_mode
    except FileNotFoundError as exc:
        raise ResidualBlocked("residual_custom_socket_absent") from exc
    if not stat.S_ISSOCK(socket_mode):
        raise ResidualBlocked("residual_custom_socket_absent")
    base = [str(docker), "--host", "unix://" + str(socket)]
    listed = subprocess.run([*base, "ps", "-aq"], text=True, capture_output=True, timeout=30, check=False)
    if listed.returncode:
        raise ResidualBlocked("residual_docker_unavailable")
    ids = [line for line in listed.stdout.splitlines() if line]
    if not ids:
        return []
    inspected = subprocess.run([*base, "inspect", *ids], text=True, capture_output=True, timeout=30, check=False)
    if inspected.returncode:
        raise ResidualBlocked("residual_docker_inspect_failed")
    try:
        records = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise ResidualBlocked("residual_docker_inspect_malformed") from exc
    hits: list[dict[str, object]] = []
    for record in records:
        for mount in record.get("Mounts", []):
            source = mount.get("Source")
            if not isinstance(source, str):
                continue
            try:
                Path(source).resolve(strict=True).relative_to(root)
            except (FileNotFoundError, ValueError):
                continue
            hits.append({"container": record.get("Id"), "source": source, "destination": mount.get("Destination")})
    return hits


def assert_absent(root: Path, device: int, inode: int, mount_id: int, socket: Path, aliases: list[Path]) -> dict[str, object]:
    root = root.resolve(strict=True)
    value = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_dev != device or value.st_ino != inode:
        raise ResidualBlocked("residual_root_authority_changed")
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if fd_mount_id(fd) != mount_id:
            raise ResidualBlocked("residual_mount_authority_changed")
    finally:
        os.close(fd)
    # The root cannot remain patient-writable while checking it.  The caller
    # has already recorded RELEASE/RELEASING in SQLite; this is an additional
    # kernel-enforced revocation before the second residual sweep.
    if value.st_uid != 0 or value.st_mode & 0o077:
        raise ResidualBlocked("residual_patient_access_not_revoked")
    for alias in aliases:
        try:
            alias_value = alias.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if alias_value.st_dev == device and alias_value.st_ino == inode and alias.resolve(strict=True) != root:
            raise ResidualBlocked("residual_registered_alias")
    proc_hits = _proc_references(root, device)
    mount_hits = _mount_references(root)
    docker_hits = _docker_references(socket, root)
    if proc_hits or mount_hits or docker_hits:
        raise ResidualBlocked("residual_reference_present")
    return {"root": str(root), "device": device, "inode": inode, "mount_id": mount_id, "proc_hits": 0, "mount_hits": 0, "docker_hits": 0}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--device", type=int, required=True)
    p.add_argument("--inode", type=int, required=True)
    p.add_argument("--mount-id", type=int, required=True)
    p.add_argument("--socket", type=Path, required=True)
    p.add_argument("--aliases-json", type=Path, required=True)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise ResidualBlocked("residual_root_required")
    require_staged_script(Path(__file__))
    aliases = [Path(item) for item in json.loads(a.aliases_json.read_text(encoding="utf-8"))]
    print(json.dumps(assert_absent(a.root, a.device, a.inode, a.mount_id, a.socket, aliases), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ResidualBlocked, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print("residual_error:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
