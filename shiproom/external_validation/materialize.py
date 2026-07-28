from __future__ import annotations

import os, re, shutil, subprocess
from pathlib import Path
from .security import canonical_safe_path

def _git(cwd: Path, *args: str) -> str:
    env=os.environ.copy(); env.update({"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_LFS_SKIP_SMUDGE":"1","GIT_CONFIG_COUNT":"3","GIT_CONFIG_KEY_0":"core.hooksPath","GIT_CONFIG_VALUE_0":os.devnull,"GIT_CONFIG_KEY_1":"submodule.recurse","GIT_CONFIG_VALUE_1":"false","GIT_CONFIG_KEY_2":"filter.lfs.smudge","GIT_CONFIG_VALUE_2":"cat"})
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", *args],cwd=cwd,text=True,capture_output=True,check=True,env=env).stdout.strip()

def materialize_snapshot(mirror: Path, commit_sha: str, destination: Path) -> Path:
    """Export only tracked bytes; no checkout, hook, filter, LFS, or submodule execution."""
    if not mirror.is_dir() or not (mirror / "HEAD").exists(): raise ValueError("isolated_bare_mirror_required")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit_sha): raise ValueError("immutable_commit_required")
    try:
        resolved = _git(mirror, "rev-parse", "--verify", commit_sha + "^{commit}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("immutable_checkout_mismatch") from exc
    if resolved != commit_sha: raise ValueError("immutable_checkout_mismatch")
    if any(line.startswith("160000 ") for line in _git(mirror, "ls-tree", "-r", commit_sha).splitlines()): raise ValueError("submodules_not_qualified")
    if destination.exists(): raise FileExistsError("patient_snapshot_destination_exists")
    env=os.environ.copy(); env.update({"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_LFS_SKIP_SMUDGE":"1","GIT_CONFIG_COUNT":"3","GIT_CONFIG_KEY_0":"core.hooksPath","GIT_CONFIG_VALUE_0":os.devnull,"GIT_CONFIG_KEY_1":"submodule.recurse","GIT_CONFIG_VALUE_1":"false","GIT_CONFIG_KEY_2":"filter.lfs.smudge","GIT_CONFIG_VALUE_2":"cat"})
    archive = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "archive", "--format=tar", commit_sha], cwd=mirror, capture_output=True, check=True, env=env).stdout
    import tarfile, io
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        members = tar.getmembers()
        # Git archive legitimately emits directories.  Validate the entire
        # member set before creating a staging tree, so a malformed archive
        # cannot leave a partially materialized patient snapshot behind.
        for member in members:
            if member.issym() or member.islnk() or (not member.isfile() and not member.isdir()):
                raise ValueError("unsafe_patient_tree_entry")
            canonical_safe_path(destination, destination/member.name)
        destination.mkdir(parents=True)
        for member in members:
            if member.isdir():
                continue
            target=canonical_safe_path(destination, destination/member.name)
            target.parent.mkdir(parents=True,exist_ok=True)
            source = tar.extractfile(member)
            if source is None: raise ValueError("archive_member_missing")
            with source, target.open("xb") as output: shutil.copyfileobj(source,output)
    return destination
