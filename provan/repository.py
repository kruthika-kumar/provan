from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_bytes, sha256_bytes
from .errors import CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, QUALIFIED_SANDBOX_REQUIRED, ProvanError
from .state import state_root, trusted_output_path, write_output
from .validators import validate_inspection_semantics

SAFE_GITHUB = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
PINNED_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_OBJECT_FILES = 200_000
MAX_REPOSITORY_BYTES = 512 * 1024 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_TREE_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_INSPECTION_BYTES = 64 * 1024 * 1024
MAX_FINGERPRINT_FILES = 250_000
MAX_FINGERPRINT_BYTES = 1024 * 1024 * 1024
FINGERPRINT_TIMEOUT_SECONDS = 30


def _reject_source(source: str) -> None:
    lowered = source.lower()
    parsed = urlsplit(source)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ProvanError("CREDENTIAL_BEARING_URL_FORBIDDEN", "repository URL may not contain credentials")
    if lowered.startswith(("file://", "ext::", "ssh://", "git://", "http://")) or "::" in source:
        raise ProvanError("UNSAFE_GIT_PROTOCOL_FORBIDDEN", "unsafe Git protocol or helper")
    if "://" in source and not SAFE_GITHUB.fullmatch(source):
        raise ProvanError("REPOSITORY_ORIGIN_NOT_ALLOWED", "only credential-free public GitHub HTTPS is allowed")


def _tree_fingerprint(root: Path) -> str:
    # XOR of per-entry digests is deterministic without sorting or first
    # materialising an unbounded path list.
    accumulator=bytearray(32); entries=0; total=0; deadline=time.monotonic()+FINGERPRINT_TIMEOUT_SECONDS
    stack=[root]
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries+=1
                if entries>MAX_FINGERPRINT_FILES or time.monotonic()>deadline:
                    raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","target fingerprint exceeds entry or time limit")
                path=Path(entry.path); relative=path.relative_to(root).as_posix(); item=hashlib.sha256(relative.encode())
                if entry.is_symlink(): item.update(b"SYMLINK"); item.update(os.readlink(path).encode())
                elif entry.is_dir(follow_symlinks=False): item.update(b"DIR"); stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    size=entry.stat(follow_symlinks=False).st_size; total+=size
                    if total>MAX_FINGERPRINT_BYTES: raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","target fingerprint exceeds byte limit")
                    item.update(b"FILE"); item.update(str(size).encode())
                    with path.open("rb") as handle:
                        while chunk:=handle.read(1024*1024):
                            item.update(chunk)
                            if time.monotonic()>deadline: raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","target fingerprint exceeded time limit")
                observed=item.digest()
                for index,value in enumerate(observed): accumulator[index]^=value
    return bytes(accumulator).hex()


def _require_pinned_commit(value: str, label: str) -> None:
    if not PINNED_COMMIT.fullmatch(value):
        raise ProvanError("PINNED_COMMIT_REQUIRED", f"{label} must be a full commit object ID")


def _bounded_object_store(git_dir: Path) -> None:
    objects = git_dir / "objects"
    alternate = objects / "info" / "alternates"
    if alternate.exists() or alternate.is_symlink():
        raise ProvanError("UNSAFE_GIT_ALTERNATES_FORBIDDEN", "repository object alternates are not inspectable")
    count=0; size=0; deadline=time.monotonic()+FINGERPRINT_TIMEOUT_SECONDS; stack=[objects]
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                count+=1
                if count>MAX_OBJECT_FILES or time.monotonic()>deadline:
                    raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","repository object store exceeds entry or time limit")
                if entry.is_symlink(): raise ProvanError("UNSAFE_GIT_OBJECT_STORE_FORBIDDEN","symlinked object-store content is forbidden")
                if entry.is_dir(follow_symlinks=False): stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    size+=entry.stat(follow_symlinks=False).st_size
                    if size>MAX_REPOSITORY_BYTES: raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","repository object store exceeds byte limit")


def _scratch_usage(root: Path) -> tuple[int, int]:
    count = 0; size = 0; deadline = time.monotonic() + FINGERPRINT_TIMEOUT_SECONDS; stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    count += 1
                    if count > MAX_OBJECT_FILES or time.monotonic() > deadline:
                        return MAX_OBJECT_FILES + 1, size
                    try:
                        if entry.is_symlink():
                            return MAX_OBJECT_FILES + 1, size
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            size += entry.stat(follow_symlinks=False).st_size
                            if size > MAX_REPOSITORY_BYTES: return count, size
                    except FileNotFoundError:
                        # Git mutates its private scratch clone concurrently
                        # with this resource monitor. A vanished scratch entry
                        # consumes no remaining resource and is not a target
                        # repository integrity signal.
                        continue
        except FileNotFoundError:
            # A directory queued from the prior scan may be removed by Git
            # before traversal. Never leak a platform exception from the
            # source-only fail-closed monitor.
            continue
    return count, size


def _git_env(home: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home), "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / "xdg"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "", "GIT_SSH_COMMAND": "false", "GIT_OPTIONAL_LOCKS": "0",
    }
    # Git for Windows requires these process-runtime variables for DNS and
    # helper startup. They carry no repository credentials or Git policy.
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"):
        if os.environ.get(name): env[name] = os.environ[name]
    return env


def _run(argv: list[str], cwd: Path, home: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    env = _git_env(home)
    argv = [argv[0], "-c", f"core.excludesFile={os.devnull}", *argv[1:]]
    started = time.monotonic()
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", dir=cwd, delete=True) as stdout, tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", dir=cwd, delete=True) as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env, text=True, stdout=stdout, stderr=stderr,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=="nt" else 0,
                                   start_new_session=os.name!="nt")
        exceeded = False
        while process.poll() is None:
            count, size = _scratch_usage(cwd)
            if count > MAX_OBJECT_FILES or size > MAX_REPOSITORY_BYTES or time.monotonic() - started > timeout:
                exceeded = True
                if os.name == "nt":
                    subprocess.run(["taskkill","/PID",str(process.pid),"/T","/F"],capture_output=True,check=False)
                else:
                    os.killpg(process.pid,signal.SIGKILL)
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                break
            time.sleep(0.02)
        count, size = _scratch_usage(cwd)
        if count > MAX_OBJECT_FILES or size > MAX_REPOSITORY_BYTES:
            exceeded = True
        stdout.seek(0); stderr.seek(0)
        out = stdout.read(MAX_TREE_OUTPUT_BYTES + 1); err = stderr.read(MAX_TREE_OUTPUT_BYTES + 1)
        if exceeded or len(out.encode("utf-8")) > MAX_TREE_OUTPUT_BYTES or len(err.encode("utf-8")) > MAX_TREE_OUTPUT_BYTES:
            raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED", "Git inspection exceeded bounded time, storage, or output")
        return subprocess.CompletedProcess(argv, process.returncode, out, err)


def _inspect_blob_contents(git_dir: Path, blobs: list[tuple[str, str, int]], home: Path) -> tuple[int, int, str]:
    total = sum(size for _, _, size in blobs)
    if total > MAX_SOURCE_INSPECTION_BYTES:
        raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED", "source blobs exceed inspection byte limit")
    request = b"".join(oid.encode("ascii") + b"\n" for oid, _, _ in blobs)
    try:
        result = subprocess.run(
            ["git", "--git-dir", str(git_dir), "cat-file", "--batch"],
            input=request, capture_output=True, check=False, timeout=60, env=_git_env(home),
        )
    except subprocess.TimeoutExpired as exc:
        raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED", "source blob inspection exceeded time limit") from exc
    if result.returncode or result.stderr:
        raise ProvanError("BLOB_INSPECTION_FAILED", result.stderr.decode("utf-8", errors="replace")[:300])
    cursor = 0; digest = hashlib.sha256()
    for expected_oid, name, expected_size in blobs:
        header_end = result.stdout.find(b"\n", cursor)
        if header_end < 0 or header_end - cursor > 256:
            raise ProvanError("BLOB_INSPECTION_FAILED", "invalid cat-file batch header")
        header = result.stdout[cursor:header_end].decode("ascii", errors="strict").split()
        if len(header) != 3 or header[0] != expected_oid or header[1] != "blob" or int(header[2]) != expected_size:
            raise ProvanError("BLOB_INSPECTION_FAILED", "blob identity or size changed during inspection")
        start = header_end + 1; end = start + expected_size
        if end >= len(result.stdout) or result.stdout[end:end + 1] != b"\n":
            raise ProvanError("BLOB_INSPECTION_FAILED", "truncated cat-file batch content")
        content = result.stdout[start:end]
        digest.update(name.encode("utf-8")); digest.update(b"\0"); digest.update(expected_oid.encode("ascii")); digest.update(b"\0"); digest.update(content)
        cursor = end + 1
    if cursor != len(result.stdout):
        raise ProvanError("BLOB_INSPECTION_FAILED", "unexpected cat-file batch output")
    return len(blobs), total, "sha256:" + digest.hexdigest()


def inspect_repository(source: str, base: str, head: str, output: Path | None = None, *, allow_exec: bool = False) -> dict[str, Any]:
    if allow_exec:
        raise ProvanError(QUALIFIED_SANDBOX_REQUIRED, "repository execution is unavailable without a qualified sandbox")
    _reject_source(source)
    _require_pinned_commit(base, "base"); _require_pinned_commit(head, "head")
    local = Path(source).resolve() if "://" not in source else None
    if local is not None and (not local.is_dir() or not (local / ".git").exists()):
        raise ProvanError("LOCAL_REPOSITORY_INVALID", "local source must be a Git working tree")
    if local is not None:
        _bounded_object_store(local / ".git")
    # Receipts are Provan output, never target-repository output.  Resolve both
    # paths before doing any Git work so symlinked parents cannot bypass this
    # boundary.
    receipt_id = str(uuid.uuid4())
    output = output or state_root() / "outputs" / f"repository-inspection-{receipt_id}.json"
    resolved_output = trusted_output_path(output)
    if local is not None and (resolved_output == local or local in resolved_output.parents):
        raise ProvanError(
            CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
            "inspection output must be outside the customer repository",
        )
    before = _tree_fingerprint(local) if local else None
    ledger: list[list[str]] = []
    with tempfile.TemporaryDirectory(prefix="provan-inspect-") as temp:
        scratch = Path(temp)
        home = scratch / "home"; home.mkdir(); hooks = home / "hooks"; hooks.mkdir()
        mirror = scratch / "repository.git"
        clone_source = str(local) if local is not None else source
        clone = ["git", "-c", f"core.hooksPath={hooks}", "-c", "protocol.file.allow=always" if local is not None else "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "clone", "--bare", "--no-tags", "--filter=blob:none", "--", clone_source, str(mirror)]
        if local is not None:
            # Local transport must not invoke upload-pack: repository config can
            # define uploadpack.packObjectsHook. A no-hardlink local copy reads
            # objects/refs as data and Git rejects symlinked object stores.
            clone[clone.index("--filter=blob:none")] = "--local"
            clone.insert(clone.index("--"), "--no-hardlinks")
        ledger.append(clone[1:])
        completed = _run(clone, scratch, home)
        if completed.returncode:
            raise ProvanError("REPOSITORY_FETCH_FAILED", completed.stderr.strip()[:300])
        _bounded_object_store(mirror)
        resolved: dict[str, str] = {}
        for label, ref in (("base", base), ("head", head)):
            argv = ["git", "--git-dir", str(mirror), "rev-parse", "--verify", ref + "^{commit}"]
            ledger.append(argv[1:]); result = _run(argv, scratch, home)
            if result.returncode:
                raise ProvanError("REVISION_NOT_FOUND", f"{label} revision unavailable")
            resolved[label] = result.stdout.strip()
        argv = ["git", "--git-dir", str(mirror), "ls-tree", "-rz", "-r", "-l", "--full-tree", resolved["head"]]
        ledger.append(argv[1:]); result = _run(argv, scratch, home)
        if result.returncode:
            raise ProvanError("TREE_INSPECTION_FAILED", result.stderr.strip()[:300])
        if len(result.stdout.encode("utf-8")) > MAX_TREE_OUTPUT_BYTES:
            raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED", "tree output exceeds inspection limit")
        entries = 0; blobs: list[tuple[str, str, int]] = []
        for raw in result.stdout.split("\0"):
            if not raw: continue
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED", "tree entry count exceeds inspection limit")
            meta, _, name = raw.partition("\t")
            fields = meta.split()
            if len(fields) != 4 or fields[1] != "blob":
                raise ProvanError("TREE_INSPECTION_FAILED", "unexpected non-blob tree entry")
            mode, _, oid, size_text = fields; size = int(size_text)
            parts = name.replace("\\", "/").split("/")
            if mode == "120000" or any(part in {"", ".", ".."} for part in parts) or name.startswith(("/", "\\")):
                raise ProvanError("UNSAFE_TREE_PATH_FORBIDDEN", "symlink or path traversal entry")
            blobs.append((oid, name, size))
        ledger.append(["cat-file", "--batch"])
        blob_count, blob_bytes, blob_digest = _inspect_blob_contents(mirror, blobs, home)
        receipt = {
            "schema_id": "provan.repository_inspection.v1", "mode": "source-only",
            "receipt_id": receipt_id, "output_path": str(resolved_output),
            "status": "SOURCE_ONLY_INSPECTED", "requested": {"base": base, "head": head},
            "resolved": resolved, "tree_entry_count": entries, "blob_content_count": blob_count,
            "blob_content_bytes": blob_bytes, "blob_content_digest": blob_digest, "executed_repository_code": False,
            "target_unchanged": before == (_tree_fingerprint(local) if local else None) if local else True,
            "verdict": None, "command_ledger": ledger,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    validate_inspection_semantics(receipt)
    receipt_bytes = canonical_bytes(receipt)
    write_output(resolved_output, receipt_bytes)
    if local is not None and before != _tree_fingerprint(local):
        resolved_output.unlink(missing_ok=True)
        raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED", "target changed during receipt publication")
    return {
        **receipt,
        "write_result": {
            "receipt_sha256": sha256_bytes(receipt_bytes),
            "output_path": str(resolved_output),
        },
    }
