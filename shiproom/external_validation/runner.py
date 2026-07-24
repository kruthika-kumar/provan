from __future__ import annotations

"""Docker-only execution control plane; it deliberately has no host fallback."""
from dataclasses import dataclass
from pathlib import Path
from .security import external_root, canonical_safe_path
import hashlib
import os
import shutil
import subprocess
import time


FORBIDDEN_OPTIONS = {"--privileged", "--pid=host", "--ipc=host", "--uts=host", "--userns=host", "--network=host", "--device", "-v", "--volume"}


def docker_executable() -> str | None:
    return shutil.which("docker") or next((str(path) for path in (Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),) if path.is_file()), None)


@dataclass(frozen=True)
class DockerPolicy:
    image_digest: str
    uid_gid: str = "65532:65532"
    cpus: float = 1
    memory: str = "1g"
    pids: int = 128
    timeout_seconds: int = 900
    output_limit_bytes: int = 1_048_576

    def validate(self) -> None:
        if "@sha256:" not in self.image_digest or self.cpus <= 0 or self.pids < 1 or self.timeout_seconds < 1 or self.output_limit_bytes < 1:
            raise ValueError("docker_policy_invalid")


def docker_argv(policy: DockerPolicy, patient: Path, packet: Path, output: Path, remediation: bool = False, remediation_worktree: Path | None = None) -> list[str]:
    policy.validate()
    if not all(path.is_absolute() for path in (patient, packet, output)):
        raise ValueError("docker_mount_must_be_absolute")
    if len({path.resolve(strict=False) for path in (patient, packet, output)}) != 3:
        raise ValueError("docker_mount_roots_must_be_distinct")
    if remediation and remediation_worktree is None:
        raise PermissionError("remediation_worktree_required")
    if remediation_worktree and (not remediation_worktree.is_absolute() or remediation_worktree.resolve(strict=False) in {patient.resolve(strict=False), packet.resolve(strict=False), output.resolve(strict=False)}):
        raise PermissionError("remediation_worktree_invalid")
    docker = docker_executable()
    if not docker:
        raise RuntimeError("docker_cli_unavailable")
    args = [docker, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", policy.uid_gid,
            "--cpus", str(policy.cpus), "--memory", policy.memory, "--memory-swap", policy.memory, "--pids-limit", str(policy.pids),
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "--mount", f"type=bind,src={patient},dst=/patient,ro",
            "--mount", f"type=bind,src={packet},dst=/release,ro", "--mount", f"type=bind,src={output},dst=/output,rw"]
    if remediation:
        args += ["--mount", f"type=bind,src={remediation_worktree},dst=/remediation,rw"]
    args.append(policy.image_digest)
    validate_docker_argv(args)
    return args


def validate_docker_argv(argv: list[str]) -> None:
    joined = " ".join(argv)
    if any(option in argv or option + "=" in joined for option in FORBIDDEN_OPTIONS):
        raise ValueError("forbidden_docker_option")
    for required in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", "--pids-limit"):
        if required not in argv:
            raise ValueError("docker_security_option_missing")
    if any("docker.sock" in token.lower() or token.startswith(("-e", "--env")) for token in argv):
        raise ValueError("docker_secret_or_socket_exposure")


def docker_available() -> bool:
    try:
        docker = docker_executable()
        if not docker:
            return False
        result = subprocess.run([docker, "info", "--format", "{{.OSType}}"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and result.stdout.strip() == "linux"
    except (OSError, subprocess.TimeoutExpired):
        return False


def tree_snapshot(root: Path) -> dict[str, str]:
    """Host-side content audit for the separately writable remediation worktree."""
    if not root.is_dir():
        raise ValueError("remediation_worktree_missing")
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PermissionError("remediation_symlink_forbidden")
        if path.is_file():
            snapshot[path.relative_to(root).as_posix()] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def create_remediation_worktree(patient: Path, destination: Path) -> Path:
    """Make a disposable copy, so the staged patient snapshot never becomes writable."""
    if destination.exists():
        raise FileExistsError("remediation_worktree_already_exists")
    if not patient.is_dir() or patient.is_symlink():
        raise PermissionError("patient_snapshot_invalid")
    shutil.copytree(patient, destination, symlinks=False, ignore=shutil.ignore_patterns(".git"))
    tree_snapshot(destination)
    return destination


def _bounded(value: str | bytes | None, limit: int) -> tuple[str, bool]:
    if value is None:
        return "", False
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "replace"), True


def run_container(policy: DockerPolicy, patient: Path, packet: Path, output: Path, command: list[str], remediation: bool = False, *, shiproom_root: Path | None = None, remediation_worktree: Path | None = None) -> dict:
    """Execute only through hardened Docker argv and collect bounded host-owned output."""
    if shiproom_root is None:
        raise PermissionError("shiproom_root_required")
    root = external_root(os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT", ""), shiproom_root, patient)
    canonical_safe_path(root, output)
    if not docker_available():
        raise RuntimeError("docker_linux_engine_unavailable")
    if not command or any(not isinstance(token, str) or not token for token in command):
        raise ValueError("container_command_invalid")
    argv = docker_argv(policy, patient, packet, output, remediation, remediation_worktree) + command
    before = tree_snapshot(remediation_worktree) if remediation and remediation_worktree else None
    started = time.monotonic()
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=policy.timeout_seconds,
                                   env={"PATH": os.environ.get("PATH", ""), "NO_PROXY": "", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": ""})
        stdout, stdout_truncated = _bounded(completed.stdout, policy.output_limit_bytes)
        stderr, stderr_truncated = _bounded(completed.stderr, policy.output_limit_bytes)
        result = {"terminal_state": "completed" if completed.returncode == 0 else "error", "exit_code": completed.returncode,
                  "stdout": stdout, "stderr": stderr, "output_truncated": stdout_truncated or stderr_truncated}
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = _bounded(exc.stdout, policy.output_limit_bytes)
        stderr, stderr_truncated = _bounded(exc.stderr, policy.output_limit_bytes)
        result = {"terminal_state": "timeout", "exit_code": None, "stdout": stdout, "stderr": stderr,
                  "output_truncated": stdout_truncated or stderr_truncated}
    result.update({"wall_time_seconds": time.monotonic() - started, "argv": argv})
    if before is not None and remediation_worktree is not None:
        after = tree_snapshot(remediation_worktree)
        result["remediation_file_change_audit"] = {"before": before, "after": after,
                                                   "changed": sorted({*before, *after})}
    return result
