"""Qualified Docker v2 execution control plane.

The container is deliberately persistent only while the trusted supervisor is
alive.  The patient is a separate ``docker exec`` process under a different
UID; it never inherits the supervisor's transfer channel.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import threading
import queue
from typing import Any

from .identity import canonical_json
from .runner import docker_executable
from .v2 import BackendLock, TransferLimits, parse_transfer, validate_artifact_manifest

SUPERVISOR_UID = "65532:65532"
PATIENT_UID = "65533:65533"
SUPERVISOR_DIR = "/supervisor"


@dataclass(frozen=True)
class ExecutionPolicyV2:
    image_digest: str
    runner_image_digest: str
    security_policy_hash: str
    resource_policy_hash: str
    seccomp_profile: Path
    cpus: float = 1.0
    memory: str = "1g"
    pids: int = 128
    output_tmpfs_bytes: int = 64 * 1024 * 1024
    stdout_limit_bytes: int = 1024 * 1024
    stderr_limit_bytes: int = 1024 * 1024
    wall_seconds: int = 900
    grace_seconds: int = 5

    def validate(self) -> None:
        if self.image_digest != self.runner_image_digest or not all("@sha256:" in value for value in (self.image_digest, self.runner_image_digest)):
            raise ValueError("immutable_runner_image_required")
        if self.cpus <= 0 or self.pids < 2 or min(self.output_tmpfs_bytes, self.stdout_limit_bytes, self.stderr_limit_bytes, self.wall_seconds, self.grace_seconds) < 1:
            raise ValueError("execution_policy_invalid")
        if not self.seccomp_profile.is_file(): raise ValueError("seccomp_profile_missing")


def policy_hash(policy: ExecutionPolicyV2) -> str:
    return "sha256:" + sha256(canonical_json({
        "image": policy.image_digest, "runner": policy.runner_image_digest,
        "security": policy.security_policy_hash, "resource": policy.resource_policy_hash,
        "cpus": policy.cpus, "memory": policy.memory, "pids": policy.pids,
        "output": policy.output_tmpfs_bytes, "stdout": policy.stdout_limit_bytes,
        "stderr": policy.stderr_limit_bytes, "wall": policy.wall_seconds,
    })).hexdigest()


def create_argv(policy: ExecutionPolicyV2, *, name: str, cidfile: Path, patient: Path, packet: Path, backend_label: str) -> list[str]:
    policy.validate()
    docker = docker_executable()
    if not docker: raise RuntimeError("docker_cli_unavailable")
    if not all(path.is_absolute() for path in (cidfile, patient, packet, policy.seccomp_profile)): raise ValueError("absolute_paths_required")
    args = [docker, "create", "--name", name, "--cidfile", str(cidfile), "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--security-opt", f"seccomp={policy.seccomp_profile}",
            "--user", SUPERVISOR_UID, "--cpus", str(policy.cpus), "--memory", policy.memory, "--memory-swap", policy.memory,
            "--pids-limit", str(policy.pids), "--restart=no", "--log-driver=none", "--label", f"shiproom.external_validation.backend={backend_label}",
            "--label", f"shiproom.external_validation.policy={policy_hash(policy)}",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size=16m", "--tmpfs", f"/output:rw,nosuid,nodev,noexec,size={policy.output_tmpfs_bytes}",
            "--mount", f"type=bind,src={patient},dst=/patient,readonly", "--mount", f"type=bind,src={packet},dst=/release,readonly",
            policy.image_digest, f"{SUPERVISOR_DIR}/supervisor"]
    validate_create_argv(args)
    return args


def validate_create_argv(argv: list[str]) -> None:
    forbidden = ("--privileged", "--device", "--volume", "-v", "--pid=host", "--ipc=host", "--userns=host", "--network=host", "--env", "-e")
    joined = " ".join(argv)
    if any(option in argv or option + "=" in joined for option in forbidden): raise ValueError("forbidden_docker_option")
    required = {"--network=none", "--read-only", "--cap-drop=ALL", "--restart=no", "--log-driver=none", "--user", "--cidfile", "--name", "--pids-limit", "--memory", "--memory-swap", "--tmpfs", "--mount"}
    if not required.issubset(argv): raise ValueError("docker_security_option_missing")
    if any("docker.sock" in token.lower() or token.startswith(("HOME=", "SSH_", "AWS_", "HTTP_", "HTTPS_", "ALL_PROXY=")) for token in argv): raise ValueError("docker_secret_exposure")


def effective_projection(inspect: dict[str, Any]) -> dict[str, Any]:
    host = inspect.get("HostConfig", {}); config = inspect.get("Config", {})
    return {
        "image": config.get("Image"), "user": config.get("User"), "readonly": host.get("ReadonlyRootfs"), "network": host.get("NetworkMode"),
        "cap_drop": sorted(host.get("CapDrop") or []), "security": sorted(host.get("SecurityOpt") or []),
        "pid": host.get("PidMode"), "ipc": host.get("IpcMode"), "userns": host.get("UsernsMode"), "devices": host.get("Devices") or [],
        "memory": host.get("Memory"), "memory_swap": host.get("MemorySwap"), "pids": host.get("PidsLimit"),
        "cpu_nano": host.get("NanoCpus"), "restart": (host.get("RestartPolicy") or {}).get("Name"), "log_driver": (host.get("LogConfig") or {}).get("Type"), "env": sorted(config.get("Env") or []),
        "labels": config.get("Labels") or {}, "mounts": sorted(({"destination": m.get("Destination"), "rw": m.get("RW"), "type": m.get("Type")} for m in inspect.get("Mounts", [])), key=lambda x: str(x)),
    }


def _memory_bytes(value: str) -> int:
    suffix = value[-1:].lower(); multiplier = {"g": 1024**3, "m": 1024**2, "k": 1024}.get(suffix, 1)
    return int(float(value[:-1] if suffix in {"g", "m", "k"} else value) * multiplier)


def assert_effective_policy(projection: dict[str, Any], policy: ExecutionPolicyV2, patient: Path, packet: Path, backend: str) -> None:
    mounts = {item["destination"]: item for item in projection["mounts"]}
    required_security = {"no-new-privileges"}
    security = " ".join(projection["security"])
    if projection["image"] != policy.image_digest or projection["network"] != "none" or not projection["readonly"] or projection["user"] != SUPERVISOR_UID:
        raise RuntimeError("effective_docker_policy_mismatch")
    if "ALL" not in projection["cap_drop"] or not all(word in security for word in required_security) or "seccomp=" not in security:
        raise RuntimeError("effective_docker_policy_mismatch")
    if projection["pid"] or projection["ipc"] not in {"", "private"} or projection["userns"] or projection["devices"] or projection["restart"] not in {"", "no"}:
        raise RuntimeError("effective_docker_policy_mismatch")
    if projection["memory"] != _memory_bytes(policy.memory) or projection["memory_swap"] != _memory_bytes(policy.memory) or projection["pids"] != policy.pids or projection["cpu_nano"] != int(policy.cpus * 1_000_000_000) or projection["log_driver"] != "none":
        raise RuntimeError("effective_docker_policy_mismatch")
    if any(item.startswith(("HTTP_", "HTTPS_", "ALL_PROXY=", "HOME=", "SSH_", "AWS_")) for item in projection["env"]): raise RuntimeError("effective_docker_policy_mismatch")
    if set(mounts) != {"/patient", "/release"} or mounts["/patient"]["rw"] or mounts["/release"]["rw"] or projection["labels"].get("shiproom.external_validation.backend") != backend:
        raise RuntimeError("effective_docker_policy_mismatch")


def projection_hash(value: dict[str, Any]) -> str:
    return "sha256:" + sha256(canonical_json(value)).hexdigest()


def _run(argv: list[str], *, timeout: int = 30, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=not binary, timeout=timeout, env={"PATH": os.environ.get("PATH", ""), "NO_PROXY": "", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": ""})


def _bounded_exec(argv: list[str], stdout_limit: int, stderr_limit: int, timeout: int) -> dict[str, Any]:
    """Concurrent raw-byte drain with bounded retention and immediate CLI stop."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": os.environ.get("PATH", ""), "NO_PROXY": "", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": ""})
    events: queue.Queue[tuple[str, bytes | None]] = queue.Queue()
    def drain(name: str, stream) -> None:
        try:
            while True:
                block = stream.read(65536)
                if not block: break
                events.put((name, block))
        finally: events.put((name, None))
    threads = [threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True), threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True)]
    for thread in threads: thread.start()
    kept={"stdout":bytearray(), "stderr":bytearray()}; observed={"stdout":0, "stderr":0}; closed=set(); cause=None; deadline=time.monotonic()+timeout
    try:
        while len(closed) < 2 or process.poll() is None:
            if time.monotonic() > deadline and cause is None: cause="WALL_TIME_EXCEEDED"; process.terminate()
            try: name, block = events.get(timeout=.05)
            except queue.Empty: continue
            if block is None: closed.add(name); continue
            observed[name] += len(block); limit = stdout_limit if name == "stdout" else stderr_limit
            room=max(0,limit-len(kept[name])); kept[name].extend(block[:room])
            if observed[name] > limit and cause is None:
                cause = "STDOUT_LIMIT_EXCEEDED" if name == "stdout" else "STDERR_LIMIT_EXCEEDED"; process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); cause = cause or "WALL_TIME_EXCEEDED"
    for thread in threads: thread.join(timeout=1)
    cause = cause or ("completed" if process.returncode == 0 else "command_failed")
    return {"returncode": process.returncode, "termination": cause, "stdout": bytes(kept["stdout"]), "stderr": bytes(kept["stderr"]),
            "stdout_observed": observed["stdout"], "stderr_observed": observed["stderr"], "stdout_retained": len(kept["stdout"]), "stderr_retained": len(kept["stderr"]), "stdout_discarded": observed["stdout"]-len(kept["stdout"]), "stderr_discarded": observed["stderr"]-len(kept["stderr"])}


def _safe_extract(archive: bytes, destination: Path, manifest: dict[str, Any]) -> None:
    validate_artifact_manifest(manifest)
    expected = {item["path"]: item for item in manifest["artifacts"] if item["type"] == "regular"}
    with tarfile.open(fileobj=__import__("io").BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        if any(not member.isfile() and not member.isdir() for member in members): raise ValueError("archive_special_entry")
        observed = set()
        for member in members:
            name = member.name.rstrip("/")
            if not name: continue
            if member.isdir(): continue
            if name not in expected or member.size != expected[name]["size"]: raise ValueError("archive_manifest_mismatch")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None: raise ValueError("archive_file_missing")
            with target.open("xb") as handle: shutil.copyfileobj(source, handle)
            digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
            if digest != expected[name]["sha256"]: raise ValueError("archive_hash_mismatch")
            observed.add(name)
    if observed != set(expected): raise ValueError("archive_member_set_mismatch")


class DockerSupervisorV2:
    def __init__(self, policy: ExecutionPolicyV2, backend: str, lock: BackendLock):
        self.policy, self.backend, self.lock = policy, backend, lock

    def execute(self, *, owner: str, name: str, cidfile: Path, patient: Path, packet: Path, command: list[str], seal_root: Path) -> dict[str, Any]:
        """Run one patient only after backend lock/effective-policy verification."""
        self.lock.acquire(self.backend, owner)
        create = create_argv(self.policy, name=name, cidfile=cidfile, patient=patient, packet=packet, backend_label=self.backend)
        started = time.time(); cleanup: list[str] = []; container_id = ""; outcome: dict[str, Any] | None = None
        try:
            result = _run(create)
            if result.returncode: raise RuntimeError("docker_create_failed")
            container_id = cidfile.read_text(encoding="utf-8").strip()
            inspect = _run([docker_executable(), "inspect", container_id])
            if inspect.returncode: raise RuntimeError("docker_inspect_failed")
            projection = effective_projection(json.loads(inspect.stdout)[0])
            assert_effective_policy(projection, self.policy, patient, packet, self.backend)
            start = _run([docker_executable(), "start", container_id])
            if start.returncode: raise RuntimeError("docker_start_failed")
            patient_result = _bounded_exec([docker_executable(), "exec", "--user", PATIENT_UID, "--workdir", "/patient", container_id, "/gateway/patient-launcher", *command], self.policy.stdout_limit_bytes, self.policy.stderr_limit_bytes, self.policy.wall_seconds)
            # The reaper is a separate exec with no patient-inherited descriptor.
            reaper = _run([docker_executable(), "exec", "--user", PATIENT_UID, container_id, "/gateway/patient-reaper", PATIENT_UID], timeout=self.policy.grace_seconds + 10)
            probe = _run([docker_executable(), "exec", "--user", SUPERVISOR_UID, container_id, f"{SUPERVISOR_DIR}/quiescence_probe.py", PATIENT_UID.split(":")[0]], timeout=15)
            if reaper.returncode or probe.returncode:
                patient_result["termination"] = "artifact_transfer_failed"
                outcome = {**patient_result, "container_id": container_id, "evidence_eligible": False, "quiescence": False, "reaper_code": reaper.returncode, "probe_code": probe.returncode, "reaper_stderr": reaper.stderr, "probe_stderr": probe.stderr}
            else:
                transfer = subprocess.Popen([docker_executable(), "exec", "--user", SUPERVISOR_UID, container_id, f"{SUPERVISOR_DIR}/transfer_helper.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                raw, transfer_err = transfer.communicate(timeout=30)
                if transfer.returncode: raise RuntimeError("transfer_helper_failed:" + transfer_err.decode("utf-8", "replace"))
                manifest, archive = parse_transfer(__import__("io").BytesIO(raw), TransferLimits(self.policy.output_tmpfs_bytes, 4096, self.policy.output_tmpfs_bytes * 2))
                sealed = seal_root / container_id; sealed.mkdir(parents=True, exist_ok=False); _safe_extract(archive, sealed, manifest)
                outcome = {**patient_result, "container_id": container_id, "evidence_eligible": True, "artifact_manifest": manifest, "sealed_output": sealed,
                           "requested_policy_hash": policy_hash(self.policy), "effective_inspect_hash": projection_hash(projection), "started_at": started, "completed_at": time.time()}
        finally:
            absent = False
            if container_id:
                for argv, label in (([docker_executable(), "stop", "--time", str(self.policy.grace_seconds), container_id], "stop"), ([docker_executable(), "kill", container_id], "kill"), ([docker_executable(), "rm", "--force", container_id], "remove")):
                    try: _run(argv, timeout=self.policy.grace_seconds + 10); cleanup.append(label)
                    except Exception: cleanup.append(label + "_failed")
                try:
                    absent = _run([docker_executable(), "inspect", container_id], timeout=10).returncode != 0
                except Exception:
                    absent = False
                # Scope the sweep to this backend label; never prune unrelated containers.
                try:
                    listed = _run([docker_executable(), "ps", "-aq", "--filter", f"label=shiproom.external_validation.backend={self.backend}"], timeout=10)
                    residual = [line for line in listed.stdout.splitlines() if line.strip()] if listed.returncode == 0 else [container_id]
                    absent = absent and not residual
                except Exception:
                    absent = False
                if not absent:
                    incident = "incident_" + sha256((self.backend + container_id + str(time.time())).encode()).hexdigest()
                    self.lock.record_incident(self.backend, incident)
            if outcome is not None:
                outcome["teardown"] = "proven" if absent else "containment_failure"
                outcome["residual_absence"] = absent
                outcome["cleanup"] = cleanup
                if not absent:
                    outcome["termination"] = "CONTAINMENT_FAILURE"; outcome["evidence_eligible"] = False
            if absent:
                self.lock.release(self.backend, owner)
        if outcome is None:
            raise RuntimeError("docker_execution_no_outcome")
        return outcome
