from __future__ import annotations

import os
import queue
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .onboarding import paths as project_paths
from .project import AUTHORITY_POLICY_VERSION, ALLOWED_ENVIRONMENT, activation_status, content_hash, resolve_policy_path, validate_command

PROFILE_OPERATIONS = {
    "inspect": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read"},
    "verify": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read", "command.execute"},
    "remediate": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read", "command.execute", "source.write.isolated"},
}
BINDING_SCHEMA = "release_project_authority_binding.v1"
DEPLOYMENT_GRANT_SCHEMA = "release_deployment_read_grant.v1"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=check)


def require_operation(status: dict, operation: str) -> None:
    if operation not in PROFILE_OPERATIONS[status["effective_profile"]]:
        raise PermissionError(f"operation denied by {status['effective_profile']} profile: {operation}")


def normalize_deployment_grant(url: str, allowed_paths: list[str]) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("live URL must be credential-free HTTP(S)")
    host = parsed.hostname.lower(); port = parsed.port
    default_port = 80 if parsed.scheme == "http" else 443
    origin = f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")
    normalized = []
    for path in allowed_paths:
        candidate = urlparse(path).path
        if not candidate.startswith("/") or ".." in Path(candidate).parts: raise ValueError("deployment grant paths must be absolute URL paths")
        normalized.append(candidate)
    return {"schema_version": DEPLOYMENT_GRANT_SCHEMA, "origin": origin, "allowed_paths": sorted(set(normalized)), "created_from": "owner_release_input", "granted_at": datetime.now(UTC).isoformat()}


def bind_release_authority(repo: Path, live_url: str, generated_path: str) -> tuple[dict, dict]:
    shared, receipt = project_paths(repo); local, _ = project_paths(repo, True)
    contract_path = shared if shared.is_file() else local
    if not contract_path.is_file(): raise ValueError("local release requires an activated project_contract.v1")
    status = activation_status(repo, contract_path, receipt)
    if not status["activation_fresh"] or not status["activation_receipt_hash"]: raise ValueError("project activation receipt is missing or stale; reactivate before release init")
    source = str(contract_path.resolve().relative_to(repo.resolve())).replace("\\", "/") if shared == contract_path else "local-only"
    commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
    binding = {"schema_version": BINDING_SCHEMA, "project_id": status["contract"]["project_id"], "contract_hash": status["contract_hash"], "authority_policy_version": AUTHORITY_POLICY_VERSION, "declared_profile": status["declared_profile"], "effective_profile": status["effective_profile"], "activation_receipt_hash": status["activation_receipt_hash"], "contract_source": source, "bound_at": datetime.now(UTC).isoformat(), "repository_commit": commit}
    return binding, normalize_deployment_grant(live_url, [generated_path])


@dataclass
class BoundedCommandResult:
    status: str
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    bytes_captured: int
    output_limit_bytes: int
    termination: str
    side_effect_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict: return asdict(self)


def _terminate_tree(process: subprocess.Popen) -> str:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=3, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3); return "killed"
    except Exception:
        try: process.kill(); process.wait(timeout=2); return "terminated"
        except Exception: return "failed"


def run_bounded_command(command: dict, cwd: Path) -> BoundedCommandResult:
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT") if k in os.environ}
    env.update({k: v for k, v in command["allowed_environment"].items() if k in ALLOWED_ENVIRONMENT})
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    started = time.monotonic()
    process = subprocess.Popen(command["argv"], cwd=cwd, shell=False, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags, start_new_session=os.name != "nt")
    chunks: queue.Queue[tuple[str, bytes | None]] = queue.Queue()
    def reader(name: str, stream) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk: break
                chunks.put((name, chunk))
        finally: chunks.put((name, None))
    threads = [threading.Thread(target=reader, args=("stdout", process.stdout), daemon=True), threading.Thread(target=reader, args=("stderr", process.stderr), daemon=True)]
    for thread in threads: thread.start()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}; finished=set(); status=None; termination="not_required"; limit=command["output_limit_bytes"]
    deadline = started + command["timeout_seconds"]
    terminated_at=None
    while len(finished) < 2:
        if time.monotonic() >= deadline and process.poll() is None:
            status="timeout"; termination=_terminate_tree(process); terminated_at=time.monotonic()
        if terminated_at and process.poll() is not None and time.monotonic()-terminated_at>2: break
        try: name, chunk = chunks.get(timeout=.05)
        except queue.Empty:
            if status and process.poll() is not None: continue
            continue
        if chunk is None: finished.add(name); continue
        remaining = max(0, limit - sum(len(v) for v in buffers.values()))
        buffers[name].extend(chunk[:remaining])
        if len(chunk) > remaining and not status:
            status="output_limit_exceeded"; termination=_terminate_tree(process); terminated_at=time.monotonic()
    for thread in threads: thread.join(timeout=.1)
    if process.poll() is None: termination=_terminate_tree(process)
    code=process.returncode
    if termination == "failed": status="termination_failed"
    elif status is None: status="passed" if code == 0 else "failed"
    return BoundedCommandResult(status, code, int((time.monotonic()-started)*1000), buffers["stdout"].decode(errors="replace"), buffers["stderr"].decode(errors="replace"), sum(len(v) for v in buffers.values()), limit, termination)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


@dataclass
class LocalExecutionContext:
    repository_root: Path
    release: dict
    authority_binding: dict
    activation: dict
    deployment_grant: dict

    @classmethod
    def from_release(cls, release: dict) -> "LocalExecutionContext":
        raw = release.get("repository", {}).get("path")
        if not raw: raise ValueError("local execution requires repository.path")
        repo = Path(_git(Path(raw).resolve(), "rev-parse", "--show-toplevel").stdout.strip()).resolve()
        binding = release.get("project_authority")
        if not binding or binding.get("schema_version") != BINDING_SCHEMA: raise ValueError("release is not bound to project authority")
        shared, receipt = project_paths(repo); local, _ = project_paths(repo, True)
        contract_path = shared if binding.get("contract_source") != "local-only" else local
        expected_source = ".shiproom/project-contract.json" if contract_path == shared else "local-only"
        if binding.get("contract_source") != expected_source: raise ValueError("release project authority source is invalid")
        if not contract_path.is_file() or not receipt.is_file(): raise ValueError("release authority source or activation receipt is missing")
        status = activation_status(repo, contract_path, receipt)
        expected = {"project_id": status["contract"]["project_id"], "contract_hash": status["contract_hash"], "authority_policy_version": AUTHORITY_POLICY_VERSION, "declared_profile": status["declared_profile"], "effective_profile": status["effective_profile"], "activation_receipt_hash": status["activation_receipt_hash"]}
        mismatches = [key for key, value in expected.items() if binding.get(key) != value]
        if mismatches or not status["activation_fresh"]: raise ValueError("release project authority is stale: " + ", ".join(mismatches or ["activation_fresh"]))
        commit = release.get("repository", {}).get("commit_sha") or binding.get("repository_commit")
        if binding.get("repository_commit") != commit: raise ValueError("release repository commit differs from authority binding")
        grant = release.get("deployment", {}).get("read_grant")
        required_grant={"schema_version","origin","allowed_paths","created_from","granted_at"}
        if not grant or set(grant)!=required_grant or grant.get("schema_version") != DEPLOYMENT_GRANT_SCHEMA or grant.get("created_from")!="owner_release_input": raise ValueError("release deployment read grant is missing or invalid")
        parsed=urlparse(grant["origin"])
        if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"","/"}: raise ValueError("release deployment origin is invalid")
        if not isinstance(grant["allowed_paths"],list) or any(not isinstance(p,str) or not p.startswith("/") or ".." in Path(p).parts for p in grant["allowed_paths"]): raise ValueError("release deployment paths are invalid")
        return cls(repo, release, binding, status, grant)

    def require(self, operation: str) -> None: require_operation(self.activation, operation)

    def read_allowed_file(self, relative: str) -> str:
        self.require("file.read"); path=resolve_policy_path(self.repository_root, relative, self.activation["contract"]["protected_paths"], self.activation["contract"]["excluded_paths"], operation="read"); return path.read_text(encoding="utf-8")

    def read_git_metadata(self, *args: str) -> str:
        self.require("git.metadata.read"); allowed={"rev-parse", "status", "branch", "show"}
        if not args or args[0] not in allowed or any(a.startswith(("--output", "--exec-path", "--config-env")) for a in args): raise PermissionError("Git metadata operation is not allowlisted")
        return _git(self.repository_root, *args).stdout

    def read_git_diff(self, *args: str) -> str:
        self.require("git.diff.read")
        if any(a.startswith(("--output", "--ext-diff", "--no-index")) for a in args): raise PermissionError("Git diff option is not allowlisted")
        return _git(self.repository_root, "diff", "--no-ext-diff", *args).stdout

    def read_configured_deployment(self, path: str, timeout: float = 10) -> dict:
        self.require("deployment.read")
        if path not in self.deployment_grant["allowed_paths"]: raise PermissionError("deployment path is not granted")
        url=urljoin(self.deployment_grant["origin"]+"/", path.lstrip("/")); opener=urllib.request.build_opener(_NoRedirect)
        try:
            response=opener.open(urllib.request.Request(url, headers={"User-Agent":"Shiproom-Release-Assurance/0.1"}), timeout=timeout); status=response.status; final=response.geturl()
        except urllib.error.HTTPError as exc:
            if 300<=exc.code<400: raise PermissionError("deployment redirects are not allowed by the release grant")
            status=exc.code; final=exc.geturl()
        except Exception as exc: return {"type":"http","target":url,"passed":False,"status":None,"evidence_status":"missing_evidence","error":type(exc).__name__}
        if urlparse(final).scheme+"://"+urlparse(final).netloc != self.deployment_grant["origin"] or urlparse(final).path not in self.deployment_grant["allowed_paths"]: raise PermissionError("deployment redirect escaped the release grant")
        return {"type":"http","target":url,"passed":200<=status<300,"status":status,"evidence_status":"deterministically_verified"}

    def _verification_worktree(self) -> Path:
        self.require("command.execute"); root=(self.repository_root/".shiproom/local/worktrees").resolve(); root.mkdir(parents=True,exist_ok=True); target=(root/f"verify-{self.release['release_id']}-{uuid.uuid4().hex[:8]}").resolve()
        if root not in target.parents: raise PermissionError("verification worktree path escaped local storage")
        _git(self.repository_root,"worktree","add","--detach",str(target),self.authority_binding["repository_commit"])
        if _git(target,"rev-parse","HEAD").stdout.strip()!=self.authority_binding["repository_commit"]: raise PermissionError("verification worktree commit mismatch")
        return target

    def execute_approved_commands(self) -> list[tuple[dict, BoundedCommandResult]]:
        commands=self.activation["contract"]["execution_policy"]["approved_commands"]
        if not commands: return []
        worktree=self._verification_worktree(); results=[]
        try:
            before=_git(worktree,"status","--porcelain","--untracked-files=all").stdout
            for command in commands:
                validate_command(command,worktree); cwd=resolve_policy_path(worktree,command["cwd"],self.activation["contract"]["protected_paths"],self.activation["contract"]["excluded_paths"],operation="read"); result=run_bounded_command(command,cwd); result.side_effect_paths=[line[3:] for line in _git(worktree,"status","--porcelain","--untracked-files=all").stdout.splitlines()]; results.append((command,result))
            return results
        finally:
            _git(self.repository_root,"worktree","remove","--force",str(worktree),check=False); _git(self.repository_root,"worktree","prune",check=False)

    def write_isolated_file(self, worktree: Path, relative: str) -> Path:
        self.require("source.write.isolated"); local=(self.repository_root/".shiproom/local/worktrees").resolve(); resolved=worktree.resolve()
        if local not in resolved.parents or resolved==self.repository_root: raise PermissionError("writes require a validated isolated worktree")
        if Path(_git(resolved,"rev-parse","--show-toplevel").stdout.strip()).resolve()!=resolved: raise PermissionError("isolated write target is not a Git worktree root")
        common_raw=_git(resolved,"rev-parse","--git-common-dir").stdout.strip(); common=(resolved/common_raw).resolve() if not Path(common_raw).is_absolute() else Path(common_raw).resolve()
        if common!=(self.repository_root/".git").resolve(): raise PermissionError("isolated worktree belongs to another repository")
        head=_git(resolved,"rev-parse","HEAD").stdout.strip()
        if _git(resolved,"merge-base","--is-ancestor",self.authority_binding["repository_commit"],head,check=False).returncode!=0: raise PermissionError("isolated worktree is not based on the release commit")
        return resolve_policy_path(resolved,relative,self.activation["contract"]["protected_paths"],self.activation["contract"]["excluded_paths"],operation="write")
