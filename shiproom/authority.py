from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .project import ALLOWED_ENVIRONMENT, activation_status, resolve_policy_path, validate_command

PROFILE_OPERATIONS = {
    "inspect": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read"},
    "verify": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read", "command.execute"},
    "remediate": {"file.read", "git.metadata.read", "git.diff.read", "deployment.read", "command.execute", "source.write.isolated"},
}


def require_operation(status: dict, operation: str) -> None:
    if operation not in PROFILE_OPERATIONS[status["effective_profile"]]:
        raise PermissionError(f"operation denied by {status['effective_profile']} profile: {operation}")


def execute_operation(status: dict, operation: str, executor: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    require_operation(status, operation)
    return executor(*args, **kwargs)


def execute_approved_command(repo: Path, status: dict, command_id: str, executor: Callable[..., Any] = subprocess.run) -> subprocess.CompletedProcess[str]:
    require_operation(status, "command.execute")
    command = next((c for c in status["contract"]["execution_policy"]["approved_commands"] if c["command_id"] == command_id), None)
    if not command: raise PermissionError(f"command is not approved: {command_id}")
    validate_command(command, repo)
    cwd = resolve_policy_path(repo, command["cwd"], status["contract"]["protected_paths"], status["contract"]["excluded_paths"], operation="read")
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT") if k in os.environ}
    env.update({k: v for k, v in command["allowed_environment"].items() if k in ALLOWED_ENVIRONMENT})
    result = executor(command["argv"], cwd=cwd, shell=False, env=env, text=True, capture_output=True, timeout=command["timeout_seconds"])
    limit = command["output_limit_bytes"]
    result.stdout = (result.stdout or "").encode()[:limit].decode(errors="replace")
    result.stderr = (result.stderr or "").encode()[:limit].decode(errors="replace")
    return result
