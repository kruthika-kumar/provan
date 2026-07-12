from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .runs import RunStore


POLICY_VERSION = "external_read_only_policy.v1"

OPERATION_CAPABILITIES = {
    "public.inspect": "inspect_public_surfaces",
    "shell.run": "run_safe_commands",
    "package.install": "run_safe_commands",
    "test.run": "run_safe_commands",
    "build.run": "run_safe_commands",
    "source.write": "create_local_diff",
    "git.push": "push_branch",
    "github.open_pr": "open_pr",
    "github.comment": "comment_upstream",
    "report.publish": "publish_report",
    "deployment.modify": "modify_deployment",
}


def guard_external_operation(release: dict, store: RunStore, operation: str) -> str:
    """Authorize before any external executor is called; record every denial."""
    capability = OPERATION_CAPABILITIES.get(operation)
    if capability is None:
        raise ValueError(f"unknown external operation: {operation}")
    if not release.get("capabilities", {}).get(capability, False):
        store.append(
            release["release_id"],
            "operation_rejected",
            operation=operation,
            status="rejected",
            metadata={"capability": capability, "policy_version": POLICY_VERSION},
        )
        raise PermissionError(f"capability denied: {capability}")
    return capability


def execute_external_operation(
    release: dict,
    store: RunStore,
    operation: str,
    executor: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    guard_external_operation(release, store, operation)
    return executor(*args, **kwargs)
