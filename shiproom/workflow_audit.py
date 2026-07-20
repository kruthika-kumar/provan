"""Opt-in, no-op-by-default invocation evidence for workflow acceptance.

The domain compilers do not depend on this module.  Test and workflow harnesses
wrap real callables with :func:`invoke`; outside an active session it simply
calls the function unchanged.  The emitted records are operational evidence and
are deliberately excluded from every substantive domain identity.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar


T = TypeVar("T")
_ACTIVE: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("shiproom_workflow_audit", default=None)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
    except TypeError:
        return repr(value).encode("utf-8")


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _commit(root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True).stdout.strip()


@contextmanager
def session(root: Path, workflow_case: str) -> Iterator[list[dict[str, Any]]]:
    """Capture invocation records for one workflow case.

    Nested calls receive the current invocation as their parent.  A disabled
    audit context is indistinguishable from a direct production invocation.
    """
    state = {"root": root, "workflow_case": workflow_case, "records": [], "stack": []}
    token = _ACTIVE.set(state)
    try:
        yield state["records"]
    finally:
        _ACTIVE.reset(token)


def invoke(production_function: str, callable_: Callable[..., T], *args: Any, artifact_paths: list[str] | None = None, **kwargs: Any) -> T:
    state = _ACTIVE.get()
    if state is None:
        return callable_(*args, **kwargs)
    invocation_id = "inv_" + uuid.uuid4().hex
    record: dict[str, Any] = {
        "invocation_id": invocation_id,
        "workflow_case": state["workflow_case"],
        "production_function": production_function,
        "input_semantic_hash": _hash({"args": args, "kwargs": kwargs}),
        "started": time.time_ns(),
        "completed": None,
        "outcome": None,
        "typed_status_or_error": None,
        "generated_artifact_paths": list(artifact_paths or []),
        "generated_artifact_hashes": {},
        "parent_invocation_id": state["stack"][-1] if state["stack"] else None,
        "final_commit": _commit(state["root"]),
    }
    state["records"].append(record)
    state["stack"].append(invocation_id)
    try:
        value = callable_(*args, **kwargs)
    except Exception as exc:
        record["outcome"] = "rejected"
        record["typed_status_or_error"] = str(exc)
        raise
    else:
        record["outcome"] = "accepted"
        record["typed_status_or_error"] = value.get("status") if isinstance(value, dict) else "ok"
        for path in artifact_paths or []:
            candidate = Path(path)
            if candidate.is_file():
                record["generated_artifact_hashes"][path] = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        return value
    finally:
        record["completed"] = time.time_ns()
        state["stack"].pop()


def assertion(assertion_id: str, description: str, actual: Any, expected: Any) -> dict[str, Any]:
    return {"assertion_id": assertion_id, "description": description, "actual": actual, "expected": expected, "passed": actual == expected}
