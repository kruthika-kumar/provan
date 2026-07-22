"""Opt-in, no-op-by-default invocation evidence for workflow acceptance.

The domain compilers do not depend on this module.  Test and workflow harnesses
wrap real callables with :func:`invoke`; outside an active session it simply
calls the function unchanged.  The emitted records are operational evidence and
are deliberately excluded from every substantive domain identity.
"""
from __future__ import annotations

import contextvars
import functools
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


def _component_hashes(args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[str]:
    return [_hash(value) for value in args] + [_hash({key: kwargs[key]}) for key in sorted(kwargs)]


def _commit(root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True).stdout.strip()


def _persisted_state(args: tuple[Any, ...]) -> dict[str,str]:
    if not args or not hasattr(args[0],"repository_root"):
        return {}
    repository=Path(args[0].repository_root).resolve();local=repository/".shiproom"/"local"
    if not local.is_dir():
        return {}
    return {path.relative_to(repository).as_posix():"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(local.rglob("*")) if path.is_file() and not path.is_symlink()}


@contextmanager
def session(root: Path, workflow_case: str) -> Iterator[list[dict[str, Any]]]:
    """Capture invocation records for one workflow case.

    Nested calls receive the current invocation as their parent.  A disabled
    audit context is indistinguishable from a direct production invocation.
    """
    state = {"root": root, "workflow_case": workflow_case, "records": [], "stack": [], "subcase": None}
    token = _ACTIVE.set(state)
    try:
        yield state["records"]
    finally:
        _ACTIVE.reset(token)


@contextmanager
def subcase(subcase_id: str) -> Iterator[None]:
    """Bind subsequently observed production calls to one controlled subcase.

    This context can only label calls already captured by :func:`session`; it
    cannot create invocation records.  Nested or overlapping subcases are
    rejected so an error cannot be retrospectively attached to another proof.
    """
    state = _ACTIVE.get()
    if state is None:
        raise ValueError("workflow_audit_subcase_without_session")
    if not isinstance(subcase_id, str) or not subcase_id or state["subcase"] is not None:
        raise ValueError("workflow_audit_subcase_invalid")
    state["subcase"] = subcase_id
    try:
        yield
    finally:
        state["subcase"] = None


def invoke(callable_: Callable[..., T], *args: Any, artifact_paths: list[str] | None = None, **kwargs: Any) -> T:
    """Invoke a real callable and derive its identity from the callable itself.

    Harness code cannot supply an asserted function name.  This prevents a
    workflow from claiming coverage for a boundary it never invoked.
    """
    state = _ACTIVE.get()
    if state is None:
        return callable_(*args, **kwargs)
    module = getattr(callable_, "__module__", None)
    qualified = getattr(callable_, "__qualname__", None)
    if not isinstance(module, str) or not module or not isinstance(qualified, str) or not qualified:
        raise ValueError("workflow_audit_callable_identity_invalid")
    invocation_id = "inv_" + uuid.uuid4().hex
    persisted_before=_persisted_state(args)
    record: dict[str, Any] = {
        "invocation_id": invocation_id,
        "workflow_case": state["workflow_case"],
        "subcase_id": state["subcase"],
        "module": module,
        "qualified_function": module + "." + qualified,
        "input_semantic_hash": _hash({"args": args, "kwargs": kwargs}),
        "input_component_hashes": _component_hashes(args, kwargs),
        "output_semantic_hash": None,
        "exception_type": None,
        "typed_status_or_error": None,
        "generated_artifact_paths": list(artifact_paths or []),
        "generated_artifact_hashes": {},
        "parent_invocation_id": state["stack"][-1] if state["stack"] else None,
        "final_commit": _commit(state["root"]),
        "persisted_state_before": persisted_before,
        "persisted_state_after": None,
    }
    state["records"].append(record)
    state["stack"].append(invocation_id)
    try:
        value = callable_(*args, **kwargs)
    except Exception as exc:
        record["exception_type"] = type(exc).__name__
        record["typed_status_or_error"] = str(exc)
        raise
    else:
        record["output_semantic_hash"] = _hash(value)
        record["typed_status_or_error"] = value.get("status") if isinstance(value, dict) else "ok"
        for path in artifact_paths or []:
            candidate = Path(path)
            if candidate.is_file():
                record["generated_artifact_hashes"][path] = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        return value
    finally:
        persisted_after=_persisted_state(args)
        record["persisted_state_after"] = persisted_after
        changed={path:digest for path,digest in persisted_after.items() if persisted_before.get(path)!=digest}
        if changed:
            record["generated_artifact_paths"]=sorted(changed)
            record["generated_artifact_hashes"]=changed
        state["stack"].pop()


def observed_boundary(callable_: Callable[..., T]) -> Callable[..., T]:
    """Record this real boundary only while an audit session is enabled."""
    @functools.wraps(callable_)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        if _ACTIVE.get() is None:
            return callable_(*args, **kwargs)
        return invoke(callable_, *args, **kwargs)

    return wrapper


def assertion(assertion_id: str, description: str, actual: Any, expected: Any) -> dict[str, Any]:
    return {"assertion_id": assertion_id, "description": description, "actual": actual, "expected": expected, "passed": actual == expected}
