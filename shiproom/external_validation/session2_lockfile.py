"""Derive a hash-checked, target-specific requirements file from ``uv.lock``.

The Session 2 executor must never turn a project manifest's loose dependency
constraints into an authority.  This module consumes the committed lockfile,
selects the records applicable to one declared Python/Linux target, and emits
only pinned registry requirements with every lockfile artifact hash retained.
It deliberately refuses editable, Git, URL, or ambiguous package records.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping
import tomllib

from .identity import canonical_json


class LockfileError(ValueError):
    """Stable rejection for an unsafe or unsupported lock authority."""


def _fail(code: str) -> None:
    raise LockfileError(code)


DEFAULT_ENVIRONMENT = {
    "implementation_name": "cpython",
    "implementation_version": "3.12.10",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_system": "Linux",
    "platform_version": "",
    "python_full_version": "3.12.10",
    "python_version": "3.12",
    "sys_platform": "linux",
}


@dataclass(frozen=True)
class RequirementsExport:
    requirements: bytes
    manifest: dict[str, Any]


def _strip_outer_parentheses(value: str) -> str:
    """Remove only a pair that encloses the whole marker expression."""
    while value.startswith("(") and value.endswith(")"):
        depth = 0; quote = None; enclosing = True
        for index, character in enumerate(value):
            if quote:
                if character == quote:
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(value) - 1:
                    enclosing = False; break
            if depth < 0:
                _fail("session2_lock_marker_invalid")
        if depth != 0:
            _fail("session2_lock_marker_invalid")
        if not enclosing:
            break
        value = value[1:-1].strip()
    return value


def _split_marker(value: str, operator: str) -> list[str]:
    """Split a PEP 508 boolean operator outside quoted/nested expressions."""
    needle = " " + operator + " "
    pieces: list[str] = []; begin = 0; depth = 0; quote = None; index = 0
    while index < len(value):
        character = value[index]
        if quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                _fail("session2_lock_marker_invalid")
        elif depth == 0 and value.startswith(needle, index):
            pieces.append(value[begin:index].strip()); index += len(needle); begin = index; continue
        index += 1
    if depth or quote:
        _fail("session2_lock_marker_invalid")
    pieces.append(value[begin:].strip())
    return pieces


def _version(value: str) -> tuple[tuple[int, object], ...]:
    parts: list[tuple[int, object]] = []
    for part in value.split("."):
        if part.isdigit():
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return tuple(parts)


def _compare(actual: str, operator: str, expected: str) -> bool:
    if operator == "==":
        return actual.startswith(expected[:-1]) if expected.endswith("*") else actual == expected
    if operator == "!=":
        return not _compare(actual, "==", expected)
    if operator in {"in", "not in"}:
        result = actual in {item.strip() for item in expected.split(",")}
        return not result if operator == "not in" else result
    left, right = _version(actual), _version(expected)
    return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right}[operator]


def _applies(marker: object, environment: Mapping[str, str]) -> bool:
    if marker is None:
        return True
    if not isinstance(marker, str) or not marker:
        _fail("session2_lock_marker_invalid")
    def evaluate(expression: str) -> bool:
        expression = _strip_outer_parentheses(expression.strip())
        alternatives = _split_marker(expression, "or")
        if len(alternatives) > 1:
            return any(evaluate(item) for item in alternatives)
        conjunctions = _split_marker(expression, "and")
        if len(conjunctions) > 1:
            return all(evaluate(item) for item in conjunctions)
        for operator in (" not in ", " in ", " == ", " != ", " >= ", " <= ", " > ", " < "):
            if operator in expression:
                key, expected = (item.strip() for item in expression.split(operator, 1))
                if key not in environment or len(expected) < 2 or expected[0] not in {"'", '"'} or expected[-1] != expected[0]:
                    _fail("session2_lock_marker_invalid")
                return _compare(environment[key], operator.strip(), expected[1:-1])
        _fail("session2_lock_marker_invalid")
    return evaluate(marker)


def _record_applies(record: dict[str, Any], environment: Mapping[str, str]) -> bool:
    markers = record.get("resolution-markers")
    if markers is None:
        return True
    if not isinstance(markers, list) or not markers:
        _fail("session2_lock_resolution_marker_invalid")
    return any(_applies(value, environment) for value in markers)


def _registry_record(record: dict[str, Any]) -> bool:
    source = record.get("source")
    return isinstance(source, dict) and set(source) == {"registry"} and source["registry"] == "https://pypi.org/simple"


def _dependency_items(record: dict[str, Any], extras: set[str], groups: set[str]) -> list[dict[str, Any]]:
    values = record.get("dependencies", [])
    if not isinstance(values, list):
        _fail("session2_lock_dependencies_invalid")
    result = list(values)
    optional = record.get("optional-dependencies", {})
    if optional is None:
        optional = {}
    if not isinstance(optional, dict):
        _fail("session2_lock_optional_dependencies_invalid")
    for extra in sorted(extras):
        entries = optional.get(extra)
        if entries is None:
            _fail("session2_lock_extra_missing")
        if not isinstance(entries, list):
            _fail("session2_lock_optional_dependencies_invalid")
        result.extend(entries)
    dev = record.get("dev-dependencies", {})
    if dev is None:
        dev = {}
    if not isinstance(dev, dict):
        _fail("session2_lock_dev_dependencies_invalid")
    for group in sorted(groups):
        entries = dev.get(group)
        if entries is None:
            _fail("session2_lock_group_missing")
        if not isinstance(entries, list):
            _fail("session2_lock_dev_dependencies_invalid")
        result.extend(entries)
    return result


def _choose(records: list[dict[str, Any]], name: str, version: object, environment: Mapping[str, str]) -> dict[str, Any]:
    possible = [record for record in records if record.get("name") == name and (version is None or record.get("version") == version) and _record_applies(record, environment)]
    if len(possible) != 1:
        _fail("session2_lock_dependency_ambiguous" if possible else "session2_lock_dependency_missing")
    return possible[0]


def _artifact_hashes(record: dict[str, Any]) -> list[str]:
    raw: list[object] = []
    if record.get("sdist") is not None:
        raw.append(record["sdist"])
    wheels = record.get("wheels", [])
    if not isinstance(wheels, list):
        _fail("session2_lock_wheels_invalid")
    raw.extend(wheels)
    hashes: list[str] = []
    for artifact in raw:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("url"), str) or not artifact["url"].startswith("https://files.pythonhosted.org/"):
            _fail("session2_lock_artifact_source_invalid")
        digest = artifact.get("hash")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
            _fail("session2_lock_artifact_hash_invalid")
        hashes.append(digest[7:])
    if not hashes:
        _fail("session2_lock_artifacts_missing")
    return sorted(set(hashes))


def export_uv_requirements(lock_bytes: bytes, *, project_name: str, extras: set[str], groups: set[str], additional_packages: set[str] = frozenset(), environment: Mapping[str, str] | None = None) -> RequirementsExport:
    """Return exact ``pip --require-hashes`` input from one committed lock.

    Only a registry-backed, immutable dependency closure is supported.  The
    project itself is purposefully omitted: the patient snapshot is mounted
    read-only and imported from that exact snapshot at execution time.
    """
    if not isinstance(lock_bytes, bytes) or not lock_bytes or not isinstance(project_name, str) or not project_name:
        _fail("session2_lock_input_invalid")
    target = dict(DEFAULT_ENVIRONMENT if environment is None else environment)
    try:
        document = tomllib.loads(lock_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise LockfileError("session2_lock_toml_invalid") from exc
    if document.get("version") != 1 or not isinstance(document.get("package"), list):
        _fail("session2_lock_header_invalid")
    records = document["package"]
    if not all(isinstance(record, dict) and isinstance(record.get("name"), str) and isinstance(record.get("version"), str) for record in records):
        _fail("session2_lock_package_invalid")
    root = _choose(records, project_name, None, target)
    if _registry_record(root):
        _fail("session2_lock_project_must_be_local")
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    if not all(isinstance(name, str) and name for name in additional_packages):
        _fail("session2_lock_additional_packages_invalid")
    queued: deque[tuple[dict[str, Any], set[str], set[str]]] = deque([(root, set(extras), set(groups))])
    for name in sorted(additional_packages):
        queued.append((_choose(records, name, None, target), set(), set()))
    while queued:
        record, required_extras, required_groups = queued.popleft()
        name, version = record["name"], record["version"]
        key = (name, version)
        if key in selected:
            continue
        selected[key] = record
        for dependency in _dependency_items(record, required_extras, required_groups):
            if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                _fail("session2_lock_dependency_invalid")
            if not _applies(dependency.get("marker"), target):
                continue
            resolved = _choose(records, dependency["name"], dependency.get("version"), target)
            queued.append((resolved, set(dependency.get("extra", [])), set()))
    exported: list[dict[str, Any]] = []
    lines: list[str] = []
    for (name, version), record in sorted(selected.items()):
        if name == project_name:
            continue
        if not _registry_record(record):
            _fail("session2_lock_nonregistry_dependency")
        hashes = _artifact_hashes(record)
        lines.append(name + "==" + version + " \\")
        lines.extend("    --hash=sha256:" + digest + " \\" for digest in hashes[:-1])
        lines.append("    --hash=sha256:" + hashes[-1])
        exported.append({"name": name, "version": version, "artifact_hashes": ["sha256:" + digest for digest in hashes]})
    if not lines:
        _fail("session2_lock_dependency_closure_empty")
    requirements = ("\n".join(lines) + "\n").encode("utf-8")
    manifest = {
        "schema_id": "external_validation.session2_lock_requirements.v1",
        "schema_version": "1",
        "project_name": project_name,
        "extras": sorted(extras),
        "groups": sorted(groups),
        "additional_packages": sorted(additional_packages),
        "target": {key: target[key] for key in sorted(DEFAULT_ENVIRONMENT)},
        "lock_sha256": "sha256:" + sha256(lock_bytes).hexdigest(),
        "requirements_sha256": "sha256:" + sha256(requirements).hexdigest(),
        "packages": exported,
    }
    return RequirementsExport(requirements=requirements, manifest=manifest)


def requirements_manifest_hash(export: RequirementsExport) -> str:
    return "sha256:" + sha256(canonical_json(export.manifest)).hexdigest()
