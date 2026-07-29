"""Derive a transient, source-bound Python distribution metadata overlay.

Some immutable Python snapshots import their own source directly but ask
``importlib.metadata`` for the installed distribution version.  Installing a
patient project during a qualifying run would either mutate the snapshot or
introduce an unfrozen build-backend dependency.  This module derives the
minimal PEP 621 metadata from the *immutable* ``pyproject.toml`` and creates
it only in the container's disposable ``/tmp`` before the frozen test argv is
executed.  It never writes the patient tree and it is not a dependency
resolver.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import shlex
import tomllib
from typing import Any

from .identity import canonical_json


class ProjectOverlayError(ValueError):
    """Stable source-metadata overlay rejection."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")
_ENTRY_GROUP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRY_VALUE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?::[A-Za-z_][A-Za-z0-9_.]*)?$")
_RUNTIME_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_RUNTIME_VALUE = re.compile(r"^/tmp/shiproom-[a-z0-9-]{1,64}$")


def _fail(code: str) -> None:
    raise ProjectOverlayError(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def project_metadata_overlay(snapshot: Path, command: list[str], *, runtime_environment: dict[str, str] | None = None, working_directory: str | None = None) -> dict[str, Any]:
    """Return a frozen wrapper argv and the source-derived authority record.

    Dynamic project versions are rejected: a qualification command cannot
    derive its installed identity by executing project-controlled code.
    """
    if (not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink()
            or not isinstance(command, list) or not command
            or any(not isinstance(item, str) or not item for item in command)):
        _fail("session2_project_metadata_overlay_input_invalid")
    if runtime_environment is None:
        runtime_environment = {}
    if (not isinstance(runtime_environment, dict)
            or any(not isinstance(key, str) or not isinstance(value, str)
                   or not _RUNTIME_KEY.fullmatch(key) or not _RUNTIME_VALUE.fullmatch(value)
                   for key, value in runtime_environment.items())):
        _fail("session2_project_metadata_overlay_runtime_environment_invalid")
    if working_directory is not None and (not isinstance(working_directory, str) or not _RUNTIME_VALUE.fullmatch(working_directory)):
        _fail("session2_project_metadata_overlay_working_directory_invalid")
    pyproject = snapshot / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        _fail("session2_project_metadata_overlay_pyproject_missing")
    raw = pyproject.read_bytes()
    try:
        document = tomllib.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProjectOverlayError("session2_project_metadata_overlay_pyproject_invalid") from exc
    project = document.get("project")
    if not isinstance(project, dict):
        _fail("session2_project_metadata_overlay_project_invalid")
    name, version = project.get("name"), project.get("version")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        _fail("session2_project_metadata_overlay_name_invalid")
    if not isinstance(version, str) or not _VERSION.fullmatch(version) or "dynamic" in project:
        _fail("session2_project_metadata_overlay_version_not_static")
    metadata = ("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n").encode("utf-8")
    raw_entry_points = project.get("entry-points", {})
    if raw_entry_points is None:
        raw_entry_points = {}
    if not isinstance(raw_entry_points, dict):
        _fail("session2_project_metadata_overlay_entry_points_invalid")
    entry_lines: list[str] = []
    for group in sorted(raw_entry_points):
        entries = raw_entry_points[group]
        if (not isinstance(group, str) or not _ENTRY_GROUP.fullmatch(group)
                or not isinstance(entries, dict) or not entries):
            _fail("session2_project_metadata_overlay_entry_points_invalid")
        entry_lines.append("[" + group + "]")
        for entry_name in sorted(entries):
            target = entries[entry_name]
            if (not isinstance(entry_name, str) or not _ENTRY_NAME.fullmatch(entry_name)
                    or not isinstance(target, str) or not _ENTRY_VALUE.fullmatch(target)):
                _fail("session2_project_metadata_overlay_entry_points_invalid")
            entry_lines.append(entry_name + " = " + target)
        entry_lines.append("")
    entry_points = ("\n".join(entry_lines)).encode("utf-8")
    # The directory name is only an importlib discovery convention.  Both
    # fields were strictly validated above, so it cannot influence the shell.
    overlay_root = "/tmp/shiproom-project-metadata"
    dist_info = overlay_root + "/" + name.replace("-", "_") + "-" + version + ".dist-info"
    script = (
        "set -eu; umask 077; d=" + shlex.quote(dist_info) + "; "
        "mkdir -p \"$d\"; printf '%s' " + shlex.quote(metadata.decode("utf-8"))
        + " > \"$d/METADATA\"; "
        + ("printf '%s' " + shlex.quote(entry_points.decode("utf-8")) + " > \"$d/entry_points.txt\"; " if entry_points else "")
        + ("mkdir -p " + shlex.quote(working_directory) + "; cd " + shlex.quote(working_directory) + "; " if working_directory else "")
        + "exec env PYTHONPATH=" + shlex.quote(overlay_root + ":/patient")
        + "\"${PYTHONPATH:+:$PYTHONPATH}\" \"$@\""
    )
    if runtime_environment:
        assignments = " ".join(key + "=" + shlex.quote(value) for key, value in sorted(runtime_environment.items()))
        script = script.replace("exec env PYTHONPATH=", "exec env " + assignments + " PYTHONPATH=", 1)
    wrapper = ["sh", "-ec", script, "shiproom-project-metadata-overlay", *command]
    authority = {
        "schema_id": "external_validation.session2_project_metadata_overlay.v1",
        "schema_version": "1",
        "snapshot_pyproject_hash": _sha(raw),
        "project_name": name,
        "project_version": version,
        "metadata_sha256": _sha(metadata),
        "entry_points_sha256": _sha(entry_points),
        "runtime_environment": {key: runtime_environment[key] for key in sorted(runtime_environment)},
        "working_directory": working_directory,
        "overlay_root": overlay_root,
        "patient_tree_write_policy": "forbidden",
        "network_policy": "none",
        "wrapped_argv": wrapper,
    }
    authority["authority_hash"] = _sha(canonical_json(authority))
    return authority
