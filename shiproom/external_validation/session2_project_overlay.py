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


def _fail(code: str) -> None:
    raise ProjectOverlayError(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def project_metadata_overlay(snapshot: Path, command: list[str]) -> dict[str, Any]:
    """Return a frozen wrapper argv and the source-derived authority record.

    Dynamic project versions are rejected: a qualification command cannot
    derive its installed identity by executing project-controlled code.
    """
    if (not snapshot.is_absolute() or not snapshot.is_dir() or snapshot.is_symlink()
            or not isinstance(command, list) or not command
            or any(not isinstance(item, str) or not item for item in command)):
        _fail("session2_project_metadata_overlay_input_invalid")
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
    # The directory name is only an importlib discovery convention.  Both
    # fields were strictly validated above, so it cannot influence the shell.
    overlay_root = "/tmp/shiproom-project-metadata"
    dist_info = overlay_root + "/" + name.replace("-", "_") + "-" + version + ".dist-info"
    script = (
        "set -eu; umask 077; d=" + shlex.quote(dist_info) + "; "
        "mkdir -p \"$d\"; printf '%s' " + shlex.quote(metadata.decode("utf-8"))
        + " > \"$d/METADATA\"; "
        "exec env PYTHONPATH=" + shlex.quote(overlay_root)
        + "\"${PYTHONPATH:+:$PYTHONPATH}\" \"$@\""
    )
    wrapper = ["sh", "-ec", script, "shiproom-project-metadata-overlay", *command]
    authority = {
        "schema_id": "external_validation.session2_project_metadata_overlay.v1",
        "schema_version": "1",
        "snapshot_pyproject_hash": _sha(raw),
        "project_name": name,
        "project_version": version,
        "metadata_sha256": _sha(metadata),
        "overlay_root": overlay_root,
        "patient_tree_write_policy": "forbidden",
        "network_policy": "none",
        "wrapped_argv": wrapper,
    }
    authority["authority_hash"] = _sha(canonical_json(authority))
    return authority
