"""Validate a complete hash-pinned pip requirements authority.

This deliberately accepts neither loose project metadata nor a partially
pinned constraints file.  It is the non-``uv.lock`` counterpart to the
Session 2 lock exporter, and returns the exact bytes that pip must consume.
"""
from __future__ import annotations

from hashlib import sha256
import re

from .identity import canonical_json


class RequirementsAuthorityError(ValueError):
    pass


_PIN = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,. -]+\])?==[^\s;]+(?:\s|\\|$)")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")
_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,. -]+\])?==([^\s;]+)")


def export_hash_pinned_requirements(raw: bytes, *, source_path: str) -> tuple[bytes, dict[str, object]]:
    """Return canonical requirements bytes only when every requirement is pinned.

    Includes, editable installs, direct URLs, environment markers, and index
    switches make the source non-self-contained and therefore fail closed.
    """
    if not isinstance(raw, bytes) or not raw or not isinstance(source_path, str) or not source_path or source_path.startswith("/") or ".." in source_path.split("/"):
        raise RequirementsAuthorityError("session2_requirements_authority_invalid")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RequirementsAuthorityError("session2_requirements_authority_invalid") from exc
    if not text.endswith("\n") or "\r" in text:
        raise RequirementsAuthorityError("session2_requirements_authority_invalid")
    logical: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # A continuation line is necessarily a ``--hash`` option.  It is the
        # one permitted option because it is the cryptographic authority; all
        # index/include/editable/direct-reference switches still fail closed.
        if ((stripped.startswith("-") and not stripped.startswith("--hash=sha256:"))
                or stripped.startswith("@") or ";" in stripped or "://" in stripped):
            raise RequirementsAuthorityError("session2_requirements_authority_noncanonical")
        current += " " + stripped
        if stripped.endswith("\\"):
            continue
        logical.append(current.strip()); current = ""
    if current or not logical:
        raise RequirementsAuthorityError("session2_requirements_authority_invalid")
    for entry in logical:
        if not _PIN.match(entry) or not _HASH.search(entry):
            raise RequirementsAuthorityError("session2_requirements_authority_unpinned")
    manifest = {"schema_id":"external_validation.session2_hash_pinned_requirements.v1", "schema_version":"1", "source_path":source_path, "requirements_sha256":"sha256:" + sha256(raw).hexdigest(), "requirement_count":len(logical)}
    return raw, manifest


def requirements_authority_hash(manifest: dict[str, object]) -> str:
    return "sha256:" + sha256(canonical_json(manifest)).hexdigest()


def pinned_requirement_records(raw: bytes, *, source_path: str) -> list[dict[str, object]]:
    """Expose only exact name/version/hash tuples for supervised fetching."""
    export_hash_pinned_requirements(raw, source_path=source_path)
    records: list[dict[str, object]] = []
    current = ""
    for line in raw.decode("utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        current += " " + value
        if value.endswith("\\"):
            continue
        match = _ENTRY.match(current.strip())
        if match is None:  # established by the parser above
            raise RequirementsAuthorityError("session2_requirements_authority_invalid")
        records.append({"name": match.group(1).lower().replace("_", "-"), "version": match.group(2), "hashes": sorted(set(_HASH.findall(current)))})
        current = ""
    return records
