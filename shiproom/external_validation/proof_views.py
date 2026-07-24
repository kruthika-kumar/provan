"""Deterministic public views of private canonical proof artifacts."""
from __future__ import annotations

from hashlib import sha256
from typing import Any

from .identity import canonical_json

PRIVATE_KEYS = {"external_root", "host_path", "container_id", "container_name", "docker_endpoint", "username", "canary_secret", "cidfile"}


def sanitize_proof(canonical: dict[str, Any], *, canonical_hash: str, policy_version: str, tool_hash: str) -> dict[str, Any]:
    """Public evidence is a deterministic view, never qualification authority."""
    def clean(value: Any) -> Any:
        if isinstance(value, list): return [clean(item) for item in value]
        if isinstance(value, dict): return {key: clean(value[key]) for key in sorted(value) if key not in PRIVATE_KEYS}
        return value
    view = {"schema_id": "external_validation.public_proof_view.v1", "schema_version": "1", "canonical_artifact_hash": canonical_hash,
            "sanitization_policy_version": policy_version, "sanitization_tool_hash": tool_hash, "authority": "non_qualifying_public_view",
            "redacted_fields": sorted(key for key in canonical if key in PRIVATE_KEYS), "proof": clean(canonical)}
    view["view_hash"] = "sha256:" + sha256(canonical_json(view)).hexdigest()
    return view


def public_doctor_view(canonical: dict[str, Any], *, canonical_hash: str, policy_version: str, tool_hash: str) -> dict[str, Any]:
    """A compact deterministic view that cannot locate private receipts/runs."""
    proof = canonical["proof"]
    view = {
        "schema_id": "external_validation.public_proof_view.v1", "schema_version": "1",
        "canonical_artifact_hash": canonical_hash, "sanitization_policy_version": policy_version,
        "sanitization_tool_hash": tool_hash, "authority": "non_qualifying_public_view",
        "redacted_fields": ["proof.index", "proof.receipt_ids", "proof.schedule", "private_artifact_locations"],
        "proof": {"kind": "session1_repair_detection_qualification", "implementation_commit": canonical["implementation_commit"],
                  "source_tree": canonical["source_tree"], "runner_image": canonical["runner_image"],
                  "receipt_count": proof["corpus"]["receipt_count"], "adversarial_canaries": canonical["adversarial_canaries"],
                  "detection_profile": "QUALIFIED", "remediation_profile": "BLOCKED", "overall_status": "PARTIALLY_QUALIFIED"},
    }
    view["view_hash"] = "sha256:" + sha256(canonical_json(view)).hexdigest()
    return view
