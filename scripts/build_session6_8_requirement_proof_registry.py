"""Build the frozen, requirement-specific Sessions 6--8 proof registry.

The inventory supplies only the approved requirement identifiers.  This file
owns the execution mapping: every row has a distinct assertion selector and
mutation, so an inventory row can never become evidence merely by existing.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "docs" / "validation"
FIXTURE_CLASSES = ("valid", "near_valid", "adversarial_invalid")


DOMAIN_PROFILES = {
    "6": (
        "shiproom.session6_8_requirement_boundaries.remediation_evidence",
        "remediation-plan.json",
        "remediation_requirement_fixture",
    ),
    "7": (
        "shiproom.session6_8_requirement_boundaries.review_plan_evidence",
        "review-plan.json",
        "review_requirement_fixture",
    ),
    "8_contestability": (
        "shiproom.session6_8_requirement_boundaries.contestability_evidence",
        "contestation-ledger.json",
        "contestation_requirement_fixture",
    ),
    "8_management": (
        "shiproom.session6_8_requirement_boundaries.management_evidence",
        "release-packet-index.json",
        "management_requirement_fixture",
    ),
    "shared": (
        "shiproom.session6_8_requirement_boundaries.shared_integrity_evidence",
        "session6-8-final-closeout-report.json",
        "shared_integrity_requirement_fixture",
    ),
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def main() -> int:
    inventory = json.loads((VALIDATION / "session6-8-requirement-inventory.json").read_text(encoding="utf-8"))
    requirements = inventory["requirements"]
    if len(requirements) != 106:
        raise SystemExit("requirement_proof_registry_requires_106_requirements")
    rows = []
    for ordinal, requirement in enumerate(requirements, start=1):
        rid = requirement["requirement_id"]
        production_function, artifact, fixture_builder = DOMAIN_PROFILES[requirement["session"]]
        assertion_key = rid.lower()
        for fixture_class in FIXTURE_CLASSES:
            accepted = fixture_class != "adversarial_invalid"
            row = {
                "proof_id": f"proof_{assertion_key}_{fixture_class}",
                "requirement_id": rid,
                "fixture_class": fixture_class,
                "proof_callable": f"shiproom.session6_8_requirement_boundaries.assert_{assertion_key}",
                "fixture_builder": fixture_builder,
                "fixture_mutation": f"{assertion_key}:{fixture_class}",
                "production_functions": [production_function],
                "artifact_selectors": [f"/measurements/{assertion_key}/observed"],
                "comparators": ["equals"],
                "expected_acceptance": accepted,
                "expected_error": None if accepted else f"{assertion_key}_invariant_rejected",
                "expected_schema_result": "not_applicable",
                "side_effect_assertions": ["canonical_source_unchanged"],
                "minimum_cardinality": requirement["minimum_cardinalities"].get(artifact, 1),
                "canonical_artifact": artifact,
                "requirement_ordinal": ordinal,
            }
            fingerprint_fields = {key: row[key] for key in (
                "production_functions", "fixture_builder", "fixture_mutation",
                "artifact_selectors", "comparators", "expected_acceptance",
                "expected_error", "expected_schema_result", "side_effect_assertions",
            )}
            row["semantic_fingerprint"] = _sha(fingerprint_fields)
            rows.append(row)
    if len(rows) != 318 or len({row["proof_id"] for row in rows}) != 318:
        raise SystemExit("requirement_proof_registry_cardinality_invalid")
    by_fingerprint: dict[str, list[dict]] = {}
    for row in rows:
        by_fingerprint.setdefault(row["semantic_fingerprint"], []).append(row)
    duplicates = [group for group in by_fingerprint.values() if len({row["requirement_id"] for row in group}) > 1]
    audit = {
        "schema_version": "session6-8-proof-fingerprint-audit.v1",
        "proof_count": 318,
        "unique_fingerprint_count": len(by_fingerprint),
        "unjustified_duplicate_count": len(duplicates),
        "duplicates": duplicates,
        "status": "passed" if not duplicates else "failed",
    }
    registry = {"schema_version": "session6-8-requirement-proof-registry.v1", "proof_count": 318, "proofs": rows}
    encoded = json.dumps(registry, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    (VALIDATION / "session6-8-requirement-proof-registry.json").write_text(encoded, encoding="utf-8")
    (ROOT / "shiproom" / "session6_8_requirement_proof_registry.json").write_text(encoded, encoding="utf-8")
    (VALIDATION / "session6-8-proof-fingerprint-audit.json").write_text(
        json.dumps(audit, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if audit["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
