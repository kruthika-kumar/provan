from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provan.errors import ProvanError
from provan.leakage import validate_candidate_surfaces, validate_public_tree
from provan.validators import (
    validate_access_warning_audit_semantics,
    validate_correction_closeout_semantics,
    validate_correction_layer4_semantics,
    validate_external_publication_state_semantics,
    validate_mirror_attestation_semantics,
    validate_private_projection_semantics,
    validate_reviewer_receipt_semantics,
)

CORRECTION = ROOT / "artifacts" / "session9" / "correction"
BASE = "371f1e823a94165f735db907c2853cc490d20360"
PROTECTED = [
    "artifacts/session9/layer4_claim_matrix.public.json",
    "artifacts/session9/closeout_manifest.public.json",
    "artifacts/session9/proof_registry.public.json",
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def registry() -> dict[str, dict]:
    return {load(path)["$id"]: load(path) for path in (ROOT / "provan" / "schemas").glob("*.json")}


def validate_historical_status_artifacts() -> None:
    for relative in PROTECTED:
        historical = subprocess.run(["git", "show", f"{BASE}:{relative}"], cwd=ROOT, check=True, capture_output=True).stdout
        if (ROOT / relative).read_bytes() != historical:
            raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", relative)


def validate_manifest(path: Path, schemas: dict[str, dict]) -> dict:
    value = load(path); jsonschema.validate(value, schemas["provan.session9_correction_proof_manifest.v1"])
    rows = value["artifacts"]
    if rows != sorted(rows, key=lambda row: row["path"]) or len({row["path"] for row in rows}) != len(rows):
        raise ProvanError("CORRECTION_PROOF_MANIFEST_INVALID", "artifact inventory must be deterministic and unique")
    for row in rows:
        artifact = ROOT / row["path"]
        if not artifact.is_file() or digest(artifact) != row["sha256"]:
            raise ProvanError("CORRECTION_PROOF_HASH_MISMATCH", row["path"])
    expected = "sha256:" + hashlib.sha256(("\n".join(row["path"] + " " + row["sha256"] for row in rows) + "\n").encode()).hexdigest()
    if value["proof_root"] != expected:
        raise ProvanError("CORRECTION_PROOF_ROOT_MISMATCH", path.name)
    return value


def validate_proof_registry(path: Path, schemas: dict[str, dict]) -> None:
    value=load(path); jsonschema.validate(value, schemas["provan.session9_correction_proof_registry.v1"])
    entries=value["entries"]
    expected={(family,kind) for family in [f"C9{x}" for x in "ABCDEFGHI"] for kind in ("valid","near-valid","adversarial")}
    if {(entry["family"],entry["fixture_class"]) for entry in entries} != expected or len(entries) != 27:
        raise ProvanError("CORRECTION_PROOF_TRIAD_INCOMPLETE", "C9A-C9I each require one exact triad")
    for entry in entries:
        if entry["schema_result"] != "PASS" or entry["exit_code"] != 0:
            raise ProvanError("CORRECTION_PROOF_BINDING_INCOMPLETE", entry["proof_id"])
        expected_python = "REJECT:" + entry["python_error"] if entry["fixture_class"] == "adversarial" else "PASS"
        if entry["python_result"] != expected_python or len(entry["artifact_locations"]) != len(entry["artifact_hashes"]):
            raise ProvanError("CORRECTION_PROOF_BINDING_INCOMPLETE", entry["proof_id"])
        for location, expected_hash in zip(entry["artifact_locations"], entry["artifact_hashes"]):
            artifact=ROOT/location
            if not artifact.is_file() or digest(artifact) != expected_hash:
                raise ProvanError("CORRECTION_PROOF_HASH_MISMATCH", location)
        if entry["transcript_hash"] != entry["artifact_hashes"][-1]:
            raise ProvanError("CORRECTION_PROOF_HASH_MISMATCH", entry["proof_id"])
        expected_test = (
            "tests/test_session9_correction.py::"
            f"test_correction_proof_fixture_executes_independent_semantics[{entry['family']}-{entry['fixture_class']}]"
        )
        expected_production = {
            "C9A": "provan.validators.validate_inspection_write_result_semantics",
            "C9B": "provan.validators.validate_doctor_semantics",
            "C9C": "provan.validators.validate_telemetry_status_semantics",
            "C9D": "provan.validators.validate_reviewer_receipt_semantics",
            "C9E": "provan.validators.validate_private_projection_semantics",
            "C9F": "provan.validators.validate_correction_layer4_semantics",
            "C9G": "provan.validators.validate_access_warning_audit_semantics",
            "C9H": "provan.validators.validate_state_link_proof_semantics",
            "C9I": (
                "provan.validators.validate_mirror_attestation_semantics"
                if entry["fixture_class"] == "near-valid"
                else "provan.validators.validate_external_publication_state_semantics"
            ),
        }[entry["family"]]
        if entry["test_id"] != expected_test or entry["production_function"] != expected_production:
            raise ProvanError("CORRECTION_PROOF_BINDING_INCOMPLETE", entry["proof_id"])


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--implementation-only", action="store_true"); parser.add_argument("--pre-review", action="store_true"); parser.add_argument("--external-receipt"); parser.add_argument("--mirror-attestation"); args=parser.parse_args()
    schemas=registry(); validate_historical_status_artifacts()
    validate_public_tree(ROOT, [p for p in CORRECTION.rglob("*") if p.is_file()])
    validate_candidate_surfaces(ROOT)
    if args.external_receipt:
        receipt=load(Path(args.external_receipt)); jsonschema.validate(receipt,schemas["provan.external_publication_receipt.v1"]); validate_external_publication_state_semantics(receipt)
    if args.mirror_attestation:
        mirror=load(Path(args.mirror_attestation)); jsonschema.validate(mirror,schemas["provan.external_mirror_attestation.v1"]); validate_mirror_attestation_semantics(mirror)
    required_pre=["proof_registry.v1.public.json","pre_review_proof_manifest.v1.public.json","access_warning_audit.v1.public.json"]
    if args.implementation_only:
        print(json.dumps({"status":"SESSION9_CORRECTION_VALID","mode":"IMPLEMENTATION"},sort_keys=True)); return 0
    if all((CORRECTION/name).exists() for name in required_pre):
        validate_proof_registry(CORRECTION/required_pre[0],schemas)
        validate_manifest(CORRECTION/required_pre[1],schemas)
        warning=load(CORRECTION/required_pre[2]); jsonschema.validate(warning,schemas["provan.access_warning_audit.v1"]); validate_access_warning_audit_semantics(warning)
    elif args.pre_review:
        raise ProvanError("CORRECTION_PRE_REVIEW_SET_INCOMPLETE", "pre-review artifacts are missing")
    if not args.pre_review:
        crosswalk=load(CORRECTION/"layer4_claim_crosswalk.v1.public.json"); jsonschema.validate(crosswalk,schemas["provan.layer4_claim_crosswalk.v1"])
        matrix=load(CORRECTION/"layer4_claim_matrix.v2.public.json"); jsonschema.validate(matrix,schemas["provan.layer4_claim_matrix_correction.v2"]); validate_correction_layer4_semantics(matrix,crosswalk,[load(ROOT/"artifacts/session9/proof_registry.public.json"),load(CORRECTION/"proof_registry.v1.public.json")],load(CORRECTION/"correction_plan.v1.json")["claim_proof_authority"])
        for name in ("evals_projection.v1.public.json","enterprise_projection.v1.public.json"):
            value=load(CORRECTION/name); jsonschema.validate(value,schemas["provan.private_repository_projection.v1"]); validate_private_projection_semantics(value)
        review=load(CORRECTION/"reviewer_receipt.v1.public.json"); jsonschema.validate(review,schemas["provan.session9_correction_reviewer_receipt.v1"]); validate_reviewer_receipt_semantics(review)
        closeout=load(CORRECTION/"closeout_correction.v1.public.json"); jsonschema.validate(closeout,schemas["provan.session9_closeout_correction.v1"]); validate_correction_closeout_semantics(closeout)
        validate_manifest(CORRECTION/"proof_manifest.v1.public.json",schemas)
    print(json.dumps({"status":"SESSION9_CORRECTION_VALID","mode":"PRE_REVIEW" if args.pre_review else "FINAL"},sort_keys=True))
    return 0


if __name__ == "__main__":
    from scripts.session9_git_isolation import isolated_git_environment
    try:
        with isolated_git_environment(ROOT):
            raise SystemExit(main())
    except (ProvanError, jsonschema.ValidationError, FileNotFoundError) as exc:
        code=exc.code if isinstance(exc,ProvanError) else type(exc).__name__
        print(json.dumps({"status":"INVALID","error":code,"message":str(exc)},sort_keys=True)); raise SystemExit(2)
