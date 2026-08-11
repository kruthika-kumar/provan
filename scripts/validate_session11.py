from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
from provan.leakage import PRIVATE_PATTERNS

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "1cdc50d05115f8385b14ad1eee62e169fec6436d"
SESSION11_SCHEMAS = {
    "acceptance-attestation.v1.json", "acceptance-contract.v1.json", "candidate-freeze.v1.json",
    "closure-requirement.v1.json", "command-receipt.v1.json", "environment-receipt.v1.json",
    "evidence-settlement.v1.json", "external-change-receipt.v1.json", "owner-decision.v1.json",
    "protected-invariant.v1.json", "reinspection-record.v1.json", "seed-disposition.v1.json",
    "verification-result.v1.json", "verifier-capability-request.v1.json", "verifier-work-order.v1.json",
    "session11-proof-registry.v1.json", "session11-layer4-matrix.v1.json",
    "session11-proof-manifest.v1.json", "session11-reviewer-receipt.v1.json",
    "session11-closeout.v1.json",
    "session12-handoff.v1.json",
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="strict").stdout.strip()


def validate_authority() -> None:
    registry_path = ROOT / "artifacts/session11/claim_registry.v1.public.json"
    registry = load(registry_path); work = load(ROOT / "artifacts/session11/work_order.v1.public.json")
    ids = [row.get("claim_id") for row in registry.get("claims", [])]
    expected = [f"G11-{number:02d}" for number in range(1, 88)]
    if ids[:87] != expected or ids != [f"G11-{number:02d}" for number in range(1, len(ids) + 1)]:
        raise SystemExit("SESSION11_CLAIM_SET_INVALID")
    if any(not row.get("normative_claim") for row in registry["claims"]):
        raise SystemExit("SESSION11_CLAIM_TEXT_MISSING")
    if work["claim_registry"]["sha256"] != digest(registry_path.read_bytes()) or work["claim_registry"]["frozen_count"] != len(ids):
        raise SystemExit("SESSION11_CLAIM_AUTHORITY_BINDING_MISMATCH")


def validate_schemas() -> None:
    registry = load(ROOT / "artifacts/session11/schema_registry.v1.public.json")
    rows = registry.get("entries", [])
    if registry.get("registry_digest") != digest(canonical(rows)):
        raise SystemExit("SESSION11_SCHEMA_REGISTRY_DIGEST_MISMATCH")
    by_path = set()
    for row in rows:
        path = ROOT / row["path"]; value = load(path); jsonschema.Draft202012Validator.check_schema(value)
        if row["path"] in by_path or value.get("$id") != row["schema_id"] or digest(path.read_bytes()) != row["sha256"] or digest(canonical(value)) != row["normalized_sha256"]:
            raise SystemExit("SESSION11_SCHEMA_REGISTRY_ENTRY_INVALID")
        by_path.add(row["path"])
    changed = set(filter(None, git("diff", "--name-only", BASELINE, "--", "provan/schemas").splitlines()))
    expected_changed = {f"provan/schemas/{name}" for name in SESSION11_SCHEMAS}
    if changed != expected_changed:
        raise SystemExit("SESSION11_SCHEMA_HISTORY_BOUNDARY_INVALID")


def validate_boundaries() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    docs = (ROOT / "README.md").read_text(encoding="utf-8") + (ROOT / "docs/acceptance-lifecycle.md").read_text(encoding="utf-8")
    if 'version = "0.4.0"' not in pyproject or "QUALIFIED_BOUNDED" not in docs or "not available from PyPI" not in docs:
        raise SystemExit("SESSION11_UNPUBLISHED_VERSION_BOUNDARY_INVALID")
    cli = (ROOT / "provan/cli.py").read_text(encoding="utf-8")
    if "--external-change-receipt-file" not in cli or re.search(r"add_parser\(\s*[\"'](?:verify|challenge|enterprise|remediate|deploy)", cli):
        raise SystemExit("SESSION11_FORBIDDEN_CAPABILITY_EXPOSED")
    if git("diff", "--name-only", BASELINE, "--", "artifacts/session10"):
        raise SystemExit("SESSION10_HISTORICAL_ARTIFACT_CHANGED")
    runtime = (ROOT / "provan/acceptance.py").read_text(encoding="utf-8")
    if any(token in runtime for token in ("subprocess.run", "importlib.import_module", "os.system(", "shell=True")):
        raise SystemExit("SESSION11_TARGET_EXECUTION_ADAPTER_EXPOSED")
    validators = (ROOT / "provan/session11_validators.py").read_text(encoding="utf-8")
    forbidden = ("import jsonschema", "from jsonschema", "create_contract(", "freeze_contract(", "attest(", "reinspect(")
    if any(token in validators for token in forbidden) or "json.loads(raw)" not in validators or "hashlib" in validators:
        raise SystemExit("SESSION11_SEMANTIC_INDEPENDENCE_INVALID")


def validate_public_artifact_safety() -> None:
    """Scan proposed Session 11 artifacts, including untracked files."""
    public_patterns={name:PRIVATE_PATTERNS[name] for name in ("ABSOLUTE_USER_PATH","CREDENTIAL_BEARING_URL")}
    for path in sorted((ROOT/"artifacts/session11").rglob("*")):
        if not path.is_file():continue
        try:text=path.read_text(encoding="utf-8",errors="strict")
        except (UnicodeDecodeError,OSError):continue
        for name,pattern in public_patterns.items():
            if pattern.search(text):raise SystemExit("SESSION11_PUBLIC_PROOF_"+name+"_LEAK")


def validate_proofs(final: bool) -> None:
    base = ROOT / "artifacts/session11"
    registry_path = base / "proofs/proof_registry.v1.public.json"
    matrix_path = base / ("layer4_claim_matrix.final.v1.public.json" if final else "layer4_claim_matrix.v1.public.json")
    if not registry_path.exists() or not matrix_path.exists():
        raise SystemExit("SESSION11_PROOF_SET_MISSING")
    registry = load(registry_path); entries = {row["proof_id"]: row for row in registry["entries"]}
    jsonschema.validate(registry, load(ROOT/"provan/schemas/session11-proof-registry.v1.json"))
    expected_classes = {"valid", "near-valid", "adversarial", "schema-invalid", "schema-valid-python-invalid"}
    for invariant in {row["invariant"] for row in entries.values()}:
        rows=[row for row in entries.values() if row["invariant"]==invariant];actual={row["fixture_class"] for row in rows};expected={"valid","near-valid","adversarial"} if all(row["schema_result"]=="NOT_APPLICABLE:RUNTIME_BEHAVIORAL_INVARIANT" for row in rows) else expected_classes
        if actual != expected:
            raise SystemExit("SESSION11_INVARIANT_PROOF_GRANULARITY_INCOMPLETE")
    for row in entries.values():
        if not row["artifact_locations"] or len(row["artifact_locations"]) != len(row["artifact_hashes"]):
            raise SystemExit("SESSION11_PROOF_BINDING_INVALID")
        for location, expected in zip(row["artifact_locations"], row["artifact_hashes"]):
            path = ROOT / location
            if not path.is_file() or digest(path.read_bytes()) != expected:
                raise SystemExit("SESSION11_PROOF_ARTIFACT_HASH_MISMATCH")
    matrix = load(matrix_path);jsonschema.validate(matrix,load(ROOT/"provan/schemas/session11-layer4-matrix.v1.json"));claims = matrix["claims"]; authority = load(base / "claim_registry.v1.public.json")["claims"]
    ids = [row["Claim"].split(" — ", 1)[0] for row in claims]
    expected = [row["claim_id"] for row in authority]
    if ids != expected:
        raise SystemExit("SESSION11_LAYER4_CLAIM_SET_INVALID")
    expected_text = {row["claim_id"]: row["normative_claim"] for row in authority}
    for row in claims:
        claim_id = row["Claim"].split(" — ", 1)[0]
        if row["Claim"] != f"{claim_id} — {expected_text[claim_id]}": raise SystemExit("SESSION11_LAYER4_CLAIM_TEXT_CHANGED")
        if any(row[key] not in entries for key in ("Positive proof", "Near-valid proof", "Negative proof")): raise SystemExit("SESSION11_LAYER4_PROOF_UNRESOLVED")
        if final and (row["Reviewer result"] != "ACCEPTED" or row["Status"] != "CLOSED"): raise SystemExit("SESSION11_LAYER4_REVIEW_INCOMPLETE")
    crosswalk=load(base/"proofs/claim_crosswalk.v1.public.json");mapped={}
    for item in crosswalk["entries"]:
        for claim_id in item["claim_ids"]:
            if claim_id in mapped:raise SystemExit("SESSION11_CROSSWALK_DUPLICATE_CLAIM")
            mapped[claim_id]=item["major_invariant"]
        if any(proof_id not in entries or entries[proof_id]["invariant"]!=item["major_invariant"] for proof_id in item["proof_ids"]):raise SystemExit("SESSION11_CROSSWALK_PROOF_INVARIANT_MISMATCH")
    if set(mapped)!=set(ids):raise SystemExit("SESSION11_CROSSWALK_CLAIM_SET_MISMATCH")
    for row in claims:
        claim_id=row["Claim"].split(" — ",1)[0]
        if any(entries[row[key]]["invariant"]!=mapped[claim_id] for key in ("Positive proof","Near-valid proof","Negative proof")):raise SystemExit("SESSION11_LAYER4_UNRELATED_PROOF")


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--phase", choices=("implementation", "final"), default="implementation"); args = parser.parse_args()
    validate_authority(); validate_schemas(); validate_boundaries(); validate_public_artifact_safety(); validate_proofs(args.phase == "final")
    print(f"SESSION11_VALID {args.phase.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
