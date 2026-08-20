from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from provan.session12r_validators import validate_public_semantic_evidence_serialized

BASELINE = "dc156ddccc5f94c0679b678ec6a4c6ef3c4ece98"
HISTORICAL_WHEEL = "sha256:85ddf1e3c5fc9362565395c9a341bc418d58884797531c0918c94befc4caaf30"
CLAIM_DIGEST = "sha256:6b9b71650afd6218ffedfd414e46869f620771c87b58878fcb9d426bff15b386"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SystemExit(code)


def git_bytes(object_id: str) -> bytes:
    result = subprocess.run(["git", "cat-file", "blob", object_id], cwd=ROOT, capture_output=True)
    require(result.returncode == 0, "SESSION12R_HISTORICAL_OBJECT_UNRESOLVED")
    return result.stdout


def historical_paths() -> list[tuple[str, str]]:
    result = subprocess.run(["git", "ls-tree", "-r", BASELINE, "artifacts/session12", "provan/schemas"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    require(result.returncode == 0, "SESSION12R_HISTORICAL_TREE_UNRESOLVED")
    rows = []
    for line in result.stdout.splitlines():
        metadata, path = line.split("\t", 1); object_id = metadata.split()[2]
        if not path.startswith("artifacts/session12/successor_closeout/"): rows.append((path, object_id))
    return rows


def main() -> int:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    require(head.returncode == 0, "SESSION12R_GIT_STATE_UNAVAILABLE")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE, head.stdout.strip()], cwd=ROOT).returncode == 0, "SESSION12R_BASELINE_LINEAGE_INVALID")
    for path, object_id in historical_paths():
        current = ROOT / path
        require(current.is_file() and not current.is_symlink() and current.read_bytes() == git_bytes(object_id), "SESSION12R_HISTORICAL_BYTES_CHANGED")
    wheel = ROOT / "dist/provan_assurance-0.5.0-py3-none-any.whl"
    require(wheel.is_file() and digest(wheel.read_bytes()) == HISTORICAL_WHEEL, "SESSION12R_HISTORICAL_WHEEL_CHANGED")

    registry_path = ROOT / "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json"
    registry = json.loads(registry_path.read_bytes()); declared = registry.pop("registry_digest", None)
    require(declared == CLAIM_DIGEST == digest(canonical(registry)), "SESSION12R_CLAIM_REGISTRY_DIGEST_MISMATCH")
    claims = registry.get("claims", [])
    require([row.get("claim_id") for row in claims] == [f"G12R-{index:02d}" for index in range(1, 98)] and all(isinstance(row.get("normative_claim"), str) and row["normative_claim"] for row in claims), "SESSION12R_CLAIM_REGISTRY_INVALID")
    compatibility = json.loads((ROOT / "artifacts/session12/successor_closeout/authority/compatibility_registry.v1.public.json").read_bytes())
    expected_public = {"source_authority_ledger.v2", "intent_model.v2", "contract_candidate.v2", "verification_pattern_selection.v2", "foundry_acceptance_projection.v2", "foundry_owner_review.v1"}
    require({row["object"] for row in compatibility["decisions"] if row["classification"] == "public_canonical"} == expected_public, "SESSION12R_COMPATIBILITY_PUBLIC_SET_INVALID")
    require({row["classification"] for row in compatibility["decisions"]} == {"public_canonical", "internal_canonical", "private_evaluation", "reused_unchanged"}, "SESSION12R_COMPATIBILITY_CLASSIFICATION_INCOMPLETE")

    schema_names = {"source-authority-ledger.v2.json", "intent-model.v2.json", "contract-candidate.v2.json", "verification-pattern-selection.v2.json", "foundry-acceptance-projection.v2.json", "foundry-owner-review.v1.json", "source-coverage.v1.json"}
    for name in schema_names:
        path = ROOT / "provan/schemas" / name; require(path.is_file(), "SESSION12R_SCHEMA_MISSING")
        jsonschema.Draft202012Validator.check_schema(json.loads(path.read_bytes()))

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8"); readme = (ROOT / "README.md").read_text(encoding="utf-8"); docs = (ROOT / "docs/contract-foundry.md").read_text(encoding="utf-8"); cli = (ROOT / "provan/cli.py").read_text(encoding="utf-8")
    require('version = "0.5.1"' in pyproject and "0.5.1" in readme and "unpublished" in readme.lower(), "SESSION12R_VERSION_BOUNDARY_INVALID")
    require(all(token in cli for token in ("--information-boundary", "--view", "owner-review")), "SESSION12R_CLI_SURFACE_INCOMPLETE")
    require(all(token in docs for token in ("Source Bundle", "YAML comments", "implementation-aware", "Sources require", "GO_SESSION_13:NO")), "SESSION12R_DOC_SURFACE_INCOMPLETE")
    forbidden = {"subprocess", "Popen", "system", "exec", "eval", "compile", "import_module"}
    for source in ("provan/foundry.py", "provan/foundry_semantic.py"):
        tree = ast.parse((ROOT / source).read_text(encoding="utf-8")); calls = {node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else "" for node in ast.walk(tree) if isinstance(node, ast.Call)}
        require(not forbidden & calls, "SESSION12R_TARGET_EXECUTION_CAPABILITY_EXPOSED")
    semantic_source = (ROOT / "provan/foundry_semantic.py").read_text(encoding="utf-8")
    require("execution_available\": False" in semantic_source and "challenge_available\": False" in semantic_source and "previous_response_id\": None" in semantic_source, "SESSION12R_CAPABILITY_OR_STATELESS_BOUNDARY_INVALID")
    require("percentile" not in semantic_source.lower() and "p50" not in semantic_source.lower(), "SESSION12R_UNSUPPORTED_PERCENTILE_CLAIM")
    status = json.loads((ROOT / "artifacts/session12/successor_closeout/authority/operational_status.v1.public.json").read_bytes())
    require(status.get("go_session_13") is False and status.get("session_12_successor") == "IN_PROGRESS", "SESSION12R_PRE_CLOSEOUT_STATUS_INVALID")
    public_evidence = ROOT / "artifacts/session12/successor_closeout/public/real_use/public_semantic_evidence.v1.public.json"
    require(public_evidence.is_file(), "SESSION12R_PUBLIC_SEMANTIC_EVIDENCE_MISSING")
    validate_public_semantic_evidence_serialized(public_evidence.read_bytes())
    leakage = subprocess.run([sys.executable, "scripts/validate_session12_leakage.py"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    require(leakage.returncode == 0 and "PRIVATE_PLANNING_AUTHORITY_ABSENT" in leakage.stdout, "SESSION12R_PRIVATE_AUTHORITY_ABSENCE_FAILED")
    print("SESSION12R_IMPLEMENTATION_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
