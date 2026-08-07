from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provan.claims import validate_claim_files
from provan.errors import ProvanError
from scripts.session9_proof_cases import evaluate_fixture
from provan.leakage import validate_candidate_surfaces, validate_public_tree
from provan.validators import (
    validate_artifact_semantics, validate_capability_audit_semantics,
    validate_layer4_semantics, validate_proof_entry_semantics,
    validate_session9_closeout_semantics,
    validate_version_policy_semantics,
    validate_extension_overlay_semantics,
)

CORRECTION_SCHEMA_FILES = {
    "access-warning-audit.v1.json", "correction-proof-manifest.v1.json",
    "correction-proof-registry.v1.json", "external-mirror-attestation.v1.json",
    "external-publication-receipt.v1.json", "inspection-write-result.v1.json",
    "layer4-claim-crosswalk.v1.json", "layer4-claim-matrix-correction.v2.json",
    "private-repository-projection.v1.json", "reviewer-receipt-correction.v1.json",
    "session9-closeout-correction.v1.json", "session9-correction-fixture.v1.json",
    "state-link-proof.v1.json", "telemetry-status-policy.v1.json",
}


def load(path: Path): return json.loads(path.read_text(encoding="utf-8"))
def sha(path: Path): return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
def semantic_sha(path: Path): return "sha256:" + hashlib.sha256(path.read_text(encoding="utf-8").replace("\r\n","\n").encode("utf-8")).hexdigest()
def bound_sha(path: Path): return semantic_sha(path) if path.suffix.lower() in {".json",".txt",".md",".py",".toml",".yml",".yaml"} else sha(path)


def schemas() -> dict[str, tuple[Path, dict]]:
    result = {}
    for path in sorted((ROOT / "provan" / "schemas").glob("*.json")):
        value = load(path); result[value["$id"]] = (path, value)
    return result


def validate_historical_integrity() -> None:
    base = "09c5fbab239a6dcb87eee3697f25aaff2929111f"
    tree = subprocess.run(["git", "show", "-s", "--format=%T", base], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    if tree != "f37d2b620230d07924d2c7ce8e09ec1c4c4e85eb":
        raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", "base tree identity drift")
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=ROOT).returncode:
        raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", "historical base is not preserved in lineage")
    protected = subprocess.run(["git", "ls-tree", "-r", "--name-only", base, "external_validation/proofs/session2", "docs/validation"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.splitlines()
    for path in protected:
        result = subprocess.run(["git", "cat-file", "-e", f"{base}:{path}"], cwd=ROOT)
        if result.returncode:
            raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", path)
    immutable_current = [
        "scripts/validate_session2_closeout.py",
        "shiproom/external_validation/session2_closeout.py",
        "shiproom/external_validation/schemas/schema-registry.v1.json",
        "shiproom/external_validation/schemas/session2-partial-closeout.v1.json",
    ]
    for path in immutable_current:
        historical = subprocess.run(["git", "show", f"{base}:{path}"], cwd=ROOT, check=True, capture_output=True).stdout
        current = ROOT / path
        if not current.is_file() or current.read_bytes().replace(b"\r\n", b"\n") != historical.replace(b"\r\n", b"\n"):
            raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", path)


def validate_runtime_reachability() -> None:
    forbidden = {"commit", "push", "worktree", "checkout", "switch", "merge", "deploy", "remediate"}
    for path in (ROOT / "provan").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.List):
                words = {item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                if words & forbidden:
                    if path.name != "guard.py":
                        raise ProvanError("CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN", f"reachable operation in {path.name}")
    # Every actual filesystem mutation primitive in the installed runtime is
    # enumerated here. Adding a new one fails the gate until its boundary is
    # reviewed. The allowed functions independently enforce either the
    # dedicated .provan state/output root or the isolated temporary clone.
    mutation_calls = {"write_text", "write_bytes", "mkdir", "unlink", "rmtree", "rename", "replace", "remove"}
    allowed = {
        ("repository.py", "inspect_repository", "mkdir"),
        ("repository.py", "inspect_repository", "unlink"),
        ("state.py", "_ensure_state_root", "mkdir"),
        ("state.py", "secure_write", "mkdir"),
        ("state.py", "secure_write", "open"),
        ("state.py", "secure_replace", "replace"),
        ("state.py", "secure_replace", "unlink"),
        ("state.py", "validate_state_children", "mkdir"),
        ("telemetry.py", "clear_pending", "rmtree"),
        ("doctor.py", "_isolated_git_check", "mkdir"),
        ("doctor.py", "_state_checks", "unlink"),
        ("doctor.py", "_source_only_inspection_check", "mkdir"),
        ("doctor.py", "_source_only_inspection_check", "write_text"),
        ("doctor.py", "_source_only_inspection_check", "unlink"),
        # These are string normalization calls, not pathlib.Path.replace.
        ("repository.py", "inspect_repository", "replace"),
        ("validators.py", "validate_install_origin", "replace"),
        ("validators.py", "validate_layer4_semantics", "replace"),
    }
    observed=set()
    for path in (ROOT / "provan").glob("*.py"):
        tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
        for function in [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:
            for node in ast.walk(function):
                if not isinstance(node,ast.Call): continue
                call=node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id if isinstance(node.func,ast.Name) else ""
                full=ast.unparse(node.func)
                if call in mutation_calls or full == "os.open": observed.add((path.name,function.name,"open" if full=="os.open" else call))
    unexpected=observed-allowed
    missing=allowed-observed
    if unexpected or missing or "def write_new" in (ROOT/"provan/canonical.py").read_text(encoding="utf-8"):
        raise ProvanError("CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN",f"write reachability drift: unexpected={sorted(unexpected)} missing={sorted(missing)}")


def validate_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if any(name.startswith(("shiproom/", "demo_patient/", "tests/", "external_validation/")) for name in names):
            raise ProvanError("COMMUNITY_PACKAGE_PRIVATE_CONTENT", "historical or private package content")
        if not any(name.startswith("provan/") for name in names):
            raise ProvanError("COMMUNITY_PACKAGE_INVALID", "canonical package missing")
        for name in names:
            if name.endswith((".py", ".json", ".md", ".txt")):
                text = archive.read(name).decode("utf-8", errors="replace")
                if "qualification_" + "artifact_" in text or "/var/" + "lib/shiproom" in text:
                    raise ProvanError("COMMUNITY_PACKAGE_PRIVATE_CONTENT", name)


def validate_fresh_install(module_path: Path, site_packages: Path) -> None:
    if site_packages.resolve() not in module_path.resolve().parents:
        raise ProvanError("FRESH_INSTALL_RESOLVED_FROM_SOURCE_CHECKOUT", str(module_path))


def validate_remote_topology(value: dict) -> None:
    if value.get("history_rewrite_required"):
        raise ProvanError("HISTORY_REWRITE_REQUIRED", "publication would rewrite history")
    if value.get("community_visibility") != "PUBLIC" or value.get("private_visibility_valid") is not True:
        raise ProvanError("REMOTE_TOPOLOGY_MISMATCH", "repository topology differs")


def validate_content_bindings(proof: dict, fixtures: dict, artifacts: Path) -> None:
    schema_registry=schemas(); fixture_schema=schema_registry["provan.proof_fixture.v1"][1]
    from scripts.build_session9_proofs import PRODUCTION
    for entry in proof["entries"]:
        validate_proof_entry_semantics(entry)
        if len(entry["artifact_locations"]) != len(entry["artifact_hashes"]):
            raise ProvanError("PROOF_ARTIFACT_BINDING_INVALID", entry["test_id"])
        for location, expected in zip(entry["artifact_locations"],entry["artifact_hashes"]):
            path=ROOT/location
            if not path.is_file() or bound_sha(path)!=expected:
                raise ProvanError("PROOF_ARTIFACT_HASH_MISMATCH", location)
        if entry["transcript_hash"] != entry["artifact_hashes"][-1]:
            raise ProvanError("PROOF_TRANSCRIPT_HASH_MISMATCH", entry["test_id"])
        if "#/fixtures/" in entry["fixture_path"]:
            index=int(entry["fixture_path"].split("#/fixtures/",1)[1])
            fixture=load(ROOT/"tests/fixtures/session9/extension-contract-fixtures.v1.json")["fixtures"][index]
            if entry["schema_id"] not in schema_registry: raise ProvanError("PROOF_CONTRACT_SCHEMA_MISSING",entry["schema_id"])
            try: jsonschema.validate(fixture["input"],schema_registry[entry["schema_id"]][1]); schema_result="PASS"
            except jsonschema.ValidationError as exc: schema_result="REJECT:"+exc.validator
            if schema_result != entry["schema_result"]: raise ProvanError("PROOF_SCHEMA_RESULT_MISMATCH",entry["test_id"])
            try: validate_extension_overlay_semantics(fixture["input"]); observed="PASS"
            except ProvanError as exc: observed="REJECT:"+exc.code
            if observed != entry["python_result"] or entry["production_function"]!="provan.validators.validate_extension_overlay_semantics" or entry["exit_code"]!=0:
                raise ProvanError("PROOF_EXECUTION_RESULT_MISMATCH",entry["test_id"])
            continue
        _,pointer=entry["fixture_path"].split("#/families/",1); family,fixture_class=pointer.split("/",1)
        fixture=fixtures["families"][family][fixture_class]
        jsonschema.validate(fixture,fixture_schema)
        if entry["schema_id"] not in schema_registry: raise ProvanError("PROOF_CONTRACT_SCHEMA_MISSING",entry["schema_id"])
        try: jsonschema.validate(fixture["input"],schema_registry[entry["schema_id"]][1]); schema_result="PASS"
        except jsonschema.ValidationError as exc: schema_result="REJECT:"+exc.validator
        if schema_result != entry["schema_result"]: raise ProvanError("PROOF_SCHEMA_RESULT_MISMATCH",entry["test_id"])
        if entry["production_function"] != PRODUCTION[family]: raise ProvanError("PROOF_PRODUCTION_FUNCTION_MISMATCH",entry["test_id"])
        expected_test=f"tests/test_session9_proofs.py::test_proof_fixture_production_execution[{family}-{fixture_class}]"
        if entry["test_id"] != expected_test or entry["command"] != "python -m pytest -q tests/test_session9_proofs.py" or entry["exit_code"] != 0:
            raise ProvanError("PROOF_COMMAND_BINDING_MISMATCH",entry["test_id"])
        try: evaluate_fixture(fixture); observed="PASS"
        except ProvanError as exc: observed="REJECT:"+exc.code
        if observed != entry["python_result"]:
            raise ProvanError("PROOF_EXECUTION_RESULT_MISMATCH",entry["test_id"])


def validate_closeout_bindings(artifacts: Path) -> None:
    manifest_path=artifacts/"closeout_manifest.public.json"
    if not manifest_path.exists(): return
    manifest=load(manifest_path); rows=manifest.get("artifacts",[])
    for row in rows:
        path=ROOT/row["path"]
        if not path.is_file() or bound_sha(path)!=row["sha256"]:
            raise ProvanError("CLOSEOUT_ARTIFACT_HASH_MISMATCH",row["path"])
    expected= "sha256:"+hashlib.sha256(("\n".join(row["path"]+" "+row["sha256"] for row in rows)+"\n").encode()).hexdigest()
    if expected != manifest.get("proof_set_root_hash"):
        raise ProvanError("CLOSEOUT_PROOF_ROOT_MISMATCH","closeout root does not bind artifact rows")


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--allow-pending-review", action="store_true"); parser.add_argument("--regenerate-schema-registry", action="store_true"); parser.add_argument("--skip-closeout-bindings", action="store_true"); parser.add_argument("--wheel", nargs="*"); parser.add_argument("--archive", nargs="*"); args=parser.parse_args()
    registry = schemas()
    artifacts = ROOT / "artifacts" / "session9"
    artifact_files = sorted(artifacts.glob("*.json"))
    public_artifact_text = sorted(
        p for p in artifacts.rglob("*")
        if p.is_file() and p.suffix.lower() in {".json", ".txt", ".md", ".toml", ".yml", ".yaml", ".rst"}
    )
    validate_public_tree(ROOT, [ROOT/"README.md", ROOT/"pyproject.toml", *[p for p in (ROOT/"provan").rglob("*.py")], *sorted((ROOT/"docs").glob("*.md")), *public_artifact_text])
    validate_claim_files([ROOT/"README.md", *sorted((ROOT/"docs").glob("*.md"))])
    validate_historical_integrity(); validate_runtime_reachability()
    for path in artifact_files:
        value=load(path)
        if "sensitivity" in value: validate_artifact_semantics(value)
    capability=load(artifacts/"capability_audit.public.json"); jsonschema.validate(capability, registry["provan.operational_capability_audit_projection.v1"][1]); validate_capability_audit_semantics(capability)
    version=load(artifacts/"version_policy.public.json"); jsonschema.validate(version, registry["provan.version_policy_decision.v1"][1]); validate_version_policy_semantics(version)
    proof=load(artifacts/"proof_registry.public.json"); jsonschema.validate(proof, registry["provan.proof_registry.v1"][1])
    fixtures=load(ROOT/"tests/fixtures/session9/proof-fixtures.v1.json")
    validate_content_bindings(proof,fixtures,artifacts)
    test_tree=ast.parse((ROOT/"tests/test_session9.py").read_text(encoding="utf-8"))
    direct_tests={f"tests/test_session9.py::{node.name}" for node in test_tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    matrix=load(artifacts/"layer4_claim_matrix.public.json"); jsonschema.validate(matrix, registry["provan.layer4_claim_matrix.v1"][1]); validate_layer4_semantics(matrix,proof,direct_tests,allow_pending_review=args.allow_pending_review)
    closeout_path=artifacts/"closeout_manifest.public.json"
    if closeout_path.exists():
        closeout=load(closeout_path); jsonschema.validate(closeout,registry["provan.session9_closeout_manifest.v1"][1]); validate_session9_closeout_semantics(closeout)
        bound={row["path"]:row["sha256"] for row in closeout.get("artifacts",[])}
        for row in matrix["claims"]:
            if not row["Python result"].startswith("PASS") or not row["Schema result"].startswith("PASS"):
                raise ProvanError("LAYER4_PROOF_BINDING_INVALID",row["Claim"]+" lacks successful Python/schema results")
            if (row["Reviewer result"],row["Status"]) not in ({("PENDING","PENDING_REVIEW"),("ACCEPTED","CLOSED")}):
                raise ProvanError("LAYER4_PROOF_BINDING_INVALID",row["Claim"]+" review/status mismatch")
            for location in (item.strip() for item in row["Artifact evidence"].split(" + ")):
                path=ROOT/location
                if not path.is_file(): raise ProvanError("LAYER4_ARTIFACT_BINDING_INVALID",location)
                if not args.skip_closeout_bindings and location!="artifacts/session9/closeout_manifest.public.json" and (location not in bound or bound_sha(path)!=bound[location]):
                    raise ProvanError("LAYER4_ARTIFACT_BINDING_INVALID",location)
    historical_registry={key:value for key,value in registry.items() if value[0].name not in CORRECTION_SCHEMA_FILES}
    schema_index={"schema_id":"provan.schema_registry.v1","sensitivity":"PUBLIC_SAFE","hash_policy":"UTF8_LF_NORMALIZED_SHA256","schemas":[{"schema_id":key,"path":str(path.relative_to(ROOT)).replace("\\","/"),"sha256":semantic_sha(path)} for key,(path,_) in sorted(historical_registry.items())]}
    expected=json.dumps(schema_index,sort_keys=True,indent=2)+"\n"; target=artifacts/"schema_registry.public.json"
    if args.regenerate_schema_registry or not target.exists(): target.write_text(expected,encoding="utf-8")
    elif target.read_text(encoding="utf-8") != expected: raise ProvanError("SCHEMA_REGISTRY_DRIFT", "regenerate schema registry")
    if not args.skip_closeout_bindings: validate_closeout_bindings(artifacts)
    wheel_paths=[]
    for pattern in args.wheel or []:
        paths=list(ROOT.glob(pattern)) if "*" in pattern else [Path(pattern)]
        for path in paths: validate_wheel(path); wheel_paths.append(path)
    archive_paths=[]
    for pattern in args.archive or []:
        archive_paths.extend(list(ROOT.glob(pattern)) if "*" in pattern else [Path(pattern)])
    validate_candidate_surfaces(ROOT,[*wheel_paths,*archive_paths])
    print(json.dumps({"status":"SESSION9_VALID","proof_entries":len(proof["entries"]),"claims":len(matrix["claims"]),"schemas":len(registry)}))
    return 0


if __name__ == "__main__":
    from scripts.session9_git_isolation import isolated_git_environment
    try:
        with isolated_git_environment(ROOT):
            raise SystemExit(main())
    except ProvanError as exc:
        print(json.dumps({"status":"INVALID","error":exc.code,"message":exc.message})); raise SystemExit(2)
