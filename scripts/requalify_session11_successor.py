from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from provan.session11_validators import validate_session12_handoff_serialized

OUT = ROOT / "artifacts/session11/successor_closeout"
WHEEL_PATH = ROOT / "dist/provan_assurance-0.4.0-py3-none-any.whl"
WHEEL_SHA = "sha256:e250c509d1676ebb9f1ec066059b3eb770a12a3804666c22a1e65bfad6d89d4f"
QUALIFIED_RUNTIME = "b5c322cdffdaf0af80147ad021475a066459c4c2"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def ref(relative: str) -> dict[str, str]:
    return {"path": relative, "sha256": digest((ROOT / relative).read_bytes())}


def write(name: str, value: object) -> None:
    (OUT / name).write_bytes(canonical(value))


def git_value(format_string: str) -> str:
    return subprocess.run(["git", "show", "-s", f"--format={format_string}", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="strict").stdout.strip()


def run(label: str, command: list[str]) -> dict:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="strict")
    transcript = (result.stdout + result.stderr).encode("utf-8")
    if result.returncode:
        raise SystemExit(f"SESSION11_SUCCESSOR_REQUALIFICATION_FAILED:{label}:{result.returncode}")
    return {"label": label, "command": command, "exit_code": result.returncode, "transcript_sha256": digest(transcript)}


def resolve_handoff_artifacts(handoff: dict) -> dict[str, bytes]:
    refs = [handoff["brief"], handoff["preparation"], *handoff["seed_dispositions"], handoff["acceptance_contract"], handoff["candidate_freeze"], *handoff["closure_requirements"], *handoff["verifier_contracts"], *handoff["receipt_contracts"], *handoff["protected_invariants"], handoff["evidence_settlement"], handoff["attestation"], handoff["reinspection"], handoff["layer4_matrix"], handoff["proof_manifest"], *handoff["reviewer_receipts"], handoff["schema_registry"], handoff["claim_registry"], handoff["implementation_binding_ref"], handoff["wheel"]]
    artifacts = {item["path"]: (ROOT / item["path"]).read_bytes() for item in refs}
    manifest = json.loads(artifacts[handoff["proof_manifest"]["path"]])
    for item in manifest["entries"]:
        artifacts[item["path"]] = (ROOT / item["path"]).read_bytes()
    return artifacts


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    commit, tree = git_value("%H"), git_value("%T")
    binding = load("artifacts/session11/successor_closeout/implementation_binding.v1.public.json")
    if binding["implementation_commit"] != commit or binding["implementation_tree"] != tree or digest(WHEEL_PATH.read_bytes()) != WHEEL_SHA or binding["wheel_sha256"] != WHEEL_SHA:
        raise SystemExit("SESSION11_SUCCESSOR_REQUALIFICATION_BINDING_MISMATCH")
    unchanged = subprocess.run(["git", "diff", "--quiet", QUALIFIED_RUNTIME, "HEAD", "--", "provan", "pyproject.toml"], cwd=ROOT)
    if unchanged.returncode:
        raise SystemExit("SESSION11_SUCCESSOR_RUNTIME_CHANGED_FROM_QUALIFIED_WHEEL")
    checks = [
        run("session11_final", [sys.executable, "scripts/validate_session11.py", "--phase", "final"]),
        run("public_leakage", [sys.executable, "scripts/validate_session9_leakage.py"]),
        run("authoritative_wheel_fresh_install", [sys.executable, "scripts/fresh_install_gate.py", "--wheel", "dist/provan_assurance-0.4.0-py3-none-any.whl"]),
        run("successor_and_handoff", [sys.executable, "-m", "pytest", "-q", "tests/test_session11_successor_closeout.py", "tests/test_session11_acceptance.py::test_proof_session12_handoff_layers"]),
    ]
    absence = {
        "schema_id": "provan.session11_generic_absence_receipt.v1",
        "sensitivity": "PUBLIC_SAFE",
        "implementation_commit": commit,
        "implementation_tree": tree,
        "wheel_sha256": WHEEL_SHA,
        "scopes": ["history_delta", "working_tree_projection", "package_wheel", "public_proofs", "controlled_ci_artifacts"],
        "result": "PRIVATE_PLANNING_AUTHORITY_ABSENT",
        "violations": [],
        "confidential_fingerprint_known_to_ci": False,
    }
    write("generic_absence_receipt.v1.public.json", absence)
    handoff = load("artifacts/session11/session12_handoff.v1.public.json")
    handoff["implementation_binding"] = binding
    handoff["implementation_binding_ref"] = ref("artifacts/session11/successor_closeout/implementation_binding.v1.public.json")
    handoff["wheel"] = ref("dist/provan_assurance-0.4.0-py3-none-any.whl")
    handoff["reviewer_receipts"] = []
    raw = canonical(handoff)
    jsonschema.validate(handoff, load("provan/schemas/session12-handoff.v1.json"))
    validate_session12_handoff_serialized(raw, resolve_handoff_artifacts(handoff))
    write("session12_handoff_candidate.v1.public.json", handoff)
    sources = [
        "artifacts/session11/real_use/httpx_pr3699.acceptance_lifecycle.v1.public.json",
        "artifacts/session11/real_use/provan_internal_lifecycle.v1.public.json",
        "artifacts/session11/real_use/installed_wheel_origin.v1.public.json",
        "artifacts/session11/validation_summary.v1.public.json",
    ]
    replay = {
        "schema_id": "provan.session11_successor_requalification.v1",
        "sensitivity": "PUBLIC_SAFE",
        "implementation_binding": binding,
        "historical_inputs": [ref(path) for path in sources],
        "historical_inputs_current_by_themselves": False,
        "runtime_equivalence": {"qualified_runtime_commit": QUALIFIED_RUNTIME, "current_runtime_diff_empty": True},
        "current_candidate": {"repository_identity": "https://github.com/kruthika-kumar/provan", "base": QUALIFIED_RUNTIME, "head": commit},
        "checks": checks,
        "result": "REQUALIFIED",
        "limitations": ["HISTORICAL_LIFECYCLE_ARTIFACTS_REMAIN_BOUND_TO_ORIGINAL_IMPLEMENTATIONS", "CURRENT_STATUS_DERIVES_FROM_REEXECUTED_GATES_AND_RUNTIME_BYTE_EQUIVALENCE"],
    }
    write("requalification_replay.v1.public.json", replay)
    print("SESSION11_SUCCESSOR_REQUALIFIED")


if __name__ == "__main__":
    main()
