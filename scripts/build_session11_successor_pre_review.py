from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session11/successor_closeout"
WHEEL = "sha256:e250c509d1676ebb9f1ec066059b3eb770a12a3804666c22a1e65bfad6d89d4f"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(name: str, value: object) -> None:
    (OUT / name).write_bytes(canonical(value))


def ref(relative: str) -> dict[str, str]:
    return {"path": relative, "sha256": digest((ROOT / relative).read_bytes())}


def git_value(format_string: str) -> str:
    return subprocess.run(
        ["git", "show", "-s", f"--format={format_string}", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    ).stdout.strip()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    commit = git_value("%H")
    tree = git_value("%T")
    binding = {
        "schema_id": "provan.session11_implementation_binding.v1",
        "implementation_commit": commit,
        "implementation_tree": tree,
        "package_version": "0.4.0",
        "extension_api_major": 1,
        "wheel_sha256": WHEEL,
        "schema_registry_digest": "sha256:4883f894956a1a6c20135138a529c416ebd10004eea8931808a830054ff43758",
        "claim_registry_digest": "sha256:0ead7bf736f100a930a60ec8bbeca0090f993d7fdd6a49e552a0aea7c4fa6cf8",
        "maturity": "QUALIFIED_BOUNDED",
        "published": False,
    }
    write("implementation_binding.v1.public.json", binding)
    paths = [
        ".github/workflows/release-gate.yml",
        ".github/workflows/mirror-session11-receipt.yml",
        "scripts/build_session11_successor_pre_review.py",
        "scripts/validate_session11_successor_closeout.py",
        "tests/test_session11_successor_closeout.py",
        "dist/provan_assurance-0.4.0-py3-none-any.whl",
        "artifacts/session11/proofs/proof_registry.v1.public.json",
        "artifacts/session11/proofs/pre_review_proof_manifest.v1.public.json",
        "artifacts/session11/session12_handoff.v1.public.json",
        "artifacts/session11/claim_registry.v1.public.json",
        "artifacts/session11/schema_registry.v1.public.json",
        "artifacts/session11/generic_absence_receipt.v1.public.json",
        "artifacts/session11/successor_closeout/generic_absence_receipt.v1.public.json",
        "artifacts/session11/successor_closeout/requalification_replay.v1.public.json",
        "artifacts/session11/successor_closeout/session12_handoff_candidate.v1.public.json",
        "artifacts/session11/successor_closeout/implementation_binding.v1.public.json",
    ]
    entries = [ref(path) for path in paths]
    manifest = {
        "schema_id": "provan.session11_proof_manifest.v1",
        "phase": "PRE_REVIEW",
        "implementation_commit": commit,
        "implementation_tree": tree,
        "wheel_sha256": WHEEL,
        "entries": entries,
        "proof_root": digest(canonical(entries)),
        "reviewer_outputs_excluded": True,
    }
    write("pre_review_proof_manifest.v1.public.json", manifest)
    print(manifest["proof_root"])


if __name__ == "__main__":
    main()
