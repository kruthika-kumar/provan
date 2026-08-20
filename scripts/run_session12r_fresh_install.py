from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session12/successor_closeout/proofs"


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run(
    argv: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 180
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=timeout,
    )
    if result.returncode:
        raise SystemExit(
            "SESSION12R_FRESH_INSTALL_COMMAND_FAILED:"
            + " ".join(argv[:4])
            + "\n"
            + result.stdout
            + result.stderr
        )
    return result


CHILD = r'''
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import provan
from provan.change_brief import explain
from provan.foundry import foundry, pattern_library
from provan.foundry_semantic import cleanup_source_bundle


root = Path.cwd()
home = root / "state"
repo = root / "candidate"
repo.mkdir()
env = {
    **os.environ,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


git("init")
git("config", "user.email", "fixture")
git("config", "user.name", "Fixture")
(repo / "api").mkdir()
(repo / "api" / "schema.json").write_text('{"version":1}\n', encoding="utf-8")
git("add", ".")
git("commit", "-m", "base")
base = git("rev-parse", "HEAD")
(repo / "api" / "schema.json").write_text('{"version":2}\n', encoding="utf-8")
git("add", ".")
git("commit", "-m", "head")
head = git("rev-parse", "HEAD")

os.environ["PROVAN_HOME"] = str(home)
brief = explain(
    repo=str(repo),
    base=base,
    head=head,
    working_tree=False,
    brief_text="The API schema must remain backward compatible. Runtime execution is a non-goal.",
    agent_claim=None,
    context_files=[],
    aliases=[],
    journeys=[],
    journey_files=[],
    previous_brief=None,
    previous_manifest=None,
    provider_id=None,
    no_model=True,
)
source = root / "intent.md"
source.write_text(
    "The API schema must remain backward compatible.\n"
    "Runtime execution is a non-goal.\n"
    "For example, old clients may retry.\n",
    encoding="utf-8",
)
manifest = root / "manifest.json"
manifest.write_text(
    json.dumps({"sources": [{"path": "intent.md", "role": "intent"}]}),
    encoding="utf-8",
)
standard, rendered = foundry(
    brief_id=brief["brief_id"],
    source_manifest=manifest,
    depth="standard",
    no_model=True,
    information_boundary="blind",
    view="owner-review",
    format_name="markdown",
)
os.environ["PROVAN_ALLOW_SCRIPTED_PROVIDER"] = "1"
deep, _ = foundry(
    brief_id=brief["brief_id"],
    source_manifest=manifest,
    depth="deep",
    provider_id="scripted-test",
    information_boundary="blind",
)

mutable_repo = root / "mutable-candidate"
subprocess.run(["git", "clone", "--quiet", str(repo), str(mutable_repo)], check=True)
(mutable_repo / "api" / "schema.json").write_text('{"version":3}\n', encoding="utf-8")
mutable_brief = explain(
    repo=str(mutable_repo),
    base="HEAD",
    head=None,
    working_tree=True,
    brief_text="The API schema must remain backward compatible.",
    agent_claim=None,
    context_files=[],
    aliases=[],
    journeys=[],
    journey_files=[],
    previous_brief=None,
    previous_manifest=None,
    provider_id=None,
    no_model=True,
)
mutable, _ = foundry(
    brief_id=mutable_brief["brief_id"],
    source_manifest=manifest,
    no_model=True,
    information_boundary="blind",
)
tombstone = cleanup_source_bundle(standard["run_id"])

assert provan.__version__ == "0.5.1"
assert "site-packages" in str(Path(provan.__file__).resolve()).lower()
assert len(pattern_library()["patterns"]) >= 18
assert standard["schema_id"] == "provan.internal.contract_foundry_run.v2"
assert standard["run_eligibility"] == "NOT_ELIGIBLE"
assert standard["execution_available"] is False
assert standard["challenge_available"] is False
assert all(section in rendered for section in (
    "Sources require", "Provan inferred", "Audit changed",
    "Intentionally non-mandatory", "Ambiguities",
    "Patterns & evidence", "Owner decisions",
))
assert deep["run_eligibility"] == "NOT_ELIGIBLE"
assert "SCRIPTED_PROVIDER_SEMANTICALLY_UNQUALIFIED" in deep["limitations"]
assert mutable["contract_readiness"] == "NOT_READY"
assert mutable["implementation_map"]["mutable_explanatory_only"] is True
assert tombstone["raw_bytes_retained"] is False and tombstone["deleted"]

print(json.dumps({
    "installed_version": provan.__version__,
    "installed_origin": str(Path(provan.__file__).resolve()),
    "pattern_count": len(pattern_library()["patterns"]),
    "standard": {
        "eligibility": standard["run_eligibility"],
        "readiness": standard["contract_readiness"],
        "owner_review_sections": 7,
    },
    "deep": {
        "eligibility": deep["run_eligibility"],
        "scripted_provider_qualified": False,
    },
    "mutable": {
        "readiness": mutable["contract_readiness"],
        "explanatory_only": mutable["implementation_map"]["mutable_explanatory_only"],
    },
    "cleanup": {
        "raw_bytes_retained": tombstone["raw_bytes_retained"],
        "deleted_count": len(tombstone["deleted"]),
    },
    "execution_available": standard["execution_available"],
    "challenge_available": standard["challenge_available"],
}, sort_keys=True))
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--implementation-tree", required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file() or wheel.is_symlink():
        raise SystemExit("SESSION12R_FRESH_INSTALL_WHEEL_INVALID")
    wheel_sha = digest(wheel.read_bytes())
    with tempfile.TemporaryDirectory(prefix="provan-session12r-wheel-") as temporary:
        temp = Path(temporary)
        site = temp / "site-packages"
        site.mkdir()
        install = run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--disable-pip-version-check",
                "--target",
                str(site),
                str(wheel),
            ],
            cwd=temp,
        )
        child_path = temp / "fresh_install_case.py"
        child_path.write_text(textwrap.dedent(CHILD), encoding="utf-8", newline="\n")
        child_env = {
            **os.environ,
            "PYTHONPATH": str(site),
            "PYTHONNOUSERSITE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
        result = run([sys.executable, str(child_path)], cwd=temp, env=child_env, timeout=300)
        summary = json.loads(result.stdout.splitlines()[-1])
        if str(ROOT).lower() in summary["installed_origin"].lower():
            raise SystemExit("SESSION12R_FRESH_INSTALL_CHECKOUT_IMPORT")
        summary["installed_origin"] = "<temporary-site-packages>/provan/__init__.py"
    receipt = {
        "schema_id": "provan.internal.session12r_fresh_install_receipt.v1",
        "sensitivity": "PUBLIC_SAFE",
        "implementation_commit": args.implementation_commit,
        "implementation_tree": args.implementation_tree,
        "package_version": "0.5.1",
        "wheel_sha256": wheel_sha,
        "checkout_absent_from_sys_path": True,
        "commands": [
            "python -m pip install --no-deps --target <temporary-site-packages> <authoritative-wheel>",
            "python <temporary-fresh-install-case>",
        ],
        "checks": summary,
        "install_output_recorded_publicly": False,
        "temporary_state_deleted": True,
        "result": "PASS",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "fresh_install_receipt.v1.public.json"
    path.write_bytes(canonical(receipt))
    print("SESSION12R_FRESH_INSTALL_VALID", wheel_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
