from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

import jsonschema

from provan.leakage import (
    PRIVATE_PATTERNS,
    _allowed_historical,
    _allowed_private_projection,
    _archive_violations,
    _rule_literal,
)

ROOT=Path(__file__).resolve().parents[1]
BASELINE="22a73b13eee4bac00930c8afe24944286eac2023"
TEXT_SUFFIXES={".py",".md",".json",".toml",".yml",".yaml",".txt",".rst"}
PROOF_SCAN_EXCLUDED={"private_planning_absence.v1.public.json","pre_review_proof_manifest.v1.public.json","proof_manifest.v1.public.json","reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json","layer4_claim_matrix.final.v1.public.json","session11_handoff_finalization.v1.public.json","closeout.v1.public.json","claim_source_inventory.v1.public.json"}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest_names(names: list[str]) -> str:
    return "sha256:" + hashlib.sha256(canonical(sorted(names))).hexdigest()


def digest_inventory(paths: list[tuple[str, Path]]) -> str:
    entries=[{"path":relative,"sha256":"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()} for relative,path in paths]
    return "sha256:"+hashlib.sha256(canonical(entries)).hexdigest()


def isolated_git_env(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "xdg"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def scan_text(relative: str, text: str) -> list[dict[str, str]]:
    violations = []
    for line in text.splitlines():
        if _rule_literal(relative, line):
            continue
        for code, pattern in PRIVATE_PATTERNS.items():
            if (not pattern.search(line) or _allowed_historical(code, relative)
                    or _allowed_private_projection(code, relative, line)):
                continue
            reserved = relative.startswith(("tests/", "scripts/")) and (
                "@example.test" in line or "@example.invalid" in line
                or ("https" + "://" + "token" + "@github.com/o/r") in line
            )
            if not reserved:
                violations.append({"path": relative, "error": code})
    return violations


def decode_public_text(path: Path) -> str:
    raw=path.read_bytes()
    if b"\x00" in raw or raw.startswith((b"\xff\xfe",b"\xfe\xff",b"\xff\xfe\x00\x00",b"\x00\x00\xfe\xff")):
        raise SystemExit("SESSION10_GENERIC_ABSENCE_TEXT_ENCODING_INVALID:"+path.name)
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SystemExit("SESSION10_GENERIC_ABSENCE_TEXT_ENCODING_INVALID:"+path.name) from exc


def scan_files(scope: str,paths: list[Path]) -> dict[str,object]:
    if not paths:raise SystemExit("SESSION10_GENERIC_ABSENCE_SCOPE_EMPTY:"+scope)
    violations=[];items=[]
    for path in paths:
        relative=path.relative_to(ROOT).as_posix();items.append((relative,path))
        if path.suffix.lower() in TEXT_SUFFIXES:violations.extend(scan_text(relative,decode_public_text(path)))
    if violations:raise SystemExit("SESSION10_GENERIC_ABSENCE_VIOLATION:"+scope)
    return {"scope":scope,"items_inspected":len(items),"inventory_digest":digest_inventory(items),"generic_violation_count":len(violations)}


def proof_example_paths() -> list[Path]:
    paths=[path for base in (ROOT/"artifacts/session10",ROOT/"docs") for path in base.rglob("*") if path.is_file() and path.name not in PROOF_SCAN_EXCLUDED]
    paths.extend(path for path in (ROOT/"tests").glob("*session10*") if path.is_file())
    return paths


def main() -> int:
    parser=argparse.ArgumentParser();parser.add_argument("--wheel",type=Path,required=True);parser.add_argument("--implementation-commit",required=True);parser.add_argument("--implementation-tree",required=True);args=parser.parse_args();wheel=args.wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="provan-generic-absence-") as temp:
        git_env = isolated_git_env(Path(temp))
        commits=subprocess.run(["git","rev-list","--reverse",BASELINE+".."+args.implementation_commit],cwd=ROOT,text=True,capture_output=True,check=True,env=git_env).stdout.splitlines()
        diff=subprocess.run(["git","diff","--unified=0",BASELINE+".."+args.implementation_commit],cwd=ROOT,text=True,capture_output=True,check=True,env=git_env).stdout
        changed_paths=subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=A", BASELINE + ".." + args.implementation_commit],
            cwd=ROOT, text=True, capture_output=True, check=True, env=git_env,
        ).stdout.splitlines()
    if not commits or commits[-1]!=args.implementation_commit:raise SystemExit("SESSION10_GENERIC_ABSENCE_HISTORY_BINDING_INVALID")
    history_violations=[];current="";added=[]
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            if current and added:history_violations.extend(scan_text(current,"\n".join(added)))
            current=line[6:];added=[]
        elif line.startswith("+") and not line.startswith("+++"):added.append(line[1:])
    if current and added:history_violations.extend(scan_text(current,"\n".join(added)))
    if history_violations:raise SystemExit("SESSION10_GENERIC_ABSENCE_VIOLATION:history_delta")
    checks=[{"scope":"history_delta","items_inspected":len(commits),"inventory_digest":digest_names(commits),"generic_violation_count":len(history_violations)}]
    working=[ROOT/name for name in changed_paths if (ROOT/name).is_file()];checks.append(scan_files("working_tree",working))
    package_violations=_archive_violations(wheel)
    if package_violations:raise SystemExit("SESSION10_GENERIC_ABSENCE_VIOLATION:package")
    with zipfile.ZipFile(wheel) as archive:members=[name for name in archive.namelist() if not name.endswith("/")]
    checks.append({"scope":"package","items_inspected":len(members),"inventory_digest":digest_names(members),"generic_violation_count":len(package_violations)})
    checks.append(scan_files("proofs_examples",proof_example_paths()))
    ci_paths=[p for p in (ROOT/".github/workflows").rglob("*") if p.is_file()];checks.append(scan_files("controlled_ci",ci_paths))
    if len(checks)!=5 or any(row["generic_violation_count"] for row in checks):raise SystemExit("SESSION10_GENERIC_ABSENCE_INCOMPLETE")
    value={"schema_id":"provan.session10_generic_absence_receipt.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"wheel_sha256":"sha256:"+hashlib.sha256(wheel.read_bytes()).hexdigest(),"checks":checks,"result":"PRIVATE_PLANNING_AUTHORITY_ABSENT","confidential_fingerprint_known":False}
    schema=json.loads((ROOT/"provan/schemas/session10-generic-absence-receipt.v1.json").read_text());jsonschema.validate(value,schema)
    output=ROOT/"artifacts/session10/proofs/private_planning_absence.v1.public.json";output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(canonical(value));print("SESSION10_GENERIC_PRIVATE_PLANNING_ABSENCE_PASS");return 0


if __name__=="__main__":raise SystemExit(main())
