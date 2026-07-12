from __future__ import annotations

import subprocess
from pathlib import Path

from .evidence import http_check
from .verdict import calculate, close_finding

ALLOWED_CLASSES = {"route_fix", "regression_test", "broken_link", "basic_error_handling"}
PROTECTED_PARTS = {".env", ".git", "credentials", "secrets"}


def validate_target(repo: Path, target: Path, remediation_class: str) -> Path:
    if remediation_class not in ALLOWED_CLASSES:
        raise ValueError("remediation class is not allowlisted")
    repo = repo.resolve(); target = target.resolve()
    if repo not in target.parents or any(part.lower() in PROTECTED_PARTS for part in target.parts):
        raise ValueError("remediation target is outside repository or protected")
    return target


def ensure_branch(repo: Path, branch: str) -> None:
    current = subprocess.run(["git", "branch", "--show-current"], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()
    if current != branch:
        subprocess.run(["git", "switch", "-c", branch], cwd=repo, check=True)


def patch_demo_route(repo: Path, branch: str) -> Path:
    target = validate_target(repo, repo / "demo_patient" / "server.py", "route_fix")
    ensure_branch(repo, branch)
    source = target.read_text(encoding="utf-8")
    old = 'elif path.startswith("/results/"):'
    new = 'elif path.startswith("/result/"):'
    if old not in source:
        raise ValueError("expected route defect is absent; refusing broad patch")
    target.write_text(source.replace(old, new, 1), encoding="utf-8")
    return target


def verify_and_close(release: dict) -> dict:
    failed = next((c for c in release.get("checks", []) if c.get("criterion_id") == "PRODUCT_PUBLIC_RESULT_OPENS" and not c.get("passed")), None)
    finding = next((f for f in release.get("findings", []) if f.get("criterion_id") == "PRODUCT_PUBLIC_RESULT_OPENS" and f.get("state") != "CLOSED"), None)
    if not failed or not finding:
        raise ValueError("original failed check and open finding are required")
    rerun = http_check(failed["target"])
    rerun["criterion_id"] = failed["criterion_id"]
    rerun["rerun_of"] = release["checks"].index(failed)
    release["checks"].append(rerun)
    if rerun["passed"]:
        evidence = {"status": rerun["evidence_status"], "kind": "http_status", "value": rerun["status"], "reference": rerun["target"]}
        closed = close_finding(finding, evidence)
        release["findings"][release["findings"].index(finding)] = closed
    release["verdict"] = calculate(release); release["state"] = release["verdict"]["status"]
    return release

