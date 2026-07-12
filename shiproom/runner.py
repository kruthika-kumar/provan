from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

from .evidence import command_check, http_check, validate_module_result


def run_module(module_id: str, release: dict) -> dict:
    checks: list[dict] = []
    findings: list[dict] = []
    live_url = release.get("deployment", {}).get("url", "")
    if module_id == "product" and live_url:
        generated = release.get("deployment", {}).get("generated_path", "/result/demo")
        check = http_check(urljoin(live_url.rstrip("/") + "/", generated.lstrip("/")))
        check["criterion_id"] = "PRODUCT_PUBLIC_RESULT_OPENS"
        checks.append(check)
        if not check["passed"]:
            findings.append({
                "id": f"finding-{release['release_id']}-public-result",
                "criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS",
                "title": "Generated public result does not open",
                "severity": "blocker",
                "blocking": True,
                "state": "TRIAGED",
                "evidence": [{"status": check["evidence_status"], "kind": "http_status", "value": check.get("status"), "reference": check["target"]}],
            })
    elif module_id == "engineering":
        repo = Path(release.get("repository", {}).get("path") or ".").resolve()
        if (repo / "pyproject.toml").exists():
            check = command_check(["python", "-m", "pytest", "-q"], repo)
            check["criterion_id"] = "ENGINEERING_TESTS_PASS"
            checks.append(check)
            if not check["passed"]:
                findings.append({"id": f"finding-{release['release_id']}-tests", "criterion_id": "ENGINEERING_TESTS_PASS",
                                 "title": "Test suite failed", "severity": "blocker", "blocking": True,
                                 "state": "TRIAGED", "evidence": [{"status": check["evidence_status"], "kind": "exit_code", "value": check["exit_code"], "reference": None}]})
    else:
        checks.append({"criterion_id": f"{module_id.upper()}_V0", "type": "applicability", "passed": True,
                       "evidence_status": "not_applicable"})
    return validate_module_result({"schema_version": "module_result.v0", "module_id": module_id, "checks": checks, "findings": findings})

