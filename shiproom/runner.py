from __future__ import annotations

from .authority import LocalExecutionContext
from .evidence import validate_module_result


def run_module(module_id: str, release: dict, context: LocalExecutionContext) -> dict:
    checks: list[dict] = []
    findings: list[dict] = []
    live_url = release.get("deployment", {}).get("url", "")
    if module_id == "product" and live_url:
        generated = release.get("deployment", {}).get("generated_path", "/result/demo")
        check = context.read_configured_deployment(generated)
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
        commands = context.activation["contract"]["execution_policy"]["approved_commands"]
        if context.activation["effective_profile"] == "inspect" or not commands:
            for command in commands:
                checks.append({"criterion_id": command["criterion_id"], "type": "command", "required": command["required_for_release"], "passed": False, "evidence_status": "missing_evidence", "reason": "command execution is not authorized by the effective profile"})
            if not commands:
                checks.append({"criterion_id": "ENGINEERING_COMMAND_COVERAGE", "type": "command_policy", "required": False, "passed": False, "evidence_status": "missing_evidence", "reason": "no activated approved commands are declared"})
        else:
            for command, bounded in context.execute_approved_commands():
                check={"criterion_id":command["criterion_id"],"type":"command","required":command["required_for_release"],"passed":bounded.status=="passed","evidence_status":"deterministically_verified","command_id":command["command_id"],"result":bounded.to_dict()}; checks.append(check)
                if command["required_for_release"] and not check["passed"]:
                    findings.append({"id":f"finding-{release['release_id']}-{command['command_id']}","criterion_id":command["criterion_id"],"title":f"Approved command failed: {command['purpose']}","severity":"blocker","blocking":True,"state":"TRIAGED","evidence":[{"status":"deterministically_verified","kind":"command_result","value":bounded.status,"reference":command["source"]["ref"]}]})
    else:
        checks.append({"criterion_id": f"{module_id.upper()}_V0", "type": "applicability", "passed": True,
                       "evidence_status": "not_applicable"})
    return validate_module_result({"schema_version": "module_result.v0", "module_id": module_id, "checks": checks, "findings": findings})
