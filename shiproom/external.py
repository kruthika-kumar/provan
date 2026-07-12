from __future__ import annotations

import uuid
import re
from urllib.parse import urlparse

from .registry import Module
from .context import compile_project_context, context_projection

CAPABILITIES = {
    "inspect_public_surfaces", "run_safe_commands", "publish_report", "comment_upstream",
    "create_local_diff", "push_branch", "open_pr", "modify_deployment",
}
CONTRACT_SCHEMA = "external_release_contract.v1"
PACKET_SCHEMA = "review_packet.v1"


def _https(value: str, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{field} must be a public HTTPS URL")
    return value


def validate_contract(contract: dict) -> dict:
    required = {"schema_version", "project_name", "repository_url", "live_url", "target_user", "product_promise", "critical_journey", "non_goals", "owner_constraints", "capabilities"}
    missing = required - contract.keys()
    if missing or contract.get("schema_version") != CONTRACT_SCHEMA:
        raise ValueError(f"invalid external contract; missing={sorted(missing)}")
    _https(contract["repository_url"], "repository_url"); _https(contract["live_url"], "live_url")
    if contract.get("pr_url"): _https(contract["pr_url"], "pr_url")
    for key in ("project_name", "target_user", "product_promise"):
        if not isinstance(contract.get(key), str) or not contract[key].strip(): raise ValueError(f"{key} is required")
    if not isinstance(contract["critical_journey"], list) or not contract["critical_journey"]: raise ValueError("critical_journey must be non-empty")
    if set(contract["capabilities"]) != CAPABILITIES or not all(isinstance(v, bool) for v in contract["capabilities"].values()):
        raise ValueError("capabilities must contain every explicit boolean capability")
    return contract


def require_capability(release: dict, capability: str) -> None:
    if capability not in CAPABILITIES or not release.get("capabilities", {}).get(capability, False):
        raise PermissionError(f"capability denied: {capability}")


def compile_release(contract: dict) -> dict:
    contract = validate_contract(contract)
    release = {
        "release_id": f"rel_{uuid.uuid4().hex[:12]}", "schema_version": "release.v0", "mode": "external",
        "repository": {"url": contract["repository_url"], "pr_url": contract.get("pr_url"), "base_branch": None, "commit_sha": None},
        "deployment": {"url": contract["live_url"]},
        "product": {"name": contract["project_name"], "target_user": contract["target_user"], "promise": contract["product_promise"], "critical_journey": contract["critical_journey"], "non_goals": contract["non_goals"]},
        "owner_constraints": contract["owner_constraints"], "capabilities": contract["capabilities"],
        "policies": {"max_immediate_owner_decisions": 2, "auto_fix_mode": "disabled", "auto_merge": False},
        "state": "CONTRACTED", "panel": {"eligible_modules": [], "selected_modules": [], "skipped_modules": []},
        "checks": [], "findings": [], "remediation_tasks": [], "owner_decisions": [],
        "verdict": {"status": "DRAFT", "reason_codes": []}, "telemetry": {}, "integrations": {},
    }
    release["project_context"] = compile_project_context(project_id=contract["project_name"].lower().replace(" ", "-"), repository_url=contract["repository_url"], commit_sha="not_recorded", release_input={"target_user": contract["target_user"], "product_promise": contract["product_promise"], "critical_journey": contract["critical_journey"]}, owner_constraints=contract["owner_constraints"])
    return release


def eligible_modules(release: dict, modules: dict[str, Module]) -> tuple[list[str], dict[str, str]]:
    if not release.get("capabilities", {}).get("inspect_public_surfaces"):
        return [], {key: "Public-surface inspection is not permitted" for key in modules}
    text = " ".join(str(v) for v in release.get("product", {}).values()).lower()
    ai = bool(re.search(r"\b(ai|llm|machine learning|semantic search|retrieval|ranking|analytics|inference|evaluation|evals?)\b", text))
    eligible = [key for key in modules if key != "data" or ai]
    reasons = {key: ("Eligible public product/repository input is available" if key in eligible else "No Data/AI applicability signal") for key in modules}
    return eligible, reasons


def review_packet(release: dict, modules: dict[str, Module]) -> dict:
    eligible, eligibility_reasons = eligible_modules(release, modules)
    criteria = []
    for module_id in eligible:
        criteria.append({"criterion_id": f"{module_id.upper()}_EXTERNAL_REVIEW", "module_id": module_id, "required": True})
    return {"schema_version": PACKET_SCHEMA, "release_id": release["release_id"], "release_signals": {"mode": "external", "project_name": release["product"]["name"], "target_user": release["product"]["target_user"], "promise": release["product"]["promise"], "critical_journey": release["product"]["critical_journey"], "non_goals": release["product"]["non_goals"]}, "eligible_modules": [{"module_id": key, "name": modules[key].config.get("name", key), "version": modules[key].config.get("version"), "eligibility_reason": eligibility_reasons[key]} for key in eligible], "ineligible_modules": [{"module_id": key, "reason": eligibility_reasons[key]} for key in modules if key not in eligible], "applicable_criteria": criteria, "capabilities": release["capabilities"], "project_context": context_projection(release["project_context"]), "public_evidence_references": {"repository_url": release["repository"]["url"], "pr_url": release["repository"].get("pr_url"), "live_url": release["deployment"]["url"]}}
