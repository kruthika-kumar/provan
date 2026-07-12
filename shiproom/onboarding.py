from __future__ import annotations

import json
import shutil
import urllib.request
from pathlib import Path

from .project import (
    AUTHORITY_POLICY_VERSION, SHIPROOM_POLICIES, activate, activation_status,
    default_contract, deployment_target, local_locator, validate_contract,
)

CONTEXT_FILES = ("AGENTS.md", ".hermes.md", "HERMES.md", "CLAUDE.md", "pyproject.toml", "package.json", "README.md")


def paths(repo: Path, local_only: bool = False) -> tuple[Path, Path]:
    local = repo / ".shiproom" / "local"
    return (local / "project-contract.json" if local_only else repo / ".shiproom" / "project-contract.json", local / "activation-receipt.json")


def ensure_ignore(repo: Path) -> None:
    path = repo / ".gitignore"; entry = ".shiproom/local/"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if entry not in {line.strip() for line in text.splitlines()}:
        path.write_text(text + ("" if not text or text.endswith("\n") else "\n") + entry + "\n", encoding="utf-8")


def write_local_facts(repo: Path, locator: dict, target: dict) -> None:
    root = repo / ".shiproom" / "local"; root.mkdir(parents=True, exist_ok=True)
    (root / "project-locator.json").write_text(json.dumps(locator, indent=2), encoding="utf-8")
    (root / "deployment-target.json").write_text(json.dumps(target, indent=2), encoding="utf-8")


def initialize(repo: Path, *, project_name: str, product_purpose: str, primary_users: list[str], profile: str, local_only: bool, confirmed: bool) -> dict:
    locator = local_locator(repo); repo = Path(locator["repository_root"])
    contract_path, receipt_path = paths(repo, local_only)
    existing = contract_path.is_file()
    contract = validate_contract(json.loads(contract_path.read_text(encoding="utf-8")), repo) if existing else validate_contract(default_contract(project_name, product_purpose, primary_users, profile), repo)
    preview = {"contract_path": str(contract_path), "local_state": str(repo / '.shiproom/local'), "gitignore_entry": ".shiproom/local/", "contract": contract, "non_overridable_shiproom_policies": list(SHIPROOM_POLICIES)}
    if not confirmed:
        return {"status": "PREVIEW", **preview}
    ensure_ignore(repo); contract_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(contract, indent=2) + "\n"
    if not contract_path.is_file() or contract_path.read_text(encoding="utf-8") != serialized:
        contract_path.write_text(serialized, encoding="utf-8")
    write_local_facts(repo, locator, deployment_target())
    state = activation_status(repo, contract_path, receipt_path)
    if not receipt_path.is_file() or state["modified"] or not state["tracked"] or not state["activation_fresh"]: activate(repo, contract_path, receipt_path)
    return {"status": "ACTIVE", **preview, "activation": activation_status(repo, contract_path, receipt_path)}


def discover(repo: Path, *, probe: bool = False) -> dict:
    locator = local_locator(repo); repo = Path(locator["repository_root"]); shared, receipt = paths(repo)
    local_contract, _ = paths(repo, True); contract_path = shared if shared.is_file() else local_contract
    activation = activation_status(repo, contract_path, receipt) if contract_path.is_file() else None
    local = repo / ".shiproom" / "local"; target_path = local / "deployment-target.json"
    target = json.loads(target_path.read_text(encoding="utf-8")) if target_path.is_file() else deployment_target()
    target.setdefault("observed_at","not_recorded")
    context = [name for name in CONTEXT_FILES if (repo / name).is_file()]
    command_candidates = []
    for name in ("pyproject.toml", "package.json"):
        if (repo / name).is_file(): command_candidates.append({"source": name, "status": "detected_not_approved"})
    hermes = shutil.which("hermes")
    result = {"repository": {**locator, "clean": not bool(__import__('subprocess').run(["git", "status", "--porcelain"], cwd=repo, text=True, capture_output=True, check=True).stdout.strip())}, "contract": activation, "context_files": context, "command_candidates": command_candidates, "approved_commands": activation["contract"]["execution_policy"]["approved_commands"] if activation else [], "deployment": target, "hermes": {"available": bool(hermes), "executable": hermes, "profile": "not_recorded", "provider": "not_recorded", "model": "not_recorded"}, "optional_integrations": "not_configured", "network_probes": [], "authority_policy_version": AUTHORITY_POLICY_VERSION}
    if probe:
        address = target.get("address")
        if address:
            try:
                with urllib.request.urlopen(address, timeout=5) as response: status = response.status
                result["network_probes"].append({"type": "deployment", "target": address, "status": status})
            except Exception as exc:
                result["network_probes"].append({"type": "deployment", "target": address, "status": "unavailable", "error": type(exc).__name__})
    return result


def human_report(data: dict) -> str:
    repo=data["repository"]; contract=data["contract"]
    lines=["Shiproom doctor", f"Repository: {repo['repository_root']}", f"Branch/base: {repo['branch'] or 'detached'}", f"HEAD: {repo['head']}", f"Worktree clean: {repo['clean']}", f"Remote configured: {bool(repo['remote_url'])}"]
    if contract:
        lines += [f"Contract: tracked={contract['tracked']} modified={contract['modified']}", f"Activation hash agreement: {contract['hash_agreement']}", f"Activation fresh: {contract['activation_fresh']}", f"Capability profile: declared={contract['declared_profile']} effective={contract['effective_profile']}", f"Report visibility: {contract['contract']['report_visibility']}", f"Memory policy: {contract['contract']['memory_policy']}", f"Excluded paths: {', '.join(contract['contract']['excluded_paths']) or 'none'}", f"Protected paths: {', '.join(contract['contract']['protected_paths']) or 'none'}"]
    else: lines.append("Contract: not initialized")
    lines += [f"Context files found: {', '.join(data['context_files']) or 'none'}", f"Detected command sources: {', '.join(c['source'] for c in data['command_candidates']) or 'none'}", f"Approved commands: {', '.join(c['command_id'] for c in data['approved_commands']) or 'none'}", "Verify has no executable commands until command grants are explicitly added and activated." if not data['approved_commands'] else "Verify commands are limited to the activated grants shown above.", f"Deployment snapshot: {data['deployment']['kind']} observed_at={data['deployment'].get('observed_at','not_recorded')}", f"Hermes available: {data['hermes']['available']}", f"Model/provider: {data['hermes']['model']} / {data['hermes']['provider']}", f"Outbound probes: {len(data['network_probes'])}"]
    return "\n".join(lines)


def project_authority_view(repo: Path, contract_path: Path, receipt_path: Path) -> dict:
    status=activation_status(repo,contract_path,receipt_path); contract=status["contract"]; freshness={item["command_id"]:item["fresh"] for item in status["command_freshness"]}
    commands=[{"command_id":c["command_id"],"criterion_id":c["criterion_id"],"required_for_release":c["required_for_release"],"purpose":c["purpose"],"argv":c["argv"],"cwd":c["cwd"],"source":c["source"],"fresh":freshness[c["command_id"]]} for c in contract["execution_policy"]["approved_commands"]]
    return {"project":{"project_id":contract["project_id"],"name":contract["project_name"],"purpose":contract["product_purpose"],"users":contract["primary_users"],"principles":contract["project_principles"],"active_practices":contract["active_practices"],"excluded_paths":contract["excluded_paths"],"protected_paths":contract["protected_paths"],"accepted_risks":contract["accepted_risks"],"measurement_refs":contract["measurement_refs"],"report_visibility":contract["report_visibility"],"memory_policy":contract["memory_policy"]},"authority":{"declared_profile":status["declared_profile"],"effective_profile":status["effective_profile"],"tracked":status["tracked"],"modified":status["modified"],"contract_hash":status["contract_hash"],"receipt_contract_hash":status["receipt_hash"],"activation_receipt_hash":status["activation_receipt_hash"],"receipt_hash_agreement":status["hash_agreement"],"activation_fresh":status["activation_fresh"],"binding":"bound" if status["hash_agreement"] else "unbound/stale"},"approved_commands":commands}


def human_project_view(view: dict) -> str:
    project=view["project"]; authority=view["authority"]; lines=["Shiproom project authority",f"Project: {project['name']} ({project['project_id']})",f"Purpose: {project['purpose']}",f"Users: {', '.join(project['users'])}",f"Principles: {', '.join(project['principles']) or 'none'}",f"Active practices: {', '.join(project['active_practices']) or 'none'}",f"Excluded paths: {', '.join(project['excluded_paths']) or 'none'}",f"Protected paths: {', '.join(project['protected_paths']) or 'none'}",f"Accepted risks: {len(project['accepted_risks'])}",f"Measurement references: {', '.join(project['measurement_refs']) or 'none'}",f"Report visibility: {project['report_visibility']}",f"Memory policy: {project['memory_policy']}",f"Capability: declared={authority['declared_profile']} effective={authority['effective_profile']}",f"Contract: tracked={authority['tracked']} modified={authority['modified']} binding={authority['binding']}",f"Hashes: contract={authority['contract_hash']} receipt-contract={authority['receipt_contract_hash'] or 'not_recorded'} receipt={authority['activation_receipt_hash'] or 'not_recorded'} agreement={authority['receipt_hash_agreement']}"]
    if not view["approved_commands"]: lines.append("Approved commands: none. Verify has no executable commands until command grants are explicitly added and activated.")
    for command in view["approved_commands"]: lines += [f"Command {command['command_id']}: {command['purpose']}",f"  criterion={command['criterion_id']} required={command['required_for_release']} fresh={command['fresh']}",f"  argv={json.dumps(command['argv'])} cwd={command['cwd']}",f"  source={command['source']['ref']} {command['source']['hash']}"]
    return "\n".join(lines)
