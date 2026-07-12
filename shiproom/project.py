from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlparse

PROJECT_SCHEMA = "project_contract.v1"
LOCATOR_SCHEMA = "local_project_locator.v1"
DEPLOYMENT_SCHEMA = "deployment_target.v1"
RECEIPT_SCHEMA = "project_activation_receipt.v1"
AUTHORITY_POLICY_VERSION = "project_authority_policy.v1"
PROFILES = {"inspect", "verify", "remediate"}
DEFAULT_EXCLUDED = [".env", ".env.*", ".git", ".git/**", ".shiproom/local", ".shiproom/local/**", "**/credentials/**", "**/secrets/**", "**/*.pem", "**/*.key"]
SHIPROOM_POLICIES = ("deterministic_evidence_precedence", "independent_closure", "verdict_precedence", "capability_enforcement", "secret_and_path_safety", "no_auto_merge", "isolated_remediation")
ALLOWED_ENVIRONMENT = {"CI", "NO_COLOR", "PYTHONUTF8"}
SHELL_META = re.compile(r"[|&;<>()`\r\n]|\$\(|%[A-Za-z_][A-Za-z0-9_]*%|\$\{?[A-Za-z_]")
SENSITIVE_KEYS = re.compile(r"(?i)(secret|password|credential|api[_-]?key|token|session[_-]?id|local[_-]?path|repository[_-]?path|localhost|deployment[_-]?url)")
SECRET_VALUE = re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{20,}\b|\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b|https?://[^/@\s]+:[^/@\s]+@)")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=check)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, field: str, *, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{field} must be non-empty text of at most {maximum} characters")
    if SECRET_VALUE.search(value): raise ValueError(f"{field} contains credential-like content; store it under .shiproom/local instead")
    return value.strip()


def _relative(value: str, field: str) -> str:
    value = value.replace("\\", "/")
    win = PureWindowsPath(value); posix = PurePosixPath(value)
    if win.is_absolute() or win.drive or posix.is_absolute() or ".." in posix.parts or value.startswith("//"):
        raise ValueError(f"{field} must be repository-relative without traversal")
    return "." if value in {"", "."} else str(posix)


def _remote(value: str | None) -> str | None:
    if not value:
        return None
    if re.match(r"^[^/@:]+@[^/:]+:.+$", value):
        return value
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "ssh"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("remote must be credential-free HTTPS or SSH")
    return value


def default_contract(project_name: str, product_purpose: str, primary_users: list[str], profile: str = "inspect") -> dict:
    slug = re.sub(r"[^a-z0-9]+", "-", project_name.lower()).strip("-") or "project"
    return {"schema_version": PROJECT_SCHEMA, "status": "active", "project_id": slug, "project_name": project_name.strip(), "product_purpose": product_purpose.strip(), "primary_users": primary_users, "project_principles": [], "active_practices": [], "protected_paths": [], "excluded_paths": list(DEFAULT_EXCLUDED), "measurement_refs": [], "accepted_risks": [], "report_visibility": "private", "memory_policy": "disabled", "default_capability_profile": profile, "execution_policy": {"approved_commands": []}}


def validate_command(command: dict, repo: Path | None = None, *, storage_scope: str = "shared") -> None:
    if storage_scope not in {"shared","local_only"}: raise ValueError("invalid contract storage scope")
    required = {"command_id", "criterion_id", "required_for_release", "argv", "cwd", "purpose", "source", "timeout_seconds", "output_limit_bytes", "allowed_environment"}
    if set(command) != required:
        raise ValueError(f"approved command fields must be exactly {sorted(required)}")
    _text(command["command_id"], "command_id", maximum=80); _text(command["criterion_id"], "criterion_id", maximum=120); _text(command["purpose"], "purpose")
    if not isinstance(command["required_for_release"], bool): raise ValueError("required_for_release must be boolean")
    argv = command["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or not v or SHELL_META.search(v) or v.startswith("@") for v in argv):
        raise ValueError("argv must be normalized tokens without shell syntax, expansion, or response files")
    if storage_scope=="shared":
        for index,token in enumerate(argv):
            machine_path=bool(re.match(r"^[A-Za-z]:[\\/]",token) or token.startswith(("\\\\","//","~/","file://")))
            posix_path=token.startswith("/") and (index==0 or "/" in token[1:] or not re.fullmatch(r"/[A-Za-z?][A-Za-z0-9_-]*",token))
            if machine_path or posix_path: raise ValueError("shared approved command argv contains a machine-specific absolute path")
    command["cwd"] = _relative(command["cwd"], "approved command cwd")
    source = command["source"]
    if set(source) != {"ref", "hash"} or not str(source["hash"]).startswith("sha256:"):
        raise ValueError("approved command requires exact source ref and sha256 hash")
    source["ref"] = _relative(source["ref"], "approved command source.ref")
    if not isinstance(command["timeout_seconds"], int) or not 1 <= command["timeout_seconds"] <= 900:
        raise ValueError("timeout_seconds must be between 1 and 900")
    if not isinstance(command["output_limit_bytes"], int) or not 1024 <= command["output_limit_bytes"] <= 10_485_760:
        raise ValueError("output_limit_bytes must be between 1024 and 10485760")
    env = command["allowed_environment"]
    if not isinstance(env, dict) or any(k not in ALLOWED_ENVIRONMENT or not isinstance(v, str) for k, v in env.items()):
        raise ValueError("allowed_environment contains an unapproved or non-text variable")
    if repo:
        source_path = resolve_policy_path(repo, source["ref"], [], DEFAULT_EXCLUDED, operation="read")
        if not source_path.is_file() or file_hash(source_path) != source["hash"]:
            raise ValueError(f"approved command source hash is stale: {source['ref']}")


def validate_contract(contract: dict, repo: Path | None = None, *, storage_scope: str = "shared") -> dict:
    required = {"schema_version", "status", "project_id", "project_name", "product_purpose", "primary_users", "project_principles", "active_practices", "protected_paths", "excluded_paths", "measurement_refs", "accepted_risks", "report_visibility", "memory_policy", "default_capability_profile", "execution_policy"}
    if set(contract) != required or contract.get("schema_version") != PROJECT_SCHEMA or contract.get("status") != "active":
        raise ValueError("invalid project_contract.v1 fields or status")
    for field in ("project_id", "project_name", "product_purpose"): _text(contract[field], field)
    if not isinstance(contract["primary_users"], list) or not contract["primary_users"]: raise ValueError("primary_users must be non-empty")
    for field in ("primary_users", "project_principles", "active_practices", "protected_paths", "excluded_paths", "measurement_refs"):
        if not isinstance(contract[field], list) or any(not isinstance(v, str) for v in contract[field]): raise ValueError(f"{field} must be a list of strings")
        for index, value in enumerate(contract[field]):
            if SECRET_VALUE.search(value): raise ValueError(f"{field}[{index}] contains credential-like content; store it under .shiproom/local instead")
    for field in ("protected_paths", "excluded_paths"):
        for value in contract[field]: _relative(value, field)
    if contract["report_visibility"] != "private" or contract["memory_policy"] != "disabled": raise ValueError("Session 1 requires private reports and disabled memory")
    if contract["default_capability_profile"] not in PROFILES: raise ValueError("unknown capability profile")
    if any(SENSITIVE_KEYS.search(key) for key in contract): raise ValueError("sensitive fields belong in .shiproom/local")
    risks = contract["accepted_risks"]
    if not isinstance(risks, list): raise ValueError("accepted_risks must be a list")
    for risk in risks:
        needed = {"risk_id", "scope", "rationale", "decision_ref", "adopted_at", "review_or_expiry"}
        if not isinstance(risk, dict) or set(risk) != needed: raise ValueError("durable risks require named decision, scope, rationale, and review/expiry")
        for key, value in risk.items(): _text(value, f"accepted_risks.{key}")
    policy = contract["execution_policy"]
    if set(policy) != {"approved_commands"} or not isinstance(policy["approved_commands"], list): raise ValueError("invalid execution_policy")
    criterion_ids = []
    for command in policy["approved_commands"]:
        validate_command(command, repo,storage_scope=storage_scope); criterion_ids.append(command["criterion_id"])
    if len(criterion_ids) != len(set(criterion_ids)): raise ValueError("approved command criterion_id values must be unique")
    return contract


def contract_hash(contract: dict) -> str:
    validate_contract(contract)
    return content_hash(contract)


def contract_git_state(repo: Path, contract_path: Path) -> dict:
    rel = str(contract_path.resolve().relative_to(repo.resolve())).replace("\\", "/")
    tracked = _git(repo, "ls-files", "--error-unmatch", "--", rel, check=False).returncode == 0
    status = _git(repo, "status", "--porcelain", "--", rel).stdout.strip()
    return {"tracked": tracked, "modified": bool(status), "status": status or "clean"}


def activation_status(repo: Path, contract_path: Path, receipt_path: Path, *, validate_command_sources: bool = True) -> dict:
    scope="local_only" if ".shiproom/local" in contract_path.as_posix().lower() else "shared"
    contract = validate_contract(json.loads(contract_path.read_text(encoding="utf-8")),storage_scope=scope)
    invalid_commands = []
    if validate_command_sources:
        for command in contract["execution_policy"]["approved_commands"]:
            try: validate_command(command, repo,storage_scope=scope)
            except ValueError: invalid_commands.append(command.get("command_id", "unknown"))
    state = contract_git_state(repo, contract_path) if repo in contract_path.resolve().parents else {"tracked": False, "modified": True, "status": "local-only"}
    receipt = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.is_file() else None
    actual = content_hash(contract)
    reusable = state["tracked"] and not state["modified"]
    agreement = bool(receipt and receipt.get("schema_version") == RECEIPT_SCHEMA and receipt.get("contract_hash") == actual and receipt.get("contract_file_hash") == file_hash(contract_path) and receipt.get("policy_version") == AUTHORITY_POLICY_VERSION)
    fresh = (agreement or (not receipt and reusable)) and not invalid_commands
    declared = contract["default_capability_profile"]
    command_freshness = [{"command_id": c["command_id"], "fresh": c["command_id"] not in invalid_commands} for c in contract["execution_policy"]["approved_commands"]]
    return {"contract": contract, "contract_hash": actual, "receipt_hash": receipt.get("contract_hash") if receipt else None, "activation_receipt_hash": content_hash(receipt) if receipt else None, "hash_agreement": agreement, "tracked": state["tracked"], "modified": state["modified"], "activation_fresh": fresh, "declared_profile": declared, "effective_profile": declared if fresh else "inspect", "reusable": reusable, "invalid_command_grants": invalid_commands, "command_freshness": command_freshness}


def activate(repo: Path, contract_path: Path, receipt_path: Path) -> dict:
    scope="local_only" if ".shiproom/local" in contract_path.as_posix().lower() else "shared"
    validate_contract(json.loads(contract_path.read_text(encoding="utf-8")), repo,storage_scope=scope)
    status = activation_status(repo, contract_path, receipt_path)
    receipt = {"schema_version": RECEIPT_SCHEMA, "contract_hash": status["contract_hash"], "contract_file_hash": file_hash(contract_path), "activated_at": datetime.now(UTC).isoformat(), "contract_tracked": status["tracked"], "contract_clean": not status["modified"], "capability_profile": status["contract"]["default_capability_profile"], "policy_version": AUTHORITY_POLICY_VERSION}
    receipt_path.parent.mkdir(parents=True, exist_ok=True); receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return receipt


def validate_policy_relative(relative: str, protected: list[str], excluded: list[str], *, operation: str) -> str:
    rel = _relative(relative, "path")
    normalized = str(PurePosixPath(rel)); parts = PurePosixPath(normalized).parts
    lower_parts=tuple(p.lower() for p in parts); basename = lower_parts[-1] if lower_parts else ""; lower_normalized=normalized.lower()
    sensitive = any(part == ".git" or part in {"credentials", "secrets"} for part in lower_parts) or basename == ".env" or basename.startswith(".env.") or basename.endswith((".pem", ".key")) or lower_normalized == ".shiproom/local" or lower_normalized.startswith(".shiproom/local/")
    def matches(patterns: list[str]) -> bool:
        for raw in patterns:
            pattern = raw.replace("\\", "/").rstrip("/")
            candidate=normalized
            if os.name=="nt": pattern=pattern.lower(); candidate=candidate.lower()
            if not pattern: continue
            if any(ch in pattern for ch in "*?["):
                if fnmatch.fnmatch(candidate, pattern) or fnmatch.fnmatch(candidate.rsplit("/",1)[-1], pattern.removeprefix("**/")): return True
            elif candidate == pattern or candidate.startswith(pattern + "/"):
                return True
        return False
    if sensitive or matches(excluded): raise PermissionError("path is excluded")
    if operation == "write" and matches(protected): raise PermissionError("path is protected from modification")
    return normalized


def resolve_policy_path(repo: Path, relative: str, protected: list[str], excluded: list[str], *, operation: str) -> Path:
    rel=validate_policy_relative(relative,protected,excluded,operation=operation)
    lexical = repo / rel
    resolved_repo = repo.resolve(); resolved = lexical.resolve(strict=False)
    if resolved != resolved_repo and resolved_repo not in resolved.parents: raise PermissionError("path escapes repository")
    return resolved


def local_locator(repo: Path) -> dict:
    root = Path(_git(repo.resolve(), "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    remote = _git(root, "config", "--get", "remote.origin.url", check=False).stdout.strip() or None
    return {"schema_version": LOCATOR_SCHEMA, "observed_at": datetime.now(UTC).isoformat(), "repository_root": str(root), "remote_url": _remote(remote), "branch": _git(root, "branch", "--show-current").stdout.strip() or None, "head": _git(root, "rev-parse", "HEAD").stdout.strip(), "source_mappings": {}}


def deployment_target(kind: str = "none", address: str | None = None) -> dict:
    if kind not in {"none", "localhost", "preview", "public"}: raise ValueError("invalid deployment target kind")
    if kind == "none" and address is not None: raise ValueError("none deployment cannot have an address")
    if kind != "none" and not address: raise ValueError("deployment address is required")
    if address:
        parsed = urlparse(address)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname: raise ValueError("deployment address must be HTTP(S)")
        is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (kind == "localhost") != is_local: raise ValueError("deployment kind does not match address")
    return {"schema_version": DEPLOYMENT_SCHEMA, "observed_at": datetime.now(UTC).isoformat(), "kind": kind, "address": address}
