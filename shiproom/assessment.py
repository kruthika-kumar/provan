from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import subprocess
import uuid
from datetime import datetime
from importlib import resources
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlparse

from .authority import LocalExecutionContext
from .graph import load_assessment_input
from .project import canonical_json, content_hash, validate_command, validate_policy_relative


ROLE_SCHEMA = "shiproom.assessment-role.v1"
WORK_ORDER_SCHEMA = "shiproom.work-order.v1"
CAPABILITIES_SCHEMA = "shiproom.assessment-capabilities.v1"
SOURCE_PACKET_SCHEMA = "assessment-source-packet.v1"
ROLE_CONTEXT_SCHEMA = "assessment-role-context.v1"
WORK_ORDERS_SCHEMA = "assessment-work-orders.v1"
POINTER_SCHEMA = "active-assessment-preparation.v1"
PREPARATION_COMPILER_VERSION = "assessment-preparation.v2"
DISCOVERY_VERSION = "assessment-source-discovery.v1"
DISCOVERY_SELECTION_ORDER = ("graph_mapped_source", "owner_role_path", "relevant_configuration", "python_test_name_match", "javascript_test_name_match", "python_static_import_one_hop", "javascript_literal_import_one_hop", "test_helper_import_one_hop", "approved_command_source", "ci_approved_command_match")
DISCOVERY_LANGUAGES = ("python", "javascript", "typescript")
DISCOVERY_UNSUPPORTED = ("dynamic imports", "package execution", "installed package traversal", "node_modules", "path aliases", "namespace package inference", "recursive import discovery")

CORE_ROLES = ("product_assessment", "engineering_assessment", "test_adequacy", "targeted_test_planning")
ALL_ROLES = (*CORE_ROLES, "browser_journey")
ROLE_REQUIRED = {role: role in CORE_ROLES for role in ALL_ROLES}
ROLE_OUTPUT_SCHEMAS = {
    "product_assessment": "schemas/product-assessment-result.v1.json",
    "engineering_assessment": "schemas/engineering-assessment-result.v1.json",
    "test_adequacy": "schemas/test-adequacy-result.v1.json",
    "targeted_test_planning": "schemas/targeted-test-result.v1.json",
    "browser_journey": "schemas/browser-journey-result.v1.json",
}
SOURCE_FILE_LIMIT = 256 * 1024
ROLE_FILE_LIMIT = 64
ROLE_TEXT_LIMIT = 2 * 1024 * 1024
ROLE_STRUCTURAL_RECORD_LIMIT = 2048
ROLE_STRUCTURAL_BYTES_LIMIT = 2 * 1024 * 1024
RESULT_BYTES_LIMIT = 1024 * 1024
RESULT_RECORD_LIMIT = 500
TARGETED_SPEC_LIMIT = 200
ASSUMPTION_LIMIT = 100
LIMITATION_LIMIT = 100
RATIONALE_LIMIT = 4096
DETAIL_LIMIT = 16384
RESULT_SCHEMAS = {
    "product_assessment": "product-assessment-result.v1",
    "engineering_assessment": "engineering-assessment-result.v1",
    "test_adequacy": "test-adequacy-result.v1",
    "targeted_test_planning": "targeted-test-result.v1",
    "browser_journey": "browser-journey-result.v1",
}
RECEIPT_SCHEMA = "shiproom.assessment-completion-receipt.v1"
DISPOSITIONS = {"assessed", "not_inspected", "not_applicable", "blocked_by_input_ambiguity"}
UNCERTAINTIES = {"none", "bounded", "material", "not_assessed"}
EVIDENCE_CLASSES = {"model_reviewed", "not_inspected"}
TEST_LAYERS = {"unit", "component", "integration", "contract", "end_to_end", "browser", "manual", "unknown"}
ADEQUACY = {"adequate", "partial", "inadequate", "not_inspected"}
TEST_PRIORITIES = {"release_blocking_candidate", "high", "medium", "low"}
ACTIONABILITY = {"actionable", "product_decision_required", "architecture_decision_required", "insufficient_evidence", "not_actionable"}
RELEASE_EFFECTS = {"blocker_candidate", "condition_candidate", "recommendation", "none"}
CAPABILITIES_LIMIT = 64 * 1024
SUPPORTED_CODE = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
CONFIG_FILES = ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock")
SCOPE_STATUSES = {"confirmed", "explicit_pending_confirmation", "inferred_requires_owner", "blocked_by_ambiguity", "not_applicable"}


class AssessmentPreparationError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _root(ctx: LocalExecutionContext) -> Path:
    return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "assessment"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _render(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_bytes(_render(value))
    os.replace(temporary, path)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON value: {value}")))
    except UnicodeDecodeError as exc:
        raise ValueError("JSON input must be UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def _text(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{field} must be bounded non-empty text")
    return value.strip()


def _string_list(value: object, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(item, str) or not item for item in value) or len(value) != len(set(value)):
        raise ValueError(f"{field} must be a unique string list")
    return value


def _role_resource(role_id: str):
    return resources.files("shiproom.assessment_roles").joinpath(role_id + ".json")


def _validate_role(value: dict, expected_role: str | None = None) -> dict:
    required = {"schema_version", "role_id", "role_version", "mandate", "assessment_method", "assigned_record_types", "required_coverage", "evidence_hierarchy", "allowed_basis_references", "gap_taxonomy", "aspect_codes", "forbidden_claims", "required_output_schema", "completion_rules", "reasoning_examples"}
    if set(value) != required or value.get("schema_version") != ROLE_SCHEMA or value.get("role_id") not in ALL_ROLES or (expected_role and value.get("role_id") != expected_role):
        raise ValueError("invalid assessment role definition")
    _text(value["role_version"], "role_version", 32); _text(value["mandate"], "mandate")
    for field in ("assessment_method", "assigned_record_types", "required_coverage", "evidence_hierarchy", "allowed_basis_references", "aspect_codes", "forbidden_claims", "completion_rules"):
        _string_list(value[field], field, nonempty=True)
    if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) for item in value["aspect_codes"]):
        raise ValueError("invalid role aspect code")
    if not isinstance(value["gap_taxonomy"], list) or any(not isinstance(item, dict) or set(item) != {"gap_kind", "aspect_codes"} or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", str(item["gap_kind"])) or not set(_string_list(item["aspect_codes"], "gap aspect codes", nonempty=True)).issubset(value["aspect_codes"]) for item in value["gap_taxonomy"]):
        raise ValueError("invalid role gap taxonomy")
    _text(value["required_output_schema"], "required_output_schema", 200)
    if value["required_output_schema"] != ROLE_OUTPUT_SCHEMAS[value["role_id"]]:
        raise ValueError("role output schema mismatch")
    examples = value["reasoning_examples"]
    if not isinstance(examples, dict) or set(examples) != {"adequate", "inadequate"}:
        raise ValueError("invalid reasoning examples")
    _string_list(examples["adequate"], "adequate examples", nonempty=True); _string_list(examples["inadequate"], "inadequate examples", nonempty=True)
    return value


def load_role_definitions() -> dict[str, dict]:
    result = {}
    for role_id in ALL_ROLES:
        raw = _role_resource(role_id).read_bytes(); value = _validate_role(_load_json_bytes(raw), role_id)
        result[role_id] = {"value": value, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "snapshot_bytes": raw}
    return result


def _role_snapshot(raw: bytes, role_id: str) -> dict:
    value = _validate_role(_load_json_bytes(raw), role_id)
    return {"value": value, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "snapshot_bytes": raw}


def _discovery_snapshot(raw: bytes) -> dict:
    value = _load_json_bytes(raw)
    fields = {"schema_version", "selection_order", "supported_languages", "rule_ids", "configuration_allowlist", "javascript_extensions", "limits", "unsupported"}
    if set(value) != fields or value.get("schema_version") != DISCOVERY_VERSION:
        raise ValueError("invalid assessment source-discovery registry")
    for field in ("selection_order", "supported_languages", "rule_ids", "configuration_allowlist", "javascript_extensions", "unsupported"):
        _string_list(value[field], f"discovery.{field}", nonempty=True)
    if tuple(value["selection_order"]) != DISCOVERY_SELECTION_ORDER or set(value["rule_ids"]) != set(DISCOVERY_SELECTION_ORDER) or tuple(value["supported_languages"]) != DISCOVERY_LANGUAGES or tuple(value["configuration_allowlist"]) != CONFIG_FILES or tuple(value["javascript_extensions"]) != JS_EXTENSIONS or tuple(value["unsupported"]) != DISCOVERY_UNSUPPORTED:
        raise ValueError("assessment discovery snapshot is incompatible with this preparation compiler")
    limits = value["limits"]
    if not isinstance(limits, dict) or set(limits) != {"per_file_bytes", "files_per_role", "source_text_bytes_per_role"} or limits != {"per_file_bytes": SOURCE_FILE_LIMIT, "files_per_role": ROLE_FILE_LIMIT, "source_text_bytes_per_role": ROLE_TEXT_LIMIT}:
        raise ValueError("invalid assessment discovery limits")
    return {"value": value, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "snapshot_bytes": raw}


def load_discovery_registry() -> dict:
    return _discovery_snapshot(resources.files("shiproom.assessment_roles").joinpath("source-discovery.v1.json").read_bytes())


def default_capabilities() -> dict:
    return {
        "schema_version": CAPABILITIES_SCHEMA,
        "substrate": {"id": "manual_external", "execution_mode": "manual_external"},
        "capabilities": {name: {"available": name == "file_read"} for name in ("file_read", "browser", "shell", "network")},
        "permissions": {
            "file_read": {"granted": True, "scope": "prepared_packet_only"},
            "browser": {"granted": False},
            "shell": {"granted": False, "allowed_command_ids": []},
            "network": {"granted": False},
        },
    }


def validate_capabilities(value: dict, approved_commands: list[dict]) -> dict:
    if set(value) != {"schema_version", "substrate", "capabilities", "permissions"} or value.get("schema_version") != CAPABILITIES_SCHEMA:
        raise ValueError("invalid assessment capability declaration")
    substrate = value["substrate"]
    if not isinstance(substrate, dict) or set(substrate) != {"id", "execution_mode"} or substrate.get("execution_mode") not in {"manual_external", "agent_harness"}:
        raise ValueError("invalid assessment substrate")
    _text(substrate.get("id"), "substrate.id", 120)
    capabilities = value["capabilities"]
    if not isinstance(capabilities, dict) or set(capabilities) != {"file_read", "browser", "shell", "network"} or any(not isinstance(item, dict) or set(item) != {"available"} or not isinstance(item["available"], bool) for item in capabilities.values()):
        raise ValueError("invalid assessment capabilities")
    permissions = value["permissions"]
    if not isinstance(permissions, dict) or set(permissions) != {"file_read", "browser", "shell", "network"}:
        raise ValueError("invalid assessment permissions")
    if set(permissions["file_read"]) != {"granted", "scope"} or permissions["file_read"].get("scope") != "prepared_packet_only" or not isinstance(permissions["file_read"].get("granted"), bool):
        raise ValueError("invalid assessment file-read permission")
    for name in ("browser", "network"):
        if not isinstance(permissions[name], dict) or set(permissions[name]) != {"granted"} or not isinstance(permissions[name]["granted"], bool):
            raise ValueError(f"invalid assessment {name} permission")
    shell = permissions["shell"]
    if not isinstance(shell, dict) or set(shell) != {"granted", "allowed_command_ids"} or not isinstance(shell["granted"], bool):
        raise ValueError("invalid assessment shell permission")
    allowed = _string_list(shell["allowed_command_ids"], "allowed_command_ids")
    known = {command["command_id"] for command in approved_commands}
    if not set(allowed).issubset(known):
        raise ValueError("assessment shell permission references an unapproved command")
    for name in ("file_read", "browser", "shell", "network"):
        if permissions[name]["granted"] and not capabilities[name]["available"]:
            raise ValueError(f"{name} permission granted without capability")
    if not capabilities["file_read"]["available"] or not permissions["file_read"]["granted"]:
        raise ValueError("prepared packet reading is required")
    return json.loads(canonical_json(value))


def _load_capabilities(ctx: LocalExecutionContext, path_value: str | None, approved_commands: list[dict]) -> tuple[dict, bytes | None]:
    if path_value is None:
        value = default_capabilities(); return validate_capabilities(value, approved_commands), None
    inputs = (_root(ctx) / "inputs").resolve(); raw_path = Path(path_value).absolute()
    if raw_path.is_symlink():
        raise ValueError("capability declaration must be a regular release-local JSON file")
    path = raw_path.resolve()
    if inputs not in path.parents or path.suffix.lower() != ".json" or not path.is_file() or path.stat().st_size > CAPABILITIES_LIMIT:
        raise ValueError("capability declaration must be bounded JSON under assessment/inputs")
    raw = path.read_bytes(); return validate_capabilities(_load_json_bytes(raw), approved_commands), raw


def _git_bytes(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, check=check)


def _release_paths(ctx: LocalExecutionContext) -> list[str]:
    commit = ctx.authority_binding["repository_commit"]
    raw = _git_bytes(ctx.repository_root, "ls-tree", "-r", "--name-only", "-z", commit).stdout
    result = []
    for item in raw.decode("utf-8", "strict").split("\x00"):
        if not item:
            continue
        path = item.replace("\\", "/")
        try:
            validate_policy_relative(path, ctx.activation["contract"]["protected_paths"], ctx.activation["contract"]["excluded_paths"], operation="read")
        except (PermissionError, ValueError):
            continue
        result.append(path)
    return sorted(set(result))


def _normal_path(value: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid repository path")
    path = posixpath.normpath(value.replace("\\", "/"))
    if path in {"", "."} or path.startswith("/") or path.startswith("../") or "/../" in path or re.match(r"^[A-Za-z]:", path):
        raise ValueError("assessment paths must be repository-relative")
    return path


def _owner_paths(values: list[str] | None) -> dict[str, list[str]]:
    result = {role: [] for role in ALL_ROLES}
    for value in values or []:
        if not isinstance(value, str) or ":" not in value:
            raise ValueError("assessment --path must be role_id:repository-path")
        role, raw_path = value.split(":", 1)
        if role not in ALL_ROLES:
            raise ValueError("assessment --path uses unknown role")
        path = _normal_path(raw_path)
        if path.casefold() in {item.casefold() for item in result[role]}:
            raise ValueError("duplicate owner assessment path")
        result[role].append(path)
    return {role: sorted(paths) for role, paths in result.items()}


def _source(ctx: LocalExecutionContext, path: str, mandatory: bool, rules: list[str], reason: str, provenance: str) -> dict:
    try:
        blob = ctx.read_release_blob(path, byte_limit=SOURCE_FILE_LIMIT)
    except FileNotFoundError as exc:
        raise AssessmentPreparationError("assessment_source_missing", path) from exc
    except PermissionError as exc:
        raise AssessmentPreparationError("assessment_source_unsupported_git_object", path) from exc
    except ValueError as exc:
        code = "assessment_source_oversized" if "byte limit" in str(exc) else "assessment_source_excluded"
        raise AssessmentPreparationError(code, path) from exc
    if blob["classification"] != "text" or blob["text"] is None:
        raise AssessmentPreparationError("assessment_source_unsupported_type", path)
    text = blob["text"].removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    return {"path": blob["path"], "returned_git_path": blob["path"], "git_blob_hash": blob["blob_hash"], "normalized_text_hash": _sha(text.encode("utf-8")), "size_bytes": len(text.encode("utf-8")), "text": text, "mandatory": mandatory, "selection_rule_ids": sorted(set(rules)), "selection_reason": reason, "provenance": provenance}


def _test_matches(path: str, available: set[str]) -> list[tuple[str, str, int]]:
    pure = PurePosixPath(path); suffix = pure.suffix.lower(); stem = pure.stem; parent = str(pure.parent)
    candidates: list[tuple[str, str, int]] = []
    if suffix == ".py":
        for candidate in (f"tests/test_{stem}.py", f"{parent}/test_{stem}.py", f"{parent}/{stem}_test.py"):
            normalized = posixpath.normpath(candidate)
            if normalized in available and normalized != path:
                candidates.append((normalized, "python_test_name_match", 30))
    elif suffix in JS_EXTENSIONS:
        for extension in JS_EXTENSIONS:
            for candidate in (f"{parent}/{stem}.test{extension}", f"{parent}/{stem}.spec{extension}", f"{parent}/__tests__/{stem}{extension}"):
                normalized = posixpath.normpath(candidate)
                if normalized in available and normalized != path:
                    candidates.append((normalized, "javascript_test_name_match", 30))
    return candidates


def _python_imports(path: str, text: str, available: set[str]) -> tuple[list[str], str | None]:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return [], "python_static_import_parse_failed"
    parent = PurePosixPath(path).parent; found = set()
    for node in ast.walk(tree):
        names: list[tuple[str, int]] = []
        if isinstance(node, ast.Import):
            names.extend((alias.name, 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append((node.module, node.level))
            elif node.level:
                names.extend((alias.name, node.level) for alias in node.names if alias.name != "*")
        for name, level in names:
            parts = list(parent.parts)
            if level:
                parts = parts[:max(0, len(parts) - level + 1)]
            else:
                parts = []
            module = "/".join([*parts, *name.split(".")])
            for candidate in (module + ".py", module + "/__init__.py"):
                candidate = posixpath.normpath(candidate)
                if candidate in available and candidate != path:
                    found.add(candidate)
    return sorted(found), None


JS_IMPORT = re.compile(r"(?:from\s+|import\s*\(\s*|require\s*\(\s*)[\"'](\.[^\"']+)[\"']")


def _javascript_imports(path: str, text: str, available: set[str]) -> tuple[list[str], str | None]:
    parent = str(PurePosixPath(path).parent); found = set()
    for match in JS_IMPORT.finditer(text):
        base = posixpath.normpath(posixpath.join(parent, match.group(1)))
        candidates = [base] if PurePosixPath(base).suffix.lower() in JS_EXTENSIONS else [base + extension for extension in JS_EXTENSIONS] + [base + "/index" + extension for extension in JS_EXTENSIONS]
        found.update(candidate for candidate in candidates if candidate in available and candidate != path)
    return sorted(found), None


def _config_candidates(seeds: set[str], available: set[str]) -> list[tuple[str, str, int]]:
    result = set()
    for seed in seeds:
        parent = PurePosixPath(seed).parent
        directories = [PurePosixPath("."), parent, *parent.parents]
        for directory in directories:
            for name in CONFIG_FILES:
                candidate = name if str(directory) == "." else str(directory / name)
                if candidate in available:
                    result.add(candidate)
    return [(path, "relevant_configuration", 20) for path in sorted(result)]


def _ci_candidates(ctx: LocalExecutionContext, available: set[str], commands: list[dict]) -> list[tuple[str, str, int]]:
    workflows = [path for path in available if path.startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml"))][:32]
    result = []
    for path in workflows:
        if any(command["source"]["ref"] == path for command in commands):
            result.append((path, "approved_command_source", 10)); continue
        try:
            text = ctx.read_release_blob(path, byte_limit=SOURCE_FILE_LIMIT)["text"] or ""
        except (FileNotFoundError, PermissionError, ValueError):
            continue
        if any(all(token in text for token in command["argv"]) for command in commands):
            result.append((path, "ci_approved_command_match", 60))
    return result


ROLE_REPOSITORY_NODE_TYPES = {
    "product_assessment": {"implementation_reference", "instrumentation_reference"},
    "engineering_assessment": {"implementation_reference", "test_reference", "instrumentation_reference"},
    "test_adequacy": {"implementation_reference", "test_reference"},
    "targeted_test_planning": {"implementation_reference", "test_reference"},
    "browser_journey": set(),
}


def _mapped_paths(graph_artifacts: dict, role: str) -> set[str]:
    result = set(); allowed_types = ROLE_REPOSITORY_NODE_TYPES[role]
    graph = graph_artifacts["requirement-evidence-graph.json"]
    for node in graph["nodes"]:
        if node.get("node_type") in allowed_types and isinstance(node.get("path"), str):
            result.add(_normal_path(node["path"]))
    return result


def _role_sources(ctx: LocalExecutionContext, role: str, available: set[str], mapped: set[str], owner: list[str], commands: list[dict]) -> tuple[list[dict], dict, list[dict]]:
    mandatory: dict[str, tuple[set[str], str, str]] = {}
    for path in mapped:
        mandatory[path] = ({"graph_mapped_source"}, "Base graph repository reference.", "base_graph")
    for path in owner:
        mandatory.setdefault(path, (set(), "Owner supplied role source.", "owner_input"))[0].add("owner_role_path")
    if role in {"engineering_assessment", "test_adequacy", "targeted_test_planning"}:
        for command in commands:
            path = _normal_path(command["source"]["ref"])
            mandatory.setdefault(path, (set(), "Activated command authority source.", "project_contract"))[0].add("approved_command_source")
    loaded_mandatory = []
    for path in sorted(mandatory):
        rules, reason, provenance = mandatory[path]
        loaded_mandatory.append(_source(ctx, path, True, sorted(rules), reason, provenance))
    mandatory_bytes = sum(item["size_bytes"] for item in loaded_mandatory)
    if len(loaded_mandatory) > ROLE_FILE_LIMIT or mandatory_bytes > ROLE_TEXT_LIMIT:
        raise AssessmentPreparationError("assessment_mandatory_source_budget_exceeded", role)

    supplemental: dict[str, tuple[int, set[str]]] = {}
    seeds = set(mandatory)
    for path, rule, priority in _config_candidates(seeds, available) + _ci_candidates(ctx, available, commands):
        supplemental.setdefault(path, (priority, set()))[1].add(rule)
    test_paths = set()
    for seed in sorted(seeds):
        for path, rule, priority in _test_matches(seed, available):
            supplemental.setdefault(path, (priority, set()))[1].add(rule); test_paths.add(path)

    original_import_seeds = sorted(path for path in seeds | test_paths if PurePosixPath(path).suffix.lower() in SUPPORTED_CODE)
    limitations = []
    for seed in original_import_seeds:
        try:
            item = next((value for value in loaded_mandatory if value["path"] == seed), None) or _source(ctx, seed, False, ["import_seed"], "Static import seed.", "assessment_discovery")
        except AssessmentPreparationError as exc:
            limitations.append({"kind": exc.code, "path": seed, "rule_id": "static_import"}); continue
        suffix = PurePosixPath(seed).suffix.lower()
        imports, limitation = _python_imports(seed, item["text"], available) if suffix == ".py" else _javascript_imports(seed, item["text"], available)
        if limitation:
            limitations.append({"kind": limitation, "path": seed, "rule_id": "static_import"})
        rule = "test_helper_import_one_hop" if seed in test_paths else ("python_static_import_one_hop" if suffix == ".py" else "javascript_literal_import_one_hop")
        for path in imports:
            supplemental.setdefault(path, (40 if seed in seeds else 50, set()))[1].add(rule)

    for path in mandatory:
        supplemental.pop(path, None)
    included = list(loaded_mandatory); omitted = []; considered = 0
    for path, (priority, rules) in sorted(supplemental.items(), key=lambda item: (item[1][0], item[0])):
        considered += 1
        try:
            item = _source(ctx, path, False, sorted(rules), "Deterministic supplemental context.", "assessment_discovery")
        except AssessmentPreparationError as exc:
            limitations.append({"kind": exc.code, "path": path, "rule_id": sorted(rules)[0]}); continue
        if len(included) >= ROLE_FILE_LIMIT or sum(value["size_bytes"] for value in included) + item["size_bytes"] > ROLE_TEXT_LIMIT:
            omitted.append(path); continue
        included.append(item)
    coverage = {"coverage_status": "bounded_incomplete" if omitted else "fully_included", "mandatory_files": len(loaded_mandatory), "candidate_files_considered": considered, "files_included": len(included), "files_omitted_due_to_cap": len(omitted), "omitted_paths": omitted, "source_text_bytes": sum(item["size_bytes"] for item in included)}
    return sorted(included, key=lambda item: item["path"]), coverage, sorted(limitations, key=canonical_json)


def _tree_blob_hash(ctx: LocalExecutionContext, commit: str, path: str) -> str | None:
    path = validate_policy_relative(path, ctx.activation["contract"]["protected_paths"], ctx.activation["contract"]["excluded_paths"], operation="read")
    raw = _git_bytes(ctx.repository_root, "ls-tree", "-z", commit, "--", f":(literal){path}").stdout
    records = [item for item in raw.decode("utf-8", "strict").split("\x00") if item]
    if len(records) != 1 or "\t" not in records[0]:
        return None
    metadata, returned = records[0].split("\t", 1); fields = metadata.split()
    if returned.replace("\\", "/") != path or len(fields) != 3 or fields[1] != "blob" or fields[0] not in {"100644", "100755"}:
        return None
    return fields[2]


def _change_impact(ctx: LocalExecutionContext, base_commit: str | None) -> dict:
    release = ctx.authority_binding["repository_commit"]
    if base_commit is None:
        return {"status": "unavailable", "authority": "none", "reason_code": "no_authoritative_base"}
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base_commit):
        raise AssessmentPreparationError("invalid_assessment_base", "base commit must be a full SHA")
    base = base_commit.lower()
    probe = _git_bytes(ctx.repository_root, "cat-file", "-t", base, check=False)
    if probe.returncode or probe.stdout.strip() != b"commit" or base == release:
        raise AssessmentPreparationError("invalid_assessment_base", "base must be a distinct commit object")
    ancestor = _git_bytes(ctx.repository_root, "merge-base", "--is-ancestor", base, release, check=False)
    if ancestor.returncode:
        raise AssessmentPreparationError("invalid_assessment_base", "base is not an ancestor of the release commit")
    raw = _git_bytes(ctx.repository_root, "diff", "--name-status", "-z", "--no-renames", base, release).stdout.decode("utf-8", "strict")
    fields = [item for item in raw.split("\x00") if item]; changes = []
    if len(fields) % 2:
        raise AssessmentPreparationError("invalid_change_impact", "Git returned malformed name-status output")
    statuses = {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}
    for index in range(0, len(fields), 2):
        code, raw_path = fields[index], fields[index + 1]
        if code not in statuses:
            raise AssessmentPreparationError("unsupported_change_status", code)
        path = _normal_path(raw_path); base_hash = _tree_blob_hash(ctx, base, path); release_hash = _tree_blob_hash(ctx, release, path)
        changes.append({"path": path, "status": statuses[code], "base_blob_hash": base_hash, "release_blob_hash": release_hash, "content_inspection": "metadata_only" if code == "D" else "not_selected"})
    return {"status": "available", "authority": "owner_supplied_explicit_base", "base_commit": base, "release_commit": release, "validation": {"base_exists": True, "release_exists": True, "base_is_ancestor": True, "repository_matches": True}, "changed_path_count": len(changes), "changed_paths": sorted(changes, key=lambda item: item["path"])}


def _scope(requirement: dict, criterion: dict | None = None) -> str:
    if requirement["status"] == "blocked_by_ambiguity" or requirement.get("ambiguity_dependencies") or (criterion and criterion.get("ambiguity_dependencies")):
        return "blocked_by_ambiguity"
    if criterion is None:
        if requirement.get("classification") == "inferred_requires_owner" or requirement.get("owner_confirmation_required"):
            return "inferred_requires_owner"
        return "confirmed"
    if criterion["classification"] == "inferred_requires_owner":
        return "inferred_requires_owner"
    if criterion["confirmation_state"] == "confirmed":
        return "confirmed"
    return "explicit_pending_confirmation"


def _population(inputs: dict) -> dict:
    intent = inputs["intent_artifacts"]; requirements = [item for item in intent["requirements.json"]["requirements"] if item["status"] != "superseded"]; req = {item["requirement_id"]: item for item in requirements}; criteria = [item for item in intent["acceptance-criteria.json"]["criteria"] if item["requirement_id"] in req]
    requirement_records = [{"requirement_id": item["requirement_id"], "scope_status": _scope(item)} for item in requirements]
    summaries = {item["criterion_id"]: item for item in inputs["graph_artifacts"]["criterion-evidence-summary.json"]["criteria"]}
    criterion_records = []
    for item in criteria:
        summary = summaries[item["criterion_id"]]
        meaningful = any(
            record["detail"].get("slot_status") != "not_inspected"
            for field in ("implementation", "tests", "instrumentation", "runtime")
            for record in summary[field]
        )
        categories = item["required_evidence_categories"]
        criterion_records.append({"criterion_id": item["criterion_id"], "requirement_id": item["requirement_id"], "scope_status": _scope(req[item["requirement_id"]], item), "required_evidence_categories": categories, "has_meaningful_repository_or_evidence_reference": meaningful, "repository_not_applicable_allowed": categories == ["owner_confirmation"] and not meaningful})
    graph = inputs["graph_artifacts"]["requirement-evidence-graph.json"]
    journeys = [
        {"journey_id": item["node_id"], "journey_text": item["journey_text"], "scope_status": "confirmed"}
        for item in graph["nodes"]
        if item["node_type"] == "critical_journey"
    ]
    return {"requirements": sorted(requirement_records, key=lambda item: item["requirement_id"]), "criteria": sorted(criterion_records, key=lambda item: item["criterion_id"]), "journeys": sorted(journeys, key=lambda item: item["journey_id"])}


def _authorized_browser_target(origin: str, allowed: list[str], raw: str, authority: str) -> dict | None:
    url = raw if raw.startswith(("http://", "https://")) else urljoin(origin + "/", raw.lstrip("/")); parsed = urlparse(url)
    normalized_origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if normalized_origin != origin or not any(path == pattern or fnmatch.fnmatchcase(path, pattern) for pattern in allowed):
        return None
    return {"url": url, "origin": origin, "path_pattern": path, "authority": authority}


def _browser_scope(ctx: LocalExecutionContext, inputs: dict, population: dict) -> dict:
    relevant = [item for item in population["criteria"] if "browser_or_http" in item["required_evidence_categories"]]
    if not relevant:
        return {"issued": False, "reason_code": "not_browser_relevant", "assigned_criterion_ids": [], "assigned_journey_ids": [], "criterion_targets": [], "scope_limited_criterion_ids": []}
    origin = ctx.deployment_grant["origin"].rstrip("/"); allowed = ctx.deployment_grant["allowed_paths"]
    summaries = {item["criterion_id"]: item for item in inputs["graph_artifacts"]["criterion-evidence-summary.json"]["criteria"]}
    generated = ctx.release.get("deployment", {}).get("generated_path")
    criterion_targets = []; limited = []
    for criterion in relevant:
        candidates = []
        summary = summaries[criterion["criterion_id"]]
        for record in summary["runtime"]:
            target = record["detail"].get("target")
            if isinstance(target, str) and target:
                authorized = _authorized_browser_target(origin, allowed, target, "canonical_runtime_target")
                if authorized:
                    candidates.append(authorized)
        if not candidates and isinstance(generated, str) and generated:
            authorized = _authorized_browser_target(origin, allowed, generated, "deployment_grant")
            if authorized:
                candidates.append(authorized)
        unique = {canonical_json(item): item for item in candidates}
        if not unique:
            limited.append(criterion["criterion_id"]); continue
        criterion_targets.append({"criterion_id": criterion["criterion_id"], "targets": [unique[key] for key in sorted(unique)]})
    assigned = [item["criterion_id"] for item in criterion_targets]
    requirements = {item["requirement_id"]: item for item in inputs["intent_artifacts"]["requirements.json"]["requirements"]}
    journey_by_text = {item["journey_text"]: item["journey_id"] for item in population["journeys"]}
    journeys = sorted({journey_by_text[text] for item in relevant if item["criterion_id"] in assigned for text in requirements[item["requirement_id"]].get("related_journey_ids", []) if text in journey_by_text})
    return {"issued": bool(assigned), "reason_code": None if assigned else "no_authorized_browser_target", "assigned_criterion_ids": assigned, "assigned_journey_ids": journeys, "criterion_targets": criterion_targets, "scope_limited_criterion_ids": sorted(limited)}


def _browser_issue(scope: dict, capabilities: dict) -> dict:
    if scope["reason_code"] == "not_browser_relevant":
        return scope
    if not capabilities["capabilities"]["browser"]["available"]:
        return {**scope, "issued": False, "reason_code": "browser_capability_unavailable"}
    if not capabilities["permissions"]["browser"]["granted"]:
        return {**scope, "issued": False, "reason_code": "browser_permission_not_granted"}
    if not scope["assigned_criterion_ids"]:
        return {**scope, "issued": False, "reason_code": "no_authorized_browser_target"}
    return {**scope, "issued": True, "reason_code": "browser_scope_insufficient" if scope["scope_limited_criterion_ids"] else None}


def _role_assignments(role: str, population: dict, browser: dict) -> tuple[list[str], list[str], list[str]]:
    criteria = [item["criterion_id"] for item in population["criteria"]]
    requirements = [item["requirement_id"] for item in population["requirements"]]
    journeys = [item["journey_id"] for item in population["journeys"]]
    if role == "product_assessment":
        return requirements, criteria, journeys
    if role == "browser_journey":
        assigned_criteria = browser["assigned_criterion_ids"] if browser["issued"] else []
        requirement_by_criterion = {item["criterion_id"]: item["requirement_id"] for item in population["criteria"]}
        return sorted({requirement_by_criterion[item] for item in assigned_criteria}), assigned_criteria, browser["assigned_journey_ids"] if browser["issued"] else []
    return [], criteria, []


def _intent_context(inputs: dict, role: str, requirement_ids: list[str], criterion_ids: list[str], journey_ids: list[str]) -> dict:
    artifacts = inputs["intent_artifacts"]
    requirements = [item for item in artifacts["requirements.json"]["requirements"] if item["requirement_id"] in requirement_ids or item["requirement_id"] in {criterion["requirement_id"] for criterion in artifacts["acceptance-criteria.json"]["criteria"] if criterion["criterion_id"] in criterion_ids}]
    criteria = [item for item in artifacts["acceptance-criteria.json"]["criteria"] if item["criterion_id"] in criterion_ids]
    ambiguity_ids = {item for record in requirements + criteria for item in record.get("ambiguity_dependencies", [])}
    ambiguities = [item for item in artifacts["ambiguities.json"]["ambiguities"] if item["ambiguity_id"] in ambiguity_ids]
    journeys_by_id = {item["node_id"]: item["journey_text"] for item in inputs["graph_artifacts"]["requirement-evidence-graph.json"]["nodes"] if item["node_type"] == "critical_journey"}
    return {
        "schema_version": "assessment-intent-context.v1",
        "product_intent": artifacts["product-intent.json"] if role == "product_assessment" else None,
        "requirements": sorted(requirements, key=lambda item: item["requirement_id"]),
        "criteria": sorted(criteria, key=lambda item: item["criterion_id"]),
        "ambiguities": sorted(ambiguities, key=lambda item: item["ambiguity_id"]),
        "journeys": [{"journey_id": item, "journey_text": journeys_by_id[item]} for item in sorted(journey_ids)],
    }


ROLE_GRAPH_NODE_TYPES = {
    "product_assessment": {"source", "requirement", "acceptance_criterion", "critical_journey", "implementation_reference", "instrumentation_reference", "runtime_evidence", "finding", "owner_decision", "closure_evidence"},
    "engineering_assessment": {"requirement", "acceptance_criterion", "implementation_reference", "test_reference", "instrumentation_reference", "runtime_evidence", "finding", "closure_evidence"},
    "test_adequacy": {"requirement", "acceptance_criterion", "implementation_reference", "test_reference", "runtime_evidence"},
    "targeted_test_planning": {"requirement", "acceptance_criterion", "implementation_reference", "test_reference"},
    "browser_journey": {"requirement", "acceptance_criterion", "critical_journey", "runtime_evidence", "finding", "closure_evidence"},
}


def _graph_context(inputs: dict, role: str, requirement_ids: list[str], criterion_ids: list[str], journey_ids: list[str]) -> dict:
    graph = inputs["graph_artifacts"]["requirement-evidence-graph.json"]
    nodes = {item["node_id"]: item for item in graph["nodes"]}; edge_map = {item["edge_id"]: item for item in graph["edges"]}; selected = set(requirement_ids) | set(criterion_ids) | set(journey_ids)
    # Two fixed hops admit criterion facts and their typed decision/closure context
    # without turning context preparation into repository or graph discovery.
    frontier = set(selected)
    for _ in range(2):
        discovered = set()
        for edge in graph["edges"]:
            if edge["source_node_id"] in frontier and nodes[edge["target_node_id"]]["node_type"] in ROLE_GRAPH_NODE_TYPES[role]:
                discovered.add(edge["target_node_id"])
            if edge["target_node_id"] in frontier and nodes[edge["source_node_id"]]["node_type"] in ROLE_GRAPH_NODE_TYPES[role]:
                discovered.add(edge["source_node_id"])
        frontier = discovered - selected; selected.update(discovered)
    selected = {item for item in selected if item in nodes and nodes[item]["node_type"] in ROLE_GRAPH_NODE_TYPES[role]}
    edges = [item for item in graph["edges"] if item["source_node_id"] in selected and item["target_node_id"] in selected]
    edge_ids = {item["edge_id"] for item in edges}; gaps = []
    for gap in inputs["graph_artifacts"]["evidence-gaps.json"]["gaps"]:
        if gap["criterion_id"] not in criterion_ids:
            continue
        basis_edges = [edge_map.get(item) for item in gap["basis_edge_ids"]]
        basis_nodes = set(gap["basis_node_ids"])
        if any(item is None for item in basis_edges):
            continue
        basis_nodes.update(item["source_node_id"] for item in basis_edges); basis_nodes.update(item["target_node_id"] for item in basis_edges)
        if any(item not in nodes or nodes[item]["node_type"] not in ROLE_GRAPH_NODE_TYPES[role] for item in basis_nodes):
            continue
        selected.update(basis_nodes); gaps.append(gap)
        for item in basis_edges:
            if item["edge_id"] not in edge_ids:
                edges.append(item); edge_ids.add(item["edge_id"])
    context = {"schema_version": "assessment-base-graph-context.v1", "nodes": sorted((nodes[item] for item in selected), key=lambda item: item["node_id"]), "edges": sorted(edges, key=lambda item: item["edge_id"]), "gaps": sorted(gaps, key=lambda item: item["gap_id"])}
    _validate_graph_context(context, set(criterion_ids))
    record_count = len(context["nodes"]) + len(context["edges"]) + len(context["gaps"])
    if record_count > ROLE_STRUCTURAL_RECORD_LIMIT or len(canonical_json(context).encode("utf-8")) > ROLE_STRUCTURAL_BYTES_LIMIT:
        raise AssessmentPreparationError("assessment_structural_context_budget_exceeded", role)
    return context


def _validate_graph_context(context: dict, assigned_criterion_ids: set[str]) -> None:
    node_ids = {item["node_id"] for item in context["nodes"]}; edge_ids = {item["edge_id"] for item in context["edges"]}
    if len(node_ids) != len(context["nodes"]) or len(edge_ids) != len(context["edges"]):
        raise ValueError("assessment graph context contains duplicate records")
    if any(item["source_node_id"] not in node_ids or item["target_node_id"] not in node_ids for item in context["edges"]):
        raise ValueError("assessment graph context edge is not referentially closed")
    for gap in context["gaps"]:
        if gap["criterion_id"] not in assigned_criterion_ids or not set(gap["basis_node_ids"]).issubset(node_ids) or not set(gap["basis_edge_ids"]).issubset(edge_ids):
            raise ValueError("assessment graph context gap is not referentially closed")


def _work_order_hash(value: dict) -> str:
    return content_hash({key: item for key, item in value.items() if key != "work_order_hash"})


def _validate_work_order(value: dict) -> None:
    required = {"schema_version", "work_order_id", "work_order_hash", "preparation_id", "preparation_semantic_hash", "release_id", "release_commit", "role_id", "role_version", "role_definition_hash", "role_definition_snapshot_hash", "objective", "inputs", "capability_requirements", "permissions", "required_output", "forbidden_claims"}
    if set(value) != required or value.get("schema_version") != WORK_ORDER_SCHEMA or value.get("role_id") not in ALL_ROLES or value.get("work_order_hash") != _work_order_hash(value):
        raise ValueError("invalid assessment work order")
    for field in ("work_order_id", "preparation_id", "preparation_semantic_hash", "release_id", "release_commit", "role_version", "role_definition_hash", "role_definition_snapshot_hash", "objective"):
        _text(value[field], field)
    if not re.fullmatch(r"wo_[a-z_]+_[0-9a-f]{16}", value["work_order_id"]) or not re.fullmatch(r"prep_[0-9a-f]{32}", value["preparation_id"]) or not re.fullmatch(r"[0-9a-f]{40}", value["release_commit"]):
        raise ValueError("invalid work-order identity")
    if not value["work_order_id"].startswith("wo_" + value["role_id"] + "_"):
        raise ValueError("work-order role identity mismatch")
    for field in ("work_order_hash", "preparation_semantic_hash", "role_definition_hash", "role_definition_snapshot_hash"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]):
            raise ValueError(f"invalid {field}")
    inputs = value["inputs"]
    input_fields = {"packet_path", "packet_hash", "criterion_ids", "requirement_ids", "journey_ids", "allowed_paths", "base_graph_generation", "base_graph_semantic_hash", "product_intent_semantic_hash", "mapping_packet_hash", "change_impact_status"}
    if not isinstance(inputs, dict) or set(inputs) != input_fields:
        raise ValueError("invalid work-order inputs")
    for field in ("criterion_ids", "requirement_ids", "journey_ids", "allowed_paths"):
        _string_list(inputs[field], f"inputs.{field}")
    for field in ("packet_path", "packet_hash", "base_graph_generation", "base_graph_semantic_hash", "product_intent_semantic_hash", "change_impact_status"):
        _text(inputs[field], f"inputs.{field}")
    if inputs["mapping_packet_hash"] is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", inputs["mapping_packet_hash"]):
        raise ValueError("invalid mapping packet hash")
    if set(value["capability_requirements"]) != {"file_read", "shell", "browser", "network"} or any(item not in {"required", "optional", "unavailable"} for item in value["capability_requirements"].values()):
        raise ValueError("invalid work-order capability requirements")
    permissions = value["permissions"]
    if not isinstance(permissions, dict) or set(permissions) != {"repository", "shell", "browser"} or permissions["repository"] != "read_only":
        raise ValueError("invalid work-order permissions")
    if not isinstance(permissions["shell"], dict) or set(permissions["shell"]) != {"allowed_commands"} or not isinstance(permissions["shell"]["allowed_commands"], list) or any(not isinstance(item, dict) for item in permissions["shell"]["allowed_commands"]):
        raise ValueError("invalid work-order shell permission")
    for command in permissions["shell"]["allowed_commands"]:
        validate_command(command)
    if permissions["shell"]["allowed_commands"] and value["role_id"] not in {"engineering_assessment", "test_adequacy"}:
        raise ValueError("work-order role cannot receive shell commands")
    if not isinstance(permissions["browser"], dict) or set(permissions["browser"]) != {"allowed_targets"} or not isinstance(permissions["browser"]["allowed_targets"], list) or any(not isinstance(item, dict) or set(item) != {"url", "origin", "path_pattern", "authority"} for item in permissions["browser"]["allowed_targets"]):
        raise ValueError("invalid work-order browser permission")
    for target in permissions["browser"]["allowed_targets"]:
        if target["authority"] not in {"deployment_grant", "canonical_runtime_target"} or any(not isinstance(target[field], str) or not target[field] for field in ("url", "origin", "path_pattern")):
            raise ValueError("invalid work-order browser target")
    if permissions["browser"]["allowed_targets"] and value["role_id"] != "browser_journey":
        raise ValueError("non-browser work order cannot receive browser targets")
    output = value["required_output"]
    if not isinstance(output, dict) or set(output) != {"schema_path", "output_path", "completion_receipt_path", "evidence_directory"}:
        raise ValueError("invalid work-order output")
    for field in output:
        _text(output[field], f"required_output.{field}", 500)
    _string_list(value["forbidden_claims"], "forbidden_claims", nonempty=True)


def _build_preparation(ctx: LocalExecutionContext, preparation_id: str, capabilities_bundle: dict, roles: dict[str, dict], discovery: dict, base_commit: str | None, owner: dict[str, list[str]]) -> dict:
    """Purely derive every semantic preparation artifact from trusted inputs."""
    inputs = load_assessment_input(ctx); approved_commands = ctx.activation["contract"]["execution_policy"]["approved_commands"]
    capabilities = capabilities_bundle["value"]; available = set(_release_paths(ctx)); population = _population(inputs); change = _change_impact(ctx, base_commit)
    browser = _browser_issue(_browser_scope(ctx, inputs, population), capabilities)
    role_sources = {}; role_coverages = {}; role_limitations = {}
    for role in ALL_ROLES:
        sources, coverage, limitations = _role_sources(ctx, role, available, _mapped_paths(inputs["graph_artifacts"], role), owner[role], approved_commands)
        if role == "browser_journey" and browser["scope_limited_criterion_ids"]:
            limitations.append({"kind": "browser_scope_insufficient", "criterion_ids": browser["scope_limited_criterion_ids"], "rule_id": "release_browser_target_authority"})
        role_sources[role] = sources; role_coverages[role] = coverage; role_limitations[role] = sorted(limitations, key=canonical_json)
    mapping_hash = inputs["mapping_packet_snapshot"]["packet_hash"] if inputs["mapping_packet_snapshot"] else None
    authority = {key: ctx.authority_binding[key] for key in ("project_id", "contract_hash", "contract_source", "authority_policy_version")}
    semantic_basis = {"release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": authority, "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities": capabilities, "roles": {role: roles[role]["semantic_hash"] for role in ALL_ROLES}, "discovery_registry_hash": discovery["semantic_hash"], "population": population, "owner_paths": owner, "change_impact": change, "role_sources": role_sources, "role_coverages": role_coverages, "role_limitations": role_limitations, "browser": browser}
    semantic_hash = content_hash(semantic_basis)
    preparation_inputs = {"base_commit": base_commit, "owner_paths": owner}
    source_packet = {"schema_version": SOURCE_PACKET_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "preparation_inputs": preparation_inputs, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": authority, "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities_hash": content_hash(capabilities), "role_definition_hashes": semantic_basis["roles"], "discovery_registry_hash": discovery["semantic_hash"], "population": population, "change_impact": change, "role_sources": {role: {"coverage": role_coverages[role], "limitations": role_limitations[role], "sources": role_sources[role]} for role in ALL_ROLES}, "browser_work_order": browser, "coverage_boundary": "Validated Product Intent and Session 3 graph plus bounded role-specific commit-pinned context only.", "packet_hash": ""}
    source_packet["packet_hash"] = content_hash({key: value for key, value in source_packet.items() if key != "packet_hash"})
    contexts = {}; work_orders = {}; work_order_bytes = {}
    for role in ALL_ROLES:
        requirement_ids, criterion_ids, journey_ids = _role_assignments(role, population, browser)
        browser_targets = browser["criterion_targets"] if role == "browser_journey" else []
        context = {"schema_version": ROLE_CONTEXT_SCHEMA, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "role_id": role, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "assigned_requirements": [item for item in population["requirements"] if item["requirement_id"] in requirement_ids], "assigned_criteria": [item for item in population["criteria"] if item["criterion_id"] in criterion_ids], "assigned_journeys": [item for item in population["journeys"] if item["journey_id"] in journey_ids], "intent_context": _intent_context(inputs, role, requirement_ids, criterion_ids, journey_ids), "base_graph_context": _graph_context(inputs, role, requirement_ids, criterion_ids, journey_ids), "change_impact": change, "sources": role_sources[role], "source_coverage": role_coverages[role], "limitations": role_limitations[role], "browser_criterion_targets": browser_targets, "packet_hash": ""}
        structural = {key: context[key] for key in ("assigned_requirements", "assigned_criteria", "assigned_journeys", "intent_context", "base_graph_context", "change_impact", "limitations", "browser_criterion_targets")}
        if len(canonical_json(structural).encode("utf-8")) > ROLE_STRUCTURAL_BYTES_LIMIT:
            raise AssessmentPreparationError("assessment_structural_context_budget_exceeded", role)
        context["packet_hash"] = content_hash({key: value for key, value in context.items() if key != "packet_hash"}); contexts[role] = context
        issued = role != "browser_journey" or browser["issued"]
        if not issued:
            continue
        work_order_id = "wo_" + role + "_" + hashlib.sha256(canonical_json({"preparation": semantic_hash, "role": role, "version": roles[role]["value"]["role_version"], "requirements": requirement_ids, "criteria": criterion_ids, "journeys": journey_ids}).encode()).hexdigest()[:16]
        relative_root = f".shiproom/local/releases/{ctx.release['release_id']}/assessment"; inbox = f"{relative_root}/inbox/{preparation_id}/{work_order_id}"
        allowed_command_ids = capabilities["permissions"]["shell"]["allowed_command_ids"] if role in {"engineering_assessment", "test_adequacy"} else []
        allowed_commands = [command for command in approved_commands if command["command_id"] in allowed_command_ids]
        flattened_targets = {canonical_json(item): item for record in browser_targets for item in record["targets"]}
        work_order = {"schema_version": WORK_ORDER_SCHEMA, "work_order_id": work_order_id, "work_order_hash": "", "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "role_id": role, "role_version": roles[role]["value"]["role_version"], "role_definition_hash": roles[role]["semantic_hash"], "role_definition_snapshot_hash": roles[role]["snapshot_hash"], "objective": roles[role]["value"]["mandate"], "inputs": {"packet_path": f"{relative_root}/preparations/{preparation_id}/role-context/{role}.json", "packet_hash": context["packet_hash"], "criterion_ids": criterion_ids, "requirement_ids": requirement_ids, "journey_ids": journey_ids, "allowed_paths": sorted(item["path"] for item in role_sources[role]), "base_graph_generation": inputs["graph_generation"], "base_graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "product_intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "change_impact_status": change["status"]}, "capability_requirements": {"file_read": "required", "shell": "optional" if allowed_commands else "unavailable", "browser": "required" if role == "browser_journey" else "unavailable", "network": "unavailable"}, "permissions": {"repository": "read_only", "shell": {"allowed_commands": allowed_commands}, "browser": {"allowed_targets": [flattened_targets[key] for key in sorted(flattened_targets)]}}, "required_output": {"schema_path": roles[role]["value"]["required_output_schema"], "output_path": inbox + "/result.json", "completion_receipt_path": inbox + "/completion-receipt.json", "evidence_directory": inbox + "/evidence"}, "forbidden_claims": roles[role]["value"]["forbidden_claims"]}
        work_order["work_order_hash"] = _work_order_hash(work_order); _validate_work_order(work_order); work_orders[role] = work_order; work_order_bytes[role] = _render(work_order)
    entries = []
    for role in ALL_ROLES:
        work_order = work_orders.get(role); issued = work_order is not None
        entries.append({"role_id": role, "required": ROLE_REQUIRED[role], "issued": issued, "reason_code": None if issued else browser["reason_code"], "work_order_id": work_order["work_order_id"] if issued else None, "work_order_hash": work_order["work_order_hash"] if issued else None, "work_order_snapshot_hash": _sha(work_order_bytes[role]) if issued else None, "work_order_path": f"work-orders/{work_order['work_order_id']}.json" if issued else None, "result_path": work_order["required_output"]["output_path"] if issued else None, "completion_receipt_path": work_order["required_output"]["completion_receipt_path"] if issued else None})
    manifest = {"schema_version": WORK_ORDERS_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "preparation_inputs": preparation_inputs, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "source_packet_hash": source_packet["packet_hash"], "capabilities_hash": content_hash(capabilities), "capabilities_snapshot_filename": capabilities_bundle["snapshot_filename"], "capabilities_snapshot_hash": _sha(capabilities_bundle["snapshot_bytes"]), "discovery_registry": {"semantic_hash": discovery["semantic_hash"], "snapshot_hash": discovery["snapshot_hash"]}, "role_definitions": {role: {"semantic_hash": roles[role]["semantic_hash"], "snapshot_hash": roles[role]["snapshot_hash"]} for role in ALL_ROLES}, "work_orders": entries, "manifest_hash": ""}
    manifest["manifest_hash"] = content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    pointer = {"schema_version": POINTER_SCHEMA, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "manifest_snapshot_hash": _sha(_render(manifest))}
    return {"inputs": inputs, "source_packet": source_packet, "contexts": contexts, "work_orders": work_orders, "work_order_bytes": work_order_bytes, "manifest": manifest, "pointer": pointer}


def prepare(ctx: LocalExecutionContext, *, capabilities_path: str | None = None, base_commit: str | None = None, owner_paths: list[str] | None = None) -> dict:
    ctx.require("file.read"); approved = ctx.activation["contract"]["execution_policy"]["approved_commands"]
    capabilities, submitted = _load_capabilities(ctx, capabilities_path, approved); snapshot = submitted if submitted is not None else _render(capabilities)
    capabilities_bundle = {"value": capabilities, "snapshot_bytes": snapshot, "snapshot_filename": "submitted-capabilities.json" if submitted is not None else "capabilities.json"}
    roles = load_role_definitions(); discovery = load_discovery_registry(); preparation_id = "prep_" + uuid.uuid4().hex
    expected = _build_preparation(ctx, preparation_id, capabilities_bundle, roles, discovery, base_commit, _owner_paths(owner_paths))
    root = _root(ctx); directory = root / "preparations" / preparation_id
    if directory.exists(): raise ValueError("assessment preparation collision")
    directory.mkdir(parents=True); _atomic(directory / "assessment-source-packet.json", expected["source_packet"]); _atomic(directory / "assessment-work-orders.json", expected["manifest"]); _atomic(directory / "capabilities.json", capabilities)
    if submitted is not None: (directory / "submitted-capabilities.json").write_bytes(submitted)
    (directory / "source-discovery.v1.json").write_bytes(discovery["snapshot_bytes"])
    for role in ALL_ROLES:
        role_root = directory / "role-definitions"; role_root.mkdir(exist_ok=True); role_root.joinpath(role + ".json").write_bytes(roles[role]["snapshot_bytes"])
        _atomic(directory / "role-context" / f"{role}.json", expected["contexts"][role])
        if role in expected["work_orders"]:
            work = expected["work_orders"][role]; path = directory / "work-orders" / f"{work['work_order_id']}.json"; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(expected["work_order_bytes"][role]); (root / "inbox" / preparation_id / work["work_order_id"] / "evidence").mkdir(parents=True, exist_ok=True)
    _atomic(root / "active-preparation.json", expected["pointer"])
    return {"preparation_id": preparation_id, "preparation_semantic_hash": expected["manifest"]["preparation_semantic_hash"], "source_packet_hash": expected["source_packet"]["packet_hash"], "work_orders": expected["manifest"]["work_orders"]}


def load_preparation(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    root = _root(ctx); pointer = None
    if preparation_id is None:
        pointer_path = root / "active-preparation.json"
        if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("active assessment preparation unavailable")
        pointer = _load_json_bytes(pointer_path.read_bytes()); preparation_id = pointer.get("preparation_id")
    if not isinstance(preparation_id, str) or not re.fullmatch(r"prep_[0-9a-f]{32}", preparation_id): raise ValueError("invalid assessment preparation ID")
    directory = root / "preparations" / preparation_id
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != (root / "preparations").resolve(): raise ValueError("invalid assessment preparation directory")
    manifest_path = directory / "assessment-work-orders.json"
    if manifest_path.is_symlink() or not manifest_path.is_file(): raise ValueError("incomplete assessment preparation")
    stored_manifest = _load_json_bytes(manifest_path.read_bytes())
    if stored_manifest.get("compiler_version") != PREPARATION_COMPILER_VERSION: raise ValueError("stale_assessment_preparation_compiler_version")
    preparation_inputs = stored_manifest.get("preparation_inputs")
    if not isinstance(preparation_inputs, dict) or set(preparation_inputs) != {"base_commit", "owner_paths"}: raise ValueError("invalid assessment preparation inputs")
    owner = _owner_paths([f"{role}:{path}" for role, paths in preparation_inputs["owner_paths"].items() for path in paths])
    capabilities_path = directory / "capabilities.json"
    if capabilities_path.is_symlink() or not capabilities_path.is_file(): raise ValueError("assessment capabilities unavailable")
    capabilities = validate_capabilities(_load_json_bytes(capabilities_path.read_bytes()), ctx.activation["contract"]["execution_policy"]["approved_commands"])
    snapshot_name = stored_manifest.get("capabilities_snapshot_filename")
    if snapshot_name not in {"capabilities.json", "submitted-capabilities.json"}: raise ValueError("invalid assessment capability snapshot")
    snapshot_path = directory / snapshot_name
    if snapshot_path.is_symlink() or not snapshot_path.is_file(): raise ValueError("assessment capability snapshot unavailable")
    capabilities_bundle = {"value": capabilities, "snapshot_bytes": snapshot_path.read_bytes(), "snapshot_filename": snapshot_name}
    role_root = directory / "role-definitions"
    if role_root.is_symlink() or not role_root.is_dir() or {path.name for path in role_root.iterdir()} != {role + ".json" for role in ALL_ROLES}: raise ValueError("invalid assessment role snapshot set")
    roles = {role: _role_snapshot((role_root / f"{role}.json").read_bytes(), role) for role in ALL_ROLES}
    discovery_path = directory / "source-discovery.v1.json"
    if discovery_path.is_symlink() or not discovery_path.is_file(): raise ValueError("assessment discovery snapshot unavailable")
    discovery = _discovery_snapshot(discovery_path.read_bytes())
    expected = _build_preparation(ctx, preparation_id, capabilities_bundle, roles, discovery, preparation_inputs["base_commit"], owner)
    if stored_manifest != expected["manifest"] or manifest_path.read_bytes() != _render(expected["manifest"]): raise ValueError("assessment preparation semantic rederivation failed: manifest")
    source_path = directory / "assessment-source-packet.json"
    if source_path.is_symlink() or not source_path.is_file() or source_path.read_bytes() != _render(expected["source_packet"]): raise ValueError("assessment preparation semantic rederivation failed: source packet")
    context_root = directory / "role-context"; expected_contexts = {role + ".json" for role in ALL_ROLES}
    if context_root.is_symlink() or not context_root.is_dir() or {path.name for path in context_root.iterdir()} != expected_contexts: raise ValueError("invalid assessment role context set")
    for role in ALL_ROLES:
        path = context_root / f"{role}.json"
        if path.is_symlink() or path.read_bytes() != _render(expected["contexts"][role]): raise ValueError("assessment preparation semantic rederivation failed: role context")
    work_root = directory / "work-orders"; expected_work_names = {f"{item['work_order_id']}.json" for item in expected["work_orders"].values()}
    if work_root.is_symlink() or not work_root.is_dir() or {path.name for path in work_root.iterdir()} != expected_work_names: raise ValueError("invalid assessment work-order set")
    for role, work in expected["work_orders"].items():
        path = work_root / f"{work['work_order_id']}.json"
        if path.is_symlink() or path.read_bytes() != expected["work_order_bytes"][role]: raise ValueError("assessment preparation semantic rederivation failed: work order")
    if pointer is not None and pointer != expected["pointer"]: raise ValueError("assessment preparation pointer semantic binding is stale")
    return {"directory": directory, "manifest": expected["manifest"], "source_packet": expected["source_packet"], "capabilities": capabilities, "graph_input": expected["inputs"], "contexts": expected["contexts"], "work_orders": expected["work_orders"]}


def _enum(value: object, allowed: set[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed: raise ValueError(f"invalid {field}")
    return value


def _bounded_strings(value: object, field: str, maximum: int = 100) -> list[str]:
    result = _string_list(value, field)
    if len(result) > maximum or any(len(item) > DETAIL_LIMIT for item in result): raise ValueError(f"{field} exceeds result bounds")
    return result


def _node_ids_of_types(context: dict, allowed_types: set[str]) -> set[str]:
    return {item["node_id"] for item in context["base_graph_context"]["nodes"] if item["node_type"] in allowed_types}


def _bounded_node_refs(value: object, field: str, context: dict, allowed_types: set[str]) -> list[str]:
    result = _bounded_strings(value, field)
    if not set(result).issubset(_node_ids_of_types(context, allowed_types)):
        raise ValueError(f"{field} contains an invalid base graph node reference")
    return result


def _common_result_record(record: dict, identifier_field: str, assigned: dict[str, dict], context: dict, seen: set[str]) -> dict:
    fields = {"local_id", identifier_field, "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"}
    if not isinstance(record, dict) or not fields.issubset(record): raise ValueError("invalid assessment result record")
    local_id = _text(record["local_id"], "local_id", 120)
    if local_id in seen: raise ValueError("duplicate assessment local ID")
    seen.add(local_id); record_id = _text(record[identifier_field], identifier_field, 160)
    if record_id not in assigned or record["scope_status"] != assigned[record_id]["scope_status"]: raise ValueError("assessment result changes assigned scope")
    disposition = _enum(record["disposition"], DISPOSITIONS, "disposition"); evidence_class = _enum(record["evidence_class"], EVIDENCE_CLASSES, "evidence_class")
    if (disposition == "assessed") != (evidence_class == "model_reviewed"): raise ValueError("assessment evidence class contradicts disposition")
    if disposition == "not_applicable" and identifier_field == "criterion_id" and not assigned[record_id].get("repository_not_applicable_allowed", False): raise ValueError("criterion is not canonically not-applicable")
    _enum(record["uncertainty"], UNCERTAINTIES, "uncertainty"); _text(record["rationale"], "rationale", RATIONALE_LIMIT)
    nodes = {item["node_id"] for item in context["base_graph_context"]["nodes"]}; edges = {item["edge_id"] for item in context["base_graph_context"]["edges"]}; gaps = {item["gap_id"] for item in context["base_graph_context"]["gaps"]}
    for field, allowed in (("basis_node_ids", nodes), ("basis_edge_ids", edges), ("basis_gap_ids", gaps)):
        values = _bounded_strings(record[field], field)
        if not set(values).issubset(allowed): raise ValueError(f"assessment {field} escapes prepared context")
    return record


def _validate_gap(record: dict, role: str, assigned_criteria: set[str], role_definition: dict, context: dict, seen: set[str]) -> dict:
    fields = {"local_id", "criterion_id", "gap_kind", "aspect_code", "actionability", "recommended_release_effect", "summary", "uncertainty", "evidence_class", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"}
    if not isinstance(record, dict) or set(record) != fields: raise ValueError("invalid assessment gap record")
    local_id = _text(record["local_id"], "gap.local_id", 120)
    if local_id in seen: raise ValueError("duplicate assessment local ID")
    seen.add(local_id)
    if record["criterion_id"] not in assigned_criteria: raise ValueError("assessment gap criterion is unassigned")
    taxonomy = {item["gap_kind"]: set(item["aspect_codes"]) for item in role_definition["gap_taxonomy"]}
    if record["gap_kind"] not in taxonomy or record["aspect_code"] not in taxonomy[record["gap_kind"]]: raise ValueError("assessment gap taxonomy violation")
    _enum(record["actionability"], ACTIONABILITY, "gap actionability"); _enum(record["recommended_release_effect"], RELEASE_EFFECTS, "recommended release effect"); _enum(record["uncertainty"], UNCERTAINTIES, "gap uncertainty")
    if record["evidence_class"] != "model_reviewed": raise ValueError("assessment gaps must remain model_reviewed")
    _text(record["summary"], "gap summary", RATIONALE_LIMIT)
    nodes = {item["node_id"] for item in context["base_graph_context"]["nodes"]}; edges = {item["edge_id"] for item in context["base_graph_context"]["edges"]}; gaps = {item["gap_id"] for item in context["base_graph_context"]["gaps"]}
    for field, allowed in (("basis_node_ids", nodes), ("basis_edge_ids", edges), ("basis_gap_ids", gaps)):
        values = _bounded_strings(record[field], field)
        if not set(values).issubset(allowed): raise ValueError(f"assessment gap {field} escapes prepared context")
    record = json.loads(canonical_json(record)); record["gap_key"] = f"{role}|{record['criterion_id']}|{record['gap_kind']}|{record['aspect_code']}"; return record


def _validate_product_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"requirements", "journeys", "criteria", "gaps", "decision_candidates"}: raise ValueError("invalid Product assessment payload")
    seen = set(); req = {item["requirement_id"]: item for item in context["assigned_requirements"]}; crit = {item["criterion_id"]: item for item in context["assigned_criteria"]}; journeys = {item["journey_id"]: item for item in context["assigned_journeys"]}
    required_extra = {"intended_user_outcome", "partial_or_missing"}; journey_extra = {"journey_completeness", "declared_vs_evidence_assessed_scope"}; criterion_extra = {"implementation_status", "honest_success_state", "honest_failure_state", "evidence_required_after_launch"}
    for record in payload["requirements"]:
        if set(record) != {"local_id", "requirement_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"} | required_extra: raise ValueError("invalid Product requirement assessment")
        _common_result_record(record, "requirement_id", req, context, seen); _text(record["intended_user_outcome"], "intended_user_outcome", DETAIL_LIMIT); _text(record["partial_or_missing"], "partial_or_missing", DETAIL_LIMIT)
    for record in payload["journeys"]:
        if set(record) != {"local_id", "journey_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"} | journey_extra: raise ValueError("invalid Product journey assessment")
        _common_result_record(record, "journey_id", journeys, context, seen); _text(record["journey_completeness"], "journey_completeness", DETAIL_LIMIT); _text(record["declared_vs_evidence_assessed_scope"], "declared_vs_evidence_assessed_scope", DETAIL_LIMIT)
    for record in payload["criteria"]:
        if set(record) != {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"} | criterion_extra: raise ValueError("invalid Product criterion assessment")
        _common_result_record(record, "criterion_id", crit, context, seen); _text(record["implementation_status"], "implementation_status", DETAIL_LIMIT); _text(record["honest_success_state"], "honest_success_state", DETAIL_LIMIT); _text(record["honest_failure_state"], "honest_failure_state", DETAIL_LIMIT); _bounded_strings(record["evidence_required_after_launch"], "evidence_required_after_launch")
    if {item["requirement_id"] for item in payload["requirements"]} != set(req) or {item["journey_id"] for item in payload["journeys"]} != set(journeys) or {item["criterion_id"] for item in payload["criteria"]} != set(crit): raise ValueError("Product assessment is incomplete")
    gaps = [_validate_gap(item, "product_assessment", set(crit), role_definition, context, seen) for item in payload["gaps"]]
    decisions = []
    for item in payload["decision_candidates"]:
        if not isinstance(item, dict) or set(item) != {"local_id", "criterion_id", "question", "rationale"} or item["criterion_id"] not in crit: raise ValueError("invalid decision candidate")
        local_id = _text(item["local_id"], "decision_candidate.local_id", 120)
        if local_id in seen: raise ValueError("duplicate assessment local ID")
        seen.add(local_id); _text(item["question"], "decision question", DETAIL_LIMIT); _text(item["rationale"], "decision rationale", RATIONALE_LIMIT); decisions.append(item)
    return {"requirements": payload["requirements"], "journeys": payload["journeys"], "criteria": payload["criteria"], "gaps": gaps, "decision_candidates": decisions}


def _validate_engineering_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "gaps"}: raise ValueError("invalid Engineering assessment payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set()
    extras = {"probable_component_node_ids", "existing_test_node_ids", "test_layer", "assertion_adequacy", "boundary_adequacy", "overall_adequacy", "mocks_or_bypasses", "negative_cases", "recovery_cases", "state_transition_cases", "runtime_evidence_node_ids", "dependency_isolation", "rollback_concern", "migration_concern", "remaining_gap", "required_closure_evidence"}
    common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | extras: raise ValueError("invalid Engineering criterion row")
        _common_result_record(record, "criterion_id", assigned, context, seen); _enum(record["test_layer"], TEST_LAYERS, "test layer")
        for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy"): _enum(record[field], ADEQUACY, field)
        _bounded_node_refs(record["probable_component_node_ids"], "probable_component_node_ids", context, {"implementation_reference"})
        _bounded_node_refs(record["existing_test_node_ids"], "existing_test_node_ids", context, {"test_reference"})
        _bounded_node_refs(record["runtime_evidence_node_ids"], "runtime_evidence_node_ids", context, {"runtime_evidence"})
        for field in ("mocks_or_bypasses", "negative_cases", "recovery_cases", "state_transition_cases", "required_closure_evidence"): _bounded_strings(record[field], field)
        for field in ("dependency_isolation", "rollback_concern", "migration_concern", "remaining_gap"): _text(record[field], field, DETAIL_LIMIT)
    if {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("Engineering assessment is incomplete")
    return {"criteria": payload["criteria"], "gaps": [_validate_gap(item, "engineering_assessment", set(assigned), role_definition, context, seen) for item in payload["gaps"]]}


def _validate_test_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "gaps"}: raise ValueError("invalid test-adequacy payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set(); common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"}; extras = {"existing_test_node_ids", "test_layer", "assertion_adequacy", "boundary_adequacy", "overall_adequacy", "negative_cases", "recovery_cases", "state_transition_cases", "mock_boundaries"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | extras: raise ValueError("invalid test-adequacy criterion")
        _common_result_record(record, "criterion_id", assigned, context, seen); _enum(record["test_layer"], TEST_LAYERS, "test layer")
        for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy"): _enum(record[field], ADEQUACY, field)
        _bounded_node_refs(record["existing_test_node_ids"], "existing_test_node_ids", context, {"test_reference"})
        for field in ("negative_cases", "recovery_cases", "state_transition_cases", "mock_boundaries"): _bounded_strings(record[field], field)
    if {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("test-adequacy assessment is incomplete")
    return {"criteria": payload["criteria"], "gaps": [_validate_gap(item, "test_adequacy", set(assigned), role_definition, context, seen) for item in payload["gaps"]]}


def _validate_targeted_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "specifications"}: raise ValueError("invalid targeted-test payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set(); common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | {"recommendation_summary"}: raise ValueError("invalid targeted-test disposition")
        _common_result_record(record, "criterion_id", assigned, context, seen); _text(record["recommendation_summary"], "recommendation_summary", DETAIL_LIMIT)
    if {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("targeted-test planning is incomplete")
    if not isinstance(payload["specifications"], list) or len(payload["specifications"]) > TARGETED_SPEC_LIMIT: raise ValueError("too many targeted test specifications")
    fields = {"local_id", "criterion_id", "risk_addressed", "test_layer", "setup", "action", "assertions", "negative_cases", "recovery_cases", "required_fixtures", "external_boundaries", "recommended_priority", "aspect_code", "addresses_gap_key", "uncertainty", "rationale"}; specs = []
    for item in payload["specifications"]:
        if not isinstance(item, dict) or set(item) != fields or item["criterion_id"] not in assigned: raise ValueError("invalid targeted test specification")
        local_id = _text(item["local_id"], "test specification local_id", 120)
        if local_id in seen: raise ValueError("duplicate assessment local ID")
        seen.add(local_id); _enum(item["test_layer"], TEST_LAYERS, "test layer"); _enum(item["recommended_priority"], TEST_PRIORITIES, "recommended priority"); _enum(item["uncertainty"], UNCERTAINTIES, "test uncertainty")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item["aspect_code"]) or item["aspect_code"] not in set(role_definition["aspect_codes"]): raise ValueError("invalid test aspect code")
        if item["addresses_gap_key"] is not None and (not isinstance(item["addresses_gap_key"], str) or len(item["addresses_gap_key"]) > 400): raise ValueError("invalid addressed gap key")
        for field in ("risk_addressed", "setup", "action", "rationale"): _text(item[field], field, DETAIL_LIMIT if field != "rationale" else RATIONALE_LIMIT)
        for field in ("assertions", "negative_cases", "recovery_cases", "required_fixtures", "external_boundaries"): _bounded_strings(item[field], field)
        specs.append(item)
    return {"criteria": payload["criteria"], "specifications": specs}


def _validate_completion_receipt(value: dict, work: dict, result_bytes: bytes) -> dict:
    if not isinstance(value, dict) or set(value) != {"schema_version", "executor", "work_order_id", "work_order_hash", "result_snapshot_hash", "started_at", "completed_at"} or value.get("schema_version") != RECEIPT_SCHEMA: raise ValueError("invalid assessment completion receipt")
    executor = value["executor"]
    if not isinstance(executor, dict) or executor.get("executor_type") not in {"human", "agent_harness"}: raise ValueError("invalid assessment executor")
    fields = {"executor_type", "reviewer_label"} if executor["executor_type"] == "human" else {"executor_type", "harness_id", "adapter_version", "run_id", "model_id"}
    if set(executor) != fields: raise ValueError("invalid assessment executor fields")
    for field, item in executor.items():
        if field != "executor_type" and item is not None: _text(item, f"executor.{field}", 200)
    if value["work_order_id"] != work["work_order_id"] or value["work_order_hash"] != work["work_order_hash"] or value["result_snapshot_hash"] != _sha(result_bytes): raise ValueError("assessment completion receipt binding mismatch")
    try: started = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00")); completed = datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc: raise ValueError("invalid assessment receipt timestamp") from exc
    if started.tzinfo is None or completed.tzinfo is None or completed < started: raise ValueError("invalid assessment receipt time range")
    return value


def _validate_role_result(raw: bytes, receipt_raw: bytes, role: str, preparation: dict, role_definition: dict) -> tuple[dict, dict, dict]:
    if len(raw) > RESULT_BYTES_LIMIT: raise ValueError("assessment result exceeds size limit")
    value = _load_json_bytes(raw); work = preparation["work_orders"][role]; context = preparation["contexts"][role]
    fields = {"schema_version", "role_id", "role_version", "preparation_id", "preparation_semantic_hash", "work_order_id", "work_order_hash", "base_graph_generation", "base_graph_semantic_hash", "payload", "assumptions", "limitations"}
    if set(value) != fields or value.get("schema_version") != RESULT_SCHEMAS[role] or value.get("role_id") != role or value.get("role_version") != work["role_version"] or value.get("preparation_id") != work["preparation_id"] or value.get("preparation_semantic_hash") != work["preparation_semantic_hash"] or value.get("work_order_id") != work["work_order_id"] or value.get("work_order_hash") != work["work_order_hash"] or value.get("base_graph_generation") != work["inputs"]["base_graph_generation"] or value.get("base_graph_semantic_hash") != work["inputs"]["base_graph_semantic_hash"]: raise ValueError("assessment result binding mismatch")
    assumptions = _bounded_strings(value["assumptions"], "assumptions", ASSUMPTION_LIMIT); limitations = _bounded_strings(value["limitations"], "limitations", LIMITATION_LIMIT)
    if role == "product_assessment": payload = _validate_product_payload(value["payload"], context, role_definition)
    elif role == "engineering_assessment": payload = _validate_engineering_payload(value["payload"], context, role_definition)
    elif role == "test_adequacy": payload = _validate_test_payload(value["payload"], context, role_definition)
    elif role == "targeted_test_planning": payload = _validate_targeted_payload(value["payload"], context, role_definition)
    else: raise ValueError("browser results are compiled in Phase 4D")
    count = sum(len(item) for item in payload.values() if isinstance(item, list))
    if count > RESULT_RECORD_LIMIT: raise ValueError("assessment result exceeds record limit")
    receipt = _validate_completion_receipt(_load_json_bytes(receipt_raw), work, raw)
    normalized = {"schema_version": role.replace("_", "-") + ".v1", "role_id": role, "role_version": work["role_version"], "preparation_id": work["preparation_id"], "work_order_id": work["work_order_id"], "base_graph_generation": work["inputs"]["base_graph_generation"], "base_graph_semantic_hash": work["inputs"]["base_graph_semantic_hash"], "executor_provenance": receipt["executor"], "assumptions": assumptions, "limitations": limitations, "payload": json.loads(canonical_json(payload))}
    return value, receipt, normalized


def compile_core_results(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    preparation = load_preparation(ctx, preparation_id); roles = {}
    role_root = preparation["directory"] / "role-definitions"
    for role in CORE_ROLES: roles[role] = _role_snapshot((role_root / f"{role}.json").read_bytes(), role)["value"]
    raw_results = {}; receipts = {}; artifacts = {}; snapshot_hashes = {}
    for role in CORE_ROLES:
        work = preparation["work_orders"][role]; inbox = _root(ctx) / "inbox" / preparation["manifest"]["preparation_id"] / work["work_order_id"]
        result_path, receipt_path = inbox / "result.json", inbox / "completion-receipt.json"
        if any(path.is_symlink() or not path.is_file() for path in (result_path, receipt_path)): raise ValueError(f"missing required assessment result: {role}")
        evidence = inbox / "evidence"
        if evidence.is_symlink() or (evidence.exists() and any(evidence.iterdir())): raise ValueError("core assessment roles cannot submit canonical evidence files")
        raw, receipt_raw = result_path.read_bytes(), receipt_path.read_bytes(); submitted, receipt, normalized = _validate_role_result(raw, receipt_raw, role, preparation, roles[role])
        raw_results[role] = submitted; receipts[role] = receipt; artifacts[role] = normalized; snapshot_hashes[role] = {"result_snapshot_hash": _sha(raw), "completion_receipt_snapshot_hash": _sha(receipt_raw), "normalized_result_hash": content_hash(normalized)}
    return {"preparation": preparation, "artifacts": artifacts, "submitted_results": raw_results, "completion_receipts": receipts, "snapshot_hashes": snapshot_hashes}
