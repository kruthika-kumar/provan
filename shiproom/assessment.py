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
WORK_ORDER_SCHEMA = "shiproom.work-order.v2"
CAPABILITIES_SCHEMA = "shiproom.assessment-capabilities.v1"
SOURCE_PACKET_SCHEMA = "assessment-source-packet.v2"
ROLE_CONTEXT_SCHEMA = "assessment-role-context.v1"
WORK_ORDERS_SCHEMA = "assessment-work-orders.v2"
POINTER_SCHEMA = "active-assessment-preparation.v1"
PREPARATION_COMPILER_VERSION = "assessment-preparation.v4"
DISCOVERY_VERSION = "assessment-source-discovery.v1"
DISCOVERY_SELECTION_ORDER = ("graph_mapped_source", "owner_role_path", "relevant_configuration", "python_test_name_match", "javascript_test_name_match", "python_static_import_one_hop", "javascript_literal_import_one_hop", "test_helper_import_one_hop", "approved_command_source", "ci_approved_command_match")
DISCOVERY_LANGUAGES = ("python", "javascript", "typescript")
DISCOVERY_UNSUPPORTED = ("dynamic imports", "package execution", "installed package traversal", "node_modules", "path aliases", "namespace package inference", "recursive import discovery")

CORE_ROLES = ("product_assessment", "engineering_assessment", "test_adequacy", "targeted_test_planning")
ALL_ROLES = (*CORE_ROLES, "browser_journey")
ROLE_REQUIRED = {role: role in CORE_ROLES for role in ALL_ROLES}
ROLE_OUTPUT_SCHEMAS = {
    "product_assessment": "shiproom.assessment_schemas/product-assessment-result.v2.json",
    "engineering_assessment": "shiproom.assessment_schemas/engineering-assessment-result.v2.json",
    "test_adequacy": "shiproom.assessment_schemas/test-adequacy-result.v2.json",
    "targeted_test_planning": "shiproom.assessment_schemas/targeted-test-result.v2.json",
    "browser_journey": "shiproom.assessment_schemas/browser-journey-result.v2.json",
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
EVIDENCE_FILE_LIMIT = 5 * 1024 * 1024
EVIDENCE_TOTAL_LIMIT = 25 * 1024 * 1024
EVIDENCE_MEDIA_TYPES = {"image/png", "image/jpeg", "application/json", "application/x-ndjson", "text/plain; charset=utf-8"}
RESULT_SCHEMAS = {
    "product_assessment": "product-assessment-result.v2",
    "engineering_assessment": "engineering-assessment-result.v2",
    "test_adequacy": "test-adequacy-result.v2",
    "targeted_test_planning": "targeted-test-result.v2",
    "browser_journey": "browser-journey-result.v2",
}
RECEIPT_SCHEMA = "shiproom.assessment-completion-receipt.v2"
ASSESSMENT_COMPILER_VERSION = "portable-assessment.v4"
ASSESSMENT_MANIFEST_SCHEMA = "portable-assessment-manifest.v2"
ASSESSMENT_POINTER_SCHEMA = "current-portable-assessment.v1"
OVERLAY_SCHEMA = "assessment-graph-overlay.v2"
EFFECTIVE_VIEW_SCHEMA = "effective-assessment-view.v2"
ASSESSMENT_ARTIFACTS = ("product-assessment.json", "engineering-assessment.json", "test-adequacy.json", "targeted-test-plan.json", "browser-journey.json", "assessment-work-orders.json", "assessment-graph-overlay.json", "effective-assessment-view.json", "assessment-compiler-receipts.json")
OVERLAY_BASE_NODE_TYPES = {"source", "implementation_reference", "test_reference", "instrumentation_reference", "runtime_evidence", "finding", "closure_evidence"}
_BEFORE_ASSESSMENT_POINTER_REPLACE = None
_BEFORE_ASSESSMENT_GENERATION_VERIFY = None
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


def _installed_schema_bytes(filename: str) -> bytes:
    resource = resources.files("shiproom.assessment_schemas").joinpath(filename)
    if not resource.is_file(): raise ValueError(f"portable assessment schema unavailable: {filename}")
    return resource.read_bytes()


def _contract_snapshots() -> dict[str, dict]:
    names = {"work-order.v2.json", "assessment-completion-receipt.v2.json", "browser-journey-result.v2.json", *(Path(value).name for value in ROLE_OUTPUT_SCHEMAS.values())}
    result = {}
    for name in sorted(names):
        raw = _installed_schema_bytes(name); value = _load_json_bytes(raw)
        result[name] = {"bytes": raw, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "schema_version": value.get("$id", name).removesuffix(".json")}
    return result


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
        scope_status = _scope(req[item["requirement_id"]], item)
        criterion_records.append({"criterion_id": item["criterion_id"], "requirement_id": item["requirement_id"], "scope_status": scope_status, "required_evidence_categories": categories, "has_meaningful_repository_or_evidence_reference": meaningful, "product_not_applicable_allowed": scope_status == "not_applicable", "repository_not_applicable_allowed": categories == ["owner_confirmation"] and not meaningful})
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
    output_fields = {"schema_path", "schema_version", "schema_semantic_hash", "schema_snapshot_hash", "output_path", "completion_receipt_schema_path", "completion_receipt_schema_version", "completion_receipt_schema_semantic_hash", "completion_receipt_schema_snapshot_hash", "completion_receipt_path", "evidence_directory"}
    if not isinstance(output, dict) or set(output) != output_fields:
        raise ValueError("invalid work-order output")
    for field in output: _text(output[field], f"required_output.{field}", 500)
    for field in ("schema_semantic_hash", "schema_snapshot_hash", "completion_receipt_schema_semantic_hash", "completion_receipt_schema_snapshot_hash"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", output[field]): raise ValueError("invalid work-order contract hash")
    _string_list(value["forbidden_claims"], "forbidden_claims", nonempty=True)


def _build_preparation(ctx: LocalExecutionContext, preparation_id: str, capabilities_bundle: dict, roles: dict[str, dict], discovery: dict, contracts: dict[str, dict], base_commit: str | None, owner: dict[str, list[str]]) -> dict:
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
    contract_hashes = {name: {"semantic_hash": item["semantic_hash"], "snapshot_hash": item["snapshot_hash"], "schema_version": item["schema_version"]} for name, item in contracts.items()}
    semantic_basis = {"release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": authority, "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities": capabilities, "roles": {role: roles[role]["semantic_hash"] for role in ALL_ROLES}, "discovery_registry_hash": discovery["semantic_hash"], "contract_schemas": contract_hashes, "population": population, "owner_paths": owner, "change_impact": change, "role_sources": role_sources, "role_coverages": role_coverages, "role_limitations": role_limitations, "browser": browser}
    semantic_hash = content_hash(semantic_basis)
    preparation_inputs = {"base_commit": base_commit, "owner_paths": owner}
    source_packet = {"schema_version": SOURCE_PACKET_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "preparation_inputs": preparation_inputs, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": authority, "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities_hash": content_hash(capabilities), "role_definition_hashes": semantic_basis["roles"], "discovery_registry_hash": discovery["semantic_hash"], "contract_schema_hashes": contract_hashes, "population": population, "change_impact": change, "role_sources": {role: {"coverage": role_coverages[role], "limitations": role_limitations[role], "sources": role_sources[role]} for role in ALL_ROLES}, "browser_work_order": browser, "coverage_boundary": "Validated Product Intent and Session 3 graph plus bounded role-specific commit-pinned context only.", "packet_hash": ""}
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
        result_name = Path(roles[role]["value"]["required_output_schema"]).name; result_contract = contracts[result_name]; receipt_contract = contracts["assessment-completion-receipt.v2.json"]
        work_order = {"schema_version": WORK_ORDER_SCHEMA, "work_order_id": work_order_id, "work_order_hash": "", "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "role_id": role, "role_version": roles[role]["value"]["role_version"], "role_definition_hash": roles[role]["semantic_hash"], "role_definition_snapshot_hash": roles[role]["snapshot_hash"], "objective": roles[role]["value"]["mandate"], "inputs": {"packet_path": f"{relative_root}/preparations/{preparation_id}/role-context/{role}.json", "packet_hash": context["packet_hash"], "criterion_ids": criterion_ids, "requirement_ids": requirement_ids, "journey_ids": journey_ids, "allowed_paths": sorted(item["path"] for item in role_sources[role]), "base_graph_generation": inputs["graph_generation"], "base_graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "product_intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "change_impact_status": change["status"]}, "capability_requirements": {"file_read": "required", "shell": "optional" if allowed_commands else "unavailable", "browser": "required" if role == "browser_journey" else "unavailable", "network": "unavailable"}, "permissions": {"repository": "read_only", "shell": {"allowed_commands": allowed_commands}, "browser": {"allowed_targets": [flattened_targets[key] for key in sorted(flattened_targets)]}}, "required_output": {"schema_path": "contract-schemas/" + result_name, "schema_version": result_contract["schema_version"], "schema_semantic_hash": result_contract["semantic_hash"], "schema_snapshot_hash": result_contract["snapshot_hash"], "output_path": inbox + "/result.json", "completion_receipt_schema_path": "contract-schemas/assessment-completion-receipt.v2.json", "completion_receipt_schema_version": receipt_contract["schema_version"], "completion_receipt_schema_semantic_hash": receipt_contract["semantic_hash"], "completion_receipt_schema_snapshot_hash": receipt_contract["snapshot_hash"], "completion_receipt_path": inbox + "/completion-receipt.json", "evidence_directory": inbox + "/evidence"}, "forbidden_claims": roles[role]["value"]["forbidden_claims"]}
        work_order["work_order_hash"] = _work_order_hash(work_order); _validate_work_order(work_order); work_orders[role] = work_order; work_order_bytes[role] = _render(work_order)
    entries = []
    for role in ALL_ROLES:
        work_order = work_orders.get(role); issued = work_order is not None
        entries.append({"role_id": role, "required": ROLE_REQUIRED[role], "issued": issued, "reason_code": None if issued else browser["reason_code"], "work_order_id": work_order["work_order_id"] if issued else None, "work_order_hash": work_order["work_order_hash"] if issued else None, "work_order_snapshot_hash": _sha(work_order_bytes[role]) if issued else None, "work_order_path": f"work-orders/{work_order['work_order_id']}.json" if issued else None, "result_path": work_order["required_output"]["output_path"] if issued else None, "completion_receipt_path": work_order["required_output"]["completion_receipt_path"] if issued else None})
    manifest = {"schema_version": WORK_ORDERS_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "preparation_inputs": preparation_inputs, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "source_packet_hash": source_packet["packet_hash"], "capabilities_hash": content_hash(capabilities), "capabilities_snapshot_filename": capabilities_bundle["snapshot_filename"], "capabilities_snapshot_hash": _sha(capabilities_bundle["snapshot_bytes"]), "discovery_registry": {"semantic_hash": discovery["semantic_hash"], "snapshot_hash": discovery["snapshot_hash"]}, "role_definitions": {role: {"semantic_hash": roles[role]["semantic_hash"], "snapshot_hash": roles[role]["snapshot_hash"]} for role in ALL_ROLES}, "work_orders": entries, "manifest_hash": ""}
    manifest["contract_schemas"] = contract_hashes
    manifest["manifest_hash"] = content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    pointer = {"schema_version": POINTER_SCHEMA, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "manifest_snapshot_hash": _sha(_render(manifest))}
    return {"inputs": inputs, "source_packet": source_packet, "contexts": contexts, "work_orders": work_orders, "work_order_bytes": work_order_bytes, "manifest": manifest, "pointer": pointer, "contracts": contracts, "preparation_inputs": preparation_inputs}


def prepare(ctx: LocalExecutionContext, *, capabilities_path: str | None = None, base_commit: str | None = None, owner_paths: list[str] | None = None) -> dict:
    ctx.require("file.read"); approved = ctx.activation["contract"]["execution_policy"]["approved_commands"]
    capabilities, submitted = _load_capabilities(ctx, capabilities_path, approved); snapshot = submitted if submitted is not None else _render(capabilities)
    capabilities_bundle = {"value": capabilities, "snapshot_bytes": snapshot, "snapshot_filename": "submitted-capabilities.json" if submitted is not None else "capabilities.json"}
    roles = load_role_definitions(); discovery = load_discovery_registry(); contracts = _contract_snapshots(); preparation_id = "prep_" + uuid.uuid4().hex
    expected = _build_preparation(ctx, preparation_id, capabilities_bundle, roles, discovery, contracts, base_commit, _owner_paths(owner_paths))
    root = _root(ctx); directory = root / "preparations" / preparation_id
    if directory.exists(): raise ValueError("assessment preparation collision")
    directory.mkdir(parents=True); _atomic(directory / "assessment-source-packet.json", expected["source_packet"]); _atomic(directory / "assessment-work-orders.json", expected["manifest"]); _atomic(directory / "preparation-inputs.json", expected["preparation_inputs"]); _atomic(directory / "capabilities.json", capabilities)
    if submitted is not None: (directory / "submitted-capabilities.json").write_bytes(submitted)
    (directory / "source-discovery.v1.json").write_bytes(discovery["snapshot_bytes"])
    for name, contract in contracts.items():
        path = directory / "contract-schemas" / name; path.parent.mkdir(exist_ok=True); path.write_bytes(contract["bytes"])
    for role in ALL_ROLES:
        role_root = directory / "role-definitions"; role_root.mkdir(exist_ok=True); role_root.joinpath(role + ".json").write_bytes(roles[role]["snapshot_bytes"])
        _atomic(directory / "role-context" / f"{role}.json", expected["contexts"][role])
        if role in expected["work_orders"]:
            work = expected["work_orders"][role]; path = directory / "work-orders" / f"{work['work_order_id']}.json"; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(expected["work_order_bytes"][role]); (root / "inbox" / preparation_id / work["work_order_id"] / "evidence").mkdir(parents=True, exist_ok=True)
    _atomic(root / "active-preparation.json", expected["pointer"])
    return {"preparation_id": preparation_id, "preparation_semantic_hash": expected["manifest"]["preparation_semantic_hash"], "source_packet_hash": expected["source_packet"]["packet_hash"], "work_orders": expected["manifest"]["work_orders"]}


def load_preparation(ctx: LocalExecutionContext, preparation_id: str | None = None, *, _directory: Path | None = None) -> dict:
    root = _root(ctx); pointer = None
    if _directory is None and preparation_id is None:
        pointer_path = root / "active-preparation.json"
        if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("active assessment preparation unavailable")
        pointer = _load_json_bytes(pointer_path.read_bytes()); preparation_id = pointer.get("preparation_id")
    if not isinstance(preparation_id, str) or not re.fullmatch(r"prep_[0-9a-f]{32}", preparation_id): raise ValueError("invalid assessment preparation ID")
    directory = _directory if _directory is not None else root / "preparations" / preparation_id
    if directory.is_symlink() or not directory.is_dir() or (_directory is None and directory.resolve().parent != (root / "preparations").resolve()): raise ValueError("invalid assessment preparation directory")
    manifest_path = directory / "assessment-work-orders.json"
    if manifest_path.is_symlink() or not manifest_path.is_file(): raise ValueError("incomplete assessment preparation")
    stored_manifest = _load_json_bytes(manifest_path.read_bytes())
    if stored_manifest.get("compiler_version") != PREPARATION_COMPILER_VERSION: raise ValueError("stale_assessment_preparation_compiler_version")
    input_path = directory / "preparation-inputs.json"
    if input_path.is_symlink() or not input_path.is_file(): raise ValueError("assessment preparation inputs unavailable")
    preparation_inputs = _load_json_bytes(input_path.read_bytes())
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
    contract_root = directory / "contract-schemas"
    if contract_root.is_symlink() or not contract_root.is_dir(): raise ValueError("assessment contract snapshots unavailable")
    contracts = {}
    for path in contract_root.iterdir():
        if path.is_symlink() or not path.is_file(): raise ValueError("invalid assessment contract snapshot")
        raw = path.read_bytes(); value = _load_json_bytes(raw); contracts[path.name] = {"bytes": raw, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "schema_version": value.get("$id", path.name).removesuffix(".json")}
    expected_names = {"work-order.v2.json", "assessment-completion-receipt.v2.json", "browser-journey-result.v2.json", *(Path(value).name for value in ROLE_OUTPUT_SCHEMAS.values())}
    if set(contracts) != expected_names: raise ValueError("assessment contract snapshot set invalid")
    expected = _build_preparation(ctx, preparation_id, capabilities_bundle, roles, discovery, contracts, preparation_inputs["base_commit"], owner)
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
    return {"directory": directory, "manifest": expected["manifest"], "source_packet": expected["source_packet"], "capabilities": capabilities, "graph_input": expected["inputs"], "contexts": expected["contexts"], "work_orders": expected["work_orders"], "contracts": contracts}


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


def _source_refs(value: object, context: dict) -> list[dict]:
    if not isinstance(value, list) or len(value) > 100: raise ValueError("invalid packet source reference list")
    sources = {item["path"]: item for item in context["sources"]}; canonical = []
    full = {"path", "returned_git_path", "git_blob_hash", "normalized_text_hash"}; quoted = full | {"start_line", "end_line", "quote", "quote_hash"}
    for ref in value:
        if not isinstance(ref, dict) or frozenset(ref) not in {frozenset(full), frozenset(quoted)}: raise ValueError("invalid packet source reference")
        source = sources.get(ref.get("path"))
        if source is None or any(ref[field] != source[field] for field in full): raise ValueError("packet source reference escapes role context")
        if set(ref) == quoted:
            if type(ref["start_line"]) is not int or type(ref["end_line"]) is not int or ref["start_line"] < 1 or ref["end_line"] < ref["start_line"] or not isinstance(ref["quote"], str) or not ref["quote"]: raise ValueError("invalid packet source quote range")
            lines = source["text"].split("\n")
            if ref["end_line"] > len(lines): raise ValueError("packet source quote range is invalid")
            bounded = "\n".join(lines[ref["start_line"] - 1:ref["end_line"]])
            if bounded.count(ref["quote"]) != 1 or ref["quote_hash"] != _sha(ref["quote"].encode("utf-8")): raise ValueError("packet source quote binding mismatch")
        canonical.append(json.loads(canonical_json(ref)))
    tokens = [canonical_json(item) for item in canonical]
    if len(tokens) != len(set(tokens)): raise ValueError("duplicate packet source reference")
    return [json.loads(item) for item in sorted(tokens)]


def _normalize_basis(record: dict, context: dict, *, require: bool, require_empty: bool = False) -> None:
    nodes = {item["node_id"] for item in context["base_graph_context"]["nodes"]}; edges = {item["edge_id"] for item in context["base_graph_context"]["edges"]}; gaps = {item["gap_id"] for item in context["base_graph_context"]["gaps"]}
    for field, allowed in (("basis_node_ids", nodes), ("basis_edge_ids", edges), ("basis_gap_ids", gaps)):
        values = _bounded_strings(record[field], field)
        if not set(values).issubset(allowed): raise ValueError(f"assessment {field} escapes prepared context")
        record[field] = sorted(values)
    record["basis_source_refs"] = _source_refs(record["basis_source_refs"], context)
    has_basis = any(record[field] for field in ("basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"))
    if require and not has_basis: raise ValueError("assessed record requires prepared basis")
    if require_empty and has_basis: raise ValueError("non-assessed record basis must be empty")


def _common_result_record(record: dict, identifier_field: str, assigned: dict[str, dict], context: dict, seen: set[str], *, role: str, record_kind: str) -> dict:
    fields = {"local_id", identifier_field, "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}
    if not isinstance(record, dict) or not fields.issubset(record): raise ValueError("invalid assessment result record")
    local_id = _text(record["local_id"], "local_id", 120)
    if local_id in seen: raise ValueError("duplicate assessment local ID")
    seen.add(local_id); record_id = _text(record[identifier_field], identifier_field, 160)
    if record_id not in assigned or record["scope_status"] != assigned[record_id]["scope_status"]: raise ValueError("assessment result changes assigned scope")
    disposition = _enum(record["disposition"], DISPOSITIONS, "disposition"); evidence_class = _enum(record["evidence_class"], EVIDENCE_CLASSES, "evidence_class")
    if (disposition == "assessed") != (evidence_class == "model_reviewed"): raise ValueError("assessment evidence class contradicts disposition")
    if (record["scope_status"] == "blocked_by_ambiguity") != (disposition == "blocked_by_input_ambiguity"): raise ValueError("blocked assessment scope/disposition mismatch")
    if disposition == "not_applicable":
        if record_kind != "criterion": raise ValueError("requirements and journeys cannot be reviewer-marked not_applicable")
        flag = "product_not_applicable_allowed" if role == "product_assessment" else "repository_not_applicable_allowed"
        if not assigned[record_id].get(flag, False): raise ValueError("criterion is not canonically not-applicable for this role")
    uncertainty = _enum(record["uncertainty"], UNCERTAINTIES, "uncertainty")
    if (disposition == "assessed") == (uncertainty == "not_assessed"): raise ValueError("assessment disposition/uncertainty mismatch")
    _text(record["rationale"], "rationale", RATIONALE_LIMIT); _normalize_basis(record, context, require=disposition == "assessed", require_empty=disposition != "assessed")
    return record


def _validate_gap(record: dict, role: str, assigned_criteria: set[str], role_definition: dict, context: dict, seen: set[str]) -> dict:
    fields = {"local_id", "criterion_id", "gap_kind", "aspect_code", "actionability", "recommended_release_effect", "summary", "uncertainty", "evidence_class", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}
    if not isinstance(record, dict) or set(record) != fields: raise ValueError("invalid assessment gap record")
    local_id = _text(record["local_id"], "gap.local_id", 120)
    if local_id in seen: raise ValueError("duplicate assessment local ID")
    seen.add(local_id)
    if record["criterion_id"] not in assigned_criteria: raise ValueError("assessment gap criterion is unassigned")
    taxonomy = {item["gap_kind"]: set(item["aspect_codes"]) for item in role_definition["gap_taxonomy"]}
    if record["gap_kind"] not in taxonomy or record["aspect_code"] not in taxonomy[record["gap_kind"]]: raise ValueError("assessment gap taxonomy violation")
    _enum(record["actionability"], ACTIONABILITY, "gap actionability"); _enum(record["recommended_release_effect"], RELEASE_EFFECTS, "recommended release effect"); uncertainty = _enum(record["uncertainty"], UNCERTAINTIES, "gap uncertainty")
    if uncertainty == "not_assessed": raise ValueError("assessment gap must be assessed")
    criterion = next(item for item in context["assigned_criteria"] if item["criterion_id"] == record["criterion_id"])
    if record["recommended_release_effect"] == "blocker_candidate" and criterion["scope_status"] != "confirmed": raise ValueError("blocker candidate requires confirmed criterion")
    if record["evidence_class"] != "model_reviewed": raise ValueError("assessment gaps must remain model_reviewed")
    _text(record["summary"], "gap summary", RATIONALE_LIMIT)
    _normalize_basis(record, context, require=True)
    record = json.loads(canonical_json(record)); record["gap_key"] = f"{role}|{record['criterion_id']}|{record['gap_kind']}|{record['aspect_code']}"; return record


def _validate_product_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"requirements", "journeys", "criteria", "gaps", "decision_candidates"}: raise ValueError("invalid Product assessment payload")
    seen = set(); req = {item["requirement_id"]: item for item in context["assigned_requirements"]}; crit = {item["criterion_id"]: item for item in context["assigned_criteria"]}; journeys = {item["journey_id"]: item for item in context["assigned_journeys"]}
    required_extra = {"intended_user_outcome", "partial_or_missing"}; journey_extra = {"journey_completeness", "declared_vs_evidence_assessed_scope"}; criterion_extra = {"implementation_status", "honest_success_state", "honest_failure_state", "evidence_required_after_launch"}
    for record in payload["requirements"]:
        if set(record) != {"local_id", "requirement_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"} | required_extra: raise ValueError("invalid Product requirement assessment")
        _common_result_record(record, "requirement_id", req, context, seen, role="product_assessment", record_kind="requirement"); _text(record["intended_user_outcome"], "intended_user_outcome", DETAIL_LIMIT); _text(record["partial_or_missing"], "partial_or_missing", DETAIL_LIMIT)
        if record["disposition"] != "assessed" and {record["intended_user_outcome"], record["partial_or_missing"]} != {"not_inspected"}: raise ValueError("non-assessed Product requirement must use not_inspected")
    for record in payload["journeys"]:
        if set(record) != {"local_id", "journey_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"} | journey_extra: raise ValueError("invalid Product journey assessment")
        _common_result_record(record, "journey_id", journeys, context, seen, role="product_assessment", record_kind="journey"); _text(record["journey_completeness"], "journey_completeness", DETAIL_LIMIT); _text(record["declared_vs_evidence_assessed_scope"], "declared_vs_evidence_assessed_scope", DETAIL_LIMIT)
        if record["disposition"] != "assessed" and {record["journey_completeness"], record["declared_vs_evidence_assessed_scope"]} != {"not_inspected"}: raise ValueError("non-assessed Product journey must use not_inspected")
    for record in payload["criteria"]:
        if set(record) != {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"} | criterion_extra: raise ValueError("invalid Product criterion assessment")
        _common_result_record(record, "criterion_id", crit, context, seen, role="product_assessment", record_kind="criterion"); _text(record["implementation_status"], "implementation_status", DETAIL_LIMIT); _text(record["honest_success_state"], "honest_success_state", DETAIL_LIMIT); _text(record["honest_failure_state"], "honest_failure_state", DETAIL_LIMIT); _bounded_strings(record["evidence_required_after_launch"], "evidence_required_after_launch")
        if record["disposition"] != "assessed" and (any(record[field] != "not_inspected" for field in ("implementation_status", "honest_success_state", "honest_failure_state")) or record["evidence_required_after_launch"]): raise ValueError("non-assessed Product criterion must use not_inspected")
    if len(payload["requirements"]) != len(req) or len(payload["journeys"]) != len(journeys) or len(payload["criteria"]) != len(crit) or {item["requirement_id"] for item in payload["requirements"]} != set(req) or {item["journey_id"] for item in payload["journeys"]} != set(journeys) or {item["criterion_id"] for item in payload["criteria"]} != set(crit): raise ValueError("Product assessment is incomplete")
    assessed = {item["criterion_id"] for item in payload["criteria"] if item["disposition"] == "assessed"}; gaps = [_validate_gap(item, "product_assessment", assessed, role_definition, context, seen) for item in payload["gaps"]]
    if len({item["gap_key"] for item in gaps}) != len(gaps): raise ValueError("duplicate assessment gap key")
    decisions = []
    for item in payload["decision_candidates"]:
        if not isinstance(item, dict) or set(item) != {"local_id", "criterion_id", "question", "rationale"} or item["criterion_id"] not in crit: raise ValueError("invalid decision candidate")
        local_id = _text(item["local_id"], "decision_candidate.local_id", 120)
        if local_id in seen: raise ValueError("duplicate assessment local ID")
        seen.add(local_id); _text(item["question"], "decision question", DETAIL_LIMIT); _text(item["rationale"], "decision rationale", RATIONALE_LIMIT); decisions.append(item)
    return {"requirements": sorted(payload["requirements"], key=lambda item: item["requirement_id"]), "journeys": sorted(payload["journeys"], key=lambda item: item["journey_id"]), "criteria": sorted(payload["criteria"], key=lambda item: item["criterion_id"]), "gaps": sorted(gaps, key=lambda item: item["gap_key"]), "decision_candidates": sorted(decisions, key=canonical_json)}


def _validate_engineering_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "gaps"}: raise ValueError("invalid Engineering assessment payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set()
    extras = {"probable_component_node_ids", "existing_test_node_ids", "test_layer", "assertion_adequacy", "boundary_adequacy", "overall_adequacy", "mocks_or_bypasses", "negative_cases", "recovery_cases", "state_transition_cases", "runtime_evidence_node_ids", "dependency_isolation", "rollback_concern", "migration_concern", "remaining_gap", "required_closure_evidence"}
    common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | extras: raise ValueError("invalid Engineering criterion row")
        _common_result_record(record, "criterion_id", assigned, context, seen, role="engineering_assessment", record_kind="criterion"); _enum(record["test_layer"], TEST_LAYERS, "test layer")
        for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy"): _enum(record[field], ADEQUACY, field)
        record["probable_component_node_ids"] = sorted(_bounded_node_refs(record["probable_component_node_ids"], "probable_component_node_ids", context, {"implementation_reference"}))
        record["existing_test_node_ids"] = sorted(_bounded_node_refs(record["existing_test_node_ids"], "existing_test_node_ids", context, {"test_reference"}))
        record["runtime_evidence_node_ids"] = sorted(_bounded_node_refs(record["runtime_evidence_node_ids"], "runtime_evidence_node_ids", context, {"runtime_evidence"}))
        for field in ("mocks_or_bypasses", "negative_cases", "recovery_cases", "state_transition_cases", "required_closure_evidence"): _bounded_strings(record[field], field)
        for field in ("dependency_isolation", "rollback_concern", "migration_concern", "remaining_gap"): _text(record[field], field, DETAIL_LIMIT)
        if record["disposition"] != "assessed" and (record["test_layer"] != "unknown" or any(record[field] != "not_inspected" for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy", "dependency_isolation", "rollback_concern", "migration_concern", "remaining_gap")) or any(record[field] for field in ("probable_component_node_ids", "existing_test_node_ids", "runtime_evidence_node_ids", "mocks_or_bypasses", "negative_cases", "recovery_cases", "state_transition_cases", "required_closure_evidence"))): raise ValueError("non-assessed Engineering row must use unknown/not_inspected")
    if len(payload["criteria"]) != len(assigned) or {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("Engineering assessment is incomplete")
    assessed = {item["criterion_id"] for item in payload["criteria"] if item["disposition"] == "assessed"}; gaps = [_validate_gap(item, "engineering_assessment", assessed, role_definition, context, seen) for item in payload["gaps"]]
    if len({item["gap_key"] for item in gaps}) != len(gaps): raise ValueError("duplicate assessment gap key")
    return {"criteria": sorted(payload["criteria"], key=lambda item: item["criterion_id"]), "gaps": sorted(gaps, key=lambda item: item["gap_key"])}


def _validate_test_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "gaps"}: raise ValueError("invalid test-adequacy payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set(); common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}; extras = {"existing_test_node_ids", "test_layer", "assertion_adequacy", "boundary_adequacy", "overall_adequacy", "negative_cases", "recovery_cases", "state_transition_cases", "mock_boundaries"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | extras: raise ValueError("invalid test-adequacy criterion")
        _common_result_record(record, "criterion_id", assigned, context, seen, role="test_adequacy", record_kind="criterion"); _enum(record["test_layer"], TEST_LAYERS, "test layer")
        for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy"): _enum(record[field], ADEQUACY, field)
        record["existing_test_node_ids"] = sorted(_bounded_node_refs(record["existing_test_node_ids"], "existing_test_node_ids", context, {"test_reference"}))
        for field in ("negative_cases", "recovery_cases", "state_transition_cases", "mock_boundaries"): _bounded_strings(record[field], field)
        if record["disposition"] != "assessed" and (record["test_layer"] != "unknown" or any(record[field] != "not_inspected" for field in ("assertion_adequacy", "boundary_adequacy", "overall_adequacy")) or any(record[field] for field in ("existing_test_node_ids", "negative_cases", "recovery_cases", "state_transition_cases", "mock_boundaries"))): raise ValueError("non-assessed test row must use unknown/not_inspected")
    if len(payload["criteria"]) != len(assigned) or {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("test-adequacy assessment is incomplete")
    assessed = {item["criterion_id"] for item in payload["criteria"] if item["disposition"] == "assessed"}; gaps = [_validate_gap(item, "test_adequacy", assessed, role_definition, context, seen) for item in payload["gaps"]]
    if len({item["gap_key"] for item in gaps}) != len(gaps): raise ValueError("duplicate assessment gap key")
    return {"criteria": sorted(payload["criteria"], key=lambda item: item["criterion_id"]), "gaps": sorted(gaps, key=lambda item: item["gap_key"])}


def _validate_targeted_payload(payload: dict, context: dict, role_definition: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"criteria", "specifications"}: raise ValueError("invalid targeted-test payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; seen = set(); common = {"local_id", "criterion_id", "disposition", "scope_status", "evidence_class", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != common | {"recommendation_summary"}: raise ValueError("invalid targeted-test disposition")
        _common_result_record(record, "criterion_id", assigned, context, seen, role="targeted_test_planning", record_kind="criterion"); _text(record["recommendation_summary"], "recommendation_summary", DETAIL_LIMIT)
        if record["disposition"] != "assessed" and record["recommendation_summary"] != "not_inspected": raise ValueError("non-assessed targeted-test criterion must use not_inspected")
    if len(payload["criteria"]) != len(assigned) or {item["criterion_id"] for item in payload["criteria"]} != set(assigned): raise ValueError("targeted-test planning is incomplete")
    if not isinstance(payload["specifications"], list) or len(payload["specifications"]) > TARGETED_SPEC_LIMIT: raise ValueError("too many targeted test specifications")
    fields = {"local_id", "criterion_id", "risk_addressed", "test_layer", "setup", "action", "assertions", "negative_cases", "recovery_cases", "required_fixtures", "external_boundaries", "recommended_priority", "aspect_code", "addresses_gap_key", "uncertainty", "rationale", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}; specs = []; semantic_specs = set(); assessed = {item["criterion_id"] for item in payload["criteria"] if item["disposition"] == "assessed"}
    for item in payload["specifications"]:
        if not isinstance(item, dict) or set(item) != fields or item["criterion_id"] not in assessed: raise ValueError("invalid targeted test specification")
        local_id = _text(item["local_id"], "test specification local_id", 120)
        if local_id in seen: raise ValueError("duplicate assessment local ID")
        seen.add(local_id); _enum(item["test_layer"], TEST_LAYERS, "test layer"); _enum(item["recommended_priority"], TEST_PRIORITIES, "recommended priority"); _enum(item["uncertainty"], UNCERTAINTIES, "test uncertainty")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item["aspect_code"]) or item["aspect_code"] not in set(role_definition["aspect_codes"]): raise ValueError("invalid test aspect code")
        if item["addresses_gap_key"] is not None and (not isinstance(item["addresses_gap_key"], str) or len(item["addresses_gap_key"]) > 400): raise ValueError("invalid addressed gap key")
        for field in ("risk_addressed", "setup", "action", "rationale"): _text(item[field], field, DETAIL_LIMIT if field != "rationale" else RATIONALE_LIMIT)
        for field in ("assertions", "negative_cases", "recovery_cases", "required_fixtures", "external_boundaries"): _bounded_strings(item[field], field)
        _normalize_basis(item, context, require=False)
        semantic = canonical_json({key: value for key, value in item.items() if key not in {"local_id", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}})
        if semantic in semantic_specs: raise ValueError("duplicate semantic targeted test specification")
        semantic_specs.add(semantic)
        specs.append(item)
    return {"criteria": sorted(payload["criteria"], key=lambda item: item["criterion_id"]), "specifications": sorted(specs, key=lambda item: canonical_json({key: value for key, value in item.items() if key != "local_id"}))}


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
    normalized = {"schema_version": role.replace("_", "-") + ".v2", "role_id": role, "role_version": work["role_version"], "preparation_id": work["preparation_id"], "work_order_id": work["work_order_id"], "base_graph_generation": work["inputs"]["base_graph_generation"], "base_graph_semantic_hash": work["inputs"]["base_graph_semantic_hash"], "executor_provenance": receipt["executor"], "assumptions": sorted(assumptions), "limitations": sorted(limitations), "payload": json.loads(canonical_json(payload))}
    return value, receipt, normalized


def _effective_port(parsed) -> int | None:
    return parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80 if parsed.scheme.lower() == "http" else None)


def _url_is_authorized(raw: str, targets: list[dict]) -> bool:
    try: parsed = urlparse(raw)
    except ValueError: return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None: return False
    path = parsed.path or "/"
    for target in targets:
        allowed = urlparse(target["url"])
        pattern = target["path_pattern"]
        path_ok = path.startswith(pattern[:-1]) if pattern.endswith("*") else path == pattern
        if parsed.scheme.lower() == allowed.scheme.lower() and parsed.hostname.lower() == (allowed.hostname or "").lower() and _effective_port(parsed) == _effective_port(allowed) and path_ok: return True
    return False


def _validate_browser_result(raw: bytes, receipt_raw: bytes, evidence_root: Path, preparation: dict, role_definition: dict) -> dict:
    if len(raw) > RESULT_BYTES_LIMIT: raise ValueError("browser result exceeds size limit")
    value = _load_json_bytes(raw); work = preparation["work_orders"]["browser_journey"]; context = preparation["contexts"]["browser_journey"]
    fields = {"schema_version", "role_id", "role_version", "preparation_id", "preparation_semantic_hash", "work_order_id", "work_order_hash", "base_graph_generation", "base_graph_semantic_hash", "payload", "assumptions", "limitations"}
    if set(value) != fields or value.get("schema_version") != RESULT_SCHEMAS["browser_journey"] or value.get("role_id") != "browser_journey" or value.get("role_version") != work["role_version"] or value.get("preparation_id") != work["preparation_id"] or value.get("preparation_semantic_hash") != work["preparation_semantic_hash"] or value.get("work_order_id") != work["work_order_id"] or value.get("work_order_hash") != work["work_order_hash"] or value.get("base_graph_generation") != work["inputs"]["base_graph_generation"] or value.get("base_graph_semantic_hash") != work["inputs"]["base_graph_semantic_hash"]: raise ValueError("browser result binding mismatch")
    payload = value["payload"]
    if not isinstance(payload, dict) or set(payload) != {"criteria", "observations", "judgments", "evidence"}: raise ValueError("invalid browser result payload")
    assigned = {item["criterion_id"]: item for item in context["assigned_criteria"]}; criteria = []; seen_local = set()
    for record in payload["criteria"]:
        if not isinstance(record, dict) or set(record) != {"local_id", "criterion_id", "disposition", "uncertainty", "rationale"} or record.get("criterion_id") not in assigned: raise ValueError("invalid browser criterion disposition")
        local = _text(record["local_id"], "browser criterion local_id", 120)
        if local in seen_local: raise ValueError("duplicate browser local ID")
        seen_local.add(local); disposition = _enum(record["disposition"], {"assessed", "not_inspected", "blocked_by_input_ambiguity"}, "browser disposition"); uncertainty = _enum(record["uncertainty"], UNCERTAINTIES, "browser uncertainty"); _text(record["rationale"], "browser rationale", RATIONALE_LIMIT)
        if (disposition == "assessed") == (uncertainty == "not_assessed"): raise ValueError("browser disposition/uncertainty mismatch")
        if (assigned[record["criterion_id"]]["scope_status"] == "blocked_by_ambiguity") != (disposition == "blocked_by_input_ambiguity"): raise ValueError("browser blocked disposition mismatch")
        criteria.append(record)
    if len(criteria) != len(assigned) or {item["criterion_id"] for item in criteria} != set(assigned): raise ValueError("browser result criterion coverage is incomplete")
    allowed_targets = work["permissions"]["browser"]["allowed_targets"]
    evidence_by_local = {}; evidence_bytes = {}; total = 0
    if evidence_root.is_symlink() or not evidence_root.is_dir(): raise ValueError("browser evidence directory is invalid")
    for item in payload["evidence"]:
        required = {"local_id", "observation_local_id", "path", "media_type", "byte_length", "sha256", "capture_timestamp"}
        if not isinstance(item, dict) or set(item) != required or item["media_type"] not in EVIDENCE_MEDIA_TYPES: raise ValueError("invalid browser evidence record")
        local = _text(item["local_id"], "browser evidence local_id", 120)
        if local in seen_local: raise ValueError("duplicate browser local ID")
        seen_local.add(local); relative = PurePosixPath(item["path"])
        if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts): raise ValueError("browser evidence path escapes evidence directory")
        path = evidence_root.joinpath(*relative.parts)
        if item["path"] in evidence_bytes or path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != evidence_root.parent) or not path.is_file() or path.resolve().parent != evidence_root.resolve() and evidence_root.resolve() not in path.resolve().parents: raise ValueError("browser evidence file is unavailable")
        data = path.read_bytes(); total += len(data)
        if not data or len(data) > EVIDENCE_FILE_LIMIT or total > EVIDENCE_TOTAL_LIMIT or type(item["byte_length"]) is not int or item["byte_length"] != len(data) or item["sha256"] != _sha(data): raise ValueError("browser evidence artifact binding mismatch")
        if item["media_type"].startswith("text/"):
            try: data.decode("utf-8")
            except UnicodeDecodeError as exc: raise ValueError("browser text evidence is invalid UTF-8") from exc
        try: captured = datetime.fromisoformat(item["capture_timestamp"].replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc: raise ValueError("invalid browser evidence timestamp") from exc
        if captured.tzinfo is None: raise ValueError("invalid browser evidence timestamp")
        evidence_by_local[local] = item; evidence_bytes[item["path"]] = data
    observations = []; observations_by_local = {}
    for item in payload["observations"]:
        required = {"local_id", "criterion_id", "url", "action", "observed_outcome", "redirect_chain", "capture_timestamp", "evidence_local_ids", "evidence_class"}
        if not isinstance(item, dict) or set(item) != required or item.get("criterion_id") not in assigned or item.get("evidence_class") != "browser_observed": raise ValueError("invalid browser observation")
        local = _text(item["local_id"], "browser observation local_id", 120)
        if local in seen_local: raise ValueError("duplicate browser local ID")
        seen_local.add(local); _text(item["action"], "browser action", DETAIL_LIMIT); _text(item["observed_outcome"], "browser outcome", DETAIL_LIMIT)
        if not _url_is_authorized(item["url"], allowed_targets) or not isinstance(item["redirect_chain"], list) or not item["redirect_chain"] or any(not isinstance(url, str) or not _url_is_authorized(url, allowed_targets) for url in item["redirect_chain"]): raise ValueError("browser observation target exceeds grant")
        try: captured = datetime.fromisoformat(item["capture_timestamp"].replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc: raise ValueError("invalid browser observation timestamp") from exc
        if captured.tzinfo is None: raise ValueError("invalid browser observation timestamp")
        evidence_ids = _string_list(item["evidence_local_ids"], "browser observation evidence IDs")
        if len(evidence_ids) != len(set(evidence_ids)) or any(key not in evidence_by_local or evidence_by_local[key]["observation_local_id"] != local or evidence_by_local[key]["capture_timestamp"] != item["capture_timestamp"] for key in evidence_ids): raise ValueError("browser observation evidence linkage is invalid")
        observations_by_local[local] = item; observations.append(item)
    if set(evidence_by_local) != {key for item in observations for key in item["evidence_local_ids"]}: raise ValueError("unreferenced browser evidence is forbidden")
    judgments = []
    for item in payload["judgments"]:
        required = {"local_id", "criterion_id", "observation_local_ids", "conclusion", "uncertainty", "evidence_class"}
        if not isinstance(item, dict) or set(item) != required or item.get("criterion_id") not in assigned or item.get("evidence_class") != "model_reviewed": raise ValueError("invalid browser judgment")
        local = _text(item["local_id"], "browser judgment local_id", 120)
        if local in seen_local: raise ValueError("duplicate browser local ID")
        seen_local.add(local); _text(item["conclusion"], "browser judgment conclusion", DETAIL_LIMIT); _enum(item["uncertainty"], {"none", "bounded", "material"}, "browser judgment uncertainty")
        refs = _string_list(item["observation_local_ids"], "browser judgment observation IDs")
        if not refs or len(refs) != len(set(refs)) or any(key not in observations_by_local or observations_by_local[key]["criterion_id"] != item["criterion_id"] for key in refs): raise ValueError("browser judgment observation linkage is invalid")
        judgments.append(item)
    assessed = {item["criterion_id"] for item in criteria if item["disposition"] == "assessed"}
    if any(item["criterion_id"] not in assessed for item in observations + judgments): raise ValueError("browser evidence requires assessed criterion")
    receipt = _validate_completion_receipt(_load_json_bytes(receipt_raw), work, raw)
    assumptions = sorted(_bounded_strings(value["assumptions"], "browser assumptions", ASSUMPTION_LIMIT)); limitations = sorted(_bounded_strings(value["limitations"], "browser limitations", LIMITATION_LIMIT))
    normalized_payload = {"criteria": sorted(criteria, key=lambda item: item["criterion_id"]), "observations": sorted(observations, key=canonical_json), "judgments": sorted(judgments, key=canonical_json), "evidence": sorted(payload["evidence"], key=lambda item: item["path"])}
    def substantive(item):
        if isinstance(item, dict): return {key: substantive(value) for key, value in item.items() if key != "local_id"}
        if isinstance(item, list): return [substantive(value) for value in item]
        return item
    semantic = {"role_id": "browser_journey", "role_version": work["role_version"], "base_graph_semantic_hash": work["inputs"]["base_graph_semantic_hash"], "payload": substantive(normalized_payload), "assumptions": assumptions, "limitations": limitations}
    hashes = {"result_semantic_hash": content_hash(semantic), "result_snapshot_hash": _sha(raw), "completion_receipt_snapshot_hash": _sha(receipt_raw)}
    return {"submitted": value, "receipt": receipt, "artifact": normalized_payload, "hashes": hashes, "result_bytes": raw, "receipt_bytes": receipt_raw, "evidence_bytes": evidence_bytes}


def _compile_browser_result(preparation: dict, snapshot_root: Path | None = None) -> dict | None:
    entry = next(item for item in preparation["manifest"]["work_orders"] if item["role_id"] == "browser_journey")
    if not entry["issued"]: return None
    work = preparation["work_orders"]["browser_journey"]
    inbox = (snapshot_root / "browser_journey") if snapshot_root else (_root_from_preparation(preparation) / "inbox" / work["preparation_id"] / work["work_order_id"])
    result_path, receipt_path, evidence_root = inbox / "result.json", inbox / "completion-receipt.json", inbox / "evidence"
    present = [path.is_file() and not path.is_symlink() for path in (result_path, receipt_path)]
    if not any(present): return None
    if not all(present): raise ValueError("incomplete browser result submission")
    role = _role_snapshot((preparation["directory"] / "role-definitions/browser_journey.json").read_bytes(), "browser_journey")["value"]
    return _validate_browser_result(result_path.read_bytes(), receipt_path.read_bytes(), evidence_root, preparation, role)


def _root_from_preparation(preparation: dict) -> Path:
    directory = preparation["directory"]
    return directory.parents[1] if directory.name.startswith("prep_") else directory.parents[1]


def _validate_targeted_gap_links(artifacts: dict) -> None:
    gaps_by_key = {gap["gap_key"]: gap for role in ("product_assessment", "engineering_assessment", "test_adequacy") for gap in artifacts[role]["payload"]["gaps"]}
    for spec in artifacts["targeted_test_planning"]["payload"]["specifications"]:
        has_basis = any(spec[field] for field in ("basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"))
        matched = gaps_by_key.get(spec["addresses_gap_key"])
        if matched is not None and matched["criterion_id"] != spec["criterion_id"]: raise ValueError("targeted test specification addresses a different criterion")
        if matched is None and not has_basis: raise ValueError("targeted test specification requires matched gap or prepared basis")


def _compile_core_results(ctx: LocalExecutionContext, preparation: dict, snapshot_root: Path | None = None) -> dict:
    roles = {}
    role_root = preparation["directory"] / "role-definitions"
    for role in CORE_ROLES: roles[role] = _role_snapshot((role_root / f"{role}.json").read_bytes(), role)["value"]
    raw_results = {}; receipts = {}; artifacts = {}; snapshot_hashes = {}; raw_bytes = {}; receipt_bytes = {}
    for role in CORE_ROLES:
        work = preparation["work_orders"][role]
        inbox = (snapshot_root / role) if snapshot_root else (_root(ctx) / "inbox" / preparation["manifest"]["preparation_id"] / work["work_order_id"])
        result_path, receipt_path = inbox / "result.json", inbox / "completion-receipt.json"
        if any(path.is_symlink() or not path.is_file() for path in (result_path, receipt_path)): raise ValueError(f"missing required assessment result: {role}")
        evidence = inbox / "evidence"
        if evidence.is_symlink() or (evidence.exists() and any(evidence.iterdir())): raise ValueError("core assessment roles cannot submit canonical evidence files")
        raw, receipt_raw = result_path.read_bytes(), receipt_path.read_bytes(); submitted, receipt, normalized = _validate_role_result(raw, receipt_raw, role, preparation, roles[role])
        def substantive(value):
            if isinstance(value, dict): return {key: substantive(item) for key, item in value.items() if key != "local_id"}
            if isinstance(value, list): return [substantive(item) for item in value]
            return value
        semantic_result = {"role_id": role, "role_version": normalized["role_version"], "base_graph_semantic_hash": normalized["base_graph_semantic_hash"], "payload": substantive(normalized["payload"]), "assumptions": normalized["assumptions"], "limitations": normalized["limitations"]}
        raw_results[role] = submitted; receipts[role] = receipt; artifacts[role] = normalized; raw_bytes[role] = raw; receipt_bytes[role] = receipt_raw; snapshot_hashes[role] = {"result_semantic_hash": content_hash(semantic_result), "result_snapshot_hash": _sha(raw), "completion_receipt_snapshot_hash": _sha(receipt_raw)}
    _validate_targeted_gap_links(artifacts)
    browser = _compile_browser_result(preparation, snapshot_root)
    if browser is not None: snapshot_hashes["browser_journey"] = browser["hashes"]
    return {"preparation": preparation, "artifacts": artifacts, "submitted_results": raw_results, "completion_receipts": receipts, "submitted_result_bytes": raw_bytes, "completion_receipt_bytes": receipt_bytes, "snapshot_hashes": snapshot_hashes, "browser": browser}


def compile_core_results(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    return _compile_core_results(ctx, load_preparation(ctx, preparation_id))


def _assessment_id(prefix: str, value: object) -> str:
    return prefix + "_" + content_hash(value).split(":", 1)[1][:24]


def _base_index(preparation: dict) -> tuple[dict, set[str], dict]:
    nodes = {}; gaps = {}; criterion_ids = set()
    for context in preparation["contexts"].values():
        criterion_ids.update(item["criterion_id"] for item in context["assigned_criteria"])
        nodes.update({item["node_id"]: item for item in context["base_graph_context"]["nodes"]})
        gaps.update({item["gap_id"]: item for item in context["base_graph_context"]["gaps"]})
    return nodes, criterion_ids, gaps


def _browser_placeholder(preparation: dict) -> dict:
    browser = preparation["source_packet"]["browser_work_order"]
    entry = next(item for item in preparation["manifest"]["work_orders"] if item["role_id"] == "browser_journey")
    targets = {item["criterion_id"]: item["targets"] for item in browser["criterion_targets"]}
    assigned = set(browser["assigned_criterion_ids"]); limited = set(browser["scope_limited_criterion_ids"])
    criteria = []
    for criterion in preparation["source_packet"]["population"]["criteria"]:
        criterion_id = criterion["criterion_id"]
        if "browser_or_http" not in criterion["required_evidence_categories"]:
            status, reason = "not_issued", "not_browser_relevant"
        elif criterion_id in limited:
            status, reason = "not_issued", "browser_scope_insufficient"
        elif browser["issued"] and criterion_id in assigned:
            status, reason = "not_inspected", None
        elif criterion_id in assigned:
            status, reason = "not_issued", browser["reason_code"]
        else:
            status, reason = "not_issued", "no_authorized_browser_target"
        criteria.append({"criterion_id": criterion_id, "status": status, "reason_code": reason, "authorized_targets": targets.get(criterion_id, [])})
    return {"schema_version": "browser-journey.v2", "work_order_id": entry["work_order_id"], "criteria": criteria, "observations": [], "judgments": []}


def _browser_artifact(core: dict) -> dict:
    placeholder = _browser_placeholder(core["preparation"]); compiled = core.get("browser")
    if compiled is None: return placeholder
    payload = compiled["artifact"]; evidence = {item["local_id"]: item for item in payload["evidence"]}; observation_ids = {}
    observations = []
    for item in payload["observations"]:
        observation_id = _assessment_id("browser_observation", {"work_order_id": core["preparation"]["work_orders"]["browser_journey"]["work_order_id"], **{key:value for key,value in item.items() if key != "local_id"}})
        observation_ids[item["local_id"]] = observation_id
        observations.append({"observation_id": observation_id, "criterion_id": item["criterion_id"], "url": item["url"], "action": item["action"], "observed_outcome": item["observed_outcome"], "redirect_chain": item["redirect_chain"], "capture_timestamp": item["capture_timestamp"], "evidence_class": "browser_observed", "evidence": [{key: evidence[local][key] for key in ("path", "media_type", "byte_length", "sha256", "capture_timestamp")} for local in item["evidence_local_ids"]]})
    judgments = []
    for item in payload["judgments"]:
        value = {"criterion_id": item["criterion_id"], "observation_ids": sorted(observation_ids[local] for local in item["observation_local_ids"]), "conclusion": item["conclusion"], "uncertainty": item["uncertainty"], "evidence_class": "model_reviewed"}
        judgments.append({"judgment_id": _assessment_id("browser_judgment", value), **value})
    observed = {item["criterion_id"] for item in observations}
    criteria = [{**item, "status": "observed" if item["criterion_id"] in observed else item["status"], "reason_code": None if item["criterion_id"] in observed else item["reason_code"]} for item in placeholder["criteria"]]
    return {**placeholder, "criteria": criteria, "observations": sorted(observations, key=lambda item: item["observation_id"]), "judgments": sorted(judgments, key=lambda item: item["judgment_id"])}


def _build_overlay(core: dict) -> tuple[dict, dict]:
    preparation = core["preparation"]; nodes, criterion_ids, base_gaps = _base_index(preparation)
    overlay_nodes: list[dict] = []; edges: list[dict] = []; gap_nodes: dict[str, str] = {}
    record_ids: set[str] = set(); criterion_conclusions = {}; pending_gap_edges = []
    def add_edge(relationship: str, source: str, target: str, evidence_class: str) -> None:
        edge = {"edge_id": _assessment_id("assessment_edge", {"relationship": relationship, "source": source, "target": target}), "relationship": relationship, "source_node_id": source, "target_node_id": target, "assessment_evidence_class": evidence_class}
        if edge["edge_id"] not in {item["edge_id"] for item in edges}: edges.append(edge)
    for role in CORE_ROLES:
        artifact = core["artifacts"][role]; work_order_id = artifact["work_order_id"]; payload = artifact["payload"]
        collections = (("requirements", "requirement_id", "assesses_requirement"), ("journeys", "journey_id", "concerns_journey"), ("criteria", "criterion_id", "assesses_criterion"))
        for collection, identifier, relationship in collections:
            for record in payload.get(collection, []):
                substantive = {key: value for key, value in record.items() if key not in {"local_id", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}}
                node_id = _assessment_id("assessment_conclusion", {"role_id": role, "assessed_id": record[identifier], "kind": collection, "substantive": substantive, "work_order_id": work_order_id})
                if node_id in record_ids: raise ValueError("duplicate semantic assessment conclusion")
                hashes = core["snapshot_hashes"][role]
                record_ids.add(node_id); overlay_nodes.append({"node_id": node_id, "node_type": "assessment_conclusion", "role_id": role, "assessed_record_id": record[identifier], "conclusion_kind": collection, "evidence_class": record["evidence_class"], "uncertainty": record["uncertainty"], "substantive_conclusion": substantive, "basis_node_ids": record["basis_node_ids"], "basis_edge_ids": record["basis_edge_ids"], "basis_gap_ids": record["basis_gap_ids"], "basis_source_refs": record["basis_source_refs"], "work_order_id": work_order_id, **hashes, "executor_provenance": artifact["executor_provenance"]})
                if identifier == "criterion_id": criterion_conclusions[(role, record[identifier])] = node_id
                add_edge(relationship, node_id, record[identifier], record["evidence_class"])
                for basis in record["basis_node_ids"]:
                    if nodes[basis]["node_type"] in OVERLAY_BASE_NODE_TYPES: add_edge("supported_by_base_node", node_id, basis, record["evidence_class"])
        for gap in payload.get("gaps", []):
            node_id = _assessment_id("assessment_gap", gap["gap_key"]); gap_nodes[gap["gap_key"]] = node_id
            hashes = core["snapshot_hashes"][role]
            overlay_nodes.append({"node_id": node_id, "node_type": "assessment_gap", "role_id": role, "criterion_id": gap["criterion_id"], "gap_key": gap["gap_key"], "gap_kind": gap["gap_kind"], "aspect_code": gap["aspect_code"], "actionability": gap["actionability"], "recommended_release_effect": gap["recommended_release_effect"], "evidence_class": "model_reviewed", "uncertainty": gap["uncertainty"], "summary": gap["summary"], "basis_node_ids": gap["basis_node_ids"], "basis_edge_ids": gap["basis_edge_ids"], "basis_gap_ids": gap["basis_gap_ids"], "basis_source_refs": gap["basis_source_refs"], "work_order_id": work_order_id, **hashes, "executor_provenance": artifact["executor_provenance"]}); pending_gap_edges.append((role, gap["criterion_id"], node_id))
            add_edge("concerns_criterion", node_id, gap["criterion_id"], "model_reviewed")
            for basis in gap["basis_node_ids"]:
                if nodes[basis]["node_type"] in OVERLAY_BASE_NODE_TYPES: add_edge("supported_by_base_node", node_id, basis, "model_reviewed")
    targeted = core["artifacts"]["targeted_test_planning"]
    for spec in targeted["payload"]["specifications"]:
        node_id = _assessment_id("targeted_test_specification", {key: value for key, value in spec.items() if key not in {"local_id", "basis_node_ids", "basis_edge_ids", "basis_gap_ids", "basis_source_refs"}})
        overlay_nodes.append({"node_id": node_id, "node_type": "targeted_test_specification", "criterion_id": spec["criterion_id"], "specification": spec, "evidence_class": "model_reviewed", "uncertainty": spec["uncertainty"], "basis_node_ids": spec["basis_node_ids"], "basis_edge_ids": spec["basis_edge_ids"], "basis_gap_ids": spec["basis_gap_ids"], "basis_source_refs": spec["basis_source_refs"], "work_order_id": targeted["work_order_id"], **core["snapshot_hashes"]["targeted_test_planning"], "executor_provenance": targeted["executor_provenance"]})
        add_edge("proposes_test_for", node_id, spec["criterion_id"], "model_reviewed")
        if spec["addresses_gap_key"] in gap_nodes:
            gap_node = next(item for item in overlay_nodes if item["node_id"] == gap_nodes[spec["addresses_gap_key"]])
            if gap_node["criterion_id"] != spec["criterion_id"]: raise ValueError("targeted test overlay gap criterion mismatch")
            add_edge("addresses_assessment_gap", node_id, gap_node["node_id"], "model_reviewed")
    for role, criterion_id, gap_id in pending_gap_edges:
        conclusion = criterion_conclusions.get((role, criterion_id))
        if conclusion is None: raise ValueError("assessment gap lacks same-role criterion conclusion")
        add_edge("identifies_assessment_gap", conclusion, gap_id, "model_reviewed")
    browser_artifact = _browser_artifact(core)
    if core.get("browser") is not None:
        browser_hashes = core["browser"]["hashes"]; work_order_id = core["preparation"]["work_orders"]["browser_journey"]["work_order_id"]; executor = core["browser"]["receipt"]["executor"]
        for observation in browser_artifact["observations"]:
            node_id = observation["observation_id"]
            overlay_nodes.append({"node_id": node_id, "node_type": "browser_observation", "criterion_id": observation["criterion_id"], "evidence_class": "browser_observed", "observation": observation, "work_order_id": work_order_id, **browser_hashes, "executor_provenance": executor})
            add_edge("concerns_criterion", node_id, observation["criterion_id"], "browser_observed")
        for judgment in browser_artifact["judgments"]:
            node_id = judgment["judgment_id"]
            overlay_nodes.append({"node_id": node_id, "node_type": "assessment_conclusion", "role_id": "browser_journey", "assessed_record_id": judgment["criterion_id"], "conclusion_kind": "browser_judgment", "evidence_class": "model_reviewed", "uncertainty": judgment["uncertainty"], "substantive_conclusion": judgment, "basis_node_ids": [], "basis_edge_ids": [], "basis_gap_ids": [], "basis_source_refs": [], "work_order_id": work_order_id, **browser_hashes, "executor_provenance": executor})
            add_edge("assesses_criterion", node_id, judgment["criterion_id"], "model_reviewed")
            for observation_id in judgment["observation_ids"]: add_edge("supported_by_browser_observation", node_id, observation_id, "model_reviewed")
    overlay = {"schema_version": OVERLAY_SCHEMA, "release_id": preparation["manifest"]["release_id"], "release_commit": preparation["manifest"]["release_commit"], "preparation_id": preparation["manifest"]["preparation_id"], "base_graph_generation": preparation["manifest"]["graph_generation"], "base_graph_semantic_hash": preparation["manifest"]["graph_semantic_hash"], "nodes": sorted(overlay_nodes, key=lambda item: item["node_id"]), "edges": sorted(edges, key=lambda item: item["edge_id"])}
    by_criterion = {}; browser_by_criterion = {item["criterion_id"]: item for item in browser_artifact["criteria"]}; observations_by_criterion = {}; judgments_by_criterion = {}
    for item in browser_artifact["observations"]: observations_by_criterion.setdefault(item["criterion_id"], []).append(item["observation_id"])
    for item in browser_artifact["judgments"]: judgments_by_criterion.setdefault(item["criterion_id"], []).append(item["judgment_id"])
    for criterion_id in sorted(criterion_ids):
        gap_state = {gap["gap_type"]: gap["state"] for gap in base_gaps.values() if gap["criterion_id"] == criterion_id}
        assessment = {}; authority = {}
        for node in overlay_nodes:
            if node["node_type"] == "assessment_conclusion" and node["assessed_record_id"] == criterion_id:
                assessment[node["role_id"]] = node["substantive_conclusion"]; authority[node["role_id"]] = node["evidence_class"]
        browser = browser_by_criterion[criterion_id]
        assessment["browser_journey"] = {"status": browser["status"], "reason_code": browser["reason_code"], "authorized_targets": browser["authorized_targets"], "observation_ids": sorted(observations_by_criterion.get(criterion_id, [])), "judgment_ids": sorted(judgments_by_criterion.get(criterion_id, []))}; authority["browser_journey"] = "browser_observed" if observations_by_criterion.get(criterion_id) else "not_inspected"
        by_criterion[criterion_id] = {"criterion_id": criterion_id, "base_evidence_state": {"implementation": gap_state.get("implementation_gap", "unknown"), "test": gap_state.get("test_evidence_gap", "unknown"), "instrumentation": gap_state.get("instrumentation_gap", "unknown"), "runtime": gap_state.get("runtime_evidence_gap", "unknown")}, "assessment": assessment, "assessment_authority": authority, "assessment_gap_ids": sorted(node["node_id"] for node in overlay_nodes if node["node_type"] == "assessment_gap" and node["criterion_id"] == criterion_id), "targeted_test_specification_ids": sorted(node["node_id"] for node in overlay_nodes if node["node_type"] == "targeted_test_specification" and node["criterion_id"] == criterion_id)}
    effective = {"schema_version": EFFECTIVE_VIEW_SCHEMA, "release_id": preparation["manifest"]["release_id"], "base_graph_generation": preparation["manifest"]["graph_generation"], "authority": {"base_graph": "authoritative_evidence_graph", "assessment_overlay": "authoritative_assessment_record", "effective_view": "derived_only"}, "criteria": [by_criterion[key] for key in sorted(by_criterion)]}
    return overlay, effective


def _build_assessment_artifacts(core: dict) -> dict:
    overlay, effective = _build_overlay(core); prep = core["preparation"]; browser = _browser_artifact(core)
    accepted_roles = list(CORE_ROLES) + (["browser_journey"] if core.get("browser") is not None else [])
    receipts = {"schema_version": "assessment-compiler-receipts.v2", "preparation_id": prep["manifest"]["preparation_id"], "validations": [{"role_id": role, "work_order_id": prep["work_orders"][role]["work_order_id"], **core["snapshot_hashes"][role], "status": "accepted"} for role in accepted_roles]}
    return {"product-assessment.json": core["artifacts"]["product_assessment"], "engineering-assessment.json": core["artifacts"]["engineering_assessment"], "test-adequacy.json": core["artifacts"]["test_adequacy"], "targeted-test-plan.json": core["artifacts"]["targeted_test_planning"], "browser-journey.json": browser, "assessment-work-orders.json": prep["manifest"], "assessment-graph-overlay.json": overlay, "effective-assessment-view.json": effective, "assessment-compiler-receipts.json": receipts}


def _validate_assessment_artifacts(core: dict, artifacts: dict) -> None:
    if set(artifacts) != set(ASSESSMENT_ARTIFACTS): raise ValueError("assessment artifact set is invalid")
    overlay = artifacts["assessment-graph-overlay.json"]; expected_top = {"schema_version","release_id","release_commit","preparation_id","base_graph_generation","base_graph_semantic_hash","nodes","edges"}
    if not isinstance(overlay, dict) or set(overlay) != expected_top or overlay.get("schema_version") != OVERLAY_SCHEMA: raise ValueError("assessment overlay schema is invalid")
    variant_fields = {
        "assessment_conclusion": {"node_id","node_type","role_id","assessed_record_id","conclusion_kind","evidence_class","uncertainty","substantive_conclusion","basis_node_ids","basis_edge_ids","basis_gap_ids","basis_source_refs","work_order_id","result_semantic_hash","result_snapshot_hash","completion_receipt_snapshot_hash","executor_provenance"},
        "assessment_gap": {"node_id","node_type","role_id","criterion_id","gap_key","gap_kind","aspect_code","actionability","recommended_release_effect","evidence_class","uncertainty","summary","basis_node_ids","basis_edge_ids","basis_gap_ids","basis_source_refs","work_order_id","result_semantic_hash","result_snapshot_hash","completion_receipt_snapshot_hash","executor_provenance"},
        "targeted_test_specification": {"node_id","node_type","criterion_id","specification","evidence_class","uncertainty","basis_node_ids","basis_edge_ids","basis_gap_ids","basis_source_refs","work_order_id","result_semantic_hash","result_snapshot_hash","completion_receipt_snapshot_hash","executor_provenance"},
        "browser_observation": {"node_id","node_type","criterion_id","evidence_class","observation","work_order_id","result_semantic_hash","result_snapshot_hash","completion_receipt_snapshot_hash","executor_provenance"},
    }
    overlay_nodes = {}
    for node in overlay["nodes"]:
        if not isinstance(node, dict) or node.get("node_type") not in variant_fields or set(node) != variant_fields[node["node_type"]] or node.get("evidence_class") not in {"model_reviewed","browser_observed","not_inspected"} or node["node_id"] in overlay_nodes: raise ValueError("assessment overlay node schema is invalid")
        overlay_nodes[node["node_id"]] = node
    base_nodes, _, _ = _base_index(core["preparation"]); relationship_targets = {"assesses_requirement":{"requirement"},"assesses_criterion":{"acceptance_criterion"},"concerns_criterion":{"acceptance_criterion"},"concerns_journey":{"critical_journey"},"supported_by_base_node":OVERLAY_BASE_NODE_TYPES,"identifies_assessment_gap":{"assessment_gap"},"proposes_test_for":{"acceptance_criterion"},"addresses_assessment_gap":{"assessment_gap"},"supported_by_browser_observation":{"browser_observation"}}; relationship_sources = {"assesses_requirement":{"assessment_conclusion"},"assesses_criterion":{"assessment_conclusion"},"concerns_criterion":{"assessment_gap","browser_observation"},"concerns_journey":{"assessment_conclusion","assessment_gap","browser_observation"},"supported_by_base_node":{"assessment_conclusion","assessment_gap"},"identifies_assessment_gap":{"assessment_conclusion"},"proposes_test_for":{"targeted_test_specification"},"addresses_assessment_gap":{"targeted_test_specification"},"supported_by_browser_observation":{"assessment_conclusion"}}
    seen_edges = set()
    for edge in overlay["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"edge_id","relationship","source_node_id","target_node_id","assessment_evidence_class"} or edge["edge_id"] in seen_edges or edge["source_node_id"] not in overlay_nodes or edge["assessment_evidence_class"] not in {"model_reviewed","browser_observed","not_inspected"} or edge["relationship"] not in relationship_targets or overlay_nodes[edge["source_node_id"]]["node_type"] not in relationship_sources[edge["relationship"]] or edge["assessment_evidence_class"] != overlay_nodes[edge["source_node_id"]]["evidence_class"]: raise ValueError("assessment overlay edge schema is invalid")
        seen_edges.add(edge["edge_id"]); target = overlay_nodes.get(edge["target_node_id"]) or base_nodes.get(edge["target_node_id"])
        if target is None or target["node_type"] not in relationship_targets[edge["relationship"]]: raise ValueError("assessment overlay relationship target is invalid")
        if edge["relationship"] == "identifies_assessment_gap" and (overlay_nodes[edge["source_node_id"]]["role_id"] != target["role_id"] or overlay_nodes[edge["source_node_id"]]["assessed_record_id"] != target["criterion_id"]): raise ValueError("assessment gap relationship role mismatch")
        if edge["relationship"] == "addresses_assessment_gap" and overlay_nodes[edge["source_node_id"]]["criterion_id"] != target["criterion_id"]: raise ValueError("targeted test relationship criterion mismatch")
    effective = artifacts["effective-assessment-view.json"]
    if not isinstance(effective, dict) or set(effective) != {"schema_version","release_id","base_graph_generation","authority","criteria"} or effective.get("schema_version") != EFFECTIVE_VIEW_SCHEMA or effective.get("authority") != {"base_graph":"authoritative_evidence_graph","assessment_overlay":"authoritative_assessment_record","effective_view":"derived_only"}: raise ValueError("effective assessment view schema is invalid")
    for criterion in effective["criteria"]:
        if not isinstance(criterion, dict) or set(criterion) != {"criterion_id","base_evidence_state","assessment","assessment_authority","assessment_gap_ids","targeted_test_specification_ids"} or set(criterion["base_evidence_state"]) != {"implementation","test","instrumentation","runtime"} or set(criterion["assessment"]) != set(ALL_ROLES) or set(criterion["assessment_authority"]) != set(ALL_ROLES) or not set(criterion["base_evidence_state"].values()).issubset({"open","closed","unknown"}) or not set(criterion["assessment_authority"].values()).issubset({"model_reviewed","browser_observed","not_inspected"}): raise ValueError("effective assessment criterion schema is invalid")
    expected = _build_assessment_artifacts(core)
    if artifacts != expected: raise ValueError("assessment semantic artifacts are stale")


def compile_assessment(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    core = compile_core_results(ctx, preparation_id); artifacts = _build_assessment_artifacts(core); _validate_assessment_artifacts(core, artifacts)
    root = _root(ctx); directory = root / "generations" / ("gen_" + uuid.uuid4().hex); directory.mkdir(parents=True)
    hashes = {}
    for name in ASSESSMENT_ARTIFACTS:
        _atomic(directory / name, artifacts[name]); hashes[name] = _sha((directory / name).read_bytes())
    snapshots = directory / "result-snapshots"
    for role in CORE_ROLES:
        target = snapshots / role; target.mkdir(parents=True)
        (target / "result.json").write_bytes(core["submitted_result_bytes"][role]); (target / "completion-receipt.json").write_bytes(core["completion_receipt_bytes"][role])
    browser_evidence_hashes = {}
    if core.get("browser") is not None:
        target = snapshots / "browser_journey"; (target / "evidence").mkdir(parents=True)
        (target / "result.json").write_bytes(core["browser"]["result_bytes"]); (target / "completion-receipt.json").write_bytes(core["browser"]["receipt_bytes"])
        for relative, raw in core["browser"]["evidence_bytes"].items():
            evidence_path = target / "evidence" / Path(relative); evidence_path.parent.mkdir(parents=True, exist_ok=True); evidence_path.write_bytes(raw); browser_evidence_hashes[relative] = _sha(raw)
    preparation_hashes = {}; preparation_snapshot = directory / "preparation-snapshot"
    for source in sorted((path for path in core["preparation"]["directory"].rglob("*") if path.is_file()), key=lambda path: path.as_posix()):
        if source.is_symlink(): raise ValueError("assessment preparation snapshot cannot contain symlinks")
        relative = source.relative_to(core["preparation"]["directory"]).as_posix(); target = preparation_snapshot / Path(relative); target.parent.mkdir(parents=True, exist_ok=True); raw = source.read_bytes(); target.write_bytes(raw); preparation_hashes[relative] = _sha(raw)
    manifest = {"schema_version": ASSESSMENT_MANIFEST_SCHEMA, "compiler_version": ASSESSMENT_COMPILER_VERSION, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": core["preparation"]["source_packet"]["project_authority"], "preparation_id": core["preparation"]["manifest"]["preparation_id"], "preparation_semantic_hash": core["preparation"]["manifest"]["preparation_semantic_hash"], "base_graph_generation": core["preparation"]["manifest"]["graph_generation"], "base_graph_semantic_hash": core["preparation"]["manifest"]["graph_semantic_hash"], "artifact_filenames": list(ASSESSMENT_ARTIFACTS), "artifact_hashes": hashes, "preparation_snapshot_hashes": preparation_hashes, "result_snapshot_hashes": core["snapshot_hashes"], "browser_evidence_snapshot_hashes": browser_evidence_hashes}
    manifest["semantic_bundle_hash"] = content_hash({"compiler_version": ASSESSMENT_COMPILER_VERSION, "preparation_semantic_hash": manifest["preparation_semantic_hash"], "base_graph_semantic_hash": manifest["base_graph_semantic_hash"], "artifact_hashes": {key: hashes[key] for key in sorted(hashes)}}); manifest["bundle_hash"] = content_hash(manifest); _atomic(directory / "manifest.json", manifest)
    if _BEFORE_ASSESSMENT_GENERATION_VERIFY: _BEFORE_ASSESSMENT_GENERATION_VERIFY(directory)
    loaded, _ = load_assessment(ctx, _directory=directory)
    if loaded != manifest: raise ValueError("new assessment generation verification mismatch")
    if _BEFORE_ASSESSMENT_POINTER_REPLACE: _BEFORE_ASSESSMENT_POINTER_REPLACE(directory)
    _atomic(root / "current-assessment.json", {"schema_version": ASSESSMENT_POINTER_SCHEMA, "generation": directory.name, "manifest_hash": _sha((directory / "manifest.json").read_bytes())})
    return manifest


def load_assessment(ctx: LocalExecutionContext, *, _directory: Path | None = None) -> tuple[dict, dict]:
    root = _root(ctx); pointer_path = root / "current-assessment.json"
    if _directory is None:
        if pointer_path.is_symlink() or not pointer_path.is_file(): raise ValueError("complete assessment generation is unavailable")
        pointer = _load_json_bytes(pointer_path.read_bytes())
        if set(pointer) != {"schema_version", "generation", "manifest_hash"} or pointer["schema_version"] != ASSESSMENT_POINTER_SCHEMA or not re.fullmatch(r"gen_[0-9a-f]{32}", str(pointer["generation"])): raise ValueError("invalid assessment pointer")
        raw_directory = root / "generations" / pointer["generation"]
    else:
        pointer = None; raw_directory = _directory
    if raw_directory.is_symlink() or not raw_directory.is_dir() or raw_directory.resolve().parent != (root / "generations").resolve(): raise ValueError("invalid assessment generation")
    directory = raw_directory.resolve(); manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or (pointer is not None and _sha(manifest_path.read_bytes()) != pointer["manifest_hash"]): raise ValueError("invalid assessment manifest binding")
    manifest = _load_json_bytes(manifest_path.read_bytes()); required = {"schema_version","compiler_version","release_id","release_commit","project_authority","preparation_id","preparation_semantic_hash","base_graph_generation","base_graph_semantic_hash","artifact_filenames","artifact_hashes","preparation_snapshot_hashes","result_snapshot_hashes","browser_evidence_snapshot_hashes","semantic_bundle_hash","bundle_hash"}
    if set(manifest) != required or manifest["schema_version"] != ASSESSMENT_MANIFEST_SCHEMA or manifest["compiler_version"] != ASSESSMENT_COMPILER_VERSION or manifest["bundle_hash"] != content_hash({key: value for key, value in manifest.items() if key != "bundle_hash"}): raise ValueError("assessment manifest invalid or stale")
    snapshot_root = directory / "preparation-snapshot"
    preparation = load_preparation(ctx, manifest["preparation_id"], _directory=snapshot_root)
    if manifest["release_id"] != ctx.release["release_id"] or manifest["release_commit"] != ctx.authority_binding["repository_commit"] or manifest["project_authority"] != preparation["source_packet"]["project_authority"] or manifest["preparation_semantic_hash"] != preparation["manifest"]["preparation_semantic_hash"] or manifest["base_graph_generation"] != preparation["manifest"]["graph_generation"] or manifest["base_graph_semantic_hash"] != preparation["manifest"]["graph_semantic_hash"]: raise ValueError("assessment authority is stale")
    stored_preparation_files = {path.relative_to(snapshot_root).as_posix(): path for path in snapshot_root.rglob("*") if path.is_file()} if snapshot_root.is_dir() and not snapshot_root.is_symlink() else {}
    if set(manifest["preparation_snapshot_hashes"]) != set(stored_preparation_files): raise ValueError("assessment preparation snapshot set is invalid")
    for relative, stored in stored_preparation_files.items():
        if stored.is_symlink() or _sha(stored.read_bytes()) != manifest["preparation_snapshot_hashes"][relative]: raise ValueError("assessment preparation snapshot is stale")
    core = _compile_core_results(ctx, preparation, directory / "result-snapshots")
    if core["snapshot_hashes"] != manifest["result_snapshot_hashes"]: raise ValueError("assessment result snapshots are stale")
    stored_evidence = {}
    evidence_root = directory / "result-snapshots/browser_journey/evidence"
    if evidence_root.exists():
        if evidence_root.is_symlink() or not evidence_root.is_dir(): raise ValueError("assessment browser evidence snapshot is invalid")
        for path in evidence_root.rglob("*"):
            if path.is_file(): stored_evidence[path.relative_to(evidence_root).as_posix()] = _sha(path.read_bytes())
    if stored_evidence != manifest["browser_evidence_snapshot_hashes"]: raise ValueError("assessment browser evidence snapshots are stale")
    artifacts = {}
    if manifest["artifact_filenames"] != list(ASSESSMENT_ARTIFACTS) or set(manifest["artifact_hashes"]) != set(ASSESSMENT_ARTIFACTS): raise ValueError("assessment artifact manifest is invalid")
    for name in ASSESSMENT_ARTIFACTS:
        path = directory / name
        if path.is_symlink() or not path.is_file() or _sha(path.read_bytes()) != manifest["artifact_hashes"][name]: raise ValueError("assessment artifact is invalid")
        artifacts[name] = _load_json_bytes(path.read_bytes())
    semantic = content_hash({"compiler_version": ASSESSMENT_COMPILER_VERSION, "preparation_semantic_hash": manifest["preparation_semantic_hash"], "base_graph_semantic_hash": manifest["base_graph_semantic_hash"], "artifact_hashes": {key: manifest["artifact_hashes"][key] for key in sorted(ASSESSMENT_ARTIFACTS)}})
    if semantic != manifest["semantic_bundle_hash"]: raise ValueError("assessment semantic bundle is stale")
    _validate_assessment_artifacts(core, artifacts); return manifest, artifacts


def show_assessment(ctx: LocalExecutionContext, criterion_id: str | None = None) -> str:
    manifest, artifacts = load_assessment(ctx); view = artifacts["effective-assessment-view.json"]; criteria = [item for item in view["criteria"] if criterion_id is None or item["criterion_id"] == criterion_id]
    if criterion_id and not criteria: raise ValueError("assessment criterion unavailable")
    lines = [f"Assessment generation: {manifest['preparation_id']}", "Authority: base graph authoritative; assessment canonical; effective view derived only"]
    for item in criteria:
        browser = item["assessment"]["browser_journey"]
        lines.append(f"Criterion: {item['criterion_id']}"); lines.append("Base evidence: " + ", ".join(f"{key}={value}" for key, value in item["base_evidence_state"].items())); lines.append("Assessment roles: " + (", ".join(sorted(item["assessment"])) or "none")); lines.append(f"Browser: {browser['status']} authority={item['assessment_authority']['browser_journey']} observations={','.join(browser['observation_ids']) or 'none'} judgments={','.join(browser['judgment_ids']) or 'none'}"); lines.append("Assessment gaps: " + (", ".join(item["assessment_gap_ids"]) or "none")); lines.append("Targeted tests: " + (", ".join(item["targeted_test_specification_ids"]) or "none"))
    return "\n".join(lines)
