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
from importlib import resources
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlparse

from .authority import LocalExecutionContext
from .graph import load_assessment_input
from .project import canonical_json, content_hash, validate_policy_relative


ROLE_SCHEMA = "shiproom.assessment-role.v1"
WORK_ORDER_SCHEMA = "shiproom.work-order.v1"
CAPABILITIES_SCHEMA = "shiproom.assessment-capabilities.v1"
SOURCE_PACKET_SCHEMA = "assessment-source-packet.v1"
ROLE_CONTEXT_SCHEMA = "assessment-role-context.v1"
WORK_ORDERS_SCHEMA = "assessment-work-orders.v1"
POINTER_SCHEMA = "active-assessment-preparation.v1"
PREPARATION_COMPILER_VERSION = "assessment-preparation.v1"
DISCOVERY_VERSION = "assessment-source-discovery.v1"

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


def load_discovery_registry() -> dict:
    raw = resources.files("shiproom.assessment_roles").joinpath("source-discovery.v1.json").read_bytes()
    value = _load_json_bytes(raw)
    fields = {"schema_version", "selection_order", "supported_languages", "rule_ids", "configuration_allowlist", "javascript_extensions", "limits", "unsupported"}
    if set(value) != fields or value.get("schema_version") != DISCOVERY_VERSION:
        raise ValueError("invalid assessment source-discovery registry")
    for field in ("selection_order", "supported_languages", "rule_ids", "configuration_allowlist", "javascript_extensions", "unsupported"):
        _string_list(value[field], f"discovery.{field}", nonempty=True)
    limits = value["limits"]
    if not isinstance(limits, dict) or set(limits) != {"per_file_bytes", "files_per_role", "source_text_bytes_per_role"} or limits != {"per_file_bytes": SOURCE_FILE_LIMIT, "files_per_role": ROLE_FILE_LIMIT, "source_text_bytes_per_role": ROLE_TEXT_LIMIT}:
        raise ValueError("invalid assessment discovery limits")
    return {"value": value, "semantic_hash": content_hash(value), "snapshot_hash": _sha(raw), "snapshot_bytes": raw}


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


def _mapped_paths(graph_artifacts: dict, mapping_packet: dict | None) -> set[str]:
    result = set()
    graph = graph_artifacts["requirement-evidence-graph.json"]
    for node in graph["nodes"]:
        if node.get("node_type") in {"implementation_reference", "test_reference", "instrumentation_reference"} and isinstance(node.get("path"), str):
            result.add(_normal_path(node["path"]))
    for source in (mapping_packet or {}).get("selected_sources", []):
        result.add(_normal_path(source["path"]))
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
    criterion_records = [{"criterion_id": item["criterion_id"], "requirement_id": item["requirement_id"], "scope_status": _scope(req[item["requirement_id"]], item), "repository_not_applicable_allowed": item["required_evidence_categories"] == ["owner_confirmation"]} for item in criteria]
    graph = inputs["graph_artifacts"]["requirement-evidence-graph.json"]
    journeys = [
        {"journey_id": item["node_id"], "journey_text": item["journey_text"], "scope_status": "confirmed"}
        for item in graph["nodes"]
        if item["node_type"] == "critical_journey"
    ]
    return {"requirements": sorted(requirement_records, key=lambda item: item["requirement_id"]), "criteria": sorted(criterion_records, key=lambda item: item["criterion_id"]), "journeys": sorted(journeys, key=lambda item: item["journey_id"])}


def _browser_targets(ctx: LocalExecutionContext, inputs: dict, criteria: list[dict]) -> tuple[bool, list[dict], list[str]]:
    relevant_ids = {item["criterion_id"] for item in criteria if "browser_or_http" in item.get("required_evidence_categories", [])}
    if not relevant_ids:
        return False, [], []
    origin = ctx.deployment_grant["origin"].rstrip("/"); allowed = ctx.deployment_grant["allowed_paths"]; targets = [{"url": origin + path, "origin": origin, "path_pattern": path, "authority": "deployment_grant"} for path in allowed]
    outside = []
    graph = inputs["graph_artifacts"]["requirement-evidence-graph.json"]
    for node in graph["nodes"]:
        if node.get("node_type") != "runtime_evidence" or not node.get("target"):
            continue
        raw = node["target"]; url = raw if isinstance(raw, str) and raw.startswith(("http://", "https://")) else urljoin(origin + "/", str(raw).lstrip("/")); parsed = urlparse(url)
        path = parsed.path or "/"; same = f"{parsed.scheme}://{parsed.netloc}" == origin
        if same and any(path == pattern or fnmatch.fnmatchcase(path, pattern) for pattern in allowed):
            targets.append({"url": url, "origin": origin, "path_pattern": path, "authority": "canonical_runtime_target"})
        else:
            outside.append(url)
    unique = {canonical_json(item): item for item in targets}
    return True, [unique[key] for key in sorted(unique)], sorted(set(outside))


def _browser_issue(ctx: LocalExecutionContext, inputs: dict, capabilities: dict) -> tuple[bool, str | None, list[dict], list[str]]:
    criteria = inputs["intent_artifacts"]["acceptance-criteria.json"]["criteria"]; relevant, targets, outside = _browser_targets(ctx, inputs, criteria)
    if not relevant:
        return False, "not_browser_relevant", [], []
    if not capabilities["capabilities"]["browser"]["available"]:
        return False, "browser_capability_unavailable", [], []
    if not capabilities["permissions"]["browser"]["granted"]:
        return False, "browser_permission_not_granted", [], []
    if not targets:
        return False, "browser_scope_insufficient" if outside else "no_authorized_browser_target", [], outside
    return True, None, targets, outside


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
    if not isinstance(permissions["browser"], dict) or set(permissions["browser"]) != {"allowed_targets"} or not isinstance(permissions["browser"]["allowed_targets"], list) or any(not isinstance(item, dict) or set(item) != {"url", "origin", "path_pattern", "authority"} for item in permissions["browser"]["allowed_targets"]):
        raise ValueError("invalid work-order browser permission")
    output = value["required_output"]
    if not isinstance(output, dict) or set(output) != {"schema_path", "output_path", "completion_receipt_path", "evidence_directory"}:
        raise ValueError("invalid work-order output")
    for field in output:
        _text(output[field], f"required_output.{field}", 500)
    _string_list(value["forbidden_claims"], "forbidden_claims", nonempty=True)


def prepare(ctx: LocalExecutionContext, *, capabilities_path: str | None = None, base_commit: str | None = None, owner_paths: list[str] | None = None) -> dict:
    ctx.require("file.read")
    inputs = load_assessment_input(ctx); roles = load_role_definitions(); discovery = load_discovery_registry(); approved_commands = ctx.activation["contract"]["execution_policy"]["approved_commands"]
    capabilities, capability_raw = _load_capabilities(ctx, capabilities_path, approved_commands); owner = _owner_paths(owner_paths); available = set(_release_paths(ctx)); mapped = _mapped_paths(inputs["graph_artifacts"], inputs["mapping_packet_snapshot"]); population = _population(inputs); change = _change_impact(ctx, base_commit)
    browser_issued, browser_reason, browser_targets, browser_outside = _browser_issue(ctx, inputs, capabilities)

    role_sources = {}; role_coverages = {}; role_limitations = {}
    for role in ALL_ROLES:
        sources, coverage, limitations = _role_sources(ctx, role, available, mapped, owner[role], approved_commands)
        if role == "browser_journey" and browser_outside:
            limitations.append({"kind": "browser_scope_insufficient", "unauthorized_targets": browser_outside, "rule_id": "release_browser_target_authority"})
        role_sources[role] = sources; role_coverages[role] = coverage; role_limitations[role] = sorted(limitations, key=canonical_json)

    mapping_hash = inputs["mapping_packet_snapshot"]["packet_hash"] if inputs["mapping_packet_snapshot"] else None
    semantic_basis = {"release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": {key: ctx.authority_binding[key] for key in ("project_id", "contract_hash", "contract_source", "authority_policy_version")}, "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities": capabilities, "roles": {role: roles[role]["semantic_hash"] for role in ALL_ROLES}, "discovery_registry_hash": discovery["semantic_hash"], "population": population, "owner_paths": owner, "change_impact": change, "role_sources": role_sources, "role_coverages": role_coverages, "role_limitations": role_limitations, "browser": {"issued": browser_issued, "reason_code": browser_reason, "targets": browser_targets}}
    semantic_hash = content_hash(semantic_basis); preparation_id = "prep_" + uuid.uuid4().hex; root = _root(ctx); directory = root / "preparations" / preparation_id
    if directory.exists():
        raise ValueError("assessment preparation collision")

    source_packet = {"schema_version": SOURCE_PACKET_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "project_authority": semantic_basis["project_authority"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "capabilities_hash": content_hash(capabilities), "role_definition_hashes": semantic_basis["roles"], "discovery_registry_hash": discovery["semantic_hash"], "population": population, "change_impact": change, "role_sources": {role: {"coverage": role_coverages[role], "limitations": role_limitations[role], "sources": role_sources[role]} for role in ALL_ROLES}, "browser_work_order": {"issued": browser_issued, "reason_code": browser_reason, "allowed_targets": browser_targets}, "coverage_boundary": "Validated Product Intent and Session 3 graph plus bounded commit-pinned assessment-local context only.", "packet_hash": ""}
    source_packet["packet_hash"] = content_hash({key: value for key, value in source_packet.items() if key != "packet_hash"})

    contexts = {}; work_orders = {}; work_order_bytes = {}
    requirement_ids = [item["requirement_id"] for item in population["requirements"]]; criterion_ids = [item["criterion_id"] for item in population["criteria"]]; journey_ids = [item["journey_id"] for item in population["journeys"]]
    for role in ALL_ROLES:
        assigned_requirements = requirement_ids if role == "product_assessment" else []
        assigned_journeys = journey_ids if role in {"product_assessment", "browser_journey"} else []
        context = {"schema_version": ROLE_CONTEXT_SCHEMA, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "role_id": role, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "assigned_requirements": [item for item in population["requirements"] if item["requirement_id"] in assigned_requirements], "assigned_criteria": population["criteria"], "assigned_journeys": [item for item in population["journeys"] if item["journey_id"] in assigned_journeys], "intent_artifacts": inputs["intent_artifacts"], "base_graph_artifacts": inputs["graph_artifacts"], "mapping_packet_snapshot": inputs["mapping_packet_snapshot"], "change_impact": change, "sources": role_sources[role], "source_coverage": role_coverages[role], "limitations": role_limitations[role], "browser_targets": browser_targets if role == "browser_journey" else []}
        context["packet_hash"] = content_hash(context); contexts[role] = context
        issued = role != "browser_journey" or browser_issued
        if not issued:
            continue
        work_order_id = "wo_" + role + "_" + hashlib.sha256(canonical_json({"preparation": semantic_hash, "role": role, "version": roles[role]["value"]["role_version"], "requirements": assigned_requirements, "criteria": criterion_ids, "journeys": assigned_journeys}).encode()).hexdigest()[:16]
        relative_root = f".shiproom/local/releases/{ctx.release['release_id']}/assessment"
        packet_path = f"{relative_root}/preparations/{preparation_id}/role-context/{role}.json"; inbox = f"{relative_root}/inbox/{preparation_id}/{work_order_id}"
        allowed_command_ids = capabilities["permissions"]["shell"]["allowed_command_ids"] if role in {"engineering_assessment", "test_adequacy"} else []
        allowed_commands = [command for command in approved_commands if command["command_id"] in allowed_command_ids]
        work_order = {"schema_version": WORK_ORDER_SCHEMA, "work_order_id": work_order_id, "work_order_hash": "", "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "role_id": role, "role_version": roles[role]["value"]["role_version"], "role_definition_hash": roles[role]["semantic_hash"], "role_definition_snapshot_hash": roles[role]["snapshot_hash"], "objective": roles[role]["value"]["mandate"], "inputs": {"packet_path": packet_path, "packet_hash": context["packet_hash"], "criterion_ids": criterion_ids, "requirement_ids": assigned_requirements, "journey_ids": assigned_journeys, "allowed_paths": sorted(item["path"] for item in role_sources[role]), "base_graph_generation": inputs["graph_generation"], "base_graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "product_intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "change_impact_status": change["status"]}, "capability_requirements": {"file_read": "required", "shell": "optional" if allowed_commands else "unavailable", "browser": "required" if role == "browser_journey" else "unavailable", "network": "unavailable"}, "permissions": {"repository": "read_only", "shell": {"allowed_commands": allowed_commands}, "browser": {"allowed_targets": browser_targets if role == "browser_journey" else []}}, "required_output": {"schema_path": roles[role]["value"]["required_output_schema"], "output_path": inbox + "/result.json", "completion_receipt_path": inbox + "/completion-receipt.json", "evidence_directory": inbox + "/evidence"}, "forbidden_claims": roles[role]["value"]["forbidden_claims"]}
        work_order["work_order_hash"] = _work_order_hash(work_order); _validate_work_order(work_order); raw = _render(work_order); work_orders[role] = work_order; work_order_bytes[role] = raw

    manifest_entries = []
    for role in ALL_ROLES:
        issued = role in work_orders; work_order = work_orders.get(role)
        manifest_entries.append({"role_id": role, "required": ROLE_REQUIRED[role], "issued": issued, "reason_code": None if issued else browser_reason, "work_order_id": work_order["work_order_id"] if work_order else None, "work_order_hash": work_order["work_order_hash"] if work_order else None, "work_order_snapshot_hash": _sha(work_order_bytes[role]) if work_order else None, "work_order_path": f"work-orders/{work_order['work_order_id']}.json" if work_order else None, "result_path": work_order["required_output"]["output_path"] if work_order else None, "completion_receipt_path": work_order["required_output"]["completion_receipt_path"] if work_order else None})
    capability_snapshot = capability_raw if capability_raw is not None else _render(capabilities)
    capability_snapshot_name = "submitted-capabilities.json" if capability_raw is not None else "capabilities.json"
    manifest = {"schema_version": WORK_ORDERS_SCHEMA, "compiler_version": PREPARATION_COMPILER_VERSION, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "graph_generation": inputs["graph_generation"], "graph_semantic_hash": inputs["graph_manifest"]["semantic_bundle_hash"], "intent_semantic_hash": inputs["intent_manifest"]["semantic_bundle_hash"], "mapping_packet_hash": mapping_hash, "source_packet_hash": source_packet["packet_hash"], "capabilities_hash": content_hash(capabilities), "capabilities_snapshot_filename": capability_snapshot_name, "capabilities_snapshot_hash": _sha(capability_snapshot), "discovery_registry": {"semantic_hash": discovery["semantic_hash"], "snapshot_hash": discovery["snapshot_hash"]}, "role_definitions": {role: {"semantic_hash": roles[role]["semantic_hash"], "snapshot_hash": roles[role]["snapshot_hash"]} for role in ALL_ROLES}, "work_orders": manifest_entries, "manifest_hash": ""}
    manifest["manifest_hash"] = content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})

    directory.mkdir(parents=True)
    _atomic(directory / "assessment-source-packet.json", source_packet); _atomic(directory / "assessment-work-orders.json", manifest); _atomic(directory / "capabilities.json", capabilities); (directory / "source-discovery.v1.json").write_bytes(discovery["snapshot_bytes"])
    if capability_raw is not None:
        (directory / "submitted-capabilities.json").write_bytes(capability_raw)
    for role in ALL_ROLES:
        (directory / "role-definitions").mkdir(exist_ok=True); (directory / "role-definitions" / f"{role}.json").write_bytes(roles[role]["snapshot_bytes"])
        _atomic(directory / "role-context" / f"{role}.json", contexts[role])
        if role in work_orders:
            path = directory / "work-orders" / f"{work_orders[role]['work_order_id']}.json"; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(work_order_bytes[role])
            inbox_path = root / "inbox" / preparation_id / work_orders[role]["work_order_id"]; (inbox_path / "evidence").mkdir(parents=True, exist_ok=True)
    pointer = {"schema_version": POINTER_SCHEMA, "preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "manifest_snapshot_hash": _sha((directory / "assessment-work-orders.json").read_bytes())}
    _atomic(root / "active-preparation.json", pointer)
    return {"preparation_id": preparation_id, "preparation_semantic_hash": semantic_hash, "source_packet_hash": source_packet["packet_hash"], "work_orders": manifest_entries}


def load_preparation(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    inputs = load_assessment_input(ctx); root = _root(ctx)
    if preparation_id is None:
        pointer_path = root / "active-preparation.json"
        if pointer_path.is_symlink() or not pointer_path.is_file():
            raise ValueError("active assessment preparation unavailable")
        pointer = _load_json_bytes(pointer_path.read_bytes())
        if set(pointer) != {"schema_version", "preparation_id", "preparation_semantic_hash", "manifest_snapshot_hash"} or pointer.get("schema_version") != POINTER_SCHEMA:
            raise ValueError("invalid assessment preparation pointer")
        preparation_id = pointer["preparation_id"]
    else:
        pointer = None
    if not isinstance(preparation_id, str) or not re.fullmatch(r"prep_[0-9a-f]{32}", preparation_id):
        raise ValueError("invalid assessment preparation ID")
    directory = root / "preparations" / preparation_id
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != (root / "preparations").resolve():
        raise ValueError("invalid assessment preparation directory")
    manifest_path = directory / "assessment-work-orders.json"; source_path = directory / "assessment-source-packet.json"
    if any(path.is_symlink() or not path.is_file() for path in (manifest_path, source_path)):
        raise ValueError("incomplete assessment preparation")
    manifest = _load_json_bytes(manifest_path.read_bytes()); packet = _load_json_bytes(source_path.read_bytes())
    if pointer and pointer["manifest_snapshot_hash"] != _sha(manifest_path.read_bytes()):
        raise ValueError("assessment preparation pointer is stale")
    manifest_fields = {"schema_version", "compiler_version", "preparation_id", "preparation_semantic_hash", "release_id", "release_commit", "graph_generation", "graph_semantic_hash", "intent_semantic_hash", "mapping_packet_hash", "source_packet_hash", "capabilities_hash", "capabilities_snapshot_filename", "capabilities_snapshot_hash", "discovery_registry", "role_definitions", "work_orders", "manifest_hash"}
    if set(manifest) != manifest_fields or manifest.get("schema_version") != WORK_ORDERS_SCHEMA or manifest.get("compiler_version") != PREPARATION_COMPILER_VERSION or manifest.get("manifest_hash") != content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"}):
        raise ValueError("invalid assessment work-order manifest")
    if manifest["preparation_id"] != preparation_id or manifest["release_id"] != ctx.release["release_id"] or manifest["release_commit"] != ctx.authority_binding["repository_commit"] or manifest["graph_generation"] != inputs["graph_generation"] or manifest["graph_semantic_hash"] != inputs["graph_manifest"]["semantic_bundle_hash"] or manifest["intent_semantic_hash"] != inputs["intent_manifest"]["semantic_bundle_hash"]:
        raise ValueError("assessment preparation authority is stale")
    packet_fields = {"schema_version", "compiler_version", "preparation_id", "preparation_semantic_hash", "release_id", "release_commit", "project_authority", "graph_generation", "graph_semantic_hash", "intent_semantic_hash", "mapping_packet_hash", "capabilities_hash", "role_definition_hashes", "discovery_registry_hash", "population", "change_impact", "role_sources", "browser_work_order", "coverage_boundary", "packet_hash"}
    if set(packet) != packet_fields or packet.get("schema_version") != SOURCE_PACKET_SCHEMA or packet.get("packet_hash") != content_hash({key: value for key, value in packet.items() if key != "packet_hash"}) or manifest["source_packet_hash"] != packet["packet_hash"]:
        raise ValueError("invalid assessment source packet")
    if packet["preparation_id"] != preparation_id or packet["preparation_semantic_hash"] != manifest["preparation_semantic_hash"] or packet["release_id"] != manifest["release_id"] or packet["release_commit"] != manifest["release_commit"] or packet["graph_generation"] != manifest["graph_generation"] or packet["graph_semantic_hash"] != manifest["graph_semantic_hash"] or packet["intent_semantic_hash"] != manifest["intent_semantic_hash"] or packet["mapping_packet_hash"] != manifest["mapping_packet_hash"]:
        raise ValueError("assessment source packet binding is stale")
    if packet["population"] != _population(inputs):
        raise ValueError("assessment population is stale")
    for role in ALL_ROLES:
        role_packet = packet["role_sources"].get(role) if isinstance(packet.get("role_sources"), dict) else None
        if not isinstance(role_packet, dict) or set(role_packet) != {"coverage", "limitations", "sources"} or not isinstance(role_packet["sources"], list):
            raise ValueError("invalid assessment role source packet")
        seen_paths = set()
        for source in role_packet["sources"]:
            source_fields = {"path", "returned_git_path", "git_blob_hash", "normalized_text_hash", "size_bytes", "text", "mandatory", "selection_rule_ids", "selection_reason", "provenance"}
            if not isinstance(source, dict) or set(source) != source_fields or source["path"] in seen_paths or not isinstance(source["mandatory"], bool) or not isinstance(source["size_bytes"], int):
                raise ValueError("invalid assessment source record")
            seen_paths.add(source["path"])
            expected = _source(ctx, source["path"], source["mandatory"], source["selection_rule_ids"], source["selection_reason"], source["provenance"])
            if source != expected:
                raise ValueError("assessment source record is stale")
    capabilities_path = directory / "capabilities.json"; capabilities = _load_json_bytes(capabilities_path.read_bytes()); approved = ctx.activation["contract"]["execution_policy"]["approved_commands"]; validate_capabilities(capabilities, approved)
    if content_hash(capabilities) != manifest["capabilities_hash"]:
        raise ValueError("assessment capabilities snapshot is stale")
    snapshot_path = directory / manifest["capabilities_snapshot_filename"]
    if manifest["capabilities_snapshot_filename"] not in {"capabilities.json", "submitted-capabilities.json"} or snapshot_path.is_symlink() or not snapshot_path.is_file() or _sha(snapshot_path.read_bytes()) != manifest["capabilities_snapshot_hash"]:
        raise ValueError("assessment capability declaration snapshot is stale")
    roles = load_role_definitions(); contexts = {}
    discovery = load_discovery_registry(); discovery_path = directory / "source-discovery.v1.json"
    if discovery_path.is_symlink() or not discovery_path.is_file() or _sha(discovery_path.read_bytes()) != manifest["discovery_registry"]["snapshot_hash"] or discovery["semantic_hash"] != manifest["discovery_registry"]["semantic_hash"] or packet["discovery_registry_hash"] != discovery["semantic_hash"]:
        raise ValueError("assessment source-discovery registry is stale")
    for role in ALL_ROLES:
        role_path = directory / "role-definitions" / f"{role}.json"
        if role_path.is_symlink() or not role_path.is_file() or _sha(role_path.read_bytes()) != manifest["role_definitions"][role]["snapshot_hash"] or roles[role]["semantic_hash"] != manifest["role_definitions"][role]["semantic_hash"]:
            raise ValueError("assessment role definition is stale")
        context_path = directory / "role-context" / f"{role}.json"
        if context_path.is_symlink() or not context_path.is_file():
            raise ValueError("assessment role context is unavailable")
        context = _load_json_bytes(context_path.read_bytes())
        context_fields = {"schema_version", "preparation_id", "preparation_semantic_hash", "role_id", "release_id", "release_commit", "graph_generation", "graph_semantic_hash", "intent_semantic_hash", "assigned_requirements", "assigned_criteria", "assigned_journeys", "intent_artifacts", "base_graph_artifacts", "mapping_packet_snapshot", "change_impact", "sources", "source_coverage", "limitations", "browser_targets", "packet_hash"}
        if set(context) != context_fields or context.get("schema_version") != ROLE_CONTEXT_SCHEMA or context.get("role_id") != role or context.get("packet_hash") != content_hash({key: value for key, value in context.items() if key != "packet_hash"}) or context.get("preparation_id") != preparation_id or context.get("preparation_semantic_hash") != manifest["preparation_semantic_hash"]:
            raise ValueError("invalid assessment role context")
        contexts[role] = context
    for entry in manifest["work_orders"]:
        if set(entry) != {"role_id", "required", "issued", "reason_code", "work_order_id", "work_order_hash", "work_order_snapshot_hash", "work_order_path", "result_path", "completion_receipt_path"} or entry["role_id"] not in ALL_ROLES:
            raise ValueError("invalid assessment work-order entry")
        if not entry["issued"]:
            if entry["required"] or entry["role_id"] != "browser_journey":
                raise ValueError("required assessment role was not issued")
            continue
        work_path = directory / entry["work_order_path"]
        if work_path.is_symlink() or not work_path.is_file() or _sha(work_path.read_bytes()) != entry["work_order_snapshot_hash"]:
            raise ValueError("assessment work-order snapshot is invalid")
        work = _load_json_bytes(work_path.read_bytes()); _validate_work_order(work)
        if work["work_order_id"] != entry["work_order_id"] or work["work_order_hash"] != entry["work_order_hash"]:
            raise ValueError("assessment work-order manifest mismatch")
        if work["inputs"]["packet_hash"] != contexts[entry["role_id"]]["packet_hash"] or work["preparation_semantic_hash"] != manifest["preparation_semantic_hash"] or work["role_definition_hash"] != manifest["role_definitions"][entry["role_id"]]["semantic_hash"]:
            raise ValueError("assessment work-order authority is stale")
    return {"directory": directory, "manifest": manifest, "source_packet": packet, "capabilities": capabilities, "graph_input": inputs}
