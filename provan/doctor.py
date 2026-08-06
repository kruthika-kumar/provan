from __future__ import annotations

import importlib.metadata
import importlib.resources
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from . import __version__
from .canonical import canonical_bytes
from .errors import ProvanError
from .state import secure_write, state_root, validate_state_children
from .telemetry import status as telemetry_status
from .validators import validate_doctor_semantics


def _check(identifier: str, status: str, detail: str, *, required: bool = True) -> dict:
    return {"id": identifier, "status": status, "detail": detail, "required": required}


def _isolated_git_check() -> dict:
    executable = shutil.which("git")
    if not executable:
        return _check("git_local_operation", "BLOCKED", "Git executable unavailable")
    with tempfile.TemporaryDirectory(prefix="provan-doctor-git-") as raw:
        root = Path(raw)
        home = root / "home"; xdg = root / "xdg"; repo = root / "repository"
        home.mkdir(); xdg.mkdir(); repo.mkdir()
        env = {
            "PATH": os.environ.get("PATH", ""), "HOME": str(home), "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(xdg), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        }
        for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"):
            if os.environ.get(name): env[name] = os.environ[name]
        argv = [executable, "-c", f"core.hooksPath={root / 'disabled-hooks'}", "-c", f"core.excludesFile={os.devnull}", "init", "--quiet", str(repo)]
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15, check=False)
        if result.returncode or result.stderr.strip():
            return _check("git_local_operation", "BLOCKED", "isolated local Git operation failed")
        verify = subprocess.run([executable, "-C", str(repo), "rev-parse", "--git-dir"], env=env, capture_output=True, text=True, timeout=15, check=False)
        if verify.returncode or verify.stderr.strip():
            return _check("git_local_operation", "BLOCKED", "isolated Git discovery failed")
    return _check("git_local_operation", "READY", "isolated local Git operation succeeded")


def _extension_metadata_check() -> tuple[dict, list[str]]:
    limitations: list[str] = []
    try:
        points = list(importlib.metadata.entry_points(group="provan.extensions"))
    except Exception:
        return _check("extension_registry_metadata", "BLOCKED", "entry-point metadata unavailable"), limitations
    bundled = []
    metadata_compatible = []
    missing_metadata = []
    incompatible = []
    allowlisted = {item.strip() for item in os.environ.get("PROVAN_EXTENSION_ALLOWLIST", "").split(",") if item.strip()}
    load_failures = []
    for point in points:
        distribution = getattr(point, "dist", None)
        name = (distribution.metadata.get("Name", "") if distribution else "").lower()
        if name == "provan-assurance":
            bundled.append(point.name)
            continue
        declared = distribution.metadata.get("Provan-Extension-API") if distribution else None
        if declared == "1": metadata_compatible.append(point.name)
        elif declared is None: missing_metadata.append(point.name)
        else: incompatible.append(point.name)
        if point.name in allowlisted:
            try:
                point.load()
            except Exception:
                load_failures.append(point.name)
    if incompatible or load_failures:
        return _check("extension_registry_metadata", "BLOCKED", f"incompatible={len(incompatible)}; allowlisted_load_failures={len(load_failures)}"), limitations
    if metadata_compatible or missing_metadata:
        limitations.append("unconfigured_extension_metadata_not_runtime_qualified")
    if missing_metadata:
        limitations.append("extension_api_metadata_missing")
    detail = f"bundled={len(bundled)}; metadata_compatible={len(metadata_compatible)}; missing_metadata={len(missing_metadata)}; third_party_imports={len(allowlisted)}"
    return _check("extension_registry_metadata", "READY", detail), limitations


def _state_checks() -> tuple[list[dict], list[str]]:
    root = state_root()
    try:
        children = validate_state_children()
        probe_name = f"doctor-probe-{uuid.uuid4()}.json"
        probe = secure_write(Path("outputs") / probe_name, canonical_bytes({"probe": True}))
        observed = probe.read_bytes()
        probe.unlink()
        if observed != canonical_bytes({"probe": True}) or probe.exists():
            raise OSError("probe parity or cleanup failed")
        return [
            _check("provan_home", "READY", "resolved PROVAN_HOME state root"),
            _check("state_outputs", "READY", "<PROVAN_HOME>/outputs is a real directory"),
            _check("state_pending", "READY", "<PROVAN_HOME>/pending is a real directory"),
            _check("state_output_probe", "READY", "write/fsync/read/delete probe left no file residue"),
        ], []
    except (OSError, ProvanError) as exc:
        return [
            _check("provan_home", "BLOCKED", "resolved state root failed validation"),
            _check("state_outputs", "BLOCKED", "safe output directory unavailable"),
            _check("state_pending", "BLOCKED", "safe pending directory unavailable"),
            _check("state_output_probe", "BLOCKED", type(exc).__name__),
        ], ["state_safety_check_failed"]


def run_doctor() -> dict:
    checks = [
        _check("python", "READY" if sys.version_info >= (3, 11) else "BLOCKED", f"Python {sys.version_info.major}.{sys.version_info.minor}"),
        _check("installed_version", "READY" if __version__ == "0.2.0" else "BLOCKED", __version__),
    ]
    try:
        schema_files = list(importlib.resources.files("provan").joinpath("schemas").iterdir())
        packaged = any(item.name == "repository-inspection.v1.json" for item in schema_files)
    except Exception:
        packaged = False
    checks.append(_check("packaged_schemas", "READY" if packaged else "BLOCKED", "schema registry present" if packaged else "schema registry missing"))
    checks.append(_isolated_git_check())
    state_checks, limitations = _state_checks(); checks.extend(state_checks)
    checks.append(_check("source_only_inspection", "READY", "runtime available without target execution"))
    extension_check, extension_limitations = _extension_metadata_check(); checks.append(extension_check); limitations.extend(extension_limitations)
    telemetry = telemetry_status()
    checks.append(_check("telemetry_enabled", "READY" if telemetry["enabled"] else "NOT_CONFIGURED", "opt-in state" , required=False))
    checks.append(_check("telemetry_transport", telemetry["transport"], "collector endpoint configuration", required=False))
    checks.append(_check("qualified_execution_sandbox", "NOT_CONFIGURED", "qualified execution is unavailable", required=False))
    checks.append(_check("network_policy", "NOT_APPLICABLE", "doctor performs no network operations", required=False))
    limitations.extend(["qualified_execution_sandbox_not_configured", "telemetry_transport_not_configured"] if telemetry["transport"] == "NOT_CONFIGURED" else ["qualified_execution_sandbox_not_configured"])
    blocked = any(row["required"] and row["status"] in {"BLOCKED", "DEGRADED", "NOT_CONFIGURED"} for row in checks)
    value = {
        "schema_id": "provan.doctor_report.v1", "product_version": __version__,
        "status": "BLOCKED" if blocked else "READY_WITH_LIMITATIONS",
        "checks": checks, "limitations": sorted(set(limitations)),
    }
    validate_doctor_semantics(value)
    return value
