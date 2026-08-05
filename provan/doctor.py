import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .validators import validate_doctor_semantics


def run_doctor() -> dict:
    checks = [
        {"id": "python", "status": "READY" if sys.version_info >= (3, 11) else "BLOCKED"},
        {"id": "git", "status": "READY" if shutil.which("git") else "BLOCKED"},
        {"id": "source_only_inspection", "status": "READY"},
        {"id": "qualified_execution_sandbox", "status": "NOT_CONFIGURED"},
        {"id": "telemetry_transport", "status": "NOT_CONFIGURED"},
    ]
    blocked = any(row["status"] == "BLOCKED" for row in checks)
    value = {
        "schema_id": "provan.doctor_report.v1", "product_version": __version__,
        "status": "BLOCKED" if blocked else "READY_WITH_LIMITATIONS",
        "checks": checks, "limitations": ["qualified_execution_sandbox_not_configured", "telemetry_transport_not_configured"],
    }
    validate_doctor_semantics(value)
    return value
