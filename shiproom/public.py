from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .registry import Module

PUBLIC_SCHEMA = "public_release_view.v0"
ABSOLUTE_PATH = re.compile(r"(?:(?<![A-Za-z])[A-Za-z]:[\\/]|/(?:Users|home|var|tmp)/)")
SENSITIVE = re.compile(r"(?i)(api[_-]?key|password|private[_-]?key|authorization|bearer\s+[A-Za-z0-9._-]+)")


def _public_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname in {"localhost", "127.0.0.1"}:
        raise ValueError(f"public projection requires an HTTPS public URL: {value!r}")
    return value


def module_catalogue(modules: dict[str, Module]) -> list[dict]:
    return [{"module_id": key, "name": value.config.get("name", key)} for key, value in modules.items()]


def public_release_view(release: dict, modules: dict[str, Module] | None = None) -> dict:
    github = release.get("integrations", {}).get("github", {})
    cloudflare = release.get("integrations", {}).get("cloudflare", {})
    repo_name = github.get("repository")
    repo_url = f"https://github.com/{repo_name}" if repo_name else None
    pr_number = github.get("pr_number")
    public = {
        "schema_version": PUBLIC_SCHEMA,
        "release_id": release["release_id"],
        "product": {key: release.get("product", {}).get(key) for key in ("name", "target_user", "promise", "critical_journey", "non_goals")},
        "release_signals": {"has_public_repository": bool(repo_url), "has_public_deployment": bool(release.get("deployment", {}).get("url"))},
        "available_modules": module_catalogue(modules) if modules is not None else [],
        "applicable_criteria": sorted({c.get("criterion_id") for c in release.get("checks", []) if c.get("criterion_id")}),
        "manager_selection": {
            "selected_modules": release.get("panel", {}).get("selected_modules", []),
            "skipped_modules": release.get("panel", {}).get("skipped_modules", []),
            "selection_reasons": release.get("panel", {}).get("selection_reasons", {}),
            "delegation_plan": release.get("panel", {}).get("delegation_plan", []),
        },
        "checks": release.get("checks", []),
        "findings": release.get("findings", []),
        "remediation": [{key: task.get(key) for key in ("id", "class", "branch", "commit_sha", "status", "auto_merge")} for task in release.get("remediation_tasks", [])],
        "owner_decisions": [{key: decision.get(key) for key in ("id", "title", "choice", "resolution", "recorded_at")} for decision in release.get("owner_decisions", [])],
        "verdict": release.get("verdict", {}),
        "public_artifacts": {
            "repository_url": _public_url(repo_url) if repo_url else None,
            "pr_url": _public_url(f"{repo_url}/pull/{pr_number}") if repo_url and pr_number else None,
            "github_comment_url": _public_url(github["comment_url"]) if github.get("comment_url") else None,
            "deployment_url": _public_url(release["deployment"]["url"]),
            "report_url": _public_url(cloudflare.get("report_url") or release.get("deployment", {}).get("report_url")),
        },
        "native_ids": {"github_pr_id": github.get("pr_id"), "github_comment_id": github.get("comment_id"), "cloudflare_deployment_id": cloudflare.get("deployment_id")},
    }
    validate_public_release_view(public)
    return public


def validate_public_release_view(view: dict) -> None:
    allowed = {"schema_version", "release_id", "product", "release_signals", "available_modules", "applicable_criteria", "manager_selection", "checks", "findings", "remediation", "owner_decisions", "verdict", "public_artifacts", "native_ids"}
    if set(view) != allowed or view.get("schema_version") != PUBLIC_SCHEMA:
        raise ValueError("invalid public release view fields or schema")
    encoded = json.dumps(view)
    if ABSOLUTE_PATH.search(encoded) or SENSITIVE.search(encoded):
        raise ValueError("public release view contains a local path or sensitive content")
    for key, value in view["public_artifacts"].items():
        if value is not None:
            _public_url(value)


def write_public_view(release: dict, output: Path, modules: dict[str, Module]) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(public_release_view(release, modules), indent=2), encoding="utf-8")
    return output
