from __future__ import annotations

from .models import EvidenceStatus
from .registry import discover
from .runs import materialize


def release_run_view(release: dict, events: list[dict] | None = None) -> dict:
    modules = discover(); record = materialize(release, events or [])
    panel = release.get("panel", {})
    selected = panel.get("selected_modules", [])
    skipped = panel.get("skipped_modules", [])
    event_status = {event.get("module_id"): event["event_type"] for event in record["events"] if event.get("module_id")}
    cards = []
    skip_map = {item.get("module_id"): item.get("reason", "Not selected") for item in skipped if isinstance(item, dict)}
    module_order = [*selected, *(key for key in modules if key not in selected)]
    for module_id in module_order:
        module = modules[module_id]
        if module_id in skip_map or module_id not in selected:
            status, reason = "skipped", skip_map.get(module_id, "Not selected by the release manager")
        else:
            last = event_status.get(module_id, "completed")
            status = "revised" if last == "revision_accepted" else "failed" if last in {"result_rejected", "run_failed"} else "running" if last == "delegate_started" else "completed"
            reason = panel.get("selection_reasons", {}).get(module_id, "Selected by the release manager")
        cards.append({"module_id": module_id, "name": module.config.get("name", module_id), "status": status, "reason": reason})
    checks = release.get("checks", []); findings = release.get("findings", [])
    required = [check for check in checks if check.get("required", release.get("mode", "controlled") == "external")]
    counts = {"required_checks_evidenced": sum(bool(c.get("evidence_status") and c.get("evidence_status") != EvidenceStatus.MISSING) for c in required), "missing_required_evidence": sum(not c.get("evidence_status") or c.get("evidence_status") == EvidenceStatus.MISSING for c in required), "verified_blockers": sum(bool(f.get("blocking") and f.get("state") != "CLOSED") for f in findings), "model_reviewed_findings": sum(any(e.get("status") == EvidenceStatus.MODEL for e in f.get("evidence", [])) for f in findings)}
    github = release.get("integrations", {}).get("github", {}); cloudflare = release.get("integrations", {}).get("cloudflare", {})
    return {"schema_version": "release_run_view.v1", "release_id": release["release_id"], "mode": release.get("mode", "controlled"), "product": {key: release.get("product", {}).get(key) for key in ("name", "target_user", "promise", "critical_journey", "non_goals")}, "verdict": release.get("verdict", {}), "module_cards": cards, "manager_selection": {"selected_modules": selected, "skipped_modules": skipped, "selection_reasons": panel.get("selection_reasons", {}), "delegation_plan": panel.get("delegation_plan", [])}, "checks": checks, "findings": findings, "owner_decisions": release.get("owner_decisions", []), "remediation": release.get("remediation_tasks", []), "evidence_counts": counts, "run": record, "repository": {"url": release.get("repository", {}).get("url"), "pr_url": release.get("repository", {}).get("pr_url"), "base_branch": release.get("repository", {}).get("base_branch"), "commit_sha": release.get("repository", {}).get("commit_sha")}, "deployment": {"url": release.get("deployment", {}).get("url"), "report_url": cloudflare.get("report_url") or release.get("deployment", {}).get("report_url")}, "public_native_ids": {"github_repository": github.get("repository"), "github_pr_number": github.get("pr_number"), "github_comment_url": github.get("comment_url"), "cloudflare_deployment_id": cloudflare.get("deployment_id")}, "disclaimer": "Independent read-only Shiproom review; not produced or endorsed by the upstream project." if release.get("mode") == "external" else None}
