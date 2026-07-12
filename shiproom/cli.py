from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import Release
from .registry import discover, select
from .report import render
from .remediation import assert_clean_worktree, current_branch, repository_root
from .runner import run_module
from .verdict import calculate


def load(path: Path) -> dict:
    return Release.from_dict(json.loads(path.read_text(encoding="utf-8"))).to_dict()


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shiproom")
    sub = parser.add_subparsers(dest="command", required=True)
    modules = sub.add_parser("modules"); modules.add_argument("action", choices=["list"])
    release = sub.add_parser("release"); release.add_argument("action", choices=["init"]); release.add_argument("--repo", required=True); release.add_argument("--live-url", required=True); release.add_argument("--promise", required=True); release.add_argument("--target-user", default="builders"); release.add_argument("--output", default="release-state/release.json")
    review = sub.add_parser("review"); group = review.add_mutually_exclusive_group(required=True); group.add_argument("--module"); group.add_argument("--all", action="store_true"); review.add_argument("--release", required=True)
    report = sub.add_parser("report"); report.add_argument("action", choices=["render"]); report.add_argument("--release", required=True); report.add_argument("--output", default="dist/release-report.html")
    decision = sub.add_parser("decision"); decision.add_argument("action", choices=["add", "record"]); decision.add_argument("--release", required=True); decision.add_argument("--id", default="decision_publish_promise"); decision.add_argument("--title", default="Beta publication promise"); decision.add_argument("--choice"); decision.add_argument("--resolution", choices=["resolved", "accepted_condition"])
    trace = sub.add_parser("trace"); trace.add_argument("action", choices=["record"]); trace.add_argument("--release", required=True); trace.add_argument("--live-url"); trace.add_argument("--hermes-session-id"); trace.add_argument("--github-repository"); trace.add_argument("--github-pr-number", type=int); trace.add_argument("--github-pr-id"); trace.add_argument("--github-comment-id"); trace.add_argument("--github-comment-url"); trace.add_argument("--cloudflare-deployment-id"); trace.add_argument("--report-url")
    args = parser.parse_args(argv)
    registry = discover()
    if args.command == "modules":
        for module_id, module in registry.items(): print(f"{module_id}\t{module.config.get('name','')}")
    elif args.command == "release":
        repo = repository_root(Path(args.repo)); assert_clean_worktree(repo); base_branch = current_branch(repo)
        data = Release(release_id=f"rel_{uuid.uuid4().hex[:12]}", repository={"url": args.repo, "path": str(repo), "base_branch": base_branch}, deployment={"url": args.live_url, "generated_path": "/result/demo"}, product={"name": "Launch Card", "target_user": args.target_user, "promise": args.promise, "critical_journey": ["Enter project", "Generate", "Open public URL"], "non_goals": []}).to_dict()
        selected, skipped = select(data, registry); data["panel"] = {"selected_modules": selected, "skipped_modules": skipped}; save(Path(args.output), data); print(args.output)
    elif args.command == "review":
        path = Path(args.release); data = load(path); targets = data["panel"]["selected_modules"] if args.all else [args.module]
        for module_id in targets:
            if module_id not in registry: raise SystemExit(f"unknown module: {module_id}")
            result = run_module(module_id, data)
            criterion_ids = {check.get("criterion_id") for check in result["checks"]}
            finding_ids = {finding.get("id") for finding in result["findings"]}
            data["checks"] = [check for check in data["checks"] if check.get("criterion_id") not in criterion_ids]
            data["findings"] = [finding for finding in data["findings"] if finding.get("id") not in finding_ids]
            data["checks"].extend(result["checks"]); data["findings"].extend(result["findings"])
        data["verdict"] = calculate(data); data["state"] = data["verdict"]["status"]; save(path, data); print(json.dumps({"release_id": data["release_id"], "verdict": data["verdict"], "checks": len(data["checks"]), "findings": len(data["findings"])}, indent=2))
    elif args.command == "decision":
        path = Path(args.release); data = load(path)
        existing = next((d for d in data["owner_decisions"] if d.get("id") == args.id), None)
        if args.action == "add":
            if existing: raise SystemExit(f"decision already exists: {args.id}")
            data["owner_decisions"].append({"id": args.id, "title": args.title, "choice": None, "resolution": None, "evidence": []})
        else:
            if not existing: raise SystemExit(f"decision not found: {args.id}")
            if not args.choice or not args.resolution: raise SystemExit("record requires --choice and --resolution")
            existing.update({"choice": args.choice, "resolution": args.resolution, "recorded_at": datetime.now(UTC).isoformat(), "evidence": [{"status": "owner_confirmed", "kind": "owner_choice", "value": args.choice}]})
        data["verdict"] = calculate(data); data["state"] = data["verdict"]["status"]; save(path, data); print(json.dumps({"release_id": data["release_id"], "decision_id": args.id, "verdict": data["verdict"]}, indent=2))
    elif args.command == "trace":
        path = Path(args.release); data = load(path)
        if args.live_url: data["deployment"]["url"] = args.live_url
        if args.hermes_session_id: data.setdefault("telemetry", {})["hermes_session_id"] = args.hermes_session_id
        github = data.setdefault("integrations", {}).setdefault("github", {})
        cloudflare = data.setdefault("integrations", {}).setdefault("cloudflare", {})
        for key in ("github_repository", "github_pr_number", "github_pr_id", "github_comment_id", "github_comment_url"):
            value = getattr(args, key)
            if value is not None: github[key.removeprefix("github_")] = value
        if args.cloudflare_deployment_id: cloudflare["deployment_id"] = args.cloudflare_deployment_id
        if args.report_url:
            cloudflare["report_url"] = args.report_url
            data["deployment"]["report_url"] = args.report_url
        save(path, data); print(json.dumps({"release_id": data["release_id"], "telemetry": data["telemetry"], "integrations": data["integrations"]}, indent=2))
    else:
        data = load(Path(args.release)); output = render(data, Path(args.output)); print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
