from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import Release
from .hermes import apply_manager_decision, validate_receipt
from .public import public_release_view, write_public_view
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
    hermes = sub.add_parser("hermes"); hermes.add_argument("action", choices=["packet", "selection", "receipt", "verify-join"]); hermes.add_argument("--release", required=True); hermes.add_argument("--input"); hermes.add_argument("--receipt"); hermes.add_argument("--output")
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
    elif args.command == "hermes":
        path = Path(args.release); data = load(path)
        if args.action == "packet":
            output = Path(args.output or "public-artifacts/public-release-view.json")
            write_public_view(data, output, registry); print(output)
        elif args.action == "selection":
            if not args.input: raise SystemExit("selection requires --input")
            decision_data = json.loads(Path(args.input).read_text(encoding="utf-8"))
            apply_manager_decision(data, decision_data, set(registry)); save(path, data); print(json.dumps(data["panel"], indent=2))
        elif args.action == "receipt":
            if not args.receipt: raise SystemExit("receipt requires --receipt")
            receipt_data = validate_receipt(json.loads(Path(args.receipt).read_text(encoding="utf-8")), data["release_id"])
            output = Path(args.output or "hermes-receipts/receipt.json"); save(output, receipt_data)
            data.setdefault("telemetry", {})["hermes_session_id"] = receipt_data["session_id"]; save(path, data); print(output)
        else:
            if not args.receipt: raise SystemExit("verify-join requires --receipt")
            receipt_data = validate_receipt(json.loads(Path(args.receipt).read_text(encoding="utf-8")), data["release_id"])
            view = public_release_view(data, registry); release_id = data["release_id"]
            if receipt_data["release_id"] != release_id: raise SystemExit("receipt release_id mismatch")
            print(json.dumps({"status": "JOINED", "release_id": release_id, "session_id": receipt_data["session_id"], "report_url": view["public_artifacts"]["report_url"], "github_comment_url": view["public_artifacts"]["github_comment_url"]}, indent=2))
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
