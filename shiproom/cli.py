from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from .models import Release
from .registry import discover, select
from .report import render
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
    args = parser.parse_args(argv)
    registry = discover()
    if args.command == "modules":
        for module_id, module in registry.items(): print(f"{module_id}\t{module.config.get('name','')}")
    elif args.command == "release":
        data = Release(release_id=f"rel_{uuid.uuid4().hex[:12]}", repository={"url": args.repo, "path": args.repo}, deployment={"url": args.live_url, "generated_path": "/result/demo"}, product={"name": "Launch Card", "target_user": args.target_user, "promise": args.promise, "critical_journey": ["Enter project", "Generate", "Open public URL"], "non_goals": []}).to_dict()
        selected, skipped = select(data, registry); data["panel"] = {"selected_modules": selected, "skipped_modules": skipped}; save(Path(args.output), data); print(args.output)
    elif args.command == "review":
        path = Path(args.release); data = load(path); targets = data["panel"]["selected_modules"] if args.all else [args.module]
        for module_id in targets:
            if module_id not in registry: raise SystemExit(f"unknown module: {module_id}")
            result = run_module(module_id, data); data["checks"].extend(result["checks"]); data["findings"].extend(result["findings"])
        data["verdict"] = calculate(data); data["state"] = data["verdict"]["status"]; save(path, data); print(json.dumps({"release_id": data["release_id"], "verdict": data["verdict"], "checks": len(data["checks"]), "findings": len(data["findings"])}, indent=2))
    else:
        data = load(Path(args.release)); output = render(data, Path(args.output)); print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

