from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.remediation import patch_demo_route


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repo", default="."); parser.add_argument("--release", default="release-state/release.json"); parser.add_argument("--branch", default="shiproom/fix-public-result-route"); args = parser.parse_args()
    repo = Path(args.repo).resolve(); target = patch_demo_route(repo, args.branch)
    release_path = Path(args.release); release = json.loads(release_path.read_text(encoding="utf-8"))
    release["remediation_tasks"].append({"id": "rem_route_fix", "class": "route_fix", "branch": args.branch, "target": str(target.relative_to(repo)), "status": "PATCHED", "auto_merge": False})
    release_path.write_text(json.dumps(release, indent=2), encoding="utf-8")
    print(f"Patched {target} on {args.branch}; independent verification still required.")
    return 0


if __name__ == "__main__": raise SystemExit(main())

