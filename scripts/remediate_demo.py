from __future__ import annotations

import argparse
import json
from pathlib import Path

from shiproom.remediation import patch_demo_route_isolated, remediation_branch, repository_root
from shiproom.authority import LocalExecutionContext


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--release", default="release-state/release.json")
    args = parser.parse_args()
    repo = repository_root(Path(args.repo))
    release_path = Path(args.release).resolve()
    release = json.loads(release_path.read_text(encoding="utf-8"))
    branch = remediation_branch(release["release_id"])
    if any(task.get("status") == "PATCHED" for task in release.get("remediation_tasks", [])):
        raise ValueError("release already records a patched remediation; refusing no-op success")
    context=LocalExecutionContext.from_release(release)
    targets, commit_sha, worktree = patch_demo_route_isolated(context, release)
    task = {
        "id": f"rem_route_fix_{release['release_id']}",
        "class": "route_fix",
        "branch": branch,
        "base_branch": release["repository"]["base_branch"],
        "commit_sha": commit_sha,
        "targets": [str(target.relative_to(Path(worktree["worktree"]))) for target in targets],
        "worktree": worktree["worktree"],
        "base_commit": worktree["base_commit"],
        "status": "PATCHED",
        "auto_merge": False,
    }
    release.setdefault("remediation_tasks", []).append(task)
    release["state"] = "VERIFYING"
    release_path.write_text(json.dumps(release, indent=2), encoding="utf-8")
    print(json.dumps(task, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
