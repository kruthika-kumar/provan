from __future__ import annotations

import argparse
import json
import shutil
import threading
from pathlib import Path

from shiproom.evidence import http_check
from shiproom.remediation import BRANCH_PREFIX, ROUTE_TARGETS, _assert_route_state, current_branch, git, repository_root, validate_branch


RUNTIME_DIRS = ("release-state", "evidence", "dist", "reports", "session-exports", "audio")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--release", default="release-state/release.json")
    args = parser.parse_args()
    repo = repository_root(Path(args.repo))
    release_path = Path(args.release).resolve()
    release = json.loads(release_path.read_text(encoding="utf-8"))
    base = release.get("repository", {}).get("base_branch")
    tasks = release.get("remediation_tasks", [])
    branch = tasks[-1].get("branch") if tasks else None
    if not base or not branch:
        raise ValueError("reset requires recorded base and remediation branches")
    validate_branch(branch, release["release_id"])
    if not branch.startswith(BRANCH_PREFIX):
        raise ValueError("refusing to delete a non-Shiproom branch")
    if current_branch(repo) != base:
        git(repo, "switch", base)
    if git(repo, "branch", "--list", branch).stdout.strip():
        git(repo, "branch", "-D", branch)
    for relative, (broken, fixed) in ROUTE_TARGETS.items():
        _assert_route_state(repo / relative, broken, fixed, expect_broken=True)
    for name in RUNTIME_DIRS:
        path = repo / name
        if path.exists():
            shutil.rmtree(path)
    from demo_patient.server import Handler, ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        check = http_check(f"http://127.0.0.1:{server.server_port}/result/demo")
        if check.get("status") != 404:
            raise ValueError(f"reset verification failed: {check}")
    finally:
        server.shutdown(); thread.join(timeout=5); server.server_close()
    if current_branch(repo) != base:
        raise ValueError("reset did not restore the recorded base branch")
    status = git(repo, "status", "--porcelain", "--untracked-files=all").stdout.strip()
    if status:
        raise ValueError(f"reset left tracked or unexpected changes:\n{status}")
    print(json.dumps({"status": "RESET", "base_branch": base, "deleted_branch": branch, "public_result_status": 404}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
