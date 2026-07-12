from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

RULES = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
    "provider_key": r"sk-[A-Za-z0-9]{20,}",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "assigned_secret": r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{8,}",
}
FORBIDDEN_NAMES = re.compile(r"(?i)(^|/)(\.env(?:\..*)?|credentials?|session-exports?|release-state|evidence|.*\.(?:pem|key))($|/)")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--repo", default="."); parser.add_argument("--output", default="disclosure-audit.json")
    args = parser.parse_args(); repo = Path(args.repo).resolve()
    tracked = [line for line in git(repo, "ls-files").splitlines() if line]
    history_paths = [line for line in git(repo, "log", "--all", "--name-only", "--pretty=format:").splitlines() if line]
    patch = git(repo, "log", "--all", "-p", "--full-history", "--", ".")
    findings = []
    for path in sorted(set(tracked + history_paths)):
        if FORBIDDEN_NAMES.search(path.replace("\\", "/")): findings.append({"rule": "forbidden_path", "path": path})
    for name, pattern in RULES.items():
        count = len(re.findall(pattern, patch))
        if count: findings.append({"rule": name, "matches": count})
    status = git(repo, "status", "--porcelain", "--untracked-files=all").strip()
    result = {"status": "PASS" if not findings and not status else "FAIL", "tracked_files": len(tracked), "history_paths": len(set(history_paths)), "findings": findings, "worktree_clean": not bool(status)}
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
