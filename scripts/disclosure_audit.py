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
    parser = argparse.ArgumentParser(); parser.add_argument("--repo", default="."); parser.add_argument("--output", default="disclosure-audit.json"); parser.add_argument("--public-dir")
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
    public_files = 0
    if args.public_dir:
        public_root = Path(args.public_dir).resolve()
        if not public_root.is_dir(): findings.append({"rule": "public_dir_missing", "path": str(public_root)})
        else:
            forbidden_public = {"repository.path": r"repository\.path", "canonical_dump": r"Canonical release object", "raw_prompt": r"raw[_ -]?prompt", "provider_response": r"(?:complete|raw)[_ -]?(?:model|provider)[_ -]?response", "private_drawdb": r"(?i)drawdb|rel_70e7648a0731|deleg_fa605658|20260712_151747_d9963a", "windows_path": r"(?<![A-Za-z])[A-Za-z]:[\\/]", "file_url": r"file://"}
            for target in public_root.rglob("*"):
                if not target.is_file(): continue
                public_files += 1
                try: content = target.read_text(encoding="utf-8")
                except UnicodeDecodeError: continue
                for name, pattern in {**RULES, **forbidden_public}.items():
                    if re.search(pattern, content): findings.append({"rule": name, "path": str(target.relative_to(public_root))})
    result = {"status": "PASS" if not findings and not status else "FAIL", "tracked_files": len(tracked), "history_paths": len(set(history_paths)), "findings": findings, "worktree_clean": not bool(status)}
    result["public_files_scanned"] = public_files
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
