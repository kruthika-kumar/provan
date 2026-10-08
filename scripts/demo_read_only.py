"""Make a disposable repository and review it with the installed Provan CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(argv: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(argv[:2])} failed ({result.returncode}): {result.stderr.strip()[:500]}")
    return result.stdout


def snapshot(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provan", default=shutil.which("provan"), help="Path to an installed provan command")
    parser.add_argument("--workspace", type=Path, help="Empty directory outside the Provan checkout; omitted creates an OS temporary directory")
    args = parser.parse_args()
    if not args.provan:
        parser.error("install Provan in an isolated environment or pass --provan")
    workspace = args.workspace.resolve() if args.workspace else Path(tempfile.mkdtemp(prefix="provan-read-only-demo-")).resolve()
    checkout = Path(__file__).resolve().parents[1]
    if workspace == checkout or checkout in workspace.parents:
        parser.error("the demo workspace must be outside the Provan checkout")
    if workspace.exists() and any(workspace.iterdir()):
        parser.error("--workspace must be empty")
    workspace.mkdir(parents=True, exist_ok=True)
    target = workspace / "sample-repository"
    target.mkdir()
    (target / "README.md").write_text("# Small reading list\n\nA local example for source-only review.\n", encoding="utf-8")
    (target / "books.py").write_text("def titles(books):\n    return [book['title'] for book in books]\n", encoding="utf-8")
    env = dict(os.environ)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "PYTHONPATH"):
        env.pop(name, None)
    env["PROVAN_HOME"] = str(workspace / "provan-state")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    run(["git", "init", "--quiet"], cwd=target, env=env)
    run(["git", "add", "README.md", "books.py"], cwd=target, env=env)
    run(["git", "-c", "user.name=Demo", "-c", "user.email=demo", "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Add a small reading list"], cwd=target, env=env)
    commit = run(["git", "rev-parse", "HEAD"], cwd=target, env=env).strip()
    before = snapshot(target)
    inspect = json.loads(run([str(args.provan), "repository", "inspect", "--repo", str(target), "--base", commit, "--head", commit, "--mode", "source-only"], cwd=workspace, env=env))
    review = run([str(args.provan), "explain", "--repo", str(target), "--base", commit, "--head", commit, "--brief", "Review this small reading-list repository.", "--no-model", "--format", "markdown"], cwd=workspace, env=env)
    review_path = workspace / "review.md"
    review_path.write_text(review, encoding="utf-8")
    after = snapshot(target)
    if before != after or not inspect["target_unchanged"] or inspect["executed_repository_code"]:
        raise RuntimeError("source-only inspection changed or executed the target repository")
    print(json.dumps({"workspace": str(workspace), "review": str(review_path), "inspection_receipt": inspect["output_path"], "target_unchanged": True, "repository_code_executed": False, "model_used": False}, indent=2))


if __name__ == "__main__":
    main()
