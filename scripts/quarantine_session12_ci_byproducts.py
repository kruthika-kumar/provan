from __future__ import annotations

import os
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_session12_authoritative_gate import quarantine_local_test_outputs


def _linked_or_reparse(path: Path) -> bool:
    stat = path.lstat()
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)


def _require_safe_existing_directory(path: Path) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() or _linked_or_reparse(current) or not current.is_dir():
            raise SystemExit("SESSION12_CI_QUARANTINE_PATH_UNSAFE")
    return absolute


def _require_safe_contained_tree(path: Path, boundary: Path) -> None:
    resolved_boundary = boundary.resolve(strict=True)
    for current in (path, *path.rglob("*")):
        if _linked_or_reparse(current):
            raise SystemExit("SESSION12_CI_QUARANTINE_PATH_UNSAFE")
        resolved = current.resolve(strict=True)
        if resolved != resolved_boundary and resolved_boundary not in resolved.parents:
            raise SystemExit("SESSION12_CI_QUARANTINE_PATH_UNSAFE")


def main() -> int:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise SystemExit("SESSION12_CI_QUARANTINE_ROOT_MISSING")
    runner_root = _require_safe_existing_directory(Path(runner_temp))
    transcript_root = runner_root / ("provan-session12-ci-quarantine-" + uuid4().hex)
    repo = ROOT.resolve()
    if runner_root == repo or repo in runner_root.parents or runner_root in repo.parents:
        raise SystemExit("SESSION12_CI_QUARANTINE_SEPARATION_INVALID")
    transcript_root.mkdir(exist_ok=False)
    _require_safe_contained_tree(transcript_root, runner_root)
    count, receipt = quarantine_local_test_outputs(repo, transcript_root)
    (transcript_root / "quarantine-receipt.txt").write_bytes(receipt)
    _require_safe_contained_tree(transcript_root, runner_root)
    print(f"SESSION12_CI_LOCAL_BYPRODUCTS_QUARANTINED:{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
