from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BASELINE = "1cdc50d05115f8385b14ad1eee62e169fec6436d"
EXPECTED_TREE = "c71b55c60967cc10198412994541d5f65f537149"


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True,
        text=True, encoding="utf-8", errors="strict",
    ).stdout.strip()


def extract_bounded_archive(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > 4096 or sum(item.file_size for item in members) > 64 * 1024 * 1024:
            raise SystemExit("SESSION10_SUCCESSOR_ARCHIVE_BOUNDS_EXCEEDED")
        for item in members:
            relative = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts) or stat.S_ISLNK(mode):
                raise SystemExit("SESSION10_SUCCESSOR_ARCHIVE_PATH_UNSAFE")
            target = destination.joinpath(*relative.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = bundle.read(item)
            if len(raw) != item.file_size:
                raise SystemExit("SESSION10_SUCCESSOR_ARCHIVE_SIZE_MISMATCH")
            target.write_bytes(raw)


def main() -> int:
    work_order = json.loads((ROOT / "artifacts/session11/work_order.v1.public.json").read_text(encoding="utf-8"))
    baseline = work_order.get("baseline", {})
    if baseline.get("commit") != EXPECTED_BASELINE or baseline.get("package") != "0.3.0" or baseline.get("status") != "CLOSED":
        raise SystemExit("SESSION10_SUCCESSOR_BASELINE_BINDING_MISMATCH")
    if git("rev-parse", f"{EXPECTED_BASELINE}^{{tree}}") != EXPECTED_TREE:
        raise SystemExit("SESSION10_SUCCESSOR_BASELINE_TREE_MISMATCH")
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", EXPECTED_BASELINE, "HEAD"], cwd=ROOT)
    if ancestor.returncode:
        raise SystemExit("SESSION10_SUCCESSOR_LINEAGE_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="provan-session10-successor-") as temp:
        temp_root = Path(temp)
        archive = temp_root / "session10.zip"
        subprocess.run(["git", "archive", "--format=zip", f"--output={archive}", EXPECTED_BASELINE], cwd=ROOT, check=True)
        snapshot = temp_root / "snapshot"
        snapshot.mkdir()
        extract_bounded_archive(archive, snapshot)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(snapshot)
        completed = subprocess.run(
            [sys.executable, "scripts/validate_session10.py", "--phase", "final"],
            cwd=snapshot, env=env, text=True, encoding="utf-8", errors="strict",
            capture_output=True,
        )
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
        if completed.returncode:
            raise SystemExit("SESSION10_SUCCESSOR_HISTORICAL_GATE_FAILED")
    print("SESSION10_SUCCESSOR_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
