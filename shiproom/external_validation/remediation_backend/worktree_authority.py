#!/usr/bin/env python3
"""Capture immutable worktree authority immediately after supervisor creation."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path

def mount_id(path: Path) -> int:
    target = path.resolve()
    best: tuple[int, Path] | None = None
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left = line.split(" - ", 1)[0].split()
        if len(left) < 5: continue
        candidate = Path(left[4].replace("\\040", " "))
        try: target.relative_to(candidate)
        except ValueError: continue
        if best is None or len(str(candidate)) > len(str(best[1])): best = (int(left[0]), candidate)
    if best is None: raise RuntimeError("mount_id_unavailable")
    return best[0]

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--backend-instance",required=True); p.add_argument("--attempt",required=True); p.add_argument("--project",type=int,required=True); p.add_argument("--path",type=Path,required=True); p.add_argument("--source-snapshot-hash",required=True); a=p.parse_args()
    path=a.path.resolve(strict=True); st=path.stat(follow_symlinks=False)
    expected_uid = os.geteuid() if os.environ.get("SHIPROOM_REMEDIATION_TEST_MODE") == "1" else 65533
    expected_gid = os.getegid() if os.environ.get("SHIPROOM_REMEDIATION_TEST_MODE") == "1" else 65533
    if not path.is_dir() or st.st_uid != expected_uid or st.st_gid != expected_gid: raise SystemExit("worktree_owner_invalid")
    authority={"backend_instance_id":a.backend_instance,"attempt_id":a.attempt,"project_id":a.project,"allocation_record_id":a.attempt,"capacity_reservation_id":str(a.project),"canonical_path":str(path),"path_hash":"sha256:"+hashlib.sha256(str(path).encode()).hexdigest(),"device":st.st_dev,"inode":st.st_ino,"mount_id":mount_id(path),"uid":st.st_uid,"gid":st.st_gid,"source_snapshot_hash":a.source_snapshot_hash}
    print(json.dumps(authority,sort_keys=True,separators=(",",":")))
    return 0
if __name__=="__main__": raise SystemExit(main())
