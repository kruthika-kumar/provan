from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from shiproom.project import canonical_json


def _hashes(root:Path)->dict[str,str]:
    if not root.exists(): return {}
    return {path.relative_to(root).as_posix():hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(root.rglob("*")) if path.is_file()}


def snapshot_measurement_ai_read_only(ctx)->dict:
    release_root=ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]
    def git(*args): return subprocess.run(["git",*args],cwd=ctx.repository_root,text=True,capture_output=True,check=True).stdout
    release_path=next((path for path in (ctx.repository_root/"release-state").glob("*.json") if json.loads(path.read_text()).get("release_id")==ctx.release["release_id"]),None) if (ctx.repository_root/"release-state").exists() else None
    return {"release_object":canonical_json(ctx.release),"release_file":release_path.read_bytes() if release_path else None,"intent":_hashes(release_root/"product-intent"),"graph":_hashes(release_root/"requirement-evidence-graph"),"assessment":_hashes(release_root/"assessment"),"project_contract":_hashes(ctx.repository_root/".shiproom"),"head":git("rev-parse","HEAD").strip(),"branch":git("branch","--show-current").strip(),"status":git("status","--short","--untracked-files=no"),"tracked_blobs":git("ls-files","-s")}


def assert_measurement_ai_read_only(ctx,before:dict)->None:
    after=snapshot_measurement_ai_read_only(ctx)
    for key in before:
        if key=="project_contract": continue
        if after[key]!=before[key]: raise AssertionError(f"Session 5 mutated upstream authority: {key}")
    # Only the ignored Measurement & AI root and qualification store may change.
    root=ctx.repository_root/".shiproom"; allowed=("local/releases/"+ctx.release["release_id"]+"/measurement-ai-readiness/","local/measurement-reviewer-qualifications/")
    changed={path for path,value in after["project_contract"].items() if before["project_contract"].get(path)!=value}|(set(before["project_contract"])-set(after["project_contract"]))
    if any(not path.startswith(allowed) for path in changed): raise AssertionError("Session 5 wrote outside its ignored roots")
