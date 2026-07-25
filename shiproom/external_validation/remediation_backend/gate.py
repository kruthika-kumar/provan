#!/usr/bin/env python3
"""Non-root, content-addressed Stage-0 gate for a remediation bundle."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, subprocess
from datetime import datetime, timezone
from pathlib import Path

FILES=("lib.sh","setup.sh","start.sh","status.sh","recover.sh","teardown.sh","quota-worktree.sh","bounded-log.py","control.py","contracts.py","package_contract.py","path_authority.py","worktree_authority.py","release_helper.py","residual.py","xfs_project.py","lock_guard.py","release.py","doctor.py","bootstrap.py","gate.py","tests.sh","control_contract_tests.py")
SCHEMAS=("remediation-release-authorization.v1.json","remediation-package-contract.v1.json")
def sha(path:Path)->str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def trusted_host_executable(path:Path)->Path:
    """Stage 0 never inherits tool authority from a caller-controlled PATH."""
    item=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_mode&0o022 or not item.st_mode&0o111:
        raise SystemExit("stage0_tool_untrusted:"+str(path))
    return path
def git_environment(path:Path)->dict[str,str]|None:
    """Match the approved Windows worktree's line-ending view without mutating it.

    The Stage-0 gate is executed inside WSL but the authoritative repository is
    Windows-mounted and committed with ``core.autocrlf=true``.  Git otherwise
    reports an artificial dirty tree solely from that view difference.  This
    environment-local override is deliberately limited to mounted Windows
    worktrees; no git configuration is written or changed.
    """
    try: mounted_windows=path.resolve().is_relative_to(Path("/mnt/c"))
    except AttributeError: mounted_windows=str(path.resolve()).startswith("/mnt/c/")
    if not mounted_windows: return None
    result=dict(os.environ)
    result.update({"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"core.autocrlf","GIT_CONFIG_VALUE_0":"true"})
    return result
def run(command:list[str],cwd:Path)->dict:
    result=subprocess.run(command,cwd=cwd,text=True,capture_output=True,check=False,env=git_environment(cwd) if command and Path(command[0]).name=="git" else None)
    return {"command":command,"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr}
def required(result:dict,name:str)->str:
    if result["exit_code"]: raise SystemExit(name)
    return result["stdout"].strip()
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("bundle",type=Path); p.add_argument("--commit",required=True); p.add_argument("--tree",required=True); p.add_argument("--out",type=Path,required=True); a=p.parse_args()
    if os.geteuid()==0: raise SystemExit("stage0_must_be_nonroot")
    git=str(trusted_host_executable(Path("/usr/bin/git")))
    repo=Path(required(run([git,"rev-parse","--show-toplevel"],a.bundle),"gate_repository_missing"))
    if required(run([git,"rev-parse","HEAD"],repo),"gate_head_missing")!=a.commit or required(run([git,"rev-parse","HEAD^{tree}"],repo),"gate_tree_missing")!=a.tree: raise SystemExit("gate_commit_tree_mismatch")
    if required(run([git,"status","--porcelain"],repo),"gate_status_missing"): raise SystemExit("gate_worktree_dirty")
    bundle_files={name:sha(a.bundle/name) for name in FILES}
    schema_dir=a.bundle.parent/"schemas"; schemas={name:sha(schema_dir/name) for name in SCHEMAS}
    bash=str(trusted_host_executable(Path("/usr/bin/bash")))
    shellcheck=str(trusted_host_executable(Path("/usr/bin/shellcheck")))
    commands=[run([bash,"-n",*filter(lambda x:x.endswith(".sh"),FILES)],a.bundle),run([bash,"tests.sh"],a.bundle),run([git,"diff","--check"],repo),run([shellcheck,"--version"],a.bundle),run([shellcheck,"-S","warning",*filter(lambda x:x.endswith(".sh"),FILES)],a.bundle)]
    if any(item["exit_code"] for item in commands): raise SystemExit("stage0_gate_failed")
    data={"schema_id":"remediation_stage0_attestation.v1","schema_version":"1","commit":a.commit,"tree":a.tree,"bundle_files":bundle_files,"schemas":schemas,"shellcheck":{"path":shellcheck,"hash":sha(Path(shellcheck)),"version":commands[3]["stdout"]},"commands":commands,"created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    data["attestation_hash"]="sha256:"+hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    a.out.write_text(json.dumps(data,sort_keys=True,separators=(",",":")),encoding="utf-8")
    print(data["attestation_hash"]); return 0
if __name__=="__main__": raise SystemExit(main())
