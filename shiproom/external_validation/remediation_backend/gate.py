#!/usr/bin/env python3
"""Non-root, content-addressed Stage-0 gate for a remediation bundle."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, subprocess
from datetime import datetime, timezone
from pathlib import Path

FILES=("lib.sh","setup.sh","start.sh","status.sh","recover.sh","teardown.sh","quota-worktree.sh","bounded-log.py","control.py","migration.py","lifecycle.py","contracts.py","package_contract.py","path_authority.py","worktree_authority.py","release_helper.py","residual.py","xfs_project.py","lock_guard.py","release.py","doctor.py","bootstrap.py","gate.py","tests.sh","control_contract_tests.py")
SCHEMAS=("remediation-release-authorization.v1.json","remediation-package-contract.v1.json")
PRODUCTION_FILES=("identity.py","security.py","v2.py","receipts_v2.py")
APPROVED_BUNDLE=Path("/mnt/c/Users/Kruthika Kumar/Documents/Projects/Hermes buildathon - Shiproom/shiproom/external_validation/remediation_backend")
def sha(path:Path)->str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def trusted_host_executable(path:Path)->Path:
    """Stage 0 never inherits tool authority from a caller-controlled PATH."""
    item=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_mode&0o022 or not item.st_mode&0o111:
        raise SystemExit("stage0_tool_untrusted:"+str(path))
    return path
def canonical_bundle(bundle:Path)->tuple[Path,Path]:
    resolved=bundle.resolve(); approved=APPROVED_BUNDLE.resolve()
    if resolved!=approved: raise SystemExit("gate_bundle_not_approved")
    repo=approved.parents[2]
    if approved.name!="remediation_backend" or approved.parent.name!="external_validation" or approved.parents[1].name!="shiproom": raise SystemExit("gate_bundle_layout_invalid")
    return approved,repo
def git_environment(repository:Path)->dict[str,str]:
    """Closed Git environment: no caller-owned GIT_* variables cross the gate."""
    return {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/tmp","LANG":"C.UTF-8","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_TERMINAL_PROMPT":"0","GIT_CONFIG_COUNT":"2","GIT_CONFIG_KEY_0":"core.autocrlf","GIT_CONFIG_VALUE_0":"true","GIT_CONFIG_KEY_1":"safe.directory","GIT_CONFIG_VALUE_1":str(repository)}
def run(command:list[str],cwd:Path,repository:Path|None=None)->dict:
    result=subprocess.run(command,cwd=cwd,text=True,capture_output=True,check=False,env=git_environment(repository) if command and Path(command[0]).name=="git" and repository else None)
    return {"command":command,"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr}
def required(result:dict,name:str)->str:
    if result["exit_code"]: raise SystemExit(name)
    return result["stdout"].strip()
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("bundle",type=Path); p.add_argument("--commit",required=True); p.add_argument("--tree",required=True); p.add_argument("--out",type=Path,required=True); a=p.parse_args()
    if os.geteuid()==0: raise SystemExit("stage0_must_be_nonroot")
    bundle,expected_repo=canonical_bundle(a.bundle)
    git=str(trusted_host_executable(Path("/usr/bin/git")))
    repo=Path(required(run([git,"rev-parse","--show-toplevel"],bundle,expected_repo),"gate_repository_missing")).resolve()
    if repo!=expected_repo: raise SystemExit("gate_repository_not_approved")
    if required(run([git,"rev-parse","HEAD"],repo,repo),"gate_head_missing")!=a.commit or required(run([git,"rev-parse","HEAD^{tree}"],repo,repo),"gate_tree_missing")!=a.tree: raise SystemExit("gate_commit_tree_mismatch")
    if required(run([git,"status","--porcelain"],repo,repo),"gate_status_missing"): raise SystemExit("gate_worktree_dirty")
    bundle_files={name:sha(bundle/name) for name in FILES}; production_files={name:sha(bundle.parent/name) for name in PRODUCTION_FILES}
    schema_dir=bundle.parent/"schemas"; schemas={name:sha(schema_dir/name) for name in SCHEMAS}
    bash=str(trusted_host_executable(Path("/usr/bin/bash")))
    shellcheck=str(trusted_host_executable(Path("/usr/bin/shellcheck")))
    commands=[run([bash,"-n",*filter(lambda x:x.endswith(".sh"),FILES)],bundle),run([bash,"tests.sh"],bundle),run([git,"diff","--check"],repo,repo),run([shellcheck,"--version"],bundle),run([shellcheck,"-S","warning",*filter(lambda x:x.endswith(".sh"),FILES)],bundle)]
    if any(item["exit_code"] for item in commands): raise SystemExit("stage0_gate_failed")
    data={"schema_id":"remediation_stage0_attestation.v1","schema_version":"1","commit":a.commit,"tree":a.tree,"bundle_files":bundle_files,"schemas":schemas,"production_files":production_files,"shellcheck":{"path":shellcheck,"hash":sha(Path(shellcheck)),"version":commands[3]["stdout"]},"commands":commands,"created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    data["attestation_hash"]="sha256:"+hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    a.out.write_text(json.dumps(data,sort_keys=True,separators=(",",":")),encoding="utf-8")
    print(data["attestation_hash"]); return 0
if __name__=="__main__": raise SystemExit(main())
