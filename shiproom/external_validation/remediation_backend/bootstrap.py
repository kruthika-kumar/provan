#!/usr/bin/env python3
"""The sole, data-verified root bootstrap for a staged remediation bundle."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, stat, subprocess, sys
from pathlib import Path

ROOT=Path("/run/shiproom-remediation-bootstrap")
APPROVED_SOURCE=Path("/mnt/c/Users/Kruthika Kumar/Documents/Projects/Hermes buildathon - Shiproom/shiproom/external_validation/remediation_backend")
FILES=("lib.sh","setup.sh","start.sh","status.sh","recover.sh","teardown.sh","quota-worktree.sh","bounded-log.py","control.py","migration.py","lifecycle.py","contracts.py","package_contract.py","path_authority.py","worktree_authority.py","release_helper.py","residual.py","xfs_project.py","lock_guard.py","release.py","doctor.py","bootstrap.py","gate.py","tests.sh","control_contract_tests.py")
SCHEMAS=("remediation-release-authorization.v1.json","remediation-package-contract.v1.json")
PRODUCTION_FILES=("identity.py","security.py","v2.py","receipts_v2.py")
def canonical(value:object)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def sha(path:Path)->str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def trusted_host_executable(path:Path)->None:
    item=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_mode&0o022 or not item.st_mode&0o111: raise RuntimeError("attestation_tool_untrusted")
def canonical_source(source:Path)->tuple[Path,Path]:
    """Bind root Git checks to the one reviewed WSL worktree, before Git runs."""
    resolved=source.resolve()
    approved=APPROVED_SOURCE.resolve()
    if resolved!=approved:
        raise RuntimeError("bootstrap_source_not_approved")
    repo=approved.parents[2]
    if approved.name!="remediation_backend" or approved.parent.name!="external_validation" or approved.parents[1].name!="shiproom":
        raise RuntimeError("bootstrap_source_layout_invalid")
    return approved,repo
def git_environment(repository:Path)->dict[str,str]:
    """A closed Git environment; never inherit caller-controlled GIT_* state."""
    return {
        "PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "HOME":"/root", "LANG":"C.UTF-8",
        "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null", "GIT_TERMINAL_PROMPT":"0",
        "GIT_CONFIG_COUNT":"2", "GIT_CONFIG_KEY_0":"core.autocrlf", "GIT_CONFIG_VALUE_0":"true",
        "GIT_CONFIG_KEY_1":"safe.directory", "GIT_CONFIG_VALUE_1":str(repository),
    }
def git_output(repository:Path,*args:str)->str:
    return subprocess.check_output(["/usr/bin/git","-C",str(repository),*args],text=True,env=git_environment(repository)).strip()
def regular(path:Path)->None:
    item=path.lstat()
    if not stat.S_ISREG(item.st_mode): raise RuntimeError("provenance_not_regular")
def secure_root_directory(path:Path, mode:int=0o700)->None:
    """Create/verify a fixed root-owned directory without traversing a link."""
    try:
        os.mkdir(path,mode)
    except FileExistsError:
        pass
    item=path.lstat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid!=0 or item.st_gid!=0 or item.st_mode&0o022:
        raise RuntimeError("bootstrap_directory_untrusted")
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd)
        if opened.st_dev!=item.st_dev or opened.st_ino!=item.st_ino: raise RuntimeError("bootstrap_directory_raced")
        if stat.S_IMODE(opened.st_mode)!=mode:
            os.fchmod(fd,mode); os.fsync(fd)
    finally:
        os.close(fd)
def source_manifest(source:Path)->dict[str,object]:
    schema_dir=source/"schemas" if (source/"schemas").is_dir() else source.parent/"schemas"
    files={}; schemas={}; production={}
    for name in FILES:
        path=source/name; regular(path); files[name]=sha(path)
    for name in SCHEMAS:
        path=schema_dir/name; regular(path); schemas[name]=sha(path)
    for name in PRODUCTION_FILES:
        path=source.parent/name; regular(path); production[name]=sha(path)
    return {"files":files,"schemas":schemas,"production_files":production}
def source_root(source:Path)->Path:
    trusted_host_executable(Path("/usr/bin/git"))
    approved,expected_repo=canonical_source(source)
    repo=Path(git_output(expected_repo,"rev-parse","--show-toplevel")).resolve()
    if repo!=expected_repo or approved!=(repo/"shiproom/external_validation/remediation_backend").resolve():
        raise RuntimeError("bootstrap_source_not_canonical")
    return repo
def validate_attestation(path:Path,source:Path,commit:str,tree:str)->dict[str,object]:
    regular(path); data=json.loads(path.read_text(encoding="utf-8"))
    required={"schema_id","schema_version","commit","tree","bundle_files","schemas","production_files","shellcheck","commands","created_at","attestation_hash"}
    if set(data)!=required or data["schema_id"]!="remediation_stage0_attestation.v1" or data["schema_version"]!="1": raise RuntimeError("attestation_shape_invalid")
    claimed=data.pop("attestation_hash")
    if claimed!="sha256:"+hashlib.sha256(canonical(data)).hexdigest(): raise RuntimeError("attestation_hash_invalid")
    data["attestation_hash"]=claimed
    if data["commit"]!=commit or data["tree"]!=tree or data["bundle_files"]!=source_manifest(source)["files"] or data["schemas"]!=source_manifest(source)["schemas"] or data["production_files"]!=source_manifest(source)["production_files"]: raise RuntimeError("attestation_binding_mismatch")
    commands=data["commands"]
    if not isinstance(commands,list) or len(commands)!=5 or any(not isinstance(row,dict) or row.get("exit_code")!=0 or not isinstance(row.get("command"),list) for row in commands): raise RuntimeError("attestation_commands_invalid")
    expected_shells=[name for name in FILES if name.endswith(".sh")]
    if commands[0]["command"]!=["/usr/bin/bash","-n",*expected_shells] or commands[1]["command"]!=["/usr/bin/bash","tests.sh"] or commands[2]["command"]!=["/usr/bin/git","diff","--check"]: raise RuntimeError("attestation_commands_invalid")
    if commands[3]["command"]!=["/usr/bin/shellcheck","--version"] or commands[4]["command"]!=["/usr/bin/shellcheck","-S","warning",*expected_shells]: raise RuntimeError("attestation_commands_invalid")
    shell=data["shellcheck"]
    if not isinstance(shell,dict) or shell.get("path")!="/usr/bin/shellcheck" or shell.get("hash")!=sha(Path("/usr/bin/shellcheck")) or not shell.get("version"): raise RuntimeError("attestation_shellcheck_invalid")
    for executable in (Path("/usr/bin/bash"),Path("/usr/bin/git"),Path("/usr/bin/shellcheck")): trusted_host_executable(executable)
    return data
def staged_manifest(source:Path,attestation:dict[str,object],commit:str,tree:str)->dict[str,object]:
    body={"schema_id":"remediation_staged_bundle.v1","schema_version":"1","source_commit":commit,"source_tree":tree,"source_manifest":source_manifest(source),"attestation_hash":attestation["attestation_hash"]}
    body["bundle_hash"]="sha256:"+hashlib.sha256(canonical(body)).hexdigest(); return body
def verify_stage(target:Path)->None:
    if not target.is_absolute() or target.parent!=ROOT or len(target.name)!=64 or any(c not in "0123456789abcdef" for c in target.name): raise RuntimeError("staged_path_invalid")
    manifest_path=target/"manifest.json"; regular(manifest_path); manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("bundle_hash")!="sha256:"+target.name or manifest.get("schema_id")!="remediation_staged_bundle.v1": raise RuntimeError("staged_manifest_identity_invalid")
    for path in [target/name for name in FILES]+[target/name for name in PRODUCTION_FILES]+[target/"schemas"/name for name in SCHEMAS]+[target/"stage0-attestation.json",manifest_path]:
        regular(path); item=path.stat()
        if item.st_uid!=0 or item.st_mode&0o022: raise RuntimeError("staged_ownership_invalid")
    expected=manifest["source_manifest"]
    if {name:sha(target/name) for name in FILES}!=expected["files"] or {name:sha(target/name) for name in PRODUCTION_FILES}!=expected["production_files"] or {name:sha(target/"schemas"/name) for name in SCHEMAS}!=expected["schemas"]: raise RuntimeError("staged_hash_mismatch")
    attestation=validate_attestation(target/"stage0-attestation.json",target,manifest["source_commit"],manifest["source_tree"])
    if attestation["attestation_hash"]!=manifest["attestation_hash"]: raise RuntimeError("staged_attestation_mismatch")
def require_staged_script(script:Path)->None:
    verify_stage(script.resolve().parent)
def approval_path(attestation_hash:str)->Path:
    return ROOT/"approvals"/attestation_hash.removeprefix("sha256:")
def approve(source:Path,attestation_path:Path,commit:str,tree:str)->Path:
    source_root(source); attestation=validate_attestation(attestation_path,source,commit,tree)
    secure_root_directory(ROOT,0o755); secure_root_directory(ROOT/"approvals",0o700)
    path=approval_path(str(attestation["attestation_hash"]))
    body={"schema_id":"remediation_stage0_approval.v1","schema_version":"1","attestation_hash":attestation["attestation_hash"],"commit":commit,"tree":tree}
    parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=parent_fd)
        with os.fdopen(fd,"wb") as handle:
            os.fchown(handle.fileno(),0,0); os.fchmod(handle.fileno(),0o400); handle.write(canonical(body)); handle.flush(); os.fsync(handle.fileno())
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return path
def verify_approval(attestation:dict[str,object],commit:str,tree:str)->None:
    path=approval_path(str(attestation["attestation_hash"])); regular(path); item=path.stat()
    if item.st_uid!=0 or item.st_mode&0o022: raise RuntimeError("stage0_approval_untrusted")
    value=json.loads(path.read_text(encoding="utf-8"))
    if value!={"schema_id":"remediation_stage0_approval.v1","schema_version":"1","attestation_hash":attestation["attestation_hash"],"commit":commit,"tree":tree}: raise RuntimeError("stage0_approval_mismatch")
def rerun_privileged_gate(staged:Path, repository:Path)->None:
    """Root rechecks static tools and reruns behavioral shims as nobody.

    Test mode explicitly rejects EUID 0, so the bootstrap deliberately drops
    to the kernel's unprivileged nobody IDs for that subprocess.  This is a
    temporary credential drop only; it creates no account and changes no host
    configuration.
    """
    bash=Path("/usr/bin/bash"); shellcheck=Path("/usr/bin/shellcheck"); git=Path("/usr/bin/git")
    for executable in (bash,shellcheck,git): trusted_host_executable(executable)
    shells=[name for name in FILES if name.endswith(".sh")]
    def required(command:list[str], *, dropped:bool=False)->None:
        def demote()->None:
            os.setgroups([]); os.setgid(65534); os.setuid(65534)
        is_git=command[0]==str(git)
        result=subprocess.run(command,cwd=repository if is_git else staged,text=True,capture_output=True,check=False,env=git_environment(repository) if is_git else None,preexec_fn=demote if dropped else None,timeout=120)
        if result.returncode: raise RuntimeError("bootstrap_gate_failed:"+Path(command[0]).name)
    required([str(bash),"-n",*shells])
    required([str(shellcheck),"-S","warning",*shells])
    required([str(git),"diff","--check"])
    required([str(bash),"tests.sh"],dropped=True)
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("source",type=Path,nargs="?"); p.add_argument("--tree"); p.add_argument("--commit"); p.add_argument("--attestation",type=Path); p.add_argument("--stage",action="store_true"); p.add_argument("--approve-attestation",action="store_true"); p.add_argument("--verify-staged",type=Path); a=p.parse_args()
    os.environ["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin"
    if a.verify_staged:
        if os.geteuid()!=0: raise SystemExit("bootstrap_root_required")
        verify_stage(a.verify_staged); print("staged_bundle_verified"); return 0
    if not (a.stage or a.approve_attestation) or not a.source or not a.commit or not a.tree or not a.attestation: raise SystemExit("bootstrap_arguments_invalid")
    if os.geteuid()!=0: raise SystemExit("bootstrap_root_required")
    source=a.source.resolve(); repo=source_root(source)
    head=git_output(repo,"rev-parse","HEAD"); actual_tree=git_output(repo,"rev-parse","HEAD^{tree}")
    if head!=a.commit or actual_tree!=a.tree or git_output(repo,"status","--porcelain"): raise SystemExit("unclean_or_wrong_commit")
    if a.approve_attestation: print(approve(source,a.attestation,a.commit,a.tree)); return 0
    attestation=validate_attestation(a.attestation,source,a.commit,a.tree); verify_approval(attestation,a.commit,a.tree); manifest=staged_manifest(source,attestation,a.commit,a.tree); secure_root_directory(ROOT,0o755); target=ROOT/manifest["bundle_hash"].removeprefix("sha256:")
    target.mkdir(parents=True,mode=0o755,exist_ok=False)
    for name in FILES:
        out=target/name; shutil.copyfile(source/name,out); os.chown(out,0,0); out.chmod(0o555 if out.suffix==".sh" else 0o444)
    for name in PRODUCTION_FILES:
        out=target/name; shutil.copyfile(source.parent/name,out); os.chown(out,0,0); out.chmod(0o444)
    schemas=target/"schemas"; schemas.mkdir(mode=0o755); os.chown(schemas,0,0)
    for name in SCHEMAS:
        out=schemas/name; shutil.copyfile(source.parent/"schemas"/name,out); os.chown(out,0,0); out.chmod(0o444)
    staged_attestation=target/"stage0-attestation.json"; shutil.copyfile(a.attestation,staged_attestation); os.chown(staged_attestation,0,0); staged_attestation.chmod(0o400)
    out=target/"manifest.json"; out.write_bytes(canonical(manifest)); os.chown(out,0,0); out.chmod(0o400)
    verify_stage(target); rerun_privileged_gate(target,repo); print(manifest["bundle_hash"]); return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except (RuntimeError,OSError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"bootstrap_error:{exc}",file=sys.stderr); raise SystemExit(2)
