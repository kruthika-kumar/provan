#!/usr/bin/env python3
"""The sole, data-verified root bootstrap for a staged remediation bundle."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, stat, subprocess, sys
from pathlib import Path

ROOT=Path("/run/shiproom-remediation-bootstrap")
FILES=("lib.sh","setup.sh","start.sh","status.sh","recover.sh","teardown.sh","quota-worktree.sh","bounded-log.py","control.py","contracts.py","package_contract.py","path_authority.py","worktree_authority.py","release_helper.py","release.py","doctor.py","bootstrap.py","gate.py","tests.sh","control_contract_tests.py")
SCHEMAS=("remediation-release-authorization.v1.json","remediation-package-contract.v1.json")
def canonical(value:object)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def sha(path:Path)->str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def regular(path:Path)->None:
    item=path.lstat()
    if not stat.S_ISREG(item.st_mode): raise RuntimeError("provenance_not_regular")
def source_manifest(source:Path)->dict[str,object]:
    schema_dir=source/"schemas" if (source/"schemas").is_dir() else source.parent/"schemas"
    return {"files":{name:sha(source/name) for name in FILES},"schemas":{name:sha(schema_dir/name) for name in SCHEMAS}}
def source_root(source:Path)->Path:
    repo=Path(subprocess.check_output(["/usr/bin/git","-C",str(source),"rev-parse","--show-toplevel"],text=True).strip()).resolve()
    expected=(repo/"shiproom/external_validation/remediation_backend").resolve()
    if source.resolve()!=expected: raise RuntimeError("bootstrap_source_not_canonical")
    return repo
def validate_attestation(path:Path,source:Path,commit:str,tree:str)->dict[str,object]:
    regular(path); data=json.loads(path.read_text(encoding="utf-8"))
    required={"schema_id","schema_version","commit","tree","bundle_files","schemas","shellcheck","commands","created_at","attestation_hash"}
    if set(data)!=required or data["schema_id"]!="remediation_stage0_attestation.v1" or data["schema_version"]!="1": raise RuntimeError("attestation_shape_invalid")
    claimed=data.pop("attestation_hash")
    if claimed!="sha256:"+hashlib.sha256(canonical(data)).hexdigest(): raise RuntimeError("attestation_hash_invalid")
    data["attestation_hash"]=claimed
    if data["commit"]!=commit or data["tree"]!=tree or data["bundle_files"]!=source_manifest(source)["files"] or data["schemas"]!=source_manifest(source)["schemas"]: raise RuntimeError("attestation_binding_mismatch")
    if not isinstance(data["commands"],list) or not data["commands"] or any(not isinstance(row,dict) or row.get("exit_code")!=0 for row in data["commands"]): raise RuntimeError("attestation_commands_invalid")
    shell=data["shellcheck"]
    if not isinstance(shell,dict) or not isinstance(shell.get("hash"),str) or not shell.get("version"): raise RuntimeError("attestation_shellcheck_invalid")
    return data
def staged_manifest(source:Path,attestation:dict[str,object],commit:str,tree:str)->dict[str,object]:
    body={"schema_id":"remediation_staged_bundle.v1","schema_version":"1","source_commit":commit,"source_tree":tree,"source_manifest":source_manifest(source),"attestation_hash":attestation["attestation_hash"]}
    body["bundle_hash"]="sha256:"+hashlib.sha256(canonical(body)).hexdigest(); return body
def verify_stage(target:Path)->None:
    if not target.is_absolute() or target.parent!=ROOT or len(target.name)!=64 or any(c not in "0123456789abcdef" for c in target.name): raise RuntimeError("staged_path_invalid")
    manifest_path=target/"manifest.json"; regular(manifest_path); manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("bundle_hash")!="sha256:"+target.name or manifest.get("schema_id")!="remediation_staged_bundle.v1": raise RuntimeError("staged_manifest_identity_invalid")
    for path in [target/name for name in FILES]+[target/"schemas"/name for name in SCHEMAS]+[target/"stage0-attestation.json",manifest_path]:
        regular(path); item=path.stat()
        if item.st_uid!=0 or item.st_mode&0o022: raise RuntimeError("staged_ownership_invalid")
    expected=manifest["source_manifest"]
    if {name:sha(target/name) for name in FILES}!=expected["files"] or {name:sha(target/"schemas"/name) for name in SCHEMAS}!=expected["schemas"]: raise RuntimeError("staged_hash_mismatch")
    attestation=validate_attestation(target/"stage0-attestation.json",target,manifest["source_commit"],manifest["source_tree"])
    if attestation["attestation_hash"]!=manifest["attestation_hash"]: raise RuntimeError("staged_attestation_mismatch")
def require_staged_script(script:Path)->None:
    verify_stage(script.resolve().parent)
def approval_path(attestation_hash:str)->Path:
    return ROOT/"approvals"/attestation_hash.removeprefix("sha256:")
def approve(source:Path,attestation_path:Path,commit:str,tree:str)->Path:
    source_root(source); attestation=validate_attestation(attestation_path,source,commit,tree)
    path=approval_path(str(attestation["attestation_hash"])); path.parent.mkdir(parents=True,mode=0o700)
    body={"schema_id":"remediation_stage0_approval.v1","schema_version":"1","attestation_hash":attestation["attestation_hash"],"commit":commit,"tree":tree}
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
    with os.fdopen(fd,"wb") as handle: handle.write(canonical(body))
    os.chown(path,0,0); return path
def verify_approval(attestation:dict[str,object],commit:str,tree:str)->None:
    path=approval_path(str(attestation["attestation_hash"])); regular(path); item=path.stat()
    if item.st_uid!=0 or item.st_mode&0o022: raise RuntimeError("stage0_approval_untrusted")
    value=json.loads(path.read_text(encoding="utf-8"))
    if value!={"schema_id":"remediation_stage0_approval.v1","schema_version":"1","attestation_hash":attestation["attestation_hash"],"commit":commit,"tree":tree}: raise RuntimeError("stage0_approval_mismatch")
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("source",type=Path,nargs="?"); p.add_argument("--tree"); p.add_argument("--commit"); p.add_argument("--attestation",type=Path); p.add_argument("--stage",action="store_true"); p.add_argument("--approve-attestation",action="store_true"); p.add_argument("--verify-staged",type=Path); a=p.parse_args()
    os.environ["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin"
    if a.verify_staged:
        if os.geteuid()!=0: raise SystemExit("bootstrap_root_required")
        verify_stage(a.verify_staged); print("staged_bundle_verified"); return 0
    if not (a.stage or a.approve_attestation) or not a.source or not a.commit or not a.tree or not a.attestation: raise SystemExit("bootstrap_arguments_invalid")
    if os.geteuid()!=0: raise SystemExit("bootstrap_root_required")
    source=a.source.resolve(); repo=source_root(source)
    head=subprocess.check_output(["/usr/bin/git","-C",str(repo),"rev-parse","HEAD"],text=True).strip(); actual_tree=subprocess.check_output(["/usr/bin/git","-C",str(repo),"rev-parse","HEAD^{tree}"],text=True).strip()
    if head!=a.commit or actual_tree!=a.tree or subprocess.check_output(["/usr/bin/git","-C",str(repo),"status","--porcelain"],text=True): raise SystemExit("unclean_or_wrong_commit")
    if a.approve_attestation: print(approve(source,a.attestation,a.commit,a.tree)); return 0
    attestation=validate_attestation(a.attestation,source,a.commit,a.tree); verify_approval(attestation,a.commit,a.tree); manifest=staged_manifest(source,attestation,a.commit,a.tree); target=ROOT/manifest["bundle_hash"].removeprefix("sha256:")
    target.mkdir(parents=True,mode=0o700,exist_ok=False)
    for name in FILES:
        out=target/name; shutil.copyfile(source/name,out); os.chown(out,0,0); out.chmod(0o500 if out.suffix==".sh" else 0o400)
    schemas=target/"schemas"; schemas.mkdir(mode=0o700); os.chown(schemas,0,0)
    for name in SCHEMAS:
        out=schemas/name; shutil.copyfile(source.parent/"schemas"/name,out); os.chown(out,0,0); out.chmod(0o400)
    staged_attestation=target/"stage0-attestation.json"; shutil.copyfile(a.attestation,staged_attestation); os.chown(staged_attestation,0,0); staged_attestation.chmod(0o400)
    out=target/"manifest.json"; out.write_bytes(canonical(manifest)); os.chown(out,0,0); out.chmod(0o400)
    verify_stage(target); print(manifest["bundle_hash"]); return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except (RuntimeError,OSError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"bootstrap_error:{exc}",file=sys.stderr); raise SystemExit(2)
