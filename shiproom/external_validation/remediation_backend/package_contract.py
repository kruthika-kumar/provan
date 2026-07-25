#!/usr/bin/env python3
"""Validate the frozen, approval-bound Docker/XFS package transaction."""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STAGE_ROOT=Path("/run/shiproom-remediation-bootstrap")
STAGE_FILES=("lib.sh","setup.sh","start.sh","status.sh","recover.sh","teardown.sh","quota-worktree.sh","bounded-log.py","control.py","contracts.py","package_contract.py","path_authority.py","worktree_authority.py","release_helper.py","residual.py","xfs_project.py","lock_guard.py","release.py","doctor.py","bootstrap.py","gate.py","tests.sh","control_contract_tests.py")
STAGE_SCHEMAS=("remediation-release-authorization.v1.json","remediation-package-contract.v1.json")

def canonical(value:object)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def stage_hash(path:Path)->str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def staged_regular(path:Path)->None:
    item=path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_mode&0o022: raise RuntimeError("staged_file_untrusted")

def require_staged_script(script:Path)->None:
    """Independently validate the immutable staged bundle without executing it.

    This verifier intentionally does not import ``bootstrap.py``: an isolated
    Python process must never execute a sibling before ownership, type, and
    manifest hashes establish that the sibling belongs to the staged bundle.
    """
    raw=script.absolute()
    if raw.name!="package_contract.py" or raw.parent.parent!=STAGE_ROOT or len(raw.parent.name)!=64 or any(char not in "0123456789abcdef" for char in raw.parent.name): raise RuntimeError("staged_path_invalid")
    staged_regular(raw); stage=raw.parent; manifest_path=stage/"manifest.json"; attestation_path=stage/"stage0-attestation.json"
    staged_regular(manifest_path); staged_regular(attestation_path)
    manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    if set(manifest)!={"schema_id","schema_version","source_commit","source_tree","source_manifest","attestation_hash","bundle_hash"} or manifest["schema_id"]!="remediation_staged_bundle.v1" or manifest["schema_version"]!="1": raise RuntimeError("staged_manifest_invalid")
    claimed_bundle=manifest.pop("bundle_hash")
    if claimed_bundle!="sha256:"+stage.name or claimed_bundle!="sha256:"+hashlib.sha256(canonical(manifest)).hexdigest(): raise RuntimeError("staged_manifest_identity_invalid")
    source_manifest=manifest["source_manifest"]
    if not isinstance(source_manifest,dict) or set(source_manifest)!={"files","schemas"} or set(source_manifest["files"])!=set(STAGE_FILES) or set(source_manifest["schemas"])!=set(STAGE_SCHEMAS): raise RuntimeError("staged_manifest_files_invalid")
    for name in STAGE_FILES:
        path=stage/name; staged_regular(path)
        if stage_hash(path)!=source_manifest["files"][name]: raise RuntimeError("staged_hash_mismatch")
    for name in STAGE_SCHEMAS:
        path=stage/"schemas"/name; staged_regular(path)
        if stage_hash(path)!=source_manifest["schemas"][name]: raise RuntimeError("staged_hash_mismatch")
    attestation=json.loads(attestation_path.read_text(encoding="utf-8")); claimed_attestation=attestation.pop("attestation_hash",None)
    if claimed_attestation!=manifest["attestation_hash"] or claimed_attestation!="sha256:"+hashlib.sha256(canonical(attestation)).hexdigest(): raise RuntimeError("staged_attestation_mismatch")
    if attestation.get("schema_id")!="remediation_stage0_attestation.v1" or attestation.get("schema_version")!="1" or attestation.get("commit")!=manifest["source_commit"] or attestation.get("tree")!=manifest["source_tree"] or attestation.get("bundle_files")!=source_manifest["files"] or attestation.get("schemas")!=source_manifest["schemas"]: raise RuntimeError("staged_attestation_mismatch")

class PackageContractError(ValueError): pass

REQUIRED={"schema_id","schema_version","distribution_id","release","apt_sources_hash","apt_sources_artifact","simulation_hash","simulation_artifact","packages","created_at"}
NAMES={"docker.io","xfsprogs","quota"}
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")

def validate(value: Any) -> dict[str, Any]:
    if not isinstance(value,dict) or set(value)!=REQUIRED: raise PackageContractError("package_contract_shape_invalid")
    if value["schema_id"]!="remediation_package_contract.v1" or value["schema_version"]!="1": raise PackageContractError("package_contract_version_invalid")
    if not all(isinstance(value[k],str) and value[k] for k in {"distribution_id","release","created_at"}): raise PackageContractError("package_contract_text_invalid")
    if not SHA.fullmatch(value["apt_sources_hash"]) or not SHA.fullmatch(value["simulation_hash"]): raise PackageContractError("package_contract_hash_invalid")
    if any(not isinstance(value[key],str) or not (value[key].startswith("/") or Path(value[key]).is_absolute()) for key in {"apt_sources_artifact","simulation_artifact"}): raise PackageContractError("package_contract_artifact_path_invalid")
    packages=value["packages"]
    if not isinstance(packages,list) or {x.get("name") for x in packages if isinstance(x,dict)}!=NAMES or len(packages)!=3: raise PackageContractError("package_contract_packages_invalid")
    for item in packages:
        if set(item)!={"name","version","source"} or not all(isinstance(item[k],str) and item[k] for k in item): raise PackageContractError("package_contract_package_invalid")
        if any(ch.isspace() for ch in item["version"]) or "=" in item["version"]: raise PackageContractError("package_contract_version_unsafe")
    return value

def file_hash(path: Path) -> str: return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def current_sources_hash() -> str:
    return "sha256:"+hashlib.sha256(sources_payload()).hexdigest()
def sources_payload() -> bytes:
    paths=[Path("/etc/apt/sources.list"),*sorted(Path("/etc/apt/sources.list.d").glob("*"))]
    return b"".join(str(path).encode()+b"\0"+path.read_bytes()+b"\0" for path in paths if path.is_file())
def immutable_root_file(path:Path, contract:Path)->None:
    item=path.resolve(strict=True).stat()
    parent=contract.parent.resolve()
    try: path.resolve(strict=True).relative_to(parent)
    except ValueError as exc: raise PackageContractError("package_contract_artifact_outside_stage") from exc
    if item.st_uid!=0 or item.st_mode&0o022 or not stat.S_ISREG(item.st_mode): raise PackageContractError("package_contract_artifact_untrusted")
def verify_live(contract_path:Path)->None:
    value=validate(json.loads(contract_path.read_text(encoding="utf-8")))
    for key,hash_key in (("apt_sources_artifact","apt_sources_hash"),("simulation_artifact","simulation_hash")):
        path=Path(value[key]); immutable_root_file(path,contract_path)
        if file_hash(path)!=value[hash_key]: raise PackageContractError("package_contract_artifact_hash_mismatch")
    if current_sources_hash()!=value["apt_sources_hash"]: raise PackageContractError("package_contract_sources_drift")
    specs=[item["name"]+"="+item["version"] for item in sorted(value["packages"],key=lambda item:item["name"])]
    result=subprocess.run(["/usr/bin/apt-get","-s","--no-install-recommends","install",*specs],text=True,capture_output=True,timeout=60,check=False)
    if result.returncode or file_hash(Path(value["simulation_artifact"]))!="sha256:"+hashlib.sha256((result.stdout+result.stderr).encode()).hexdigest(): raise PackageContractError("package_contract_simulation_drift")
    for item in value["packages"]:
        version,source=policy_candidate(item["name"])
        if version!=item["version"] or source!=item["source"]: raise PackageContractError("package_contract_candidate_drift")
def root_stage_file(path:Path)->None:
    stage=Path(__file__).resolve().parent
    try: path.resolve().parent.relative_to(stage)
    except ValueError as exc: raise PackageContractError("package_contract_capture_outside_stage") from exc
    if path.parent!=stage or os.geteuid()!=0: raise PackageContractError("package_contract_capture_authority_invalid")
def write_immutable(path:Path,data:bytes)->None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        os.fchown(fd,0,0); os.fchmod(fd,0o400)
        pending=memoryview(data)
        while pending:
            written=os.write(fd,pending)
            if written<=0: raise PackageContractError("package_contract_write_failed")
            pending=pending[written:]
        os.fsync(fd)
    finally: os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)
def policy_candidate(name:str)->tuple[str,str]:
    result=subprocess.run(["/usr/bin/apt-cache","policy",name],text=True,capture_output=True,timeout=30,check=False)
    if result.returncode: raise PackageContractError("package_contract_policy_failed")
    candidate=next((line.split(":",1)[1].strip() for line in result.stdout.splitlines() if line.strip().startswith("Candidate:")),None)
    if not candidate or candidate=="(none)": raise PackageContractError("package_contract_candidate_missing")
    lines=result.stdout.splitlines(); found=False
    version_header=re.compile(r"^\s{1,6}(?:\*\*\*\s+)?(\S+)\s+\d+\s*$")
    source_line=re.compile(r"^\s*\d+\s+(https?://\S.*)$")
    for line in lines:
        header=version_header.match(line)
        if header:
            if found: break
            found=header.group(1)==candidate
            continue
        if found:
            source=source_line.match(line)
            if source: return candidate,source.group(1)
    raise PackageContractError("package_contract_candidate_source_missing")
def capture(out:Path)->None:
    try: require_staged_script(Path(__file__))
    except RuntimeError as exc: raise PackageContractError(str(exc)) from exc
    root_stage_file(out)
    sources=out.parent/"apt-sources.bin"; simulation=out.parent/"package-simulation.txt"
    root_stage_file(sources); root_stage_file(simulation)
    packages=[{"name":name,"version":version,"source":source} for name,version,source in ([(name,*policy_candidate(name)) for name in sorted(NAMES)])]
    specs=[item["name"]+"="+item["version"] for item in packages]
    result=subprocess.run(["/usr/bin/apt-get","-s","--no-install-recommends","install",*specs],text=False,capture_output=True,timeout=60,check=False)
    if result.returncode: raise PackageContractError("package_contract_simulation_failed")
    source_bytes=sources_payload(); simulation_bytes=result.stdout+result.stderr
    write_immutable(sources,source_bytes); write_immutable(simulation,simulation_bytes)
    os_release=dict(line.split("=",1) for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines() if "=" in line)
    value={"schema_id":"remediation_package_contract.v1","schema_version":"1","distribution_id":os_release.get("ID","").strip('"'),"release":os_release.get("VERSION_CODENAME","").strip('"'),"apt_sources_hash":"sha256:"+hashlib.sha256(source_bytes).hexdigest(),"apt_sources_artifact":str(sources),"simulation_hash":"sha256:"+hashlib.sha256(simulation_bytes).hexdigest(),"simulation_artifact":str(simulation),"packages":packages,"created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    write_immutable(out,json.dumps(value,sort_keys=True,separators=(",",":")).encode("utf-8")); verify_live(out)

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("contract",type=Path,nargs="?"); p.add_argument("--install-args",action="store_true"); p.add_argument("--verify-live",action="store_true"); p.add_argument("--capture",type=Path); a=p.parse_args()
    if a.capture:
        if a.contract or a.install_args or a.verify_live: raise SystemExit("package_contract_capture_arguments_invalid")
        capture(a.capture); print("package_contract_captured"); return 0
    if not a.contract: raise SystemExit("package_contract_required")
    value=validate(json.loads(a.contract.read_text(encoding="utf-8")))
    if a.verify_live: verify_live(a.contract)
    if a.install_args:
        for item in sorted(value["packages"],key=lambda x:x["name"]): print(item["name"]+"="+item["version"])
    else: print("package_contract_valid")
    return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except (PackageContractError, OSError, json.JSONDecodeError) as exc: print(f"package_contract_error:{exc}",file=sys.stderr); raise SystemExit(2)
