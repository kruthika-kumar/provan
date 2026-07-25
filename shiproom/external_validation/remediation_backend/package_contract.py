#!/usr/bin/env python3
"""Validate the frozen, approval-bound Docker/XFS package transaction."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, re, stat, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def require_staged_script(script:Path)->None:
    """Load only the bootstrap sibling whose stage will be verified.

    Privileged invocations use ``python -I -S`` so they do not inherit a
    caller-controlled module search path; that deliberately excludes the
    script directory.  An exact sibling load keeps that isolation while still
    making the bootstrap verifier the authority for this staged script.
    """
    bootstrap_path=script.resolve().with_name("bootstrap.py")
    spec=importlib.util.spec_from_file_location("shiproom_remediation_stage_bootstrap",bootstrap_path)
    if spec is None or spec.loader is None: raise RuntimeError("staged_bootstrap_load_invalid")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.require_staged_script(script)

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
