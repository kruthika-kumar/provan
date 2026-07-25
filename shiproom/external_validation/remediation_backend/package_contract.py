#!/usr/bin/env python3
"""Validate the frozen, approval-bound Docker/XFS package transaction."""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path
from typing import Any

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
    paths=[Path("/etc/apt/sources.list"),*sorted(Path("/etc/apt/sources.list.d").glob("*"))]
    payload=b"".join(str(path).encode()+b"\0"+path.read_bytes()+b"\0" for path in paths if path.is_file())
    return "sha256:"+hashlib.sha256(payload).hexdigest()
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
        policy=subprocess.run(["/usr/bin/apt-cache","policy",item["name"]],text=True,capture_output=True,timeout=30,check=False)
        if policy.returncode or f"Candidate: {item['version']}" not in policy.stdout or item["source"] not in policy.stdout: raise PackageContractError("package_contract_candidate_drift")

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("contract",type=Path); p.add_argument("--install-args",action="store_true"); p.add_argument("--verify-live",action="store_true"); a=p.parse_args()
    value=validate(json.loads(a.contract.read_text(encoding="utf-8")))
    if a.verify_live: verify_live(a.contract)
    if a.install_args:
        for item in sorted(value["packages"],key=lambda x:x["name"]): print(item["name"]+"="+item["version"])
    else: print("package_contract_valid")
    return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except (PackageContractError, OSError, json.JSONDecodeError) as exc: print(f"package_contract_error:{exc}",file=sys.stderr); raise SystemExit(2)
