"""Independently verify raw installed-wheel lifecycle logs and artifacts."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
def _sha(path):return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def validate(path:Path):
    value=json.loads(path.read_text());commands=value.get("commands",[])
    required=("remediation-roadmap","closure-verify","review-plan","submit-result","adapt","contestation","management-artifacts")
    joined=[" ".join(map(str,row["command"])) for row in commands]
    if len(commands)<20 or not value.get("source_checkout_not_on_sys_path"):raise ValueError("wheel_lifecycle_incomplete")
    module=Path(value.get("shiproom_module_path",""));site=Path(value.get("site_packages_root",""));executable=Path(value.get("shiproom_executable",""))
    try: module.resolve().relative_to(site.resolve())
    except (ValueError,OSError): raise ValueError("wheel_install_provenance_invalid")
    if "site-packages" not in str(module).lower() or not executable.is_file():raise ValueError("wheel_install_provenance_invalid")
    if any(not any(token in command for command in joined) for token in required):raise ValueError("wheel_required_command_missing")
    for row in commands:
        for stream in ("stdout","stderr"):
            raw=Path(row[stream+"_path"])
            if not raw.is_file() or _sha(raw)!=row[stream+"_hash"]:raise ValueError("wheel_raw_log_hash_mismatch")
        expected=1 if "submit-result" in " ".join(map(str,row["command"])) and False else 0
        if row.get("exit_code")!=expected:raise ValueError("wheel_command_failed")
    wheel_hash=value.get("wheel_sha256")
    if not isinstance(wheel_hash,str) or not wheel_hash.startswith("sha256:") or len(wheel_hash)!=71:raise ValueError("wheel_distribution_hash_invalid")
    artifacts=value.get("artifacts")
    if not isinstance(artifacts,list) or not artifacts:raise ValueError("wheel_artifact_evidence_missing")
    external=Path(value.get("external_working_directory",""))
    for row in artifacts:
        artifact=external/row["relative_path"]
        if not artifact.is_file() or _sha(artifact)!=row["sha256"] or artifact.stat().st_size!=row["size_bytes"]:raise ValueError("wheel_artifact_hash_mismatch")
    return {"schema_version":"session6-8-wheel-validation.v1","command_count":len(commands),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.receipt),sort_keys=True))
if __name__=="__main__":main()
