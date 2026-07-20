"""Independently verify an installed-wheel connected lifecycle receipt."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
def _sha(path):return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
def validate(path:Path):
    value=json.loads(path.read_text());commands=value.get("commands",[])
    required=("remediation-roadmap","closure-verify","review-plan","submit-result","adapt","contestation","management-artifacts")
    joined=[" ".join(map(str,row["command"])) for row in commands]
    if not value.get("passed") or value.get("exit_code")!=0 or not value.get("source_checkout_not_on_sys_path"):raise ValueError("wheel_lifecycle_incomplete")
    if "site-packages" not in value.get("shiproom_module_path","").lower() or not Path(value.get("shiproom_executable","")).is_file():raise ValueError("wheel_install_provenance_invalid")
    if any(not any(token in command for command in joined) for token in required):raise ValueError("wheel_required_command_missing")
    for row in commands:
        for stream in ("stdout","stderr"):
            raw=Path(row[stream+"_path"])
            if not raw.is_file() or _sha(raw)!=row[stream+"_hash"]:raise ValueError("wheel_raw_log_hash_mismatch")
        if row["status"]!="passed":raise ValueError("wheel_command_failed")
    return {"schema_version":"session6-8-wheel-validation.v1","command_count":len(commands),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();print(json.dumps(validate(a.receipt),sort_keys=True))
if __name__=="__main__":main()
