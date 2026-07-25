#!/usr/bin/env python3
"""Capability-scoped remediation backend doctor.

The doctor is intentionally conservative: missing evidence is BLOCKED, never
treated as an inferred quota/security capability.  It writes a private
canonical report; a separate sanitiser is required for public proof views.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

os.environ["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin"

try:
    from .control import Control, ControlError, canonical
    from .release_helper import require_openat2
    from .bootstrap import require_staged_script
except ImportError:
    from control import Control, ControlError, canonical
    from release_helper import require_openat2
    from bootstrap import require_staged_script

def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def command(argv: list[str]) -> dict[str, object]:
    try: result=subprocess.run(argv,text=True,capture_output=True,timeout=30,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc: return {"command":argv,"ok":False,"error":str(exc)}
    return {"command":argv,"ok":result.returncode==0,"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr}

def check_openat2() -> dict[str, object]:
    try: require_openat2(); return {"name":"openat2","ok":True}
    except Exception as exc: return {"name":"openat2","ok":False,"error":str(exc)}

def check_environment() -> list[dict[str, object]]:
    return [
        {"name":"linux","ok":sys.platform.startswith("linux"),"platform":platform.platform()},
        {"name":"docker_binary","ok":shutil.which("dockerd") is not None},
        {"name":"xfs_tools","ok":shutil.which("xfs_quota") is not None and shutil.which("mkfs.xfs") is not None},
        {"name":"quota_tools","ok":shutil.which("quota") is not None},
    ]

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--db",type=Path,required=True); p.add_argument("--out",type=Path,required=True); p.add_argument("--profile",choices=("detection","remediation","all"),default="all"); a=p.parse_args()
    if os.geteuid()!=0: raise SystemExit("doctor_root_required")
    require_staged_script(Path(__file__))
    checks=check_environment(); detection_checks=[]; remediation_checks=[]
    try:
        control=Control(a.db); backend=control.instance_id(); control.assert_ready(); control.close()
        detection_checks.append({"name":"control_db_ready","ok":True,"backend_instance_id":backend})
    except (ControlError,Exception) as exc:
        backend=None; detection_checks.append({"name":"control_db_ready","ok":False,"error":str(exc)})
    # status.sh is the authoritative effective-Docker/Storage inspection; its
    # nonzero result remains a block, never a best-effort success.
    status_script=Path(__file__).with_name("status.sh")
    detection_checks.append({"name":"effective_storage_and_daemon_policy","result":command([str(status_script),"--doctor-read-only"])})
    remediation_checks.append(check_openat2())
    # The destructive quota/release tests are invoked only by an explicitly
    # approved real-doctor fixture.  Their absence is a precise BLOCKED state.
    remediation_checks.append({"name":"real_quota_lifecycle_fixture","ok":False,"reason":"not_run"})
    def qualified(rows: list[dict[str, object]]) -> bool:
        return all(bool(row.get("ok", row.get("result",{}).get("ok",False))) for row in rows)
    detection_ok=qualified(checks+detection_checks)
    remediation_ok=detection_ok and qualified(remediation_checks)
    report={"schema_id":"remediation_doctor_report.v1","schema_version":"1","created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"backend_instance_id":backend,"host":{"platform":platform.platform()},"detection_profile":{"status":"QUALIFIED" if detection_ok else "BLOCKED","checks":checks+detection_checks},"remediation_profile":{"status":"QUALIFIED" if remediation_ok else "BLOCKED","checks":remediation_checks},"overall_status":"QUALIFIED" if detection_ok and remediation_ok else ("PARTIALLY_QUALIFIED" if detection_ok else "FAILED")}
    report["report_hash"]=digest(report)
    a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_bytes(canonical(report)); os.chmod(a.out,0o600)
    print(json.dumps({"detection_profile":report["detection_profile"]["status"],"remediation_profile":report["remediation_profile"]["status"],"overall_status":report["overall_status"],"report_hash":report["report_hash"]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
