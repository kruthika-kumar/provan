#!/usr/bin/env python3
"""Capability-scoped remediation backend doctor.

The doctor is intentionally conservative: missing evidence is BLOCKED, never
treated as an inferred quota/security capability.  It writes a private
canonical report; a separate sanitiser is required for public proof views.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, secrets, shutil, sqlite3, stat, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

os.environ["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin"

# The privileged invocation deliberately uses ``python -I -S`` so neither the
# caller's Python environment nor site packages can influence qualification.
# Isolated mode consequently omits the script directory from ``sys.path``.
# Make the reviewed, co-staged sibling modules explicitly importable instead
# of weakening the isolation flag or relying on a package installation.
_STAGED_MODULE_DIRECTORY = str(Path(__file__).resolve().parent)
if _STAGED_MODULE_DIRECTORY not in sys.path:
    sys.path.insert(0, _STAGED_MODULE_DIRECTORY)

try:
    from .control import Control, ControlError, canonical
    from .release_helper import require_openat2
    from .bootstrap import require_staged_script
except ImportError:
    from control import Control, ControlError, canonical
    from release_helper import require_openat2
    from bootstrap import require_staged_script

ROOT = Path("/var/lib/shiproom-remediation")
MOUNT = Path("/mnt/shiproom-remediation")
RUN = Path("/run/shiproom-remediation-docker")
SNAPSHOT_HASH = "sha256:" + "0" * 64

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

def sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

def write_root_owned(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value=path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        raise RuntimeError("doctor_supervisor_directory_untrusted")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        os.fchown(fd,0,0); os.fchmod(fd,0o400); os.write(fd,data); os.fsync(fd)
    finally:
        os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)

def invocation(argv: list[str], *, timeout: int = 90) -> dict[str, object]:
    result=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,check=False)
    return {"command":argv,"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr}

def quota_probe(path: Path, bytes_: int) -> dict[str, object]:
    # Linux filesystems can surface an XFS project-quota write refusal as
    # EDQUOT, ENOSPC, or EFBIG.  Preserve the raw errno in the canonical
    # report and accept only those documented quota/space terminal errors;
    # every other write error remains a fixture failure.
    code="""import errno,json,os,sys
p,n=sys.argv[1],int(sys.argv[2])
try:
 with open(p,'wb',buffering=0) as f:
  block=b'x'*65536
  for _ in range((n+len(block)-1)//len(block)): f.write(block[:min(len(block),n-f.tell())])
except OSError as e:
 print(json.dumps({'quota_write_errno':e.errno,'quota_write_error':e.strerror},sort_keys=True))
 raise SystemExit(42 if e.errno in (errno.EDQUOT,errno.ENOSPC,errno.EFBIG) else 43)
raise SystemExit(0)
"""
    return invocation(["/usr/bin/python3","-c",code,str(path),str(bytes_)])

def inode_probe(path: Path) -> dict[str, object]:
    code="""import errno,os,sys
root=sys.argv[1]
try:
 for n in range(4096): open(os.path.join(root,'inode-'+str(n)),'xb').close()
except OSError as e: raise SystemExit(42 if e.errno==errno.EDQUOT else 43)
raise SystemExit(44)
"""
    return invocation(["/usr/bin/python3","-c",code,str(path)])

def fixture_authorization(control: Control, attempt: str) -> Path:
    allocation=control.allocation(attempt); authority=allocation["worktree_authority_json"]
    parent=ROOT/"supervisor-owned"/"doctor-artifacts"/attempt
    labels=("sealed-manifest","patch","changed","untracked","test","log")
    records=[]; hashes=[]
    for label in labels:
        item=parent/(label+".bin")
        write_root_owned(item,(label+":"+attempt+"\n").encode("utf-8"))
        item_hash=sha(item); hashes.append(item_hash)
        records.append({"kind":label,"canonical_path":str(item),"sha256":item_hash})
    document={
        "schema_id":"remediation_release_authorization.v1","schema_version":"1",
        "authorization_id":"authorization_"+secrets.token_hex(16),"backend_instance_id":control.instance_id(),
        "attempt_id":attempt,"project_id":allocation["project_id"],"allocation_record_id":attempt,
        "capacity_reservation_id":str(allocation["project_id"]),"worktree_authority":authority,
        "source_snapshot_hash":SNAPSHOT_HASH,"sealed_artifact_manifest_hash":hashes[0],
        "receipt_id":"doctor-receipt-"+attempt,"patch_hash":hashes[1],"changed_file_manifest_hash":hashes[2],
        "untracked_file_manifest_hash":hashes[3],"test_result_hashes":[hashes[4]],"log_hashes":[hashes[5]],
        "artifact_records":records,"supervisor_package_hash":sha(Path(__file__)),
        "created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
    }
    target=ROOT/"supervisor-owned"/"authorizations"/(document["authorization_id"]+".json")
    write_root_owned(target,canonical(document))
    control.authorize_release(document,str(target))
    return target

def release_fixture_attempt(db: Path, allocation_script: Path, attempt: str, tree: Path) -> dict[str, object]:
    control=Control(db)
    try:
        authorization=fixture_authorization(control,attempt)
    finally:
        control.close()
    release=invocation([str(allocation_script),"release",attempt,str(authorization)],timeout=180)
    absent=not tree.exists()
    control=Control(db)
    try:
        allocation=control.allocation(attempt)
    finally:
        control.close()
    return {"release":release,"worktree_absent":absent,"terminal_status":allocation["terminal_status"],"ok":release["exit_code"]==0 and absent and allocation["status"]=="RELEASED_RETIRED" and allocation["terminal_status"]=="RELEASED_RETIRED"}

def fixture_incident(db: Path, attempt: str, phase: str, evidence: dict[str, object]) -> dict[str, object]:
    """Durably lock the backend if a destructive fixture cannot close safely.

    A failed SQLite incident write is itself containment-unproven evidence.  It
    is never represented as a null incident ID or as a handled fixture error.
    """
    try:
        control=Control(db)
        try:
            incident_id=control.incident("doctor_quota_fixture", "QUOTA_STATE_UNCERTAIN", {"attempt_id":attempt,"phase":phase,"evidence":evidence})
        finally:
            control.close()
    except Exception as exc:
        return {"persisted":False,"error":"incident_persistence_failed","detail":str(exc)}
    return {"persisted":True,"incident_id":incident_id}

def fixture_failure(db: Path, attempt: str, phase: str, evidence: dict[str, object], result: dict[str, object]) -> dict[str, object]:
    incident=fixture_incident(db,attempt,phase,evidence)
    result.update({"name":"real_quota_lifecycle_fixture","ok":False,"phase":phase,"attempt_id":attempt,"containment_state":"QUOTA_STATE_UNCERTAIN","incident":incident})
    if not incident["persisted"]:
        result["reason"]="incident_persistence_failed"
    return result

def allocated_tree(db: Path, attempt: str, allocation_result: dict[str, object]) -> Path:
    """Bind an allocation command's text output to SQLite worktree authority."""
    lines=str(allocation_result["stdout"]).strip().splitlines()
    if len(lines) != 1:
        raise RuntimeError("doctor_allocation_output_invalid")
    tree=Path(lines[0])
    control=Control(db)
    try:
        authority=control.allocation(attempt)["worktree_authority_json"]
    finally:
        control.close()
    expected=Path(str(authority["canonical_path"]))
    if tree != expected or not tree.is_dir():
        raise RuntimeError("doctor_allocation_authority_mismatch")
    return tree

def real_quota_lifecycle_fixture(db: Path) -> dict[str, object]:
    """Run one isolated, supervisor-owned allocation/probe/release lifecycle.

    This is intentionally opt-in: it creates only a disposable quota worktree
    below the approved XFS root and leaves an immutable incident if any safety
    check cannot complete.
    """
    if db.resolve() != (ROOT/"control.sqlite3").resolve() or not MOUNT.is_mount() or not RUN.is_dir():
        return {"name":"real_quota_lifecycle_fixture","ok":False,"reason":"doctor_paths_not_qualified"}
    allocation_script=Path(__file__).with_name("quota-worktree.sh")
    try:
        require_staged_script(allocation_script)
    except (OSError, RuntimeError) as exc:
        return {"name":"real_quota_lifecycle_fixture","ok":False,"reason":"allocation_helper_not_staged","error":str(exc)}
    attempt="doctor-byte-"+secrets.token_hex(8)
    active_attempt: str | None = None
    try:
        allocate=invocation([str(allocation_script),"allocate",attempt,str(8*1024*1024),"1024",SNAPSHOT_HASH])
        if allocate["exit_code"] != 0:
            return {"name":"real_quota_lifecycle_fixture","ok":False,"phase":"allocate","result":allocate}
        active_attempt=attempt
        tree=allocated_tree(db,attempt,allocate)
        under=quota_probe(tree/"under-limit.bin",512*1024)
        over=quota_probe(tree/"over-limit.bin",16*1024*1024)
        if under["exit_code"] != 0 or not (tree/"under-limit.bin").is_file() or (tree/"under-limit.bin").stat().st_size != 512*1024 or over["exit_code"] != 42:
            return fixture_failure(db,attempt,"byte_quota_probes",{"under_limit":under,"byte_over_limit":over},{"under_limit":under,"byte_over_limit":over})
        byte_release=release_fixture_attempt(db,allocation_script,attempt,tree)
        if not byte_release["ok"]:
            return fixture_failure(db,attempt,"byte_release",byte_release,{"under_limit":under,"byte_over_limit":over,"byte_release":byte_release})
        active_attempt=None
        inode_attempt="doctor-inode-"+secrets.token_hex(8)
        inode_allocate=invocation([str(allocation_script),"allocate",inode_attempt,str(64*1024*1024),"1024",SNAPSHOT_HASH])
        if inode_allocate["exit_code"] != 0:
            return {"name":"real_quota_lifecycle_fixture","ok":False,"phase":"inode_allocate","attempt_id":inode_attempt,"result":inode_allocate}
        active_attempt=inode_attempt
        inode_tree=allocated_tree(db,inode_attempt,inode_allocate)
        inode=inode_probe(inode_tree)
        if inode["exit_code"] != 42:
            return fixture_failure(db,inode_attempt,"inode_quota_probe",{"inode_over_limit":inode},{"inode_over_limit":inode})
        inode_release=release_fixture_attempt(db,allocation_script,inode_attempt,inode_tree)
        ok=bool(inode_release["ok"])
        if not ok:
            return fixture_failure(db,inode_attempt,"inode_release",inode_release,{"byte_attempt_id":attempt,"under_limit":under,"byte_over_limit":over,"inode_over_limit":inode,"byte_release":byte_release,"inode_release":inode_release})
        active_attempt=None
        return {"name":"real_quota_lifecycle_fixture","ok":True,"byte_attempt_id":attempt,"inode_attempt_id":inode_attempt,"under_limit":under,"byte_over_limit":over,"inode_over_limit":inode,"byte_release":byte_release,"inode_release":inode_release}
    except (OSError,sqlite3.Error,subprocess.TimeoutExpired,ControlError,RuntimeError,IndexError,KeyError,TypeError,ValueError) as exc:
        if active_attempt is None:
            return {"name":"real_quota_lifecycle_fixture","ok":False,"phase":"exception","error":str(exc),"attempt_id":attempt,"containment_state":"NOT_CREATED"}
        return fixture_failure(db,active_attempt,"exception",{"error":str(exc)},{"error":str(exc)})

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--db",type=Path,required=True); p.add_argument("--out",type=Path,required=True); p.add_argument("--profile",choices=("detection","remediation","all"),default="all"); p.add_argument("--run-remediation-fixture",action="store_true"); a=p.parse_args()
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
    if a.profile in ("remediation","all"):
        remediation_checks.append(check_openat2())
        remediation_checks.append(real_quota_lifecycle_fixture(a.db) if a.run_remediation_fixture else {"name":"real_quota_lifecycle_fixture","ok":False,"reason":"not_requested"})
    else:
        remediation_checks.append({"name":"remediation_profile_scope","ok":False,"reason":"not_requested"})
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
