#!/usr/bin/env python3
"""Move a failed, unsealed worktree to forensic quarantine without deletion.

This is intentionally not release.py: it never clears an XFS project, returns
capacity, retires a project, or resolves the blocking incident.  The caller
must hold the backend lock and retain the incident until a separately reviewed
recovery process can account for the preserved bytes.
"""
from __future__ import annotations
import argparse, json, os, stat, sys
from pathlib import Path
_STAGED_MODULE_DIRECTORY = str(Path(__file__).resolve().parent)
if _STAGED_MODULE_DIRECTORY not in sys.path: sys.path.insert(0, _STAGED_MODULE_DIRECTORY)
try:
    from .bootstrap import require_staged_script
    from .release_helper import mount_id, openat2, verify_root
    from .residual import assert_absent
except ImportError:
    from bootstrap import require_staged_script
    from release_helper import mount_id, openat2, verify_root
    from residual import assert_absent

class QuarantineBlocked(RuntimeError): pass

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('--root',type=Path,required=True); p.add_argument('--quarantine',type=Path,required=True); p.add_argument('--device',type=int,required=True); p.add_argument('--inode',type=int,required=True); p.add_argument('--mount-id',type=int,required=True); p.add_argument('--socket',type=Path,required=True); p.add_argument('--aliases-json',type=Path,required=True); p.add_argument('--name',required=True); a=p.parse_args()
    if os.geteuid()!=0: raise QuarantineBlocked('quarantine_root_required')
    require_staged_script(Path(__file__))
    if not a.root.is_absolute() or not a.quarantine.is_absolute() or '/' in a.name or a.name in {'','.','..'}: raise QuarantineBlocked('quarantine_path_invalid')
    aliases=[Path(value) for value in json.loads(a.aliases_json.read_text(encoding='utf-8'))]
    # Revocation happens before both residual sweeps and descriptor-relative
    # rename; the patient UID cannot race the preservation operation.
    os.chown(a.root,0,0); os.chmod(a.root,0o700)
    assert_absent(a.root,a.device,a.inode,a.mount_id,a.socket,aliases)
    source_parent=os.open(a.root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        # Repeat immediately before acquiring the destructive-operation
        # descriptor.  A later sweep would necessarily observe that helper
        # descriptor in /proc/self/fd and falsely classify it as a residual.
        assert_absent(a.root,a.device,a.inode,a.mount_id,a.socket,aliases)
        rootfd=openat2(source_parent,a.root.name)
        try:
            verify_root(rootfd,a.device,a.inode,a.mount_id)
            if a.quarantine.exists():
                item=a.quarantine.stat(follow_symlinks=False)
                if not stat.S_ISDIR(item.st_mode) or item.st_uid!=0 or item.st_mode&0o077: raise QuarantineBlocked('quarantine_directory_untrusted')
            else: a.quarantine.mkdir(mode=0o700)
            destination=os.open(a.quarantine,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                if os.fstat(destination).st_dev!=a.device or mount_id(destination)!=a.mount_id: raise QuarantineBlocked('quarantine_cross_filesystem')
                os.rename(a.root.name,a.name,src_dir_fd=source_parent,dst_dir_fd=destination)
            finally: os.close(destination)
        finally: os.close(rootfd)
    finally: os.close(source_parent)
    print(json.dumps({'quarantined_name':a.name,'preserved_device':a.device,'preserved_inode':a.inode},sort_keys=True)); return 0
if __name__=='__main__':
    try: raise SystemExit(main())
    except (QuarantineBlocked,OSError,ValueError) as exc: print('quarantine_error:'+str(exc),file=sys.stderr); raise SystemExit(2)
