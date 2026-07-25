#!/usr/bin/env python3
"""Read an existing directory's immutable device/inode/mount authority."""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
try:
    from .release_helper import mount_id
except ImportError:
    from release_helper import mount_id

p=argparse.ArgumentParser(); p.add_argument("path",type=Path); a=p.parse_args()
path=a.path.resolve(strict=True); st=path.stat(follow_symlinks=False)
if not path.is_dir(): raise SystemExit("path_authority_not_directory")
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
try: print(json.dumps({"path":str(path),"device":st.st_dev,"inode":st.st_ino,"mount_id":mount_id(fd)},sort_keys=True,separators=(",",":")))
finally: os.close(fd)
