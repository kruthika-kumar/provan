#!/usr/bin/env python3
"""Root-owned patient gateway: isolate every command in a new session."""
from __future__ import annotations
import os
import signal
import subprocess
import sys
import time

if len(sys.argv) < 2:
    raise SystemExit(64)

child = subprocess.Popen(sys.argv[1:], preexec_fn=os.setsid)
try:
    code = child.wait()
finally:
    # The command is the session leader.  Terminating the whole process group
    # prevents background children from writing after the main process exits.
    try: os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    time.sleep(0.25)
    try: os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError: pass
raise SystemExit(code if code >= 0 else 128 + -code)
