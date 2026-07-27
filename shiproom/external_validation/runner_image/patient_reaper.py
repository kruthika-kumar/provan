#!/usr/bin/env python3
"""Supervisor helper: terminate every remaining process of the patient UID."""
from __future__ import annotations
import os
import signal
import sys
import time

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(64)
target = int(sys.argv[1])
for sig in (signal.SIGTERM, signal.SIGKILL):
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit() or int(entry.name) <= 1 or int(entry.name) == os.getpid():
            continue
        try:
            status = open(f"/proc/{entry.name}/status", encoding="ascii").read()
            uid = next(line.split()[1] for line in status.splitlines() if line.startswith("Uid:"))
            if int(uid) == target:
                os.kill(int(entry.name), sig)
        except (FileNotFoundError, PermissionError, ProcessLookupError, StopIteration):
            continue
    time.sleep(1)
