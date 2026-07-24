#!/usr/bin/env python3
import os
import sys
import time

uid = int(sys.argv[1])
def patient_pids():
    found=[]
    for name in os.listdir('/proc'):
        if not name.isdigit(): continue
        try:
            with open(f'/proc/{name}/status', encoding='utf-8') as handle:
                fields = next(line for line in handle if line.startswith('Uid:')).split()
            if int(fields[1]) == uid: found.append(name)
        except (FileNotFoundError, StopIteration, PermissionError): pass
    return found
for _ in range(2):
    if patient_pids(): raise SystemExit(1)
    time.sleep(0.1)
raise SystemExit(0)
