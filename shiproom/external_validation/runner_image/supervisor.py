#!/usr/bin/env python3
"""Trusted PID 1: it exposes no control stream to the patient."""
import signal
import time
import os

running = True
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
def reap(*_):
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
            if child == 0: return
        except ChildProcessError:
            return
signal.signal(signal.SIGCHLD, reap)
while running:
    reap()
    time.sleep(0.2)
