#!/usr/bin/env python3
"""Trusted PID 1: it exposes no control stream to the patient."""
import signal
import time

running = True
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while running:
    time.sleep(0.2)
