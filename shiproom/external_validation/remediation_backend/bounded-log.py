#!/usr/bin/env python3
"""Copy a daemon log stream while retaining at most a fixed number of bytes."""
import argparse
import os

p = argparse.ArgumentParser()
p.add_argument("--input", required=True)
p.add_argument("--output", required=True)
p.add_argument("--maximum", type=int, required=True)
a = p.parse_args()
if not 1 <= a.maximum <= 16 * 1024 * 1024:
    raise SystemExit("invalid log maximum")
written = 0
with open(a.input, "rb", buffering=0) as src, open(a.output, "xb", buffering=0) as dst:
    while chunk := src.read(65536):
        if written < a.maximum:
            keep = chunk[: a.maximum - written]
            dst.write(keep)
            written += len(keep)
