from __future__ import annotations

import json
import uuid
from pathlib import Path


def main() -> int:
    target = Path("demo_patient/server.py")
    source = target.read_text(encoding="utf-8")
    source = source.replace('elif path.startswith("/result/"):', 'elif path.startswith("/results/"):', 1)
    target.write_text(source, encoding="utf-8")
    state = Path("release-state")
    if state.exists():
        for item in state.glob("*.json"): item.unlink()
    print(f"Demo reset to deterministic 404; next release id prefix rel_{uuid.uuid4().hex[:8]}")
    return 0


if __name__ == "__main__": raise SystemExit(main())

