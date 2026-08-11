from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifacts" / "session11" / "schema_registry.v1.public.json"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    rows = []
    for path in sorted((ROOT / "provan" / "schemas").glob("*.json")):
        raw = path.read_bytes()
        value = json.loads(raw)
        rows.append({
            "schema_id": value["$id"],
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": digest(raw),
            "normalized_sha256": digest(canonical(value)),
        })
    value = {
        "schema_id": "provan.session11_schema_registry.v1",
        "sensitivity": "PUBLIC_SAFE",
        "entries": rows,
        "registry_digest": digest(canonical(rows)),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(canonical(value))
    print(value["registry_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
