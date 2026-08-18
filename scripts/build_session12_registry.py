from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).parents[1]))
from provan.canonical import canonical_bytes,sha256_bytes


ROOT=Path(__file__).parents[1];OUT=ROOT/"artifacts"/"session12"/"schema_registry.v1.public.json"


def main()->int:
    rows=[]
    for path in sorted((ROOT/"provan"/"schemas").glob("*.json"),key=lambda item:item.name):
        raw=path.read_bytes();value=json.loads(raw);rows.append({"schema_id":value["$id"],"path":path.relative_to(ROOT).as_posix(),"sha256":sha256_bytes(raw),"normalized_sha256":sha256_bytes(canonical_bytes(value))})
    registry={"schema_id":"provan.session12_schema_registry.v1","sensitivity":"PUBLIC_SAFE","entries":rows,"registry_digest":sha256_bytes(canonical_bytes(rows))};OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_bytes(canonical_bytes(registry));print(registry["registry_digest"]);return 0


if __name__=="__main__":raise SystemExit(main())
