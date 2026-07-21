"""Materialize fixed assertion callables; never used during proof execution."""
from __future__ import annotations

import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/"shiproom/session6_8_requirement_boundaries.py"
REGISTRY=ROOT/"docs/validation/session6-8-requirement-proof-registry.json"
BEGIN="# BEGIN MATERIALIZED REQUIREMENT ASSERTIONS"
END="# END MATERIALIZED REQUIREMENT ASSERTIONS"

def main()->int:
    rows=json.loads(REGISTRY.read_text(encoding="utf-8"))["proofs"]
    names=[]
    for row in rows:
        name=row["proof_callable"].rsplit(".",1)[1]
        if name not in names:names.append(name)
    if len(names)!=106:raise SystemExit("materialized_assertion_cardinality_invalid")
    blocks=[BEGIN]
    for name in names:
        key=name.removeprefix("assert_")
        blocks.extend([f"def {name}(snapshot: dict[str, Any]) -> Any:",f"    return _assert_observed(snapshot, {key!r})",""])
    blocks.extend([f"_ASSERTION_NAMES = {tuple(name.removeprefix('assert_') for name in names)!r}","",END])
    source=TARGET.read_text(encoding="utf-8");start=source.index(BEGIN);finish=source.index(END)+len(END)
    TARGET.write_text(source[:start]+"\n".join(blocks)+source[finish:],encoding="utf-8")
    return 0

if __name__=="__main__":raise SystemExit(main())
