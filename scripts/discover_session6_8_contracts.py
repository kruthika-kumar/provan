"""Discover Sessions 6--8 contracts from resources, code, and workflow output."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


DOMAINS = ("shiproom/remediation_schemas", "shiproom/review_organisation", "shiproom/contestability_schemas", "shiproom/management_artifacts")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); root = Path(__file__).resolve().parents[1]
    discovered: dict[str, set[str]] = {}
    for relative in DOMAINS:
        directory = root / relative
        for path in directory.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            identifier = value.get("$id") or value.get("schema_version") or path.stem
            discovered.setdefault(str(identifier), set()).add("packaged:" + str(path.relative_to(root)).replace("\\", "/"))
    for relative in ("shiproom/remediation_roadmaps/__init__.py", "shiproom/review_organisation/__init__.py", "shiproom/contestability/__init__.py", "shiproom/management_artifacts/compiler.py"):
        source = (root / relative).read_text(encoding="utf-8")
        for identifier in re.findall(r'["\']([a-z][a-z0-9-]+(?:-[a-z0-9]+)*\.v[0-9]+)["\']', source):
            discovered.setdefault(identifier, set()).add("code:" + relative)
    workflow = json.loads(args.workflow_receipt.read_text(encoding="utf-8"))
    for case in workflow.get("cases", []):
        for path in case.get("required_artifacts", []):
            discovered.setdefault(path, set()).add("workflow:" + case.get("name", "unknown"))
    entries = [{"contract_id": key, "discovery_sources": sorted(value)} for key, value in sorted(discovered.items())]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": "session6-8-discovered-contracts.v1", "contracts": entries}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
