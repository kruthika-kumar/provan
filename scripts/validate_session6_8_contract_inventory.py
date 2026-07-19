"""Validate the executable Sessions 6--8 contract inventory and parity scope."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    inventory = json.loads((root / "docs/validation/session6-8-contract-inventory.json").read_text(encoding="utf-8"))["contracts"]
    registry = json.loads((root / "docs/validation/session6-8-contract-registry.json").read_text(encoding="utf-8"))["contracts"]
    required = {item["contract_id"] for item in inventory if item["parity_required"]}
    registered = {item["contract_name"] for item in registry}
    if required != registered or len(required) != len(inventory):
        raise SystemExit("session6_8_contract_inventory_parity_mismatch")
    if any(not item.get("requirement_ids") for item in registry):
        raise SystemExit("session6_8_contract_requirement_link_missing")
    package_roots = (root / "shiproom/remediation_schemas", root / "shiproom/review_organisation", root / "shiproom/contestability_schemas", root / "shiproom/management_artifacts")
    discovered = {str(path.relative_to(root)).replace("\\", "/") for directory in package_roots for path in directory.glob("*.json")}
    inventoried = {item["path"] for item in inventory if item["path"].endswith(".json")}
    unclassified = sorted(discovered - inventoried)
    if unclassified:
        raise SystemExit("session6_8_contract_inventory_unclassified:" + ",".join(unclassified))
    missing = [item["path"] for item in inventory if ".json" in item["path"] and not (root / item["path"]).is_file()]
    if missing:
        raise SystemExit("session6_8_contract_inventory_missing:" + ",".join(missing))
    report = {"schema_version": "session6-8-contract-parity-report.v1", "contract_count": len(required), "contracts": sorted(required), "passed": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
