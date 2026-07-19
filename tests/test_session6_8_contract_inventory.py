from __future__ import annotations

import json
from pathlib import Path


def test_session6_8_contract_inventory_is_exhaustive_and_parity_bound():
    root = Path(__file__).resolve().parents[1]
    inventory = json.loads((root / "docs/validation/session6-8-contract-inventory.json").read_text(encoding="utf-8"))["contracts"]
    registry = json.loads((root / "docs/validation/session6-8-contract-registry.json").read_text(encoding="utf-8"))["contracts"]
    package_roots = (root / "shiproom/remediation_schemas", root / "shiproom/review_organisation", root / "shiproom/contestability_schemas", root / "shiproom/management_artifacts")
    discovered = {str(path.relative_to(root)).replace("\\", "/") for directory in package_roots for path in directory.glob("*.json")}
    inventoried = {item["path"] for item in inventory if item["path"].endswith(".json")}
    assert discovered == inventoried
    required = {item["contract_id"] for item in inventory if item["parity_required"]}
    assert required == {item["contract_name"] for item in registry}
    assert all(item["requirement_ids"] for item in registry)
