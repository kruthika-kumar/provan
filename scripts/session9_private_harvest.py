"""Derive private Session 2 assets without staging identities in Community."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

BASE = "09c5fbab239a6dcb87eee3697f25aaff2929111f"
HANDOFF = "external_validation/handoffs/session9/session2_asset_handoff.v1.json"
USABLE = {"PRIVATE_EVAL_CASE", "PRIVATE_INCIDENT_REGRESSION"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args()
    raw = subprocess.run(["git", "show", f"{BASE}:{HANDOFF}"], check=True, capture_output=True).stdout
    handoff = json.loads(raw)
    expected = []
    exclusions = []
    for asset in handoff["assets"]:
        row = {"asset_id": asset["asset_id"], "classification": asset["classification"], "claim_authorized": asset["claim_authorized"], "limitations": asset["limitations"]}
        if asset["classification"] in USABLE:
            expected.extend((asset["asset_id"], ref["authority"], ref["sha256"].removeprefix("sha256:")) for ref in asset["evidence_refs"])
        else:
            exclusions.append({**row, "reason_code": "NOT_PRIVATE_USABLE_ASSET"})
    command = ["wsl.exe", "-u", "root", "-e", "sh", "-lc", f"find '{args.source_root}' -type f -name '*.json' -print0 | xargs -0 sha256sum"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    discovered = {}
    for line in result.stdout.splitlines():
        digest, path = line.split(maxsplit=1)
        discovered.setdefault(digest, []).append(path)
    target = args.private_root / "assets" / "session2"
    target.mkdir(parents=True, exist_ok=True)
    records = []
    for index, (asset_id, authority, digest) in enumerate(expected, 1):
        paths = discovered.get(digest, [])
        if len(paths) != 1:
            raise SystemExit(f"HASH_RESOLUTION_NOT_UNIQUE:{authority}:{len(paths)}")
        source = paths[0]
        content = subprocess.run(["wsl.exe", "-u", "root", "-e", "cat", "--", source], check=True, capture_output=True).stdout
        if hashlib.sha256(content).hexdigest() != digest:
            raise SystemExit("ASSET_HASH_DRIFT")
        json.loads(content)
        destination = target / f"asset-{index:03d}.json"
        destination.write_bytes(content)
        records.append({"private_asset_id": f"session2-private-{index:03d}", "handoff_asset_id": asset_id, "authority": authority, "source_path": source, "destination": destination.relative_to(args.private_root).as_posix(), "sha256": "sha256:" + digest, "classification": next(a["classification"] for a in handoff["assets"] if a["asset_id"] == asset_id), "claim_scope": "PRIVATE_REGRESSION_ONLY"})
    inventory = {
        "schema_id": "provan.session2_private_inventory.v1", "sensitivity": "PRIVATE_MAINTAINER",
        "authority_handoff_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "derived_asset_count": len(records), "assets": records, "typed_exclusions": exclusions,
        "headline_claims_authorized": False,
    }
    out = args.private_root / "maintainer" / "session2_inventory.private.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PRIVATE_INVENTORY_DERIVED", "asset_count": len(records), "exclusion_count": len(exclusions)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
