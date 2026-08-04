from __future__ import annotations

import argparse
from pathlib import Path

from shiproom.external_validation.session2_closeout import (
    FORBIDDEN_PUBLIC_FRAGMENTS,
    HANDOFF_PATH,
    PROOF_ROOT,
    TRANSITION_PATH,
    load_canonical,
    validate_handoff,
    validate_partial_closeout,
    validate_repository_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("bundle", "public-leakage", "private-inventory"), required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args(); root = args.repository.resolve()
    if args.mode == "bundle":
        result = validate_repository_bundle(root)
    elif args.mode == "public-leakage":
        paths = [root / PROOF_ROOT / "session2_partial_closeout.md", root / TRANSITION_PATH]
        matches = [(str(path.relative_to(root)), fragment) for path in paths for fragment in FORBIDDEN_PUBLIC_FRAGMENTS if fragment in path.read_text(encoding="utf-8")]
        leakage, _ = load_canonical(root / PROOF_ROOT / "session2_leakage_validation.v1.json")
        if matches or leakage.get("forbidden_path_match_count") != 0 or leakage.get("private_material_leaked") is not False or leakage.get("public_example_authorized") is not False:
            raise SystemExit("session2_closeout_public_leakage_failed")
        result = {"verdict": "PASS", "surface_count": len(paths), "forbidden_match_count": 0}
    else:
        closeout, _ = load_canonical(root / PROOF_ROOT / "session2_partial_closeout.v1.json")
        handoff, _ = load_canonical(root / HANDOFF_PATH)
        validate_partial_closeout(closeout); validate_handoff(handoff)
        private_assets = [item for item in handoff["assets"] if item["classification"] in {"PRIVATE_EVAL_CASE", "PRIVATE_INCIDENT_REGRESSION"}]
        if not private_assets or any(not item["evidence_refs"] for item in private_assets):
            raise SystemExit("session2_closeout_private_inventory_failed")
        result = {"verdict": "PASS", "private_asset_count": len(private_assets), "public_example_count": 0}
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
