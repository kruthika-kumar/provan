"""Canonical effective-status resolver; markdown status summaries are views."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .v2 import V2ValidationError, validate_status_chain


def resolve_status(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"schema_id", "schema_version", "records"} or value["schema_id"] != "external_validation.status_chain.v1" or value["schema_version"] != "1" or not isinstance(value["records"], list):
        raise V2ValidationError("status_chain_document_invalid")
    current = validate_status_chain(value["records"])
    return {"effective_status": current["status"], "effective_status_id": current["status_id"], "commit_sha": current["commit_sha"], "branch": current["branch"], "scope": current["scope"]}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--chain", type=Path, required=True)
    args = parser.parse_args(); print(json.dumps(resolve_status(args.chain), sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
