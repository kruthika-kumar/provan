"""Snapshot public historical routes directly into a private evidence repository."""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://shiproom-demo.bookies-litany-00.workers.dev"
ROUTES = ["/", "/health", "/result/demo", "/reports/rel_35e58f680a1a", "/release-report", "/completed_run.json", "/public_evidence_manifest.v1.json", "/public_evidence_manifest.v2.json", "/shiproom-verdict.svg", "/setup"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--private-root", type=Path, required=True); args = parser.parse_args()
    root = args.private_root / "historical-surface"; root.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, route in enumerate(ROUTES, 1):
        request = urllib.request.Request(BASE + route, headers={"User-Agent": "Provan-Historical-Snapshot/1"})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                payload = response.read(); headers = dict(response.headers.items()); status = response.status
        except urllib.error.HTTPError as response:
            payload = response.read(); headers = dict(response.headers.items()); status = response.code
        destination = root / f"route-{index:02d}.bin"; destination.write_bytes(payload)
        rows.append({"route": route, "status": status, "location": headers.get("Location"), "content_type": headers.get("Content-Type"), "etag": headers.get("ETag"), "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(), "bytes": len(payload), "snapshot": destination.relative_to(args.private_root).as_posix()})
    manifest = {"schema_id": "provan.historical_surface_snapshot.v1", "sensitivity": "PRIVATE_MAINTAINER", "base_url": BASE, "captured_at": datetime.now(timezone.utc).isoformat(), "routes": rows}
    (root / "manifest.private.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "SNAPSHOT_COMPLETE", "route_count": len(rows)}))
    return 0


if __name__ == "__main__": raise SystemExit(main())
