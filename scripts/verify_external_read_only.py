from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from shiproom.external import CAPABILITIES, compile_release
from shiproom.models import EvidenceStatus
from shiproom.policy import OPERATION_CAPABILITIES, POLICY_VERSION, execute_external_operation
from shiproom.runs import LocalRunStore
from shiproom.verdict import calculate


DENIED = tuple(op for op in OPERATION_CAPABILITIES if op != "public.inspect")


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file() and ".git" not in path.parts
    }


def contract() -> dict:
    return {
        "schema_version": "external_release_contract.v1",
        "project_name": "Redacted public project",
        "repository_url": "https://github.com/example/public-project",
        "live_url": "https://example.com",
        "target_user": "public users",
        "product_promise": "A bounded public journey remains inspectable",
        "critical_journey": ["Open", "Inspect"],
        "non_goals": [],
        "owner_constraints": ["Read only"],
        "capabilities": {key: key == "inspect_public_surfaces" for key in CAPABILITIES},
    }


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw) / "repository"; root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "README.md").write_text("public fixture\n", encoding="utf-8")
        before = snapshot(root)
        release = compile_release(contract())
        release["checks"] = [{"criterion_id": "PUBLIC_JOURNEY", "required": True, "passed": False, "evidence_status": EvidenceStatus.MISSING}]
        store = LocalRunStore(Path(raw) / "run-history")
        calls: list[str] = []
        def forbidden(operation: str) -> None: calls.append(operation)
        for operation in DENIED:
            try: execute_external_operation(release, store, operation, forbidden, operation)
            except PermissionError: pass
            else: return 1
        events = store.events(release["release_id"])
        verdict = calculate(release)
        ok = (
            not calls and before == snapshot(root) and len(events) == len(DENIED)
            and all(event["event_type"] == "operation_rejected" for event in events)
            and all(not release["capabilities"][cap] for cap in set(OPERATION_CAPABILITIES.values()) - {"inspect_public_surfaces"})
            and not release["findings"]
            and verdict == {"status": "HOLD", "reason_codes": ["INSUFFICIENT_EVIDENCE"]}
        )
        print(json.dumps({"status": "passed" if ok else "failed", "policy_version": POLICY_VERSION, "rejections": len(events), "verdict": verdict}, indent=2))
        return 0 if ok else 1


if __name__ == "__main__": sys.exit(main())
