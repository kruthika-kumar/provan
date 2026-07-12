from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from shiproom.evidence import validate_module_result
from shiproom.models import EvidenceStatus, Release
from shiproom.registry import discover, select
from shiproom.verdict import calculate, close_finding
from shiproom.external import CAPABILITIES, compile_release
from shiproom.policy import POLICY_VERSION, execute_external_operation
from shiproom.runs import LocalRunStore


def main() -> int:
    cases = []
    def check(name, condition): cases.append((name, bool(condition)))
    base = Release("rel_eval", {"url": "."}, {"url": "http://example.invalid"}, {"promise": "Share a card"}).to_dict()
    check("registry discovers modules", len(discover()) == 4)
    check("irrelevant data skipped", "data" not in select(base, discover())[0])
    ai = dict(base); ai["product"] = {"promise": "AI retrieval model with eval"}
    check("AI selects data", "data" in select(ai, discover())[0])
    blocked = dict(base); blocked["findings"] = [{"blocking": True, "state": "TRIAGED"}]
    check("blocker holds", calculate(blocked)["status"] == "HOLD")
    for label, status in (("agent report cannot close", EvidenceStatus.AGENT), ("model review cannot close", EvidenceStatus.MODEL), ("missing evidence cannot close", EvidenceStatus.MISSING)):
        try: close_finding({}, {"status": status, "kind": "claim", "value": True}); ok = False
        except ValueError: ok = True
        check(label, ok)
    try: validate_module_result({"module_id": "bad"}); ok = False
    except ValueError: ok = True
    check("malformed output rejected", ok)
    verified = close_finding({"blocking": True, "state": "VERIFYING"}, {"status": EvidenceStatus.DETERMINISTIC, "kind": "http_status", "value": 200})
    check("verified exact rerun closes", verified["state"] == "CLOSED")
    owner = dict(base); owner["owner_decisions"] = [{"title": "Promise", "choice": None}]
    check("owner decision requested", calculate(owner)["status"] == "AWAITING_OWNER")
    owner["owner_decisions"][0].update({"choice": "Revise beta promise", "resolution": "accepted_condition"})
    check("owner decision preserved", calculate(owner)["status"] == "SHIP_WITH_CONDITIONS")
    blocked_owner = dict(blocked); blocked_owner["owner_decisions"] = [{"choice": "Accept", "resolution": "accepted_condition"}]
    check("owner choice cannot erase blocker", calculate(blocked_owner)["status"] == "HOLD")
    check("report evidence linkage contract", all("evidence" in f for f in [verified]))
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); fixture = root / "README.md"; fixture.write_text("redacted public fixture\n", encoding="utf-8")
        contract = {"schema_version":"external_release_contract.v1","project_name":"Redacted public project","repository_url":"https://github.com/example/public-project","live_url":"https://example.com","target_user":"public users","product_promise":"Inspect a bounded public journey","critical_journey":["Open","Inspect"],"non_goals":[],"owner_constraints":["Read only"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}}
        external = compile_release(contract); external["checks"] = [{"criterion_id":"PUBLIC_JOURNEY","required":True,"passed":False,"evidence_status":EvidenceStatus.MISSING,"policy_version":POLICY_VERSION}]
        store = LocalRunStore(root / "history"); called = []
        try: execute_external_operation(external, store, "test.run", lambda: called.append(True))
        except PermissionError: pass
        external_verdict = calculate(external)
        check("redacted external read-only failure", not called and fixture.read_text(encoding="utf-8")=="redacted public fixture\n" and not external["findings"] and external_verdict=={"status":"HOLD","reason_codes":["INSUFFICIENT_EVIDENCE"]} and store.events(external["release_id"])[0]["event_type"]=="operation_rejected")
    for name, passed in cases: print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(p for _, p in cases) else 1


if __name__ == "__main__": sys.exit(main())
