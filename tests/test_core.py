import json
import threading
from pathlib import Path

import pytest

from demo_patient.server import Handler, ThreadingHTTPServer
from shiproom.evidence import http_check, validate_module_result
from shiproom.models import EvidenceStatus, Release
from shiproom.registry import discover, select
from shiproom.remediation import validate_target
from shiproom.verdict import calculate, close_finding, is_terminal_success


def test_registry_has_four_modules():
    assert set(discover()) == {"product", "engineering", "design", "data"}


def test_data_module_is_dynamic():
    modules = discover()
    plain = Release("rel_x", {"url": "."}, {"url": "http://x"}, {"promise": "Share a card"}).to_dict()
    ai = Release("rel_y", {"url": "."}, {"url": "http://x"}, {"promise": "AI model ranking with evals"}).to_dict()
    assert "data" not in select(plain, modules)[0]
    assert "data" in select(ai, modules)[0]


def test_malformed_module_fails_closed():
    with pytest.raises(ValueError): validate_module_result({"module_id": "x"})


@pytest.mark.parametrize("status", [EvidenceStatus.AGENT, EvidenceStatus.MODEL, EvidenceStatus.MISSING])
def test_weak_evidence_cannot_close(status):
    with pytest.raises(ValueError):
        close_finding({"evidence": []}, {"status": status, "kind": "claim", "value": True})


def test_verified_blocker_holds():
    release = Release("rel_x", {}, {}, {}).to_dict()
    release["findings"] = [{"blocking": True, "state": "TRIAGED"}]
    assert calculate(release)["status"] == "HOLD"


@pytest.mark.parametrize("status", ["READY", "SHIP_WITH_CONDITIONS"])
def test_only_explicit_terminal_successes(status):
    assert is_terminal_success(status)


@pytest.mark.parametrize("status", ["HOLD", "AWAITING_OWNER", "DRAFT", "CONTRACTED", "REVIEWING", "REMEDIATING", "VERIFYING"])
def test_non_terminal_states_fail(status):
    assert not is_terminal_success(status)


def test_owner_choice_cannot_erase_open_blocker():
    release = Release("rel_x", {}, {}, {}).to_dict()
    release["findings"] = [{"blocking": True, "state": "TRIAGED"}]
    release["owner_decisions"] = [{"choice": "accept", "resolution": "accepted_condition"}]
    assert calculate(release)["status"] == "HOLD"


def test_decision_resolution_precedence():
    release = Release("rel_x", {}, {}, {}).to_dict()
    release["owner_decisions"] = [{"choice": "revise", "resolution": "resolved"}]
    assert calculate(release)["status"] == "READY"
    release["owner_decisions"][0]["resolution"] = "accepted_condition"
    assert calculate(release)["status"] == "SHIP_WITH_CONDITIONS"


def test_demo_patient_route_mismatch():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        assert http_check(base + "/result/demo")["status"] == 404
        assert http_check(base + "/results/demo")["status"] == 200
    finally:
        server.shutdown(); thread.join()


def test_non_allowlisted_remediation_rejected(tmp_path):
    target = tmp_path / "file.txt"; target.write_text("x")
    with pytest.raises(ValueError): validate_target(tmp_path, target, "database_migration")


def test_remediation_cannot_escape_repo(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    with pytest.raises(ValueError): validate_target(tmp_path, outside, "route_fix")
