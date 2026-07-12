import json
import subprocess
from pathlib import Path

import pytest

from shiproom.evidence import validate_module_result
from shiproom.models import EvidenceStatus, Release
from shiproom.registry import discover, select
from shiproom.remediation import ROUTE_TARGETS, validate_target
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
    root = Path(__file__).resolve().parents[1]
    broken, fixed = ROUTE_TARGETS[Path("demo_patient/server.py")]
    source = ""
    for ref in ("main", "origin/main", "HEAD^1", "HEAD"):
        result = subprocess.run(["git", "show", f"{ref}:demo_patient/server.py"], cwd=root, text=True, capture_output=True)
        if result.returncode == 0 and result.stdout.count(broken) == 1 and result.stdout.count(fixed) == 0:
            source = result.stdout; break
    assert source, "no broken controlled-patient base revision found"
    assert source.count(broken) == 1
    assert fixed not in source


def test_non_allowlisted_remediation_rejected(tmp_path):
    target = tmp_path / "file.txt"; target.write_text("x")
    with pytest.raises(ValueError): validate_target(tmp_path, target, "database_migration")


def test_remediation_cannot_escape_repo(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    with pytest.raises(ValueError): validate_target(tmp_path, outside, "route_fix")
