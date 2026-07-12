from __future__ import annotations

import json
from pathlib import Path

import pytest

from shiproom.external import CAPABILITIES, compile_release, eligible_modules, require_capability, review_packet
from shiproom.hermes import validate_manager_decision
from shiproom.models import EvidenceStatus
from shiproom.registry import discover
from shiproom.report import render
from shiproom.review import ReviewerCorrection
from shiproom.runs import LocalRunStore, materialize
from shiproom.verdict import calculate


def contract(**updates):
    value = {"schema_version": "external_release_contract.v1", "project_name": "DrawDB", "repository_url": "https://github.com/drawdb-io/drawdb", "live_url": "https://drawdb.app", "target_user": "developers and data modelers", "product_promise": "Import DBML and export valid MySQL", "critical_journey": ["Open", "Import", "Inspect", "Export"], "non_goals": ["Sharing"], "owner_constraints": ["Read only"], "capabilities": {key: key == "inspect_public_surfaces" for key in CAPABILITIES}}
    value.update(updates); return value


def external_release(): return compile_release(contract())


def test_external_intake_and_fresh_ids():
    first, second = external_release(), external_release()
    assert first["mode"] == "external" and first["release_id"] != second["release_id"]
    assert "generated_path" not in first["deployment"] and "path" not in first["repository"]


def test_skill_waits_for_packet_and_forbids_commands_when_disabled():
    skill = (Path(__file__).parents[1] / "skills" / "shiproom" / "SKILL.md").read_text(encoding="utf-8")
    assert "do not inspect the working directory" in skill
    assert "run_safe_commands=false" in skill and "dependency installation" in skill


def test_external_contract_validation_and_capabilities():
    with pytest.raises(ValueError): compile_release(contract(repository_url="file:///private"))
    release = external_release(); require_capability(release, "inspect_public_surfaces")
    for denied in CAPABILITIES - {"inspect_public_surfaces"}:
        with pytest.raises(PermissionError): require_capability(release, denied)


def test_conventional_and_ai_eligibility_is_bounded():
    modules = discover(); conventional = external_release(); eligible, _ = eligible_modules(conventional, modules)
    assert "data" not in eligible
    ai = compile_release(contract(product_promise="Local AI semantic retrieval with eval evidence")); eligible_ai, _ = eligible_modules(ai, modules)
    assert "data" in eligible_ai
    packet = review_packet(conventional, modules); assert "selected_modules" not in packet
    available = set(modules)
    decision = {"selected_modules": ["product", "engineering", "design", "data"], "skipped_modules": [], "selection_reasons": {key: "reason" for key in available}, "delegation_plan": [{"role": "product_ux"}, {"role": "engineering_qa"}]}
    with pytest.raises(ValueError): validate_manager_decision(decision, available, {"data"})


def test_missing_required_evidence_is_hold_reason_not_new_state():
    release = external_release(); release["checks"] = [{"criterion_id": "X", "required": True, "evidence_status": EvidenceStatus.MISSING}]
    verdict = calculate(release); assert verdict == {"status": "HOLD", "reason_codes": ["INSUFFICIENT_EVIDENCE"]}


def invalid_result(result_id="r1"):
    return {"schema_version": "module_result.v0", "result_id": result_id, "module_id": "product", "checks": [{"criterion_id": "P", "type": "model_review", "passed": True, "evidence_status": "deterministically_verified"}], "findings": []}


def valid_result(result_id="r2"):
    return {"schema_version": "module_result.v0", "result_id": result_id, "module_id": "product", "checks": [{"criterion_id": "P", "type": "model_review", "passed": True, "target": "https://drawdb.app", "evidence_status": "model_reviewed"}], "findings": []}


def test_reviewer_gets_exactly_one_revision(tmp_path):
    store = LocalRunStore(tmp_path); correction = ReviewerCorrection(store, "rel_x")
    first = correction.submit(invalid_result(), expected_module="product", delegation_id="d1")
    assert first["status"] == "revision_required"
    second = correction.submit(valid_result(), expected_module="product", delegation_id="d1", parent_event_id=first["revision_event_id"])
    assert second["status"] == "accepted"
    assert [e["event_type"] for e in store.events("rel_x")] == ["result_rejected", "revision_requested", "revision_accepted"]


def test_second_invalid_result_fails_closed(tmp_path):
    correction = ReviewerCorrection(LocalRunStore(tmp_path), "rel_x")
    assert correction.submit(invalid_result(), expected_module="product", delegation_id="d1")["status"] == "revision_required"
    assert correction.submit(invalid_result("r2"), expected_module="product", delegation_id="d1")["status"] == "failed"


def test_events_order_parent_relationship_and_state_authority(tmp_path):
    release = external_release(); original = json.loads(json.dumps(release)); store = LocalRunStore(tmp_path)
    parent = store.append(release["release_id"], "manager_planning", agent_id="manager")
    store.append(release["release_id"], "module_selected", parent_event_id=parent["event_id"], module_id="product")
    record = materialize(release, store.events(release["release_id"]))
    assert [e["sequence"] for e in record["events"]] == [1, 2]
    assert record["events"][1]["parent_event_id"] == parent["event_id"] and release == original


def test_event_sanitization(tmp_path):
    with pytest.raises(ValueError): LocalRunStore(tmp_path).append("rel_x", "tool", metadata={"token": "secret"})


def test_visual_report_audiences_and_external_omissions(tmp_path):
    release = external_release(); release["panel"] = {"selected_modules": ["product", "engineering", "design"], "skipped_modules": [{"module_id": "data", "reason": "No AI signal"}], "selection_reasons": {}, "delegation_plan": []}; release["verdict"] = {"status": "READY", "reason_codes": []}
    for audience in ("all", "ceo", "product", "engineering"):
        text = render(release, tmp_path / f"{audience}.html", audience=audience).read_text(encoding="utf-8")
        assert "Independent read-only Shiproom review" in text and "SKIPPED" in text and "No AI signal" in text
        assert "Controlled-demo before / after" not in text and "unavailable" in text
    assert "CEO view" not in (tmp_path / "product.html").read_text(encoding="utf-8")


def test_evidence_labels_are_visually_distinct(tmp_path):
    release = external_release(); release["checks"] = [{"criterion_id": "A", "required": True, "passed": True, "target": "https://drawdb.app", "evidence_status": "model_reviewed"}, {"criterion_id": "B", "required": True, "passed": True, "target": "https://drawdb.app", "evidence_status": "deterministically_verified"}]
    text = render(release, tmp_path / "report.html").read_text(encoding="utf-8")
    assert "evidence-model_reviewed" in text and "evidence-deterministically_verified" in text


def test_controlled_report_regression(tmp_path):
    release = external_release(); release.update({"release_id": "rel_35e58f680a1a", "mode": "controlled", "repository": {"url": ".", "base_branch": "main"}, "deployment": {"url": "https://shiproom-demo.example.workers.dev", "report_url": "https://shiproom-demo.example.workers.dev/reports/rel_35e58f680a1a"}, "checks": [{"criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS", "status": 404, "passed": False, "evidence_status": "deterministically_verified"}, {"criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS", "status": 200, "passed": True, "evidence_status": "deterministically_verified"}], "findings": [{"title": "Public result", "criterion_id": "PRODUCT_PUBLIC_RESULT_OPENS", "blocking": True, "state": "CLOSED", "evidence": [{"status": "deterministically_verified", "reference": "https://shiproom-demo.example.workers.dev/result/demo"}]}], "owner_decisions": [{"title": "Beta promise", "choice": "Revise", "resolution": "accepted_condition"}], "remediation_tasks": [{"status": "PATCHED", "auto_merge": False}], "integrations": {"github": {"repository": "kruthika-kumar/shiproom", "pr_number": 1}, "cloudflare": {"deployment_id": "cf", "report_url": "https://shiproom-demo.example.workers.dev/reports/rel_35e58f680a1a"}}})
    text = render(release, tmp_path / "controlled.html").read_text(encoding="utf-8")
    for expected in ("rel_35e58f680a1a", "HTTP 404", "HTTP 200", "Finding closed: True", "Owner condition accepted: True", "kruthika-kumar/shiproom", "cf"):
        assert expected in text
    assert "C:\\Users\\" not in text and "Canonical release object" not in text
