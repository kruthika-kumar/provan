from __future__ import annotations

import json
from pathlib import Path

import pytest

from shiproom.hermes import apply_manager_decision, validate_manager_decision, validate_receipt
from shiproom.models import Release
from shiproom.public import public_release_view, validate_public_release_view
from shiproom.registry import discover
from shiproom.report import render


def release() -> dict:
    value = Release(
        "rel_public",
        {"url": ".", "path": r"C:\Users\private\shiproom", "base_branch": "main"},
        {"url": "https://shiproom-demo.example.workers.dev", "report_url": "https://shiproom-demo.example.workers.dev/reports/rel_public"},
        {"name": "Launch Card", "target_user": "builders", "promise": "Open a public result", "critical_journey": ["Generate", "Open"], "non_goals": []},
    ).to_dict()
    value["integrations"] = {"github": {"repository": "kruthika-kumar/shiproom", "pr_number": 1, "pr_id": "PR_1", "comment_id": "C_1", "comment_url": "https://github.com/kruthika-kumar/shiproom/pull/1#issuecomment-1"}, "cloudflare": {"deployment_id": "cf-1", "report_url": value["deployment"]["report_url"]}}
    return value


def test_public_projection_excludes_canonical_private_state(tmp_path):
    canonical = release(); canonical["private_notes"] = "do not publish"
    view = public_release_view(canonical, discover())
    encoded = json.dumps(view)
    assert "repository" not in view and "C:\\Users" not in encoded and "private_notes" not in encoded
    output = render(canonical, tmp_path / "report.html"); report = output.read_text(encoding="utf-8")
    assert "Canonical release object" not in report and "C:\\Users" not in report and canonical["release_id"] in report


def test_completed_manager_selection_is_projected_and_rendered(tmp_path):
    canonical = release()
    canonical["panel"] = {"selected_modules": ["product", "engineering", "design"], "skipped_modules": [{"module_id": "data", "reason": "no signal"}], "selection_reasons": {"product": "promise", "engineering": "repo", "design": "surface", "data": "no signal"}, "delegation_plan": [{"role": "product_ux"}, {"role": "engineering_qa"}]}
    view = public_release_view(canonical, discover())
    assert view["manager_selection"]["selected_modules"] == ["product", "engineering", "design"]
    report = render(canonical, tmp_path / "report.html").read_text(encoding="utf-8")
    assert "product, engineering, design" in report


def test_public_projection_rejects_paths_unknown_fields_and_private_urls():
    view = public_release_view(release(), discover())
    view["product"]["promise"] = r"Read C:\Users\private\file"
    with pytest.raises(ValueError): validate_public_release_view(view)
    view = public_release_view(release(), discover()); view["unknown"] = True
    with pytest.raises(ValueError): validate_public_release_view(view)
    canonical = release(); canonical["deployment"]["url"] = "http://127.0.0.1:8787"
    with pytest.raises(ValueError): public_release_view(canonical, discover())


def test_dynamic_selection_partitions_catalogue_and_requires_delegates():
    available = set(discover())
    decision = {"selected_modules": ["product", "engineering", "design"], "skipped_modules": ["data"], "selection_reasons": {key: "applicable" if key != "data" else "no data signal" for key in available}, "delegation_plan": [{"role": "product_ux", "modules": ["product", "design"]}, {"role": "engineering_qa", "modules": ["engineering"]}]}
    validate_manager_decision(decision, available)
    canonical = apply_manager_decision(release(), decision, available)
    assert canonical["panel"]["selected_modules"] == decision["selected_modules"]
    broken = dict(decision); broken["delegation_plan"] = []
    with pytest.raises(ValueError): validate_manager_decision(broken, available)


def test_minimal_receipt_contract():
    receipt = {"release_id": "rel_public", "session_id": "session-native-123", "session_name": "shiproom-judged-release-rel_public", "started_at": "2026-07-12T10:00:00Z", "ended_at": "2026-07-12T10:10:00Z", "public_inputs_only": True}
    assert validate_receipt(receipt, "rel_public") == receipt
    with pytest.raises(ValueError): validate_receipt({**receipt, "session_id": ""}, "rel_public")
    with pytest.raises(ValueError): validate_receipt({**receipt, "session_export": []}, "rel_public")
