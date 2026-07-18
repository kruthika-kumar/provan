from __future__ import annotations

import json
from types import SimpleNamespace

from shiproom.review_organisation import _dep, _selection, registry


def test_specialist_registry_is_closed_and_exact():
    values=registry()["specialists"]
    assert {item["specialist_id"] for item in values} == {"product_intent","browser_journey","python_engineering","typescript_engineering","test_adequacy","instrumentation","ai_evaluation","migration_and_rollback"}
    assert next(item for item in values if item["specialist_id"]=="browser_journey")["result_schema"] == "browser-journey-result.v3"


def test_optional_dependency_states_are_exactly_null_bound():
    for state in ("not_applicable","not_used","unavailable"):
        assert _dep(state) == {"state":state,"generation":None,"semantic_hash":None}
    try:
        _dep("not_used","plan_1","sha256:"+"0"*64)
    except ValueError as error:
        assert str(error)=="optional_dependency_must_be_null"
    else:
        raise AssertionError("optional dependency accepted bindings")


def test_browser_absence_is_explicit_not_applicable_not_omission():
    vector={"language_framework_signals":{"python":True,"typescript":False},"browser_applicability":{"authority":"explicitly_not_applicable","criterion_ids":[]},"ai_surface_signal":{"authority":"not_inspected","evidence_paths":[]},"migration_signal":{"authority":"not_inspected","evidence_paths":[]}}
    browser=next(item for item in _selection(vector) if item["specialist_id"]=="browser_journey")
    assert browser["state"]=="skipped" and browser["applicability_authority"]=="explicitly_not_applicable"
