from __future__ import annotations

import json
from types import SimpleNamespace

from shiproom.review_organisation import _dep, _selection, registry, submit_result


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


def test_second_invalid_submission_fails_only_the_specialist(tmp_path, monkeypatch):
    import shiproom.review_organisation as domain
    context=SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel"})
    manifest={"generation":"plan_1"}
    artifacts={"review-plan.json":{"specialists":[{"specialist_id":"python_engineering","state":"selected"}]},"revision-ledger.json":{"entries":[]}}
    monkeypatch.setattr(domain,"load",lambda ctx:(manifest,artifacts))
    monkeypatch.setattr(domain,"_publish_successor",lambda ctx, manifest, artifacts, label:{"generation":"plan_successor"})
    first=submit_result(context,"python_engineering",{},{}); assert first["status"]=="revision_required"
    artifacts["revision-ledger.json"]["entries"]=[{"specialist_id":"python_engineering"}]
    second=submit_result(context,"python_engineering",{},{}); assert second["status"]=="specialist_failed_closed"


def test_registry_symbols_and_contract_pairings_resolve():
    import shiproom.review_organisation as domain
    value=domain.validate_specialist_registries()
    assert len(value["registry"]["specialists"]) == len(value["native_boundaries"]["specialists"])


def test_review_plan_loader_rejects_pointer_tamper(tmp_path, monkeypatch):
    import shiproom.review_organisation as domain
    context=SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel_review"},authority_binding={"repository_commit":"a"*40})
    vector={"release_id":"rel_review","release_commit":"a"*40,"product_intent":_dep("not_used"),"graph":_dep("not_used"),"assessment":_dep("not_used"),"measurement_ai":_dep("not_used"),"remediation":_dep("not_used"),"browser_applicability":{"authority":"not_inspected","criterion_ids":[]},"language_framework_signals":{"python":True,"typescript":False},"migration_signal":{"authority":"not_inspected","evidence_paths":[]},"ai_surface_signal":{"authority":"not_inspected","evidence_paths":[]},"harness":{}}
    monkeypatch.setattr(domain,"_vector",lambda ctx:vector)
    manifest=domain.prepare(context); pointer=domain.root(context)/"current-review-plan.json"; value=json.loads(pointer.read_text()); value["semantic_bundle_hash"]="sha256:"+"0"*64; pointer.write_text(json.dumps(value))
    try: domain.load(context)
    except ValueError as error: assert str(error)=="review_plan_pointer_tampered"
    else: raise AssertionError("tampered review pointer accepted")
