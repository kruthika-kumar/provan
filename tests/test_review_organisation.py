from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

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


def test_adaptation_requires_an_accepted_specialist_result(tmp_path):
    from scripts.run_evals import _graph_context
    from shiproom.graph import compile_bundle, load_assessment_input
    import shiproom.review_organisation as domain

    context = _graph_context(tmp_path, multi_criteria=True)
    compile_bundle(context)
    criterion_id = load_assessment_input(context)["intent_artifacts"]["acceptance-criteria.json"]["criteria"][0]["criterion_id"]
    context.release["change_impact"] = {"migration_surface": True}
    manifest = domain.prepare(context)
    with pytest.raises(ValueError, match="adaptation_evidence_unlinked"):
        domain.adapt(context, "migration_surface_discovered", "migration_and_rollback", criterion_id, "untrusted_prose")
    order_dir = domain.root(context) / "generations" / manifest["generation"] / "specialist-work-orders"
    work = next(json.loads(path.read_text(encoding="utf-8")) for path in order_dir.glob("*.json") if json.loads(path.read_text(encoding="utf-8"))["specialist_id"] == "migration_and_rollback")
    result = {"schema_version": "migration-and-rollback-result.v1", "work_order_id": work["work_order_id"], "criterion_ids": [criterion_id], "evidence_refs": [], "rollback_required": False, "limitations": []}
    accepted = domain.submit_result(context, "migration_and_rollback", result, {"work_order_id": work["work_order_id"]})
    adapted = domain.adapt(context, "migration_surface_discovered", "migration_and_rollback", criterion_id, accepted["result_id"])
    assert adapted["status"] == "accepted"


def test_selected_native_specialists_bind_an_existing_native_preparation(tmp_path, monkeypatch):
    """A review-plan wrapper may only select the native packet it can load."""
    from scripts.run_evals import _graph_context
    from shiproom.graph import compile_bundle
    from shiproom.assessment import prepare as prepare_assessment
    import shiproom.review_organisation as domain

    context = _graph_context(tmp_path)
    compile_bundle(context)
    original_vector = domain._vector
    def with_python_surface(value):
        vector = original_vector(value)
        vector["language_framework_signals"]["python"] = True
        return vector
    monkeypatch.setattr(domain, "_vector", with_python_surface)
    first = domain.prepare(context)
    _, unavailable = domain.load(context)
    by_id = {item["specialist_id"]: item for item in unavailable["review-plan.json"]["specialists"]}
    assert by_id["python_engineering"]["state"] == "unavailable"
    prepare_assessment(context)
    second = domain.prepare(context)
    _, selected = domain.load(context)
    engineering = next(item for item in selected["review-plan.json"]["specialists"] if item["specialist_id"] == "python_engineering")
    assert engineering["state"] == "selected"
    assert engineering["native_binding"]["domain"] == "assessment"
    assert second["input_vector"]["assessment"]["state"] == "required_present"
    assert first["input_vector"]["assessment"]["state"] == "not_used"


def test_later_unused_native_preparation_does_not_stale_prior_plan(tmp_path):
    from scripts.run_evals import _graph_context
    from shiproom.graph import compile_bundle
    from shiproom.assessment import prepare as prepare_assessment
    import shiproom.review_organisation as domain

    context = _graph_context(tmp_path)
    compile_bundle(context)
    first = domain.prepare(context)
    prepare_assessment(context)
    loaded, _ = domain.load(context)
    assert loaded["generation"] == first["generation"]


def test_changed_consumed_native_preparation_stales_review_plan(tmp_path, monkeypatch):
    from scripts.run_evals import _graph_context
    from shiproom.graph import compile_bundle
    from shiproom.assessment import prepare as prepare_assessment
    import shiproom.review_organisation as domain

    context = _graph_context(tmp_path)
    compile_bundle(context)
    prepare_assessment(context)
    original_vector = domain._vector
    def with_python_surface(value):
        vector = original_vector(value)
        vector["language_framework_signals"]["python"] = True
        return vector
    monkeypatch.setattr(domain, "_vector", with_python_surface)
    domain.prepare(context)
    prepare_assessment(context)
    with pytest.raises(ValueError, match="stale_consumed_assessment_dependency"):
        domain.load(context)


def test_selection_uses_closed_surface_policy_and_keeps_candidate_scope():
    import shiproom.review_organisation as domain
    vector = {"language_framework_signals":{"python":False,"typescript":False},
              "browser_applicability":{"authority":"not_inspected","criterion_ids":[]},
              "ai_surface_signal":{"authority":"candidate_surface","evidence_paths":["src/ai.py"]},
              "migration_signal":{"authority":"confirmed_surface","evidence_paths":["migrations/v1.py"]}}
    values = {item["specialist_id"]: item for item in domain._selection(vector)}
    assert values["ai_evaluation"]["state"] == "selected"
    assert values["ai_evaluation"]["applicability_authority"] == "candidate_surface"
    # The registered migration signal caps the review at candidate scope even
    # when change impact names a migration surface.
    assert values["migration_and_rollback"]["applicability_authority"] == "candidate_surface"
