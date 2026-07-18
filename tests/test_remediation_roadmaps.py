from __future__ import annotations

import json
from types import SimpleNamespace

from shiproom.remediation_roadmaps import _dependency, compile, prepare


def _context(tmp_path):
    return SimpleNamespace(repository_root=tmp_path, release={"release_id":"rel_remediation"}, authority_binding={"repository_commit":"a" * 40})


def test_optional_dependency_states_require_null_bindings():
    for state in ("not_applicable", "not_used", "unavailable"):
        assert _dependency(state) == {"state":state,"generation":None,"semantic_hash":None}
    try:
        _dependency("not_used", "gen", "sha256:" + "0" * 64)
    except ValueError as error:
        assert str(error) == "optional_dependency_must_be_null"
    else:
        raise AssertionError("optional dependency accepted a non-null binding")


def test_remediation_prepare_compile_without_optional_planner(tmp_path, monkeypatch):
    import shiproom.remediation_roadmaps as domain
    context=_context(tmp_path)
    authority={"release_id":"rel_remediation","release_commit":"a" * 40,"product_intent":_dependency("not_used"),"graph":_dependency("not_used"),"assessment":_dependency("not_used"),"measurement_ai":_dependency("not_used")}
    issue={"source_issue_type":"finding","source_issue_id":"finding_1","criterion_id":"criterion_1","requirement_id":"requirement_1","journey_ids":[],"issue_classification":"verified_blocker","issue_authority":"deterministically_established","evidence_refs":[{"kind":"canonical_finding","id":"finding_1","authority":"deterministically_established"}],"automation_class":"exact_route_mismatch"}
    monkeypatch.setattr(domain,"_authority",lambda ctx:authority); monkeypatch.setattr(domain,"_issue_records",lambda ctx,a:[issue])
    prepared=prepare(context)
    assert prepared["actionable_issue_count"] == 1
    manifest=compile(context,prepared["preparation_id"])
    assert manifest["compiler_version"] == "portable-remediation-roadmap.v1"
    packets=list((domain.root(context)/"generations"/manifest["generation"] / "remediation-packets").glob("*.json"))
    assert len(packets) == 1
    packet=json.loads(packets[0].read_text(encoding="utf-8"))
    assert packet["automation_eligibility"] == "bounded_fix_available"
    assert packet["root_cause_hypotheses"] == {"authority":"not_inspected","value":None}
