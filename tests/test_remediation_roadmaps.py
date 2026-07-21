from __future__ import annotations

import json
from types import SimpleNamespace

from shiproom.remediation_roadmaps import _dependency, _policy_decision, compile, prepare, closure_verify, root


def _context(tmp_path):
    return SimpleNamespace(repository_root=tmp_path, release={"release_id":"rel_remediation", "branch":"current_branch"}, authority_binding={"repository_commit":"a" * 40})


def test_optional_dependency_states_require_null_bindings():
    for state in ("not_applicable", "not_used", "unavailable"):
        assert _dependency(state) == {"state":state,"generation":None,"semantic_hash":None}
    try:
        _dependency("not_used", "gen", "sha256:" + "0" * 64)
    except ValueError as error:
        assert str(error) == "optional_dependency_must_be_null"
    else:
        raise AssertionError("optional dependency accepted a non-null binding")


def test_closed_or_stale_finding_cannot_remain_actionable():
    closed=_policy_decision(blocker=True,criterion_authority="deterministically_established",evidence_class="deterministically_established",open_state="closed",owner_required=False,fresh=True,finding_state="closed")
    stale=_policy_decision(blocker=True,criterion_authority="deterministically_established",evidence_class="deterministically_established",open_state="open",owner_required=False,fresh=False,finding_state="open")
    assert closed["actionable"] is False and stale["actionable"] is False


def test_authority_policy_fails_closed_when_no_registered_rule_matches(monkeypatch):
    import shiproom.remediation_roadmaps as domain
    monkeypatch.setattr(domain, "authority_policy", lambda: {"rules": []})
    try:
        domain._policy_decision(blocker=False, criterion_authority="not_inspected", evidence_class="not_inspected",
                                open_state="open", owner_required=False, fresh=True)
    except ValueError as error:
        assert str(error) == "remediation_issue_authority_policy_no_match"
    else:
        raise AssertionError("unregistered remediation authority tuple was accepted")


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


def test_planner_human_cannot_self_declare_owner(tmp_path, monkeypatch):
    import shiproom.remediation_roadmaps as domain
    context=_context(tmp_path)
    authority={"release_id":"rel_remediation","release_commit":"a" * 40,"product_intent":_dependency("not_used"),"graph":_dependency("not_used"),"assessment":_dependency("not_used"),"measurement_ai":_dependency("not_used")}
    issue={"source_issue_type":"finding","source_issue_id":"finding_1","criterion_id":"criterion_1","requirement_id":"requirement_1","journey_ids":[],"issue_classification":"verified_blocker","issue_authority":"deterministically_established","evidence_refs":[],"automation_class":None}
    monkeypatch.setattr(domain,"_authority",lambda ctx:authority); monkeypatch.setattr(domain,"_issue_records",lambda ctx,a:[issue])
    prepared=prepare(context); work=prepared["planner_work_order"]; inbox=domain.root(context)/"inbox"/prepared["preparation_id"]/work["work_order_id"]; inbox.mkdir(parents=True)
    result={"schema_version":"remediation-planner-result.v1","work_order_id":work["work_order_id"],"preparation_id":prepared["preparation_id"],"records":[{"source_issue_id":"finding_1","root_cause_hypotheses":[],"recommended_changes":[],"test_proposals":[],"instrumentation_implications":[],"rollback_suggestions":[],"complexity":"low","risk":"low","suggested_owner":"owner"}],"assumptions":[],"limitations":[]}
    raw=(json.dumps(result,sort_keys=True)+"\n").encode(); (inbox/"result.json").write_bytes(raw)
    receipt={"schema_version":"remediation-planner-completion-receipt.v1","work_order_id":work["work_order_id"],"result_snapshot_hash":"sha256:"+__import__("hashlib").sha256(raw).hexdigest(),"executor":{"executor_type":"human","owner_authority_ref":"invented","owner_authority_snapshot_hash":"sha256:"+"0"*64}}
    (inbox/"completion-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")
    try:
        compile(context,prepared["preparation_id"])
    except ValueError as error:
        assert str(error) == "planner_owner_authority_invalid"
    else:
        raise AssertionError("self-declared human owner authority was accepted")


def test_closure_inbox_requires_exact_passing_rerun_and_independent_verifier(tmp_path, monkeypatch):
    import hashlib
    import shiproom.remediation_roadmaps as domain
    context = _context(tmp_path)
    authority={"release_id":"rel_remediation","release_commit":"a"*40,"product_intent":_dependency("not_used"),"graph":_dependency("not_used"),"assessment":_dependency("not_used"),"measurement_ai":_dependency("not_used")}
    issue={"source_issue_type":"finding","source_issue_id":"finding_1","criterion_id":"criterion_1","requirement_id":"requirement_1","journey_ids":[],"issue_classification":"verified_blocker","issue_authority":"deterministically_established","evidence_refs":[],"automation_class":None}
    monkeypatch.setattr(domain,"_authority",lambda ctx:authority); monkeypatch.setattr(domain,"_issue_records",lambda ctx,a:[issue])
    prepared=prepare(context); manifest=compile(context,prepared["preparation_id"])
    packet=json.loads((root(context)/"generations"/manifest["generation"] / "remediation-plan.json").read_text()) ["packets"][0]
    closure_id=packet["verification_contract_id"]; inbox=root(context)/"closure-inbox"/closure_id; inbox.mkdir(parents=True)
    contract=json.loads((root(context)/"generations"/manifest["generation"] / "closure-contracts" / (closure_id+".json")).read_text())
    result=lambda check_id:{"check_id":check_id,"passed":True,"evidence_class":"deterministically_established"}
    evidence={"schema_version":"remediation-closure-evidence.v1","closure_contract_id":closure_id,"release_id":"rel_remediation","release_commit":"a"*40,"branch":"current_branch","fixer_id":"fixer","reruns":[{"check_id":"finding_1","passed":True,"evidence_class":"deterministically_established"}],"regression_results":[result(item) for item in contract["regression_checks"]],"test_results":[result(item) for item in contract["test_requirements"]],"instrumentation_results":[result(item) for item in contract["instrumentation_requirements"]],"protected_invariant_outcomes":[{"invariant":"canonical_findings_unchanged","passed":True}]}
    raw=(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode(); (inbox/"evidence.json").write_bytes(raw)
    receipt={"schema_version":"remediation-closure-verifier-receipt.v1","closure_contract_id":closure_id,"evidence_snapshot_hash":"sha256:"+hashlib.sha256(raw).hexdigest(),"verifier_id":"verifier","executor_type":"human"}
    (inbox/"verifier-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")
    assert closure_verify(context,closure_id)["status"] == "satisfied_candidate"
    receipt["verifier_id"]="fixer"; (inbox/"verifier-receipt.json").write_text(json.dumps(receipt),encoding="utf-8")
    try: closure_verify(context,closure_id)
    except ValueError as error: assert str(error)=="closure_verifier_not_independent"
    else: raise AssertionError("fixer verified own closure")


def test_closure_inbox_rejects_unlisted_file_without_reading_evidence(tmp_path, monkeypatch):
    import shiproom.remediation_roadmaps as domain
    context = _context(tmp_path)
    authority={"release_id":"rel_remediation","release_commit":"a"*40,"product_intent":_dependency("not_used"),"graph":_dependency("not_used"),"assessment":_dependency("not_used"),"measurement_ai":_dependency("not_used")}
    issue={"source_issue_type":"finding","source_issue_id":"finding_1","criterion_id":"criterion_1","requirement_id":"requirement_1","journey_ids":[],"issue_classification":"verified_blocker","issue_authority":"deterministically_established","evidence_refs":[],"automation_class":None}
    monkeypatch.setattr(domain,"_authority",lambda ctx:authority); monkeypatch.setattr(domain,"_issue_records",lambda ctx,a:[issue])
    prepared=prepare(context); manifest=compile(context,prepared["preparation_id"])
    closure_id=json.loads((root(context)/"generations"/manifest["generation"] / "remediation-plan.json").read_text())["packets"][0]["verification_contract_id"]
    inbox=root(context)/"closure-inbox"/closure_id; inbox.mkdir(parents=True)
    (inbox/"extra.json").write_text("{}",encoding="utf-8")
    result=closure_verify(context,closure_id)
    assert result["status"]=="not_evaluated" and result["reason_codes"]==["storage_file_set_mismatch:closure_inbox"]


def test_planner_work_order_binds_immutable_contract_snapshots(tmp_path, monkeypatch):
    import shiproom.remediation_roadmaps as domain
    context = _context(tmp_path)
    authority={"release_id":"rel_remediation","release_commit":"a"*40,"product_intent":_dependency("not_used"),"graph":_dependency("not_used"),"assessment":_dependency("not_used"),"measurement_ai":_dependency("not_used")}
    issue={"source_issue_type":"finding","source_issue_id":"finding_1","criterion_id":"criterion_1","requirement_id":"requirement_1","journey_ids":[],"issue_classification":"verified_blocker","issue_authority":"deterministically_established","evidence_refs":[],"automation_class":None}
    monkeypatch.setattr(domain,"_authority",lambda ctx:authority); monkeypatch.setattr(domain,"_issue_records",lambda ctx,a:[issue])
    prepared = prepare(context)
    work = prepared["planner_work_order"]
    assert set(work["contract_bindings"]) == {"remediation-planner-role.v1.json","remediation-planner-result.v1.json","remediation-planner-completion-receipt.v1.json"}
    schema = domain.root(context) / "preparations" / prepared["preparation_id"] / "contract-schemas" / "remediation-planner-result.v1.json"
    schema.write_text("{}", encoding="utf-8")
    try:
        compile(context, prepared["preparation_id"])
    except ValueError as error:
        assert str(error) == "remediation_contract_snapshot_tampered"
    else:
        raise AssertionError("tampered remediation contract snapshot was accepted")
