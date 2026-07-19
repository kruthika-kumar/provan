from __future__ import annotations

from types import SimpleNamespace

from shiproom.contestability import append_action, load


def _ctx(tmp_path, owner=True):
    authority={"authority_id":"owner_1","release_id":"rel_contest","snapshot_hash":"sha256:"+"1"*64}
    return SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel_contest","owner_authorities":[authority] if owner else [],"findings":[{"id":"finding_1","blocker":True,"state":"OPEN"}]})


def _action():
    return {"action_id":"action_1","release_id":"rel_contest","actor_type":"owner","actor_label":"claimed","action":"accept_named_risk","target_type":"finding","target_id":"finding_1","source_generation":"gen_1","submitted_evidence":None,"rationale":"accepted risk","created_at":"2026-01-01T00:00:00+00:00","owner_authority_ref":"owner_1","owner_authority_snapshot_hash":"sha256:"+"1"*64}


def test_owner_bound_named_risk_is_append_only(tmp_path):
    context=_ctx(tmp_path); accepted=append_action(context,_action()); assert accepted["status"]=="accepted"
    replay=append_action(context,_action()); assert replay["status"]=="idempotent_replay"
    _,artifacts=load(context); assert artifacts["contestation-ledger.json"]["actions"][0]["action"]=="accept_named_risk"


def test_self_declared_owner_is_rejected(tmp_path):
    try: append_action(_ctx(tmp_path,owner=False),_action())
    except ValueError as error: assert str(error)=="owner_authority_invalid"
    else: raise AssertionError("self-declared owner was accepted")


def test_contestation_rejects_unregistered_evidence_compiler(tmp_path):
    action=_action(); action.update({"action":"dispute_with_evidence","owner_authority_ref":None,"owner_authority_snapshot_hash":None,"submitted_evidence":{"compiler":"prose","generation":"gen_1","record_id":"finding_1"}})
    try: append_action(_ctx(tmp_path),action)
    except ValueError as error: assert str(error)=="contestation_evidence_compiler_unregistered"
    else: raise AssertionError("unregistered compiler evidence was accepted")
