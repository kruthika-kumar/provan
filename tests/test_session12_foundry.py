from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from provan.canonical import canonical_bytes, sha256_bytes
from provan.errors import ProvanError
from provan.foundry import RUN_STAGES, foundry, pattern_library, route
from provan.modeling import (FROZEN_PUBLIC_MODEL_EGRESS, ModelProvider,
    build_envelope, invoke_frozen_public_openai_responses)
from provan.session12_validators import validate_pattern_library_serialized, validate_projection_serialized, validate_run_serialized
from provan.state import secure_read, secure_write


def _brief(home: Path) -> dict:
    value = {"schema_id":"provan.change_brief.v1","brief_id":"11111111-1111-4111-8111-111111111111","case_id":"sha256:"+"2"*64,"candidate":{"repository_identity":"https://github.com/example/project","mode":"immutable","base":"3"*40,"head":"4"*40,"working_tree_digest":None,"candidate_digest":"sha256:"+"5"*64}}
    secure_write(Path("outputs/change-brief")/value["brief_id"]/"change-brief.json", canonical_bytes(value))
    return value


def _manifest(tmp_path: Path, routing: dict | None = None, spend_control: dict | None = None) -> Path:
    (tmp_path/"intent.md").write_text("Make the public response durable and backward compatible.",encoding="utf-8")
    value={"sources":[{"path":"intent.md","role":"intent"}],"routing_inputs":routing or {"risk":"medium","ambiguity":"material","blast_radius":"public_contract","reversibility":"bounded","oracle":"missing","actor_autonomy":"low"}}
    if spend_control is not None:value["spend_control"]=spend_control
    path=tmp_path/"sources.json";path.write_text(json.dumps(value),encoding="utf-8");return path


def test_standard_no_model_is_ineligible_but_readiness_is_distinct(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),depth="standard",no_model=True,format_name="json")
    assert run["run_eligibility"]=="NOT_ELIGIBLE" and run["contract_readiness"]=="NOT_READY"
    projection_raw=secure_read(Path("outputs/contract-foundry")/run["run_id"]/"foundry-acceptance-projection.json")
    validate_run_serialized(canonical_bytes(run),projection_raw)


def test_tier_zero_deterministic_run_is_eligible(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);inputs={"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"};run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,inputs),depth="standard",no_model=True)
    assert run["routing_receipt"]["tier"]==0 and run["run_eligibility"]=="ELIGIBLE" and run["stages"]==RUN_STAGES["standard"]


def test_deep_scripted_paths_are_isolated_and_nonqualifying(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));monkeypatch.setenv("PROVAN_ALLOW_SCRIPTED_PROVIDER","1");brief=_brief(tmp_path);run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),depth="deep",provider_id="scripted-test")
    assert [row["path"] for row in run["blind_paths"]]==["A","B"]
    assert all(row["conversation_state"] is None and row["previous_response_id"] is None and not row["background"] for row in run["blind_paths"])
    assert {row["contract_output"]["kind"] for row in run["blind_paths"]}=={"candidate","structured_critique"}
    assert run["mode_qualification"]=="IMPLEMENTED_UNQUALIFIED" and run["run_eligibility"]=="NOT_ELIGIBLE" and run["provider_receipts"][0]["semantic_qualification"] is False
    root=Path("outputs/contract-foundry")/run["run_id"];projection=secure_read(root/"foundry-acceptance-projection.json");artifacts={run["source_ledger"]["path"]:secure_read(root/run["source_ledger"]["path"])}
    for name,ref in run["stage_artifacts"].items():
        if name!="revisions":artifacts[ref["path"]]=secure_read(root/ref["path"])
    for ref in run["model_envelope_refs"]:artifacts[ref["path"]]=secure_read(root/ref["path"])
    validate_run_serialized(canonical_bytes(run),projection,artifacts)
    intent=json.loads(artifacts[run["stage_artifacts"]["intent"]["path"]])
    candidate=json.loads(artifacts[run["stage_artifacts"]["contract_candidate"]["path"]])
    assert intent["synthesis_method"]=="frozen_dual_path_reconciliation_v1"
    assert intent["input_path_digests"]==[row["contract_output"]["digest"] for row in run["blind_paths"]]
    assert candidate["proposed_terms"]["conditions"] and all(row["authority"]=="model_reviewed_proposal" for row in candidate["proposed_terms"]["conditions"])
    assert [row["stage"] for row in run["stage_execution"]]==RUN_STAGES["deep"]
    ref=run["model_envelope_refs"][0];bad=dict(artifacts);envelope=json.loads(bad[ref["path"]]);envelope["instructions"]+=" undisclosed";bad[ref["path"]]=canonical_bytes(envelope);tampered=copy.deepcopy(run);tampered_ref=tampered["model_envelope_refs"][0];tampered_ref["sha256"]=sha256_bytes(bad[ref["path"]]);tampered["blind_paths"][0]["model_envelope_ref"]=tampered_ref
    with pytest.raises(ProvanError,match="FOUNDRY_MODEL_ENVELOPE_SEMANTICS_INVALID"):validate_run_serialized(canonical_bytes(tampered),projection,bad)


def test_provider_identity_is_allowlisted_and_pinned(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path)
    with pytest.raises(ProvanError,match="FOUNDRY_PROVIDER_NOT_ALLOWLISTED"):foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),provider_id="dynamic-model")
    with pytest.raises(ProvanError,match="FOUNDRY_MODEL_EGRESS_NOT_AUTHORIZED"):foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path),provider_id="openai-responses-primary")
    tier_zero={"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"}
    run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,tier_zero),provider_id="openai-responses-primary")
    receipt=run["provider_receipts"][0];assert receipt["origin"]=="https://api.openai.com" and receipt["model"]=="gpt-5.6-sol" and receipt["provider_retention"]=="PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED" and receipt["calls"]==0


def test_frozen_public_transport_spy_receives_only_envelope_semantics(monkeypatch: pytest.MonkeyPatch):
    content="public fixture intent";digest=sha256_bytes(content.encode("utf-8"));monkeypatch.setitem(FROZEN_PUBLIC_MODEL_EGRESS,"fixture-public",(digest,))
    provider=ModelProvider("openai-responses-primary","gpt-5.6-sol","pinned-work-order-v2","https://api.openai.com","high")
    envelope=build_envelope(case_id="sha256:"+"1"*64,candidate_digest="sha256:"+"2"*64,provider=provider,instructions="Return bounded proposals.",blocks=[{"category":"blind_intent","content":content}])
    requests=[]
    class Response:
        def __init__(self,raw):self.raw=raw;self.headers={}
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def read(self,*args):return self.raw
    class Opener:
        def open(self,request,timeout):
            requests.append(request)
            if request.method=="GET":return Response(b'{"id":"gpt-5.6-sol"}')
            result=json.dumps({"model_reviewed_implications":["bounded"],"unresolved":[]},separators=(",",":"));wire=json.dumps({"output":[{"type":"message","content":[{"type":"output_text","text":result}]}],"usage":{"input_tokens":10,"output_tokens":4}},separators=(",",":")).encode();return Response(wire)
    monkeypatch.setattr("urllib.request.build_opener",lambda *args:Opener())
    result,receipt=invoke_frozen_public_openai_responses(provider,envelope,"not-a-real-key",{"case_id":"fixture-public","classification":"PUBLIC_SAFE","operator_confirmed":True})
    assert result=={"model_reviewed_implications":["bounded"],"unresolved":[]} and receipt["calls"]==1
    body=json.loads(requests[1].data);assert body["store"] is False and body["background"] is False and body["reasoning"]=={"effort":"high","context":"current_turn"} and "previous_response_id" not in body
    semantic=json.loads(body["input"]);assert semantic=={"instructions":envelope["instructions"],"selected_blocks":envelope["selected_blocks"],"permitted_output_classes":envelope["permitted_output_classes"]}


def test_run_validator_rejects_projection_and_stage_tampering(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);inputs={"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"};run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,inputs),no_model=True)
    projection=secure_read(Path("outputs/contract-foundry")/run["run_id"]/"foundry-acceptance-projection.json")
    bad=copy.deepcopy(run);bad["stages"]=list(reversed(bad["stages"]))
    with pytest.raises(ProvanError,match="FOUNDRY_STAGE_ORDER_INVALID"):validate_run_serialized(canonical_bytes(bad),projection)
    p=json.loads(projection);p["creates_authority"]=True
    with pytest.raises(ProvanError,match="FOUNDRY_PROJECTION_AUTHORITY_INVALID"):validate_projection_serialized(canonical_bytes(p))


def test_run_validator_resolves_all_typed_stage_artifacts(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);inputs={"risk":"low","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"};run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,inputs),no_model=True)
    root=Path("outputs/contract-foundry")/run["run_id"]
    artifacts={ref["path"]:secure_read(root/ref["path"]) for name,ref in run["stage_artifacts"].items() if name!="revisions"}
    artifacts[run["source_ledger"]["path"]]=secure_read(root/run["source_ledger"]["path"])
    for ref in run["model_envelope_refs"]:artifacts[ref["path"]]=secure_read(root/ref["path"])
    projection=secure_read(root/"foundry-acceptance-projection.json");validate_run_serialized(canonical_bytes(run),projection,artifacts)
    first=next(iter(artifacts));tampered=dict(artifacts);value=json.loads(tampered[first]);value["limitations"]=["invented"]
    tampered[first]=canonical_bytes(value)
    with pytest.raises(ProvanError,match="FOUNDRY_STAGE_ARTIFACT_BINDING_MISMATCH"):validate_run_serialized(canonical_bytes(run),projection,tampered)


def test_pattern_library_has_all_families_and_no_execution():
    value=validate_pattern_library_serialized(canonical_bytes(pattern_library()))
    assert len(value["patterns"])==19 and value["execution_available"] is False and value["challenge_available"] is False


def test_router_escalates_unresolved_and_model_cannot_downroute():
    inputs={"risk":"unresolved","ambiguity":"low","blast_radius":"bounded","reversibility":"easy","oracle":"adequate","actor_autonomy":"low"}
    assert route(inputs)["tier"]==3
    with pytest.raises(ProvanError,match="FOUNDRY_ROUTING_INPUT_INVALID"):route({**inputs,"risk":"INVALID"})


def test_spend_reservation_is_checked_before_each_semantic_call(tmp_path:Path,monkeypatch:pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));monkeypatch.setenv("PROVAN_ALLOW_SCRIPTED_PROVIDER","1");brief=_brief(tmp_path)
    control={"spent":51,"in_flight":0,"minimum_mandatory_remaining":5,"per_call_reservation":10}
    with pytest.raises(ProvanError,match="FOUNDRY_SPEND_RESERVATION_EXCEEDED"):foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,spend_control=control),depth="deep",provider_id="scripted-test")
    control={"spent":45,"in_flight":0,"minimum_mandatory_remaining":5,"per_call_reservation":10}
    run,_=foundry(brief_id=brief["brief_id"],source_manifest=_manifest(tmp_path,spend_control=control),depth="deep",provider_id="scripted-test")
    assert [row["projected_total"] for row in run["spend"]["pre_call_reservations"]]==[60,70]
    assert run["spend"]["reserved"]==20


def test_source_manifest_traversal_is_rejected(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);path=tmp_path/"sources.json";path.write_text(json.dumps({"sources":[{"path":"../outside.md","role":"intent"}]}),encoding="utf-8")
    with pytest.raises(ProvanError,match="FOUNDRY_SOURCE_PATH_UNSAFE"):foundry(brief_id=brief["brief_id"],source_manifest=path,no_model=True)


@pytest.mark.parametrize("kind,code",[("unsupported","FOUNDRY_SOURCE_FORMAT_UNSUPPORTED"),("oversized","INPUT_FILE_TOO_LARGE"),("missing_intent","FOUNDRY_INTENT_SOURCE_REQUIRED"),("too_many","FOUNDRY_SOURCE_COUNT_EXCEEDED"),("deep","FOUNDRY_STRUCTURED_LIMIT_EXCEEDED")])
def test_source_contract_limits_fail_closed(tmp_path:Path,monkeypatch:pytest.MonkeyPatch,kind:str,code:str):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path)
    if kind=="unsupported":name="source.html";(tmp_path/name).write_text("<p>x</p>",encoding="utf-8");sources=[{"path":name,"role":"intent"}]
    elif kind=="oversized":name="source.md";(tmp_path/name).write_text("x"*(512*1024+1),encoding="utf-8");sources=[{"path":name,"role":"intent"}]
    elif kind=="missing_intent":name="source.md";(tmp_path/name).write_text("context",encoding="utf-8");sources=[{"path":name,"role":"context"}]
    elif kind=="too_many":name="source.md";(tmp_path/name).write_text("intent",encoding="utf-8");sources=[{"path":name,"role":"intent"} for _ in range(33)]
    else:
        name="source.json";value={};cursor=value
        for index in range(34):cursor["next"]={};cursor=cursor["next"]
        (tmp_path/name).write_text(json.dumps(value),encoding="utf-8");sources=[{"path":name,"role":"intent"}]
    manifest=tmp_path/"bounded.json";manifest.write_text(json.dumps({"sources":sources}),encoding="utf-8")
    with pytest.raises(ProvanError,match=code):foundry(brief_id=brief["brief_id"],source_manifest=manifest,no_model=True)


def test_source_manifest_literal_replacement_and_link_protections_are_inherited(tmp_path:Path,monkeypatch:pytest.MonkeyPatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=_brief(tmp_path);outside=tmp_path/"outside.md";outside.write_text("outside",encoding="utf-8");linked=tmp_path/"linked.md"
    try:linked.symlink_to(outside)
    except OSError:pytest.skip("local environment cannot create a test symlink")
    manifest=tmp_path/"linked.json";manifest.write_text(json.dumps({"sources":[{"path":"linked.md","role":"intent"}]}),encoding="utf-8")
    with pytest.raises(ProvanError,match="INPUT_FILE_PATH_UNSAFE"):foundry(brief_id=brief["brief_id"],source_manifest=manifest,no_model=True)
