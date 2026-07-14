from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from shiproom.authority import LocalExecutionContext, bind_release_authority
from shiproom.graph import compile_bundle as graph_compile, load_bundle as graph_load, mapping_prepare, show as graph_show
from shiproom.intent import compile_bundle as intent_compile, prepare as intent_prepare
from shiproom.models import Release
from shiproom.onboarding import initialize
from shiproom.project import canonical_json

BRIEF = """# Controlled patient release
Public launch cards provide a returned public URL.
A launch-card recipient.
A public URL has been returned.
Open the returned public URL.
The returned public URL opens successfully.
A missing public URL returns a visible not-found response.
browser_or_http
approval_required
"""

def _git(root: Path, *args: str, text: bool = True):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, check=True, text=text).stdout.strip() if text else subprocess.run(["git", *args], cwd=root, capture_output=True, check=True).stdout

def _citation(source: dict, line: int, quote: str) -> dict:
    return {"source_id":source["source_id"],"start_line":line,"end_line":line,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}

def controlled_patient_context(root: Path) -> LocalExecutionContext:
    repo=root/"repo"; repo.mkdir(); _git(repo,"init","-b","main"); _git(repo,"config","user.email","patient@example.com"); _git(repo,"config","user.name","Patient")
    (repo/".gitignore").write_text(".shiproom/local/\n",encoding="utf-8"); (repo/"docs").mkdir(); (repo/"docs/release-brief.md").write_text(BRIEF,encoding="utf-8"); (repo/"demo_patient").mkdir(); source=Path(__file__).parents[1]; (repo/"demo_patient/server.py").write_bytes(_git(source,"show","HEAD:demo_patient/server.py",text=False)); _git(repo,"add","."); _git(repo,"commit","-m","controlled patient")
    initialize(repo,project_name="Controlled patient",product_purpose="Prove a bounded public URL journey",primary_users=["launch-card recipients"],profile="inspect",local_only=False,confirmed=True); binding,grant=bind_release_authority(repo,"https://example.test","/result/demo")
    release=Release("rel_controlled_patient",{"path":str(repo),"commit_sha":binding["repository_commit"]},{"url":grant["origin"],"generated_path":"/result/demo","read_grant":grant},{"name":"Controlled patient","target_user":"launch-card recipients","promise":"Public launch cards provide a returned public URL.","critical_journey":["Open returned public URL"],"non_goals":[]},project_authority=binding).to_dict(); ctx=LocalExecutionContext.from_release(release)
    packet=intent_prepare(ctx,["docs/release-brief.md"],[]); selected=next(x for x in packet["sources"] if x["path"]=="docs/release-brief.md"); req=_citation(selected,2,"Public launch cards provide a returned public URL."); actor=_citation(selected,3,"A launch-card recipient."); pre=_citation(selected,4,"A public URL has been returned."); action=_citation(selected,5,"Open the returned public URL."); outcome=_citation(selected,6,"The returned public URL opens successfully."); failure=_citation(selected,7,"A missing public URL returns a visible not-found response."); claim=_citation(selected,9,"approval_required")
    proposal={"schema_version":"intent-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"source_packet_hash":packet["packet_hash"],"claims":[{"local_id":"publication","claim_key":"release.publication_mode","cardinality":"single","value":"approval_required","classification":"explicit","source_refs":[claim],"requirement_local_ids":["public_url"]}],"requirements":[{"local_id":"public_url","statement":"Public launch cards provide a returned public URL.","classification":"explicit","status":"active","source_refs":[req],"claim_local_ids":["publication"],"related_journey_ids":["Open returned public URL"],"materiality":"release_scope","rationale":"Controlled brief","owner_confirmation_required":False,"ambiguity_local_ids":[]}],"criteria":[{"local_id":"url_opens","parent_requirement_local_id":"public_url","actor":"A launch-card recipient.","preconditions":["A public URL has been returned."],"action":"Open the returned public URL.","expected_outcomes":["The returned public URL opens successfully."],"failure_behavior":"A missing public URL returns a visible not-found response.","required_evidence_categories":["browser_or_http"],"source_refs":[outcome],"field_source_refs":{"actor":[actor],"preconditions":[[pre]],"action":[action],"expected_outcomes":[[outcome]],"failure_behavior":[failure]},"classification":"explicit","confirmation_state":"confirmed","blocker_eligible":False,"ambiguity_local_ids":[]}],"ambiguities":[]}
    inbox=repo/".shiproom/local/releases/rel_controlled_patient/product-intent/inbox/proposal.json"; inbox.parent.mkdir(parents=True,exist_ok=True); inbox.write_text(json.dumps(proposal),encoding="utf-8"); intent_compile(ctx,str(inbox)); return ctx

def snapshot(ctx: LocalExecutionContext) -> dict:
    root=ctx.repository_root
    graph_root=root/".shiproom/local/releases/rel_controlled_patient/requirement-evidence-graph"
    local={str(path.relative_to(root)).replace("\\","/"):hashlib.sha256(path.read_bytes()).hexdigest() for path in (root/".shiproom/local").rglob("*") if path.is_file() and graph_root not in path.parents}
    return {"release":canonical_json(ctx.release),"state":ctx.release.get("state"),"verdict":canonical_json(ctx.release.get("verdict",{})),"findings":canonical_json(ctx.release.get("findings",[])),"decisions":canonical_json(ctx.release.get("owner_decisions",[])),"tasks":canonical_json(ctx.release.get("remediation_tasks",[])),"files":_git(root,"ls-files","-s"),"patient_blob":_git(root,"rev-parse","HEAD:demo_patient/server.py"),"branch":_git(root,"branch","--show-current"),"commit":_git(root,"rev-parse","HEAD"),"status":_git(root,"status","--short"),"non_graph_local":local}

def _mapping(ctx: LocalExecutionContext, packet: dict, criterion_id: str, runtime_ids: list[str]) -> Path:
    src=packet["selected_sources"][0]; quote='elif path.startswith("/results/"):'; matches=[i for i,text in enumerate(src["text"].split("\n"),1) if quote in text]
    if len(matches)!=1:raise AssertionError("controlled route quote must occur exactly once")
    ref={"path":src["path"],"returned_git_path":src["returned_git_path"],"git_blob_hash":src["git_blob_hash"],"start_line":matches[0],"end_line":matches[0],"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}
    mappings=[
        {"mapping_id":"route","criterion_id":criterion_id,"target_type":"implementation_reference","rationale":"Packet route candidate","reference":ref,"quality_assessment":"plausible"},
        {"mapping_id":"test-status","criterion_id":criterion_id,"target_type":"test_reference","rationale":"Bounded test candidate; proof not established","reference":ref,"quality_assessment":"unknown"},
        {"mapping_id":"instrumentation-status","criterion_id":criterion_id,"target_type":"instrumentation_reference","rationale":"Bounded instrumentation candidate; proof not established","reference":ref,"quality_assessment":"unknown"},
    ]+[{"mapping_id":"runtime-"+value,"criterion_id":criterion_id,"target_type":"runtime_evidence","rationale":"Historical runtime candidate","canonical_id":value} for value in runtime_ids]+[{"mapping_id":"finding","criterion_id":criterion_id,"target_type":"finding","rationale":"Historical finding candidate","canonical_id":"hist-finding"}]
    proposal={"schema_version":"evidence-mapping-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"product_intent_semantic_bundle_hash":packet["product_intent_semantic_bundle_hash"],"release_projection_hash":packet["release_projection_hash"],"mapping_packet_hash":packet["packet_hash"],"mappings":mappings}; path=ctx.repository_root/".shiproom/local/releases/rel_controlled_patient/requirement-evidence-graph/inbox/patient.json"; path.write_text(json.dumps(proposal),encoding="utf-8"); return path

def run_controlled_patient(root: Path) -> dict:
    ctx=controlled_patient_context(root); ctx.release["checks"]=[{"check_id":"hist-404","type":"http","target":"/result/demo","criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","status":404,"passed":False,"evidence_status":"deterministically_verified"}]; ctx.release["findings"]=[{"id":"hist-finding","criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","state":"TRIAGED","blocking":True,"evidence":[{"reference":"hist-404"}]}]; pre_snapshot=snapshot(ctx); packet=mapping_prepare(ctx,["demo_patient/server.py"]); criterion_id=packet["criterion_ids"][0]; graph_compile(ctx,str(_mapping(ctx,packet,criterion_id,["hist-404"]))); _,pre=graph_load(ctx); pre_show=graph_show(ctx,criterion_id)
    if snapshot(ctx)!=pre_snapshot:raise AssertionError("pre-rerun graph flow mutated canonical or tracked state")
    ctx.release["checks"].append({"check_id":"hist-200","type":"http","target":"/result/demo","criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":0}); ctx.release["findings"][0]["state"]="CLOSED"; post_snapshot=snapshot(ctx); packet=mapping_prepare(ctx,["demo_patient/server.py"]); graph_compile(ctx,str(_mapping(ctx,packet,criterion_id,["hist-404","hist-200"]))); _,post=graph_load(ctx); post_show=graph_show(ctx,criterion_id)
    if snapshot(ctx)!=post_snapshot:raise AssertionError("post-rerun graph flow mutated canonical or tracked state")
    return {"ctx":ctx,"criterion_id":criterion_id,"pre":pre,"post":post,"pre_show":pre_show,"post_show":post_show}
