from __future__ import annotations

import hashlib, json, subprocess, sys
import tempfile
from pathlib import Path

from shiproom.evidence import validate_module_result
from shiproom.models import EvidenceStatus, Release
from shiproom.registry import discover, select
from shiproom.verdict import calculate, close_finding
from shiproom.external import CAPABILITIES, compile_release
from shiproom.policy import POLICY_VERSION, execute_external_operation
from shiproom.runs import LocalRunStore
from shiproom.context import compile_project_context, context_event_metadata, verify_context_handoff, verify_context_isolation
from shiproom.authority import LocalExecutionContext, bind_release_authority
from shiproom.graph import ARTIFACTS as GRAPH_ARTIFACTS, compile_bundle as graph_compile, load_bundle as graph_load, mapping_prepare
from shiproom.intent import compile_bundle as intent_compile, prepare as intent_prepare
from shiproom.onboarding import initialize
from shiproom.project import canonical_json, content_hash


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)


def _graph_context(root: Path) -> LocalExecutionContext:
    repo=root/"repo"; repo.mkdir(); _git(repo,"init","-b","main"); _git(repo,"config","user.email","eval@example.com"); _git(repo,"config","user.name","Eval")
    (repo/".gitignore").write_text(".shiproom/local/\n",encoding="utf-8"); (repo/"docs").mkdir(); (repo/"docs/brief.md").write_text("# Brief\nUsers can publish cards.\napproval_required\n",encoding="utf-8"); _git(repo,"add","."); _git(repo,"commit","-m","fixture")
    initialize(repo,project_name="Eval",product_purpose="Evaluate graph",primary_users=["operators"],profile="inspect",local_only=False,confirmed=True); binding,grant=bind_release_authority(repo,"https://example.test","/result")
    release=Release("rel_graph_eval",{"path":str(repo),"commit_sha":binding["repository_commit"]},{"url":grant["origin"],"generated_path":"/result","read_grant":grant},{"name":"Eval","target_user":"operators","promise":"Publish cards","critical_journey":["Publish card"],"non_goals":[]},project_authority=binding).to_dict(); ctx=LocalExecutionContext.from_release(release)
    packet=intent_prepare(ctx,["docs/brief.md"],[]); src=next(x for x in packet["sources"] if x["path"]=="docs/brief.md")
    def citation(line,quote):return {"source_id":src["source_id"],"start_line":line,"end_line":line,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}
    req=citation(2,"Users can publish cards."); claim=citation(3,"approval_required")
    proposal={"schema_version":"intent-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"source_packet_hash":packet["packet_hash"],"claims":[{"local_id":"claim","claim_key":"release.publication_mode","cardinality":"single","value":"approval_required","classification":"explicit","source_refs":[claim],"requirement_local_ids":["req"]}],"requirements":[{"local_id":"req","statement":"Users can publish cards.","classification":"explicit","status":"active","source_refs":[req],"claim_local_ids":["claim"],"related_journey_ids":["Publish card"],"materiality":"release_scope","rationale":"fixture","owner_confirmation_required":False,"ambiguity_local_ids":[]}],"criteria":[{"local_id":"criterion","parent_requirement_local_id":"req","actor":None,"preconditions":[],"action":"publish","expected_outcomes":[],"failure_behavior":None,"required_evidence_categories":["owner_confirmation"],"source_refs":[req],"field_source_refs":{},"classification":"explicit","confirmation_state":"confirmed","blocker_eligible":True,"ambiguity_local_ids":[]}],"ambiguities":[]}
    inbox=repo/".shiproom/local/releases/rel_graph_eval/product-intent/inbox/proposal.json"; inbox.parent.mkdir(parents=True,exist_ok=True); inbox.write_text(json.dumps(proposal),encoding="utf-8"); intent_compile(ctx,str(inbox)); return ctx


def _graph_behavioral_evals(check) -> None:
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); packet=mapping_prepare(ctx,["docs/brief.md"]); criterion=packet["criterion_ids"][0]; src=packet["selected_sources"][0]; quote="Users can publish cards."
        proposal={"schema_version":"evidence-mapping-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"product_intent_semantic_bundle_hash":packet["product_intent_semantic_bundle_hash"],"release_projection_hash":packet["release_projection_hash"],"mapping_packet_hash":packet["packet_hash"],"mappings":[{"mapping_id":"candidate","criterion_id":criterion,"target_type":"implementation_reference","rationale":"packet candidate","reference":{"path":src["path"],"returned_git_path":src["returned_git_path"],"git_blob_hash":src["git_blob_hash"],"start_line":2,"end_line":2,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest()}}]}
        path=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/requirement-evidence-graph/inbox/map.json"; path.write_text(json.dumps(proposal),encoding="utf-8"); graph_compile(ctx,str(path)); _,art=graph_load(ctx); summary=art["criterion-evidence-summary.json"]["criteria"][0]
        check("GRAPH_CANDIDATE_IS_NOT_PROOF",summary["implementation"][0]["effective_classification"]=="model_mapped_candidate")
        check("GRAPH_FOUR_SLOT_COMPLETENESS",all(summary[k] for k in ("implementation","tests","instrumentation","runtime")))
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); packet=mapping_prepare(ctx,["docs/brief.md"]); cid=packet["criterion_ids"][0]; ctx.release["checks"]=[{"check_id":"bad","type":"http","target":"/result","criterion_id":cid,"status":404,"passed":False,"evidence_status":"deterministically_verified"},{"check_id":"good","type":"http","target":"/result","criterion_id":cid,"status":200,"passed":True,"evidence_status":"deterministically_verified","rerun_of":0}]; ctx.release["findings"]=[{"id":"finding","criterion_id":cid,"state":"CLOSED","blocking":True,"evidence":[]}]; mapping_prepare(ctx,["docs/brief.md"]); graph_compile(ctx); _,art=graph_load(ctx)
        check("GRAPH_CONTROLLED_PATIENT_LINEAGE",next(g for g in art["evidence-gaps.json"]["gaps"] if g["gap_type"]=="runtime_evidence_gap")["state"]=="closed")
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); graph_compile(ctx); intent_prepare(ctx,[],[])
        try: graph_load(ctx); stale=False
        except ValueError: stale=True
        check("GRAPH_STALE_PRODUCT_INTENT_REJECTED",stale)
    with tempfile.TemporaryDirectory() as raw:
        ctx=_graph_context(Path(raw)); graph_compile(ctx); root=ctx.repository_root/".shiproom/local/releases/rel_graph_eval/requirement-evidence-graph"; pointer=json.loads((root/"current-generation.json").read_text()); gen=root/"generations"/pointer["generation"]; artifact=gen/GRAPH_ARTIFACTS[0]; value=json.loads(artifact.read_text()); value["coverage_boundary"]="tampered"; artifact.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); manifest_path=gen/"manifest.json"; manifest=json.loads(manifest_path.read_text()); manifest["artifact_hashes"][GRAPH_ARTIFACTS[0]]="sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest(); manifest["semantic_bundle_hash"]=content_hash({"intent":manifest["product_intent_semantic_bundle_hash"],"packet":manifest["mapping_packet_hash"],"projection":manifest["release_projection_hash"],"compiler":manifest["compiler_version"],"artifacts":{k:manifest["artifact_hashes"][k] for k in sorted(GRAPH_ARTIFACTS)}}); manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"}); manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); pointer["manifest_hash"]="sha256:"+hashlib.sha256(manifest_path.read_bytes()).hexdigest(); (root/"current-generation.json").write_text(json.dumps(pointer,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        try: graph_load(ctx); tamper=False
        except ValueError: tamper=True
        check("GRAPH_SEMANTIC_TAMPER_REJECTED",tamper)


def main() -> int:
    cases = []
    def check(name, condition): cases.append((name, bool(condition)))
    base = Release("rel_eval", {"url": "."}, {"url": "http://example.invalid"}, {"promise": "Share a card"}).to_dict()
    check("registry discovers modules", len(discover()) == 4)
    check("irrelevant data skipped", "data" not in select(base, discover())[0])
    ai = dict(base); ai["product"] = {"promise": "AI retrieval model with eval"}
    check("AI selects data", "data" in select(ai, discover())[0])
    blocked = dict(base); blocked["findings"] = [{"blocking": True, "state": "TRIAGED"}]
    check("blocker holds", calculate(blocked)["status"] == "HOLD")
    for label, status in (("agent report cannot close", EvidenceStatus.AGENT), ("model review cannot close", EvidenceStatus.MODEL), ("missing evidence cannot close", EvidenceStatus.MISSING)):
        try: close_finding({}, {"status": status, "kind": "claim", "value": True}); ok = False
        except ValueError: ok = True
        check(label, ok)
    try: validate_module_result({"module_id": "bad"}); ok = False
    except ValueError: ok = True
    check("malformed output rejected", ok)
    verified = close_finding({"blocking": True, "state": "VERIFYING"}, {"status": EvidenceStatus.DETERMINISTIC, "kind": "http_status", "value": 200})
    check("verified exact rerun closes", verified["state"] == "CLOSED")
    owner = dict(base); owner["owner_decisions"] = [{"title": "Promise", "choice": None}]
    check("owner decision requested", calculate(owner)["status"] == "AWAITING_OWNER")
    owner["owner_decisions"][0].update({"choice": "Revise beta promise", "resolution": "accepted_condition"})
    check("owner decision preserved", calculate(owner)["status"] == "SHIP_WITH_CONDITIONS")
    blocked_owner = dict(blocked); blocked_owner["owner_decisions"] = [{"choice": "Accept", "resolution": "accepted_condition"}]
    check("owner choice cannot erase blocker", calculate(blocked_owner)["status"] == "HOLD")
    check("report evidence linkage contract", all("evidence" in f for f in [verified]))
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); fixture = root / "README.md"; fixture.write_text("redacted public fixture\n", encoding="utf-8")
        contract = {"schema_version":"external_release_contract.v1","project_name":"Redacted public project","repository_url":"https://github.com/example/public-project","live_url":"https://example.com","target_user":"public users","product_promise":"Inspect a bounded public journey","critical_journey":["Open","Inspect"],"non_goals":[],"owner_constraints":["Read only"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}}
        external = compile_release(contract); external["checks"] = [{"criterion_id":"PUBLIC_JOURNEY","required":True,"passed":False,"evidence_status":EvidenceStatus.MISSING,"policy_version":POLICY_VERSION}]
        store = LocalRunStore(root / "history"); called = []
        try: execute_external_operation(external, store, "test.run", lambda: called.append(True))
        except PermissionError: pass
        external_verdict = calculate(external)
        check("redacted external read-only failure", not called and fixture.read_text(encoding="utf-8")=="redacted public fixture\n" and not external["findings"] and external_verdict=={"status":"HOLD","reason_codes":["INSUFFICIENT_EVIDENCE"]} and store.events(external["release_id"])[0]["event_type"]=="operation_rejected")
    with tempfile.TemporaryDirectory() as raw:
        root=Path(raw); a_root=root/"a"; b_root=root/"b"; a_root.mkdir(); b_root.mkdir()
        (a_root/"AGENTS.md").write_text("Build: python alpha.py\nTest: python alpha_test.py\n",encoding="utf-8"); (b_root/"HERMES.md").write_text("Build: node beta.js\nTest: node beta_test.js\n",encoding="utf-8")
        a_ctx=compile_project_context(project_id="alpha",repository_url="https://github.com/example/alpha",commit_sha="a"*40,release_input={"promise":"alpha"},repository_root=a_root,prior_decisions=[{"id":"decision-alpha"}])
        b_ctx=compile_project_context(project_id="beta",repository_url="https://github.com/example/beta",commit_sha="b"*40,release_input={"promise":"beta"},repository_root=b_root,prior_decisions=[{"id":"decision-beta"}])
        metadata=context_event_metadata(a_ctx); handoff_events=[{"agent_id":agent,"metadata":metadata} for agent in ("manager","specialist","verifier")]
        check("CONTEXT_HANDOFF_INTEGRITY",verify_context_handoff(a_ctx,handoff_events))
        check("CONTEXT_PROJECT_ISOLATION",verify_context_isolation(a_ctx,b_ctx,a_run_id="run-a",b_run_id="run-b",a_storage="storage-a",b_storage="storage-b"))
        boundary=True
        for status in (EvidenceStatus.MODEL,EvidenceStatus.AGENT):
            try: close_finding({"blocking":True,"state":"VERIFYING"},{"status":status,"kind":"claim","value":True}); boundary=False
            except ValueError: pass
        try: validate_module_result({"module_id":"product","checks":[]}); boundary=False
        except ValueError: pass
        stale=dict(metadata); stale["project_context_id"]="ctx_stale"
        boundary = boundary and not verify_context_handoff(a_ctx,[{"agent_id":agent,"metadata":stale} for agent in ("manager","specialist","verifier")])
        check("CONTEXT_CANNOT_OVERRIDE_VERIFIED_EVIDENCE",boundary)
    _graph_behavioral_evals(check)
    for name, passed in cases: print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(p for _, p in cases) else 1


if __name__ == "__main__": sys.exit(main())
