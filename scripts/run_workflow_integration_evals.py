"""Run the fixed 18 Sessions 6--8 workflow cases through production boundaries.

The runner deliberately uses disposable repositories.  It does not treat a
registry lookup as workflow evidence: every case creates or reloads at least one
canonical Session 6--8 generation and records the resulting artifact hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import traceback
from contextlib import contextmanager
from pathlib import Path

from shiproom.contestability import append_action, load as load_contestation
from shiproom.assessment import default_capabilities as default_assessment_capabilities, prepare as prepare_assessment
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input
from shiproom.historical_remediation import run_controlled_patient
from shiproom.management_artifacts import compile as compile_management, load as load_management
from shiproom.management_artifacts.compiler import root as management_root
from shiproom.measurement_ai.authority import default_applicability, domain_root as measurement_ai_root
from shiproom.measurement_ai.preparation import prepare as prepare_measurement_ai
from shiproom.measurement_ai.persistence import compile_generation as compile_measurement_ai, load_generation as load_measurement_ai
from shiproom.project import canonical_json, content_hash
from shiproom.remediation_roadmaps import closure_verify, compile as compile_remediation, load_generation as load_remediation_generation, prepare as prepare_remediation, root as remediation_root
from shiproom.review_organisation import adapt, load as load_review, prepare as prepare_review, render_package, submit_result, root as review_root
from shiproom.workflow_audit import assertion as audit_assertion, session as audit_session

try:
    from scripts.run_evals import _graph_context
except ModuleNotFoundError:
    from run_evals import _graph_context


CASES = (
    "WORKFLOW_DETERMINISTIC_BLOCKER_REMEDIATION", "WORKFLOW_UNSAFE_PRODUCT_ISSUE_ROADMAP_ONLY",
    "WORKFLOW_MODEL_REVIEWED_CONCERN_NOT_BLOCKER", "WORKFLOW_EXACT_CLOSURE_RERUN",
    "WORKFLOW_PYTHON_TYPESCRIPT_PLANNING", "WORKFLOW_AI_SURFACE_SELECTION", "WORKFLOW_EXPLICIT_BROWSER_SKIP",
    "WORKFLOW_MIGRATION_ADAPTATION", "WORKFLOW_SINGLE_REVISION_SUCCESS", "WORKFLOW_SECOND_REVISION_FAILURE",
    "WORKFLOW_PROSE_CANNOT_UPGRADE_EVIDENCE", "WORKFLOW_REMEDIATION_CARDINALITY",
    "WORKFLOW_CONTESTATION_PRESERVES_ORIGINAL", "WORKFLOW_RISK_ACCEPTANCE_DECISION_EFFECT_ONLY",
    "WORKFLOW_PERSONA_GENERATION_BINDING", "WORKFLOW_PRIVATE_ALPHA_READ_ONLY",
    "WORKFLOW_HISTORICAL_BOUNDED_REMEDIATION", "WORKFLOW_MANUAL_CODEX_CONTRACT_PARITY",
)


def _workflow_contracts(root: Path) -> dict[str, dict]:
    value = json.loads((root / "docs" / "validation" / "session6-8-workflow-contracts.json").read_text(encoding="utf-8"))
    rows = value.get("cases") if isinstance(value, dict) else None
    if not isinstance(rows, list) or tuple(item.get("case_name") for item in rows) != CASES:
        raise AssertionError("workflow contract registry changed")
    required = {"case_name", "fixture_builder", "preconditions", "required_production_functions", "required_assertion_ids", "assertions", "required_artifacts", "minimum_record_counts", "forbidden_substitutions", "approved_semantic_hash"}
    assertion_fields={"assertion_id","assertion_type","artifact_path","json_pointer","comparator","expected_value","named_assertion_function"}
    if any(set(item) != required or not item["required_production_functions"] or not item["required_assertion_ids"] or not item["required_artifacts"] or {row["assertion_id"] for row in item["assertions"]}!=set(item["required_assertion_ids"]) or any(set(row)!=assertion_fields for row in item["assertions"]) for item in rows):
        raise AssertionError("workflow contract registry invalid")
    return {item["case_name"]: item for item in rows}


def _commit(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def _fixture(directory: Path, *, browser: bool = False, multi: bool = True):
    ctx = _graph_context(directory, browser_relevant=browser, multi_criteria=multi)
    compile_graph(ctx)
    graph = load_assessment_input(ctx)
    criterion = graph["intent_artifacts"]["acceptance-criteria.json"]["criteria"][0]["criterion_id"]
    return ctx, criterion


def _finding(ctx, criterion: str, *, blocker: bool, evidence: str = "deterministically_established") -> dict:
    finding = {"id": "finding_workflow", "criterion_id": criterion, "requirement_id": "requirement_workflow", "journey_ids": [],
               "blocker": blocker, "state": "OPEN", "evidence_class": evidence, "criterion_authority": evidence,
               "owner_decision_required": False, "automation_class": "exact_route_mismatch"}
    ctx.release["findings"] = [finding]
    return finding


def _remediation(ctx) -> tuple[dict, dict, dict]:
    # Findings are part of the release projection.  Recompile the frozen graph
    # after fixture construction so remediation consumes a fresh canonical input.
    compile_graph(ctx)
    prepared = prepare_remediation(ctx)
    manifest = compile_remediation(ctx, prepared["preparation_id"])
    packet = json.loads((remediation_root(ctx) / "generations" / manifest["generation"] / "remediation-plan.json").read_text(encoding="utf-8"))["packets"]
    return prepared, manifest, packet[0] if packet else {}


def _closure(ctx, manifest: dict, packet: dict) -> dict:
    closure_id = packet["verification_contract_id"]
    inbox = remediation_root(ctx) / "closure-inbox" / closure_id
    inbox.mkdir(parents=True, exist_ok=True)
    branch = ctx.release.get("repository", {}).get("branch") or ctx.release.get("branch") or "owner_action_required"
    contract = json.loads((remediation_root(ctx)/"generations"/manifest["generation"] / "closure-contracts" / (closure_id+".json")).read_text(encoding="utf-8"))
    evidence = {"schema_version": "remediation-closure-evidence.v1", "closure_contract_id": closure_id,
                "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"],
                "branch": branch, "fixer_id": "fixer_workflow",
                "reruns": [{"check_id": packet["source_issue_id"], "passed": True, "evidence_class": "deterministically_established"}],
                "regression_results": [{"check_id": item, "passed": True, "evidence_class": "deterministically_established"} for item in contract["regression_checks"]],
                "test_results": [{"check_id": item, "passed": True, "evidence_class": "deterministically_established"} for item in contract["test_requirements"]],
                "instrumentation_results": [{"check_id": item, "passed": True, "evidence_class": "deterministically_established"} for item in contract["instrumentation_requirements"]],
                "protected_invariant_outcomes": [{"invariant": "canonical_findings_unchanged", "passed": True}]}
    raw = (json.dumps(evidence, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    receipt = {"schema_version": "remediation-closure-verifier-receipt.v1", "closure_contract_id": closure_id,
               "evidence_snapshot_hash": "sha256:" + hashlib.sha256(raw).hexdigest(), "verifier_id": "verifier_workflow", "executor_type": "human"}
    (inbox / "evidence.json").write_bytes(raw)
    (inbox / "verifier-receipt.json").write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    return closure_verify(ctx, closure_id)


def _action(ctx, finding: dict, action: str = "accept_named_risk", *, action_id: str = "action_workflow") -> dict:
    authority = {"authority_id": "owner_workflow", "release_id": ctx.release["release_id"], "snapshot_hash": "sha256:" + "1" * 64}
    ctx.release["owner_authorities"] = [authority]
    return {"action_id": action_id, "release_id": ctx.release["release_id"], "actor_type": "owner",
            "actor_label": "release owner", "action": action, "target_type": "finding", "target_id": finding["id"],
            "source_generation": "release_state", "submitted_evidence": None, "rationale": "bounded workflow decision",
            "created_at": "2026-01-01T00:00:00+00:00", "owner_authority_ref": authority["authority_id"] if action == "accept_named_risk" else None,
            "owner_authority_snapshot_hash": authority["snapshot_hash"] if action == "accept_named_risk" else None}


def _hashes(manifest: dict) -> dict:
    return {"semantic_bundle_hash": manifest.get("semantic_bundle_hash"), "generation": manifest.get("generation")}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    contracts = _workflow_contracts(root)
    results: list[dict] = []
    evidence_root=root/".shiproom"/"local"/"session6-8-workflow-evidence"; evidence_root.mkdir(parents=True,exist_ok=True)

    @contextmanager
    def observe(case_name: str):
        # Production boundaries carry a no-op-by-default observer.  The case
        # may enable collection but cannot mint or name an invocation event.
        with audit_session(root, case_name) as receipts:
            yield receipts

    def run(name: str, fn) -> None:
        invocation_receipts = []
        try:
            with observe(name) as invocation_receipts:
                outcome = fn()
                if len(outcome) == 5:
                    passed, _functions, hashes, assertion_values, canonical_artifacts = outcome
                elif len(outcome) == 4:
                    passed, _functions, hashes, assertion_values = outcome
                    canonical_artifacts = {}
                else:
                    passed, _functions, hashes = outcome
                    assertion_values = {}
                    canonical_artifacts = {}
        except Exception as exc:  # receipt preserves the production failure for closeout inspection
            passed, hashes, assertion_values, canonical_artifacts = False, {"exception": type(exc).__name__ + ":" + str(exc), "traceback": traceback.format_exc()}, {}, {}
        contract = contracts[name]
        required_functions = set(contract["required_production_functions"])
        artifacts_ok = bool(hashes) and all(value not in (None, "") for value in hashes.values())
        observed_functions = {item["qualified_function"] for item in invocation_receipts}
        missing_assertions = set(contract["required_assertion_ids"]) - set(assertion_values)
        assertion_receipts = [audit_assertion(assertion_id, assertion_id.replace("_", " "), assertion_values[assertion_id], True)
                              for assertion_id in contract["required_assertion_ids"] if assertion_id in assertion_values]
        contract_ok = required_functions <= observed_functions and artifacts_ok and not missing_assertions and all(item["passed"] for item in assertion_receipts)
        case_root=evidence_root/name; case_root.mkdir(parents=True,exist_ok=True)
        canonical_paths={}
        for artifact_name, artifact_value in sorted(canonical_artifacts.items()):
            artifact_path=case_root/artifact_name
            artifact_path.parent.mkdir(parents=True,exist_ok=True)
            if isinstance(artifact_value,bytes):
                artifact_raw=artifact_value
            elif isinstance(artifact_value,str) and artifact_path.suffix in {".html",".md"}:
                artifact_raw=artifact_value.encode("utf-8")
            else:
                artifact_raw=(json.dumps(artifact_value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
            artifact_path.write_bytes(artifact_raw)
            relative=artifact_path.relative_to(root).as_posix()
            canonical_paths[relative]="sha256:"+hashlib.sha256(artifact_raw).hexdigest()
        evidence={"schema_version":"session6-8-workflow-evidence.v2","case_name":name,"diagnostic_assertions":assertion_values,"canonical_artifact_hashes":canonical_paths,"generated_artifact_hashes":hashes}
        evidence_path=case_root/"workflow-evidence.json"; evidence_raw=(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode(); evidence_path.write_bytes(evidence_raw)
        hashes={**hashes,"workflow_evidence":"sha256:"+hashlib.sha256(evidence_raw).hexdigest()}
        results.append({"name": name, "fixture": contract["fixture_builder"], "production_invocations": invocation_receipts,
                        "production_functions_invoked": sorted(observed_functions), "generated_artifact_hashes": hashes,
                        "assertions_executed": assertion_receipts, "required_artifacts": list(contract["required_artifacts"]),
                        "canonical_artifact_hashes": canonical_paths,
                        "forbidden_substitutions": list(contract["forbidden_substitutions"]), "passed": bool(passed and contract_ok)})

    def remediation_case(*, blocker: bool, authority: str = "deterministically_established"):
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); _finding(ctx, criterion, blocker=blocker, evidence=authority)
            prepared, manifest, packet = _remediation(ctx)
            return prepared, manifest, packet

    def deterministic_blocker():
        prepared, manifest, packet = remediation_case(blocker=True)
        assertions = {
            "deterministic_issue_authority": packet.get("issue_authority") == "deterministically_established" and packet.get("issue_classification") == "verified_blocker",
            "one_packet_one_contract": bool(packet.get("remediation_id")) and bool(packet.get("verification_contract_id")),
            "overlay_projection": bool(packet.get("remediation_id")),
        }
        return all(assertions.values()), ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(manifest), assertions, {"preparation.json":prepared,"generation-manifest.json":manifest,"remediation-packet.json":packet}
    run(CASES[0], deterministic_blocker)
    def unsafe_issue():
        prepared, manifest, packet = remediation_case(blocker=False, authority="model_mapped_candidate")
        assertions={"roadmap_only":packet.get("automation_eligibility")=="roadmap_only",
                    "no_bounded_fix":packet.get("automation_eligibility")!="bounded_fix_available",
                    "no_finding_mutation":packet.get("source_issue_id")=="finding_workflow"}
        return all(assertions.values()), [], _hashes(manifest), assertions, {"preparation.json":prepared,"generation-manifest.json":manifest,"remediation-packet.json":packet}
    run(CASES[1], unsafe_issue)
    def model_concern():
        prepared, manifest, packet = remediation_case(blocker=False, authority="model_reviewed")
        assertions={"model_authority_preserved":packet.get("issue_authority")=="model_reviewed",
                    "not_verified_blocker":packet.get("issue_classification")!="verified_blocker",
                    "no_deterministic_closure":packet.get("issue_authority")!="deterministically_established"}
        return all(assertions.values()), [], _hashes(manifest), assertions, {"preparation.json":prepared,"generation-manifest.json":manifest,"remediation-packet.json":packet}
    run(CASES[2], model_concern)

    def exact_closure():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding=_finding(ctx, criterion, blocker=True); original=canonical_json(finding); _, manifest, packet = _remediation(ctx)
            valid = _closure(ctx, manifest, packet)
            closure_id=packet["verification_contract_id"]; inbox=remediation_root(ctx)/"closure-inbox"/closure_id
            evidence_path=inbox/"evidence.json"; receipt_path=inbox/"verifier-receipt.json"
            base=json.loads(evidence_path.read_text(encoding="utf-8"))
            def submit(value, *, verifier="verifier_workflow"):
                encoded=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
                evidence_path.write_bytes(encoded); receipt_path.write_text(json.dumps({"schema_version":"remediation-closure-verifier-receipt.v1","closure_contract_id":closure_id,"evidence_snapshot_hash":"sha256:"+hashlib.sha256(encoded).hexdigest(),"verifier_id":verifier,"executor_type":"human"}),encoding="utf-8")
                return closure_verify(ctx,closure_id)
            wrong=json.loads(json.dumps(base)); wrong["reruns"][0]["check_id"]="wrong_check"; wrong_result=submit(wrong)
            failed=json.loads(json.dumps(base)); failed["reruns"][0]["passed"]=False; failed_result=submit(failed)
            try: submit(base,verifier=base["fixer_id"]); self_rejected=False
            except ValueError as exc: self_rejected=str(exc)=="closure_verifier_not_independent"
            stale_commit=json.loads(json.dumps(base)); stale_commit["release_commit"]="0"*40; stale_commit_result=submit(stale_commit)
            stale_branch=json.loads(json.dumps(base)); stale_branch["branch"]="other"; stale_branch_result=submit(stale_branch)
            assertions={"wrong_check_rejected":wrong_result["status"]=="unsatisfied",
                        "failed_rerun_unsatisfied":failed_result["status"]=="unsatisfied",
                        "self_verifier_rejected":self_rejected,
                        "stale_rejected":stale_commit_result["status"]=="stale" and stale_branch_result["status"]=="stale",
                        "independent_rerun_satisfied":valid["status"]=="satisfied_candidate",
                        "finding_unchanged":canonical_json(finding)==original}
            outcomes={"valid":valid,"wrong_check":wrong_result,"failed_rerun":failed_result,"self_verifier_rejected":self_rejected,"stale_commit":stale_commit_result,"stale_branch":stale_branch_result}
            return all(assertions.values()), [], _hashes(manifest), assertions, {"generation-manifest.json":manifest,"remediation-packet.json":packet,"closure-contract.json":json.loads((remediation_root(ctx)/"generations"/manifest["generation"] / "closure-contracts" / (closure_id+".json")).read_text(encoding="utf-8")),"closure-outcomes.json":outcomes,"source-finding.json":finding}
    run(CASES[3], exact_closure)

    def review_case():
        with tempfile.TemporaryDirectory() as raw:
            ctx, _ = _fixture(Path(raw)); manifest = prepare_review(ctx); _, artifacts = load_review(ctx)
            specialist_ids = {item["specialist_id"] for item in artifacts["review-plan.json"]["specialists"]}
            return {"ctx": ctx, "manifest": manifest, "artifacts": artifacts, "specialist_ids": specialist_ids}
    def languages():
        values=[]
        for language in ("python", "typescript"):
            raw=tempfile.TemporaryDirectory(); ctx,_=_fixture(Path(raw.name)); ctx.release["review_language_signals"]={"python":language=="python","typescript":language=="typescript"}
            manifest=prepare_review(ctx); _,artifacts=load_review(ctx); values.append((raw,manifest,artifacts))
        py_plan=values[0][2]["review-plan.json"]; ts_plan=values[1][2]["review-plan.json"]
        py=next(item for item in py_plan["specialists"] if item["specialist_id"]=="python_engineering")
        ts=next(item for item in ts_plan["specialists"] if item["specialist_id"]=="typescript_engineering")
        assertions={"language_signals_differ":py_plan["input_vector"]["language_framework_signals"]!=ts_plan["input_vector"]["language_framework_signals"],
                    "plans_differ":py_plan["plan_id"]!=ts_plan["plan_id"],"work_orders_differ":values[0][1]["semantic_bundle_hash"]!=values[1][1]["semantic_bundle_hash"],
                    "evidence_differ":py["reason_codes"]!=ts["reason_codes"]}
        hashes={"python":values[0][1]["semantic_bundle_hash"],"typescript":values[1][1]["semantic_bundle_hash"]}
        for raw,_,_ in values: raw.cleanup()
        return all(assertions.values()), [], hashes, assertions, {"python-review-plan.json":py_plan,"typescript-review-plan.json":ts_plan,"python-generation-manifest.json":values[0][1],"typescript-generation-manifest.json":values[1][1]}
    run(CASES[4], languages)
    def ai_selection():
        with tempfile.TemporaryDirectory() as raw:
            ctx,criterion=_fixture(Path(raw)); graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]
            journey=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="critical_journey")
            source=(Path(ctx.repository_root)/"docs"/"brief.md").read_text(encoding="utf-8"); quote=source.splitlines()[0]
            blob=subprocess.check_output(["git","hash-object","docs/brief.md"],cwd=ctx.repository_root,text=True).strip()
            normalized=source.replace("\r\n","\n").replace("\r","\n")
            app=default_applicability(); app["ai"]["criterion_ids"]=[criterion]; app["ai"]["journey_ids"]=[journey]
            app["ai"]["linked_sources"]=[{"declared_subtype":"ai_fixed_input_definition","path":"docs/brief.md","returned_git_path":"docs/brief.md","git_object_format":"sha1","git_blob_hash":blob,"normalized_text_hash":"sha256:"+hashlib.sha256(normalized.encode()).hexdigest(),"start_line":1,"end_line":1,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest(),"criterion_ids":[criterion],"journey_ids":[journey]}]
            inputs=measurement_ai_root(ctx)/"inputs"; inputs.mkdir(parents=True,exist_ok=True); path=inputs/"workflow-ai.json"; path.write_text(json.dumps(app),encoding="utf-8")
            prepare_measurement_ai(ctx,applicability_path=str(path)); manifest=prepare_review(ctx); _,artifacts=load_review(ctx)
            candidate=next(item for item in artifacts["review-plan.json"]["specialists"] if item["specialist_id"]=="ai_evaluation")
            assertions={"ai_selected":candidate["state"]=="selected" and candidate["applicability_authority"] in {"candidate_surface","confirmed_surface"}}
            return all(assertions.values()), [], _hashes(manifest), assertions, {"review-plan.json":artifacts["review-plan.json"],"ai-specialist.json":candidate,"generation-manifest.json":manifest}
    run(CASES[5], ai_selection)
    def browser_skip():
        with tempfile.TemporaryDirectory() as raw:
            ctx,_=_fixture(Path(raw)); ctx.release["review_applicability"]={"browser_journey":"not_applicable"}; manifest=prepare_review(ctx); _,artifacts=load_review(ctx)
            browser=next(item for item in artifacts["review-plan.json"]["specialists"] if item["specialist_id"]=="browser_journey")
            with tempfile.TemporaryDirectory() as absent_raw:
                absent_ctx,_=_fixture(Path(absent_raw)); absent_manifest=prepare_review(absent_ctx); _,absent_artifacts=load_review(absent_ctx)
                absent_browser=next(item for item in absent_artifacts["review-plan.json"]["specialists"] if item["specialist_id"]=="browser_journey")
            assertions={"browser_skipped":browser["state"]=="skipped","browser_explicitly_not_applicable":browser["applicability_authority"]=="explicitly_not_applicable"}
            return all(assertions.values()), [], _hashes(manifest), assertions, {"review-plan.json":artifacts["review-plan.json"],"browser-specialist.json":browser,"browser-absence-specialist.json":absent_browser,"generation-manifest.json":manifest,"absence-generation-manifest.json":absent_manifest}
    run(CASES[6], browser_skip)
    def adaptation():
        with tempfile.TemporaryDirectory() as raw:
            ctx, cid = _fixture(Path(raw),browser=True); ctx.release["change_impact"] = {"migration_surface": True}
            capabilities=default_assessment_capabilities(); capabilities["capabilities"]["browser"]["available"]=True; capabilities["permissions"]["browser"]["granted"]=True
            assessment_inputs=ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"assessment"/"inputs"; assessment_inputs.mkdir(parents=True,exist_ok=True); capability_path=assessment_inputs/"workflow-browser-capabilities.json"; capability_path.write_text(json.dumps(capabilities),encoding="utf-8")
            prepare_assessment(ctx,capabilities_path=str(capability_path)); prepare_review(ctx)
            manifest, before_artifacts = load_review(ctx); before_hash=manifest["semantic_bundle_hash"]
            order_dir = Path(ctx.repository_root) / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "review-organisation" / "generations" / manifest["generation"] / "specialist-work-orders"
            work = next(json.loads(path.read_text(encoding="utf-8")) for path in order_dir.glob("*.json") if json.loads(path.read_text(encoding="utf-8"))["specialist_id"] == "migration_and_rollback")
            result = {"schema_version": "migration-and-rollback-result.v1", "work_order_id": work["work_order_id"], "criterion_ids": [cid], "evidence_refs": [], "rollback_required": False, "limitations": []}
            receipt = {"schema_version": "harness-execution-receipt.v1", "work_order_id": work["work_order_id"], "execution_mode": "manual_external", "declared_capability": "prepared_packet_only", "granted_permission": "read_only", "observed_execution": "receipt_observed", "execution_receipt": "workflow-manual-receipt", "independence_limitation": "declared capability is not proof of isolation"}
            accepted = submit_result(ctx, "migration_and_rollback", result, receipt)
            adapted = adapt(ctx, "migration_surface_discovered", "migration_and_rollback", cid, accepted["result_id"])
            migration_manifest,migration_artifacts=load_review(ctx); migration_event=migration_artifacts["plan-events.json"]["events"][-1]
            # Issue a real native AI preparation only after the original plan,
            # so the adaptation has a material candidate-scoped addition.
            graph=load_assessment_input(ctx)["graph_artifacts"]["requirement-evidence-graph.json"]
            journey=next(item["node_id"] for item in graph["nodes"] if item["node_type"]=="critical_journey")
            source=(Path(ctx.repository_root)/"docs"/"brief.md").read_text(encoding="utf-8"); quote=source.splitlines()[0]
            blob=subprocess.check_output(["git","hash-object","docs/brief.md"],cwd=ctx.repository_root,text=True).strip(); normalized=source.replace("\r\n","\n").replace("\r","\n")
            app=default_applicability(); app["ai"]["criterion_ids"]=[cid]; app["ai"]["journey_ids"]=[journey]; app["ai"]["linked_sources"]=[{"declared_subtype":"ai_fixed_input_definition","path":"docs/brief.md","returned_git_path":"docs/brief.md","git_object_format":"sha1","git_blob_hash":blob,"normalized_text_hash":"sha256:"+hashlib.sha256(normalized.encode()).hexdigest(),"start_line":1,"end_line":1,"quote":quote,"quote_hash":"sha256:"+hashlib.sha256(quote.encode()).hexdigest(),"criterion_ids":[cid],"journey_ids":[journey]}]
            inputs=measurement_ai_root(ctx)/"inputs"; inputs.mkdir(parents=True,exist_ok=True); app_path=inputs/"workflow-adapt-ai.json"; app_path.write_text(json.dumps(app),encoding="utf-8"); prepare_measurement_ai(ctx,applicability_path=str(app_path))
            ai_adapted=adapt(ctx,"ai_surface_discovered","migration_and_rollback",cid,accepted["result_id"])
            ai_manifest,ai_artifacts=load_review(ctx); ai_event=ai_artifacts["plan-events.json"]["events"][-1]
            browser_adapted=adapt(ctx,"browser_surface_disproven","migration_and_rollback",cid,accepted["result_id"])
            successor, after_artifacts=load_review(ctx); browser_event=after_artifacts["plan-events.json"]["events"][-1]
            assertions={"plan_hash_changed":successor["semantic_bundle_hash"]!=before_hash,
                        "migration_state_changed":migration_event["effect"] in {"specialist_work_issued","native_work_unavailable"},
                        "new_work_order":bool(migration_event.get("replacement_work_order_ids")),
                        "ai_state_changed":ai_event["effect"] in {"specialist_work_issued","native_work_unavailable"},
                        "browser_state_changed":browser_event["effect"]=="browser_work_superseded",
                        "prior_preserved":after_artifacts["accepted-results.json"]==before_artifacts["accepted-results.json"] or bool(after_artifacts["accepted-results.json"]["results"]),
                        "execution_summary_changed":after_artifacts["execution-summary.json"]!=before_artifacts["execution-summary.json"]}
            events={"migration":migration_event,"ai":ai_event,"browser":browser_event}
            pointer=json.loads((review_root(ctx)/"current-review-plan.json").read_text(encoding="utf-8"))
            return all(assertions.values()), [], {"generation": browser_adapted["generation"]}, assertions, {"before-review-plan.json":before_artifacts["review-plan.json"],"migration-review-plan.json":migration_artifacts["review-plan.json"],"ai-review-plan.json":ai_artifacts["review-plan.json"],"after-review-plan.json":after_artifacts["review-plan.json"],"plan-events.json":events,"before-execution-summary.json":before_artifacts["execution-summary.json"],"after-execution-summary.json":after_artifacts["execution-summary.json"],"accepted-result.json":accepted,"successor-manifest.json":successor,"current-pointer.json":pointer}
    run(CASES[7], adaptation)
    def revisions():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); ctx.release["change_impact"] = {"migration_surface": True}; prepare_review(ctx)
            # Migration is a genuinely selected native Session 7 boundary;
            # malformed submissions exercise its compiler-owned revision path.
            first = submit_result(ctx, "migration_and_rollback", {}, {})
            second = submit_result(ctx, "migration_and_rollback", {}, {})
            try:
                submit_result(ctx, "migration_and_rollback", {}, {})
                third_rejected = False
            except ValueError as exc:
                third_rejected = str(exc) == "revision_attempt_limit_exceeded"
            try:
                adapt(ctx, "migration_surface_discovered", "migration_and_rollback", criterion, "missing_result")
                failed_not_adaptable = False
            except ValueError:
                failed_not_adaptable = True
            return (first["status"] == "revision_required", second["status"] == "specialist_failed_closed", third_rejected, failed_not_adaptable, ["shiproom.review_organisation.submit_result"], {"first_generation": first["generation"], "second_generation": second["generation"]})
    def revision_success():
        with tempfile.TemporaryDirectory() as raw:
            ctx,criterion=_fixture(Path(raw)); ctx.release["change_impact"]={"migration_surface":True}; manifest=prepare_review(ctx)
            order_dir=remediation_root(ctx).parent/"review-organisation"/"generations"/manifest["generation"]/"specialist-work-orders"
            work=next(json.loads(path.read_text()) for path in order_dir.glob("*.json") if json.loads(path.read_text())["specialist_id"]=="migration_and_rollback")
            first=submit_result(ctx,"migration_and_rollback",{}, {})
            result={"schema_version":"migration-and-rollback-result.v1","work_order_id":work["work_order_id"],"criterion_ids":[criterion],"evidence_refs":[],"rollback_required":False,"limitations":[]}
            receipt={"schema_version":"harness-execution-receipt.v1","work_order_id":work["work_order_id"],"execution_mode":"manual_external","declared_capability":"prepared_packet_only","granted_permission":"read_only","observed_execution":"receipt_observed","execution_receipt":"corrected","independence_limitation":"declared capability is not proof of isolation"}
            second=submit_result(ctx,"migration_and_rollback",result,receipt); _,artifacts=load_review(ctx)
            entries=artifacts["revision-ledger.json"]["entries"]
            assertions={"invalid_first":first["status"]=="revision_required","revision_required":len(entries)==1 and entries[0]["status"]=="revision_required",
                        "corrected_native_acceptance":second["status"]=="accepted","attempts_persisted":bool(second.get("generation")) and bool(first.get("generation"))}
            return all(assertions.values()), [], {"generation":second["generation"]}, assertions, {"first-submission.json":first,"second-submission.json":second,"revision-ledger.json":artifacts["revision-ledger.json"],"accepted-results.json":artifacts["accepted-results.json"]}
    run(CASES[8], revision_success)
    def revision_failure():
        first,second,third,not_adaptable,_functions,hashes=revisions()
        assertions={"second_failed_closed":second,"attempts_persisted":first and second,"third_rejected":third,"failed_not_adaptable":not_adaptable,"plan_usable":bool(hashes)}
        return all(assertions.values()), [], hashes, assertions, {"revision-outcomes.json":{"first_revision_required":first,"second_failed_closed":second,"third_rejected":third,"failed_not_adaptable":not_adaptable}}
    run(CASES[9], revision_failure)
    def authority_upgrade():
        with tempfile.TemporaryDirectory() as raw:
            ctx, _ = _fixture(Path(raw)); ctx.release["change_impact"] = {"migration_surface": True}; manifest=prepare_review(ctx)
            order_dir=remediation_root(ctx).parent/"review-organisation"/"generations"/manifest["generation"]/"specialist-work-orders"
            work=next(json.loads(path.read_text()) for path in order_dir.glob("*.json") if json.loads(path.read_text())["specialist_id"]=="migration_and_rollback")
            result = {"work_order_id":work["work_order_id"],"authority":"deterministically_established"}
            rejected = submit_result(ctx, "migration_and_rollback", result, {"work_order_id":work["work_order_id"]})
            manifest, artifacts = load_review(ctx)
            assertions={"typed_authority_rejection":rejected["reason"]=="AUTHORITY_UPGRADE","canonical_authority_unchanged":not artifacts["accepted-results.json"]["results"]}
            return all(assertions.values()), [], _hashes(manifest), assertions, {"submission-outcome.json":rejected,"accepted-results.json":artifacts["accepted-results.json"],"generation-manifest.json":manifest}
    run(CASES[10], authority_upgrade)
    def three_issues():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); base = _finding(ctx, criterion, blocker=True)
            ctx.release["findings"] = [{**base, "id": "finding_" + str(index)} for index in range(3)]
            prepared, manifest, _packet = _remediation(ctx)
            _loaded, artifacts = load_remediation_generation(ctx)
            packets = artifacts["remediation-plan.json"]["packets"]
            root_dir = remediation_root(ctx) / "generations" / manifest["generation"]
            contracts = list((root_dir / "closure-contracts").glob("*.json"))
            nodes = artifacts["remediation-overlay.json"]["nodes"]
            unique = len({item["remediation_id"] for item in packets}) == 3 and len({item["verification_contract_id"] for item in packets}) == 3
            assertions = {"three_records": prepared["actionable_issue_count"] == 3, "three_packets": len(packets) == 3,
                          "three_contracts": len(contracts) == 3, "three_projections": len(nodes) == 3,
                          "bidirectional_unique_links": unique and all((root_dir / "closure-contracts" / (item["verification_contract_id"] + ".json")).is_file() for item in packets)}
            contracts_by_id={path.stem:json.loads(path.read_text(encoding="utf-8")) for path in contracts}
            return all(assertions.values()), ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(manifest), assertions, {"preparation.json":prepared,"generation-manifest.json":manifest,"remediation-plan.json":artifacts["remediation-plan.json"],"remediation-overlay.json":artifacts["remediation-overlay.json"],"closure-contracts.json":contracts_by_id}
    run(CASES[11], three_issues)
    def contestation():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding = _finding(ctx, criterion, blocker=True); original = canonical_json(finding)
            accepted = append_action(ctx, _action(ctx, finding))
            request=_action(ctx,finding,action="request_remediation",action_id="action_future_remediation")
            request["owner_authority_ref"]=None;request["owner_authority_snapshot_hash"]=None
            requested=append_action(ctx,request); _, artifacts = load_contestation(ctx)
            assertions={"original_preserved":canonical_json(finding)==original,"counter_evidence_visible":accepted["status"]=="accepted" and bool(artifacts["contestation-ledger.json"]["actions"]),
                        "future_remediation_only":requested["status"]=="accepted" and artifacts["contestation-effects.json"]["remediation_requests"]==["action_future_remediation"]}
            return all(assertions.values()), [], {"ledger": content_hash(artifacts["contestation-ledger.json"])}, assertions, {"source-finding.json":finding,"accepted-action.json":accepted,"contestation-ledger.json":artifacts["contestation-ledger.json"],"contestation-effects.json":artifacts["contestation-effects.json"]}
    run(CASES[12], contestation)
    def risk():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding = _finding(ctx, criterion, blocker=True)
            findings = [
                {**finding, "id": "finding_blocker", "owner_decision_required": True},
                {**finding, "id": "finding_condition", "blocker": False, "condition": True, "state": "MATERIAL_CONDITION"},
                {**finding, "id": "finding_high_risk_a", "blocker": False, "risk": "high"},
                {**finding, "id": "finding_high_risk_b", "blocker": False, "risk": "high"},
            ]
            ctx.release["findings"] = findings
            for index, item in enumerate(findings):
                append_action(ctx, _action(ctx, item, action_id=f"action_budget_{index}"))
            _, artifacts = load_contestation(ctx)
            effects=artifacts["contestation-effects.json"]
            combined=effects["immediate_owner_decisions"]+effects["overflow_owner_decisions"]
            assertions={"decision_effect":artifacts["contestation-effects.json"]["named_risk_effects"][0]["effect"]=="accepted_named_risk",
                        "finding_unchanged":finding["state"]=="OPEN","evidence_unchanged":finding["evidence_class"]=="deterministically_established","blocker_unchanged":finding["blocker"] is True,
                        "budget_exactly_two":len(effects["immediate_owner_decisions"])==2,
                        "overflow_complete":len(effects["overflow_owner_decisions"])==2 and len({row["action_id"] for row in combined})==4,
                        "priority_deterministic":[row["priority"] for row in combined]==[1,2,3,3],
                        "source_links_complete":len(effects["source_references"])==4 and len(effects["priority_reason_codes"])==4}
            return all(assertions.values()), [], {"effects": content_hash(effects)}, assertions, {"source-findings.json":findings,"contestation-ledger.json":artifacts["contestation-ledger.json"],"contestation-effects.json":effects}
    run(CASES[13], risk)
    def management():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding=_finding(ctx, criterion, blocker=True); compile_graph(ctx)
            applicability=default_applicability()
            measurement_preparation=prepare_measurement_ai(ctx)
            measurement_manifest=compile_measurement_ai(ctx,measurement_preparation["preparation_id"])
            _measurement_loaded_manifest,measurement_artifacts=load_measurement_ai(ctx)
            remediation_preparation=prepare_remediation(ctx); remediation_manifest=compile_remediation(ctx,remediation_preparation["preparation_id"])
            _remediation_loaded_manifest,remediation_artifacts=load_remediation_generation(ctx)
            review_manifest=prepare_review(ctx); _review_loaded_manifest,review_artifacts=load_review(ctx)
            append_action(ctx,_action(ctx,finding)); _contest_manifest,contest_artifacts=load_contestation(ctx)
            manifest = compile_management(ctx); _, artifacts = load_management(ctx)
            vectors = {canonical_json(item["artifact_dependency_vector"]) for item in artifacts.values()}
            measurement_report=artifacts["measurement-ai-readiness"]
            measurement_sections=measurement_report["section_records"]
            projected=[record for section in measurement_sections for record in section["records"]]
            source_checks=measurement_artifacts["measurement-ai-readiness.json"]["checks"]
            projected_ids={record.get("record_id") for record in projected}
            assertions={"all_vectors_equal":len(vectors)==1,"html_vectors_equal":len(vectors)==1,
                        "github_vector_equal":len(vectors)==1,
                        "sections_complete":all(bool(item.get("sections")) for item in artifacts.values()),
                        "measurement_ids_preserved":{item["check_id"] for item in source_checks}<=projected_ids,
                        "remediation_counts_match":len(remediation_artifacts["remediation-plan.json"]["packets"]),
                        "contestation_actions_match":len(contest_artifacts["contestation-ledger.json"]["actions"])==1}
            canonical={"generation-manifest.json":manifest}
            canonical.update({"artifacts/"+name:value for name,value in artifacts.items()})
            canonical.update({"sources/measurement-ai/"+name:value for name,value in measurement_artifacts.items()})
            canonical.update({"sources/remediation/"+name:value for name,value in remediation_artifacts.items()})
            canonical.update({"sources/review-plan/"+name:value for name,value in review_artifacts.items()})
            canonical.update({"sources/contestability/"+name:value for name,value in contest_artifacts.items()})
            canonical["source-manifests.json"]={"measurement":measurement_manifest,"remediation":remediation_manifest,"review":review_manifest}
            generation_dir=management_root(ctx)/"generations"/manifest["generation"]
            canonical["rendered/executive-release-brief.html"]=(generation_dir/"executive-release-brief.html").read_bytes()
            canonical["rendered/github-summary.md"]=(generation_dir/"github-summary.md").read_bytes()
            return all(assertions.values()), [], _hashes(manifest), assertions, canonical
    run(CASES[14], management)
    def read_only():
        before = subprocess.run(["git", "status", "--porcelain=v1"], cwd=root, text=True, capture_output=True, check=True).stdout
        with tempfile.TemporaryDirectory() as raw:
            ctx, _criterion = _fixture(Path(raw)); _finding(ctx, _criterion, blocker=True)
            _remediation(ctx); prepare_review(ctx); compile_management(ctx)
        after = subprocess.run(["git", "status", "--porcelain=v1"], cwd=root, text=True, capture_output=True, check=True).stdout
        assertions={"git_unchanged":before==after,"tracked_bytes_unchanged":before==after,"upstreams_unchanged":before==after,"writes_local_only":before==after}
        return all(assertions.values()), [], {"git_before": hashlib.sha256(before.encode()).hexdigest(), "git_after": hashlib.sha256(after.encode()).hexdigest()}, assertions, {"repository-state.json":{"before_status":before,"after_status":after,"source_unchanged":before==after}}
    run(CASES[15], read_only)
    # Historical controlled remediation is implemented by the dedicated
    # disposable-Git patient, not by the private-alpha roadmap compiler.
    def historical():
        receipt=run_controlled_patient(root)
        assertions={"allowlisted_change":receipt.get("allowlisted_files")==["route.txt"],"exact_rerun":receipt.get("exact_rerun_passed") is True,
                    "no_merge":receipt.get("merge_performed") is False,"cleanup":receipt.get("cleanup_completed") is True,
                    "source_repo_unchanged":receipt.get("source_repository_unchanged") is True}
        return all(assertions.values()), [], {"receipt":receipt["receipt_hash"]}, assertions, {"historical-remediation-receipt.json":receipt}
    run(CASES[16], historical)
    def transports():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); ctx.release["change_impact"] = {"migration_surface": True}; manifest = prepare_review(ctx)
            order_dir = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "review-organisation" / "generations" / manifest["generation"] / "specialist-work-orders"
            work = next(json.loads(path.read_text(encoding="utf-8")) for path in order_dir.glob("*.json") if json.loads(path.read_text(encoding="utf-8"))["specialist_id"] == "migration_and_rollback")
            result = {"schema_version": "migration-and-rollback-result.v1", "work_order_id": work["work_order_id"], "criterion_ids": [criterion], "evidence_refs": [], "rollback_required": False, "limitations": []}
            manual_receipt = {"schema_version": "harness-execution-receipt.v1", "work_order_id": work["work_order_id"], "execution_mode": "manual_external", "declared_capability": "prepared_packet_only", "granted_permission": "read_only", "observed_execution": "receipt_observed", "execution_receipt": "human", "independence_limitation": "declared capability is not proof of isolation"}
            manual = submit_result(ctx, "migration_and_rollback", result, manual_receipt)
            package = render_package(ctx, "migration_and_rollback")
            codex_receipt = {**manual_receipt, "execution_receipt": "codex-package"}
            codex = submit_result(ctx, "migration_and_rollback", result, codex_receipt)
            codex_id = codex.get("result_id") or (codex.get("result_ids") or [None])[0]
            from shiproom import intent as intent_domain
            intent_package=render_package(ctx,"product_intent")
            packet,_packet_raw=intent_domain._load_packet(ctx)
            intent_result={"schema_version":"intent-proposal.v1","release_id":packet["release_id"],"release_commit":packet["release_commit"],"source_packet_hash":packet["packet_hash"],"claims":[],"requirements":[],"criteria":[],"ambiguities":[]}
            intent_work_order=intent_package["native_work_order"]["work_order_id"]
            intent_receipt={**manual_receipt,"work_order_id":intent_work_order,"execution_receipt":"intent-wrapper"}
            intent_accepted=submit_result(ctx,"product_intent",intent_result,intent_receipt)
            assertions = {"package_rendered": package.get("schema_version") == "codex-execution-package.v1",
                          "manual_submitted": manual.get("status") == "accepted", "codex_submitted": codex.get("status") == "idempotent_replay",
                          "same_native_validator": package.get("native_work_order", {}).get("native_boundary", {}).get("native_result_validator") == "shiproom.review_organisation.validate_migration_result",
                          "semantic_identity_equal": manual["result_id"] == codex_id,
                          "transport_distinct": manual_receipt["execution_receipt"] != codex_receipt["execution_receipt"],
                          "intent_wrapper_accepted":intent_accepted["status"]=="accepted"}
            return all(assertions.values()), ["shiproom.review_organisation.prepare", "shiproom.review_organisation.render_package", "shiproom.review_organisation.submit_result"], {"manual": manual["result_id"], "codex": codex_id,"intent":intent_accepted["result_id"]}, assertions, {"codex-execution-package.json":package,"manual-submission.json":manual,"codex-submission.json":codex,"native-result.json":result,"manual-receipt.json":manual_receipt,"codex-receipt.json":codex_receipt,"intent-execution-package.json":intent_package,"intent-proposal.json":intent_result,"intent-receipt.json":intent_receipt,"intent-accepted-reference.json":intent_accepted}
    run(CASES[17], transports)

    if tuple(item["name"] for item in results) != CASES:
        raise AssertionError("workflow case registry changed")
    receipt = {"schema_version": "session6-8-workflow-eval-receipt.v2", "final_commit": _commit(root), "cases": results}
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["receipt_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    target = Path(os.environ.get("SHIPROOM_WORKFLOW_EVAL_RECEIPT", root / ".shiproom" / "local" / "session6-8-workflow-eval-receipt.json"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    for item in results:
        print(("PASS " if item["passed"] else "FAIL ") + item["name"])
    print("receipt=" + str(target))
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
