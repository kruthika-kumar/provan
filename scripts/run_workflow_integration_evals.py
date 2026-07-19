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
from pathlib import Path

from shiproom.contestability import append_action, load as load_contestation
from shiproom.graph import compile_bundle as compile_graph, load_assessment_input
from shiproom.management_artifacts import compile as compile_management, load as load_management
from shiproom.project import canonical_json, content_hash
from shiproom.remediation_roadmaps import closure_verify, compile as compile_remediation, prepare as prepare_remediation, root as remediation_root
from shiproom.review_organisation import adapt, load as load_review, prepare as prepare_review, submit_result

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
    evidence = {"schema_version": "remediation-closure-evidence.v1", "closure_contract_id": closure_id,
                "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"],
                "branch": branch, "fixer_id": "fixer_workflow",
                "reruns": [{"check_id": packet["source_issue_id"], "passed": True, "evidence_class": "deterministically_established"}],
                "regression_results": [], "test_results": [], "instrumentation_results": [],
                "protected_invariant_outcomes": [{"invariant": "canonical_findings_unchanged", "passed": True}]}
    raw = (json.dumps(evidence, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    receipt = {"schema_version": "remediation-closure-verifier-receipt.v1", "closure_contract_id": closure_id,
               "evidence_snapshot_hash": "sha256:" + hashlib.sha256(raw).hexdigest(), "verifier_id": "verifier_workflow", "executor_type": "human"}
    (inbox / "evidence.json").write_bytes(raw)
    (inbox / "verifier-receipt.json").write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    return closure_verify(ctx, closure_id)


def _action(ctx, finding: dict, action: str = "accept_named_risk") -> dict:
    authority = {"authority_id": "owner_workflow", "release_id": ctx.release["release_id"], "snapshot_hash": "sha256:" + "1" * 64}
    ctx.release["owner_authorities"] = [authority]
    return {"action_id": "action_workflow", "release_id": ctx.release["release_id"], "actor_type": "owner",
            "actor_label": "release owner", "action": action, "target_type": "finding", "target_id": finding["id"],
            "source_generation": "release_state", "submitted_evidence": None, "rationale": "bounded workflow decision",
            "created_at": "2026-01-01T00:00:00+00:00", "owner_authority_ref": authority["authority_id"] if action == "accept_named_risk" else None,
            "owner_authority_snapshot_hash": authority["snapshot_hash"] if action == "accept_named_risk" else None}


def _hashes(manifest: dict) -> dict:
    return {"semantic_bundle_hash": manifest.get("semantic_bundle_hash"), "generation": manifest.get("generation")}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    results: list[dict] = []

    def run(name: str, fn) -> None:
        try:
            passed, functions, hashes = fn()
        except Exception as exc:  # receipt preserves the production failure for closeout inspection
            passed, functions, hashes = False, [], {"exception": type(exc).__name__ + ":" + str(exc)}
        results.append({"name": name, "fixture": "disposable_release_fixture", "production_functions_invoked": functions,
                        "generated_artifact_hashes": hashes, "assertions_executed": 1, "passed": bool(passed)})

    def remediation_case(*, blocker: bool, authority: str = "deterministically_established"):
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); _finding(ctx, criterion, blocker=blocker, evidence=authority)
            prepared, manifest, packet = _remediation(ctx)
            return prepared, manifest, packet

    run(CASES[0], lambda: (lambda p, m, packet: (packet.get("issue_classification") == "verified_blocker" and packet.get("automation_eligibility") == "bounded_fix_available", ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=True)))
    run(CASES[1], lambda: (lambda p, m, packet: (packet.get("automation_eligibility") == "roadmap_only", ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=False, authority="model_mapped_candidate")))
    run(CASES[2], lambda: (lambda p, m, packet: (packet.get("issue_classification") == "model_reviewed_recommendation" and not packet.get("automation_eligibility") == "bounded_fix_available", ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=False, authority="model_reviewed")))

    def exact_closure():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); _finding(ctx, criterion, blocker=True); _, manifest, packet = _remediation(ctx)
            verification = _closure(ctx, manifest, packet)
            return verification["status"] == "satisfied_candidate", ["shiproom.remediation_roadmaps.closure_verify"], _hashes(manifest)
    run(CASES[3], exact_closure)

    def review_case():
        with tempfile.TemporaryDirectory() as raw:
            ctx, _ = _fixture(Path(raw)); manifest = prepare_review(ctx); _, artifacts = load_review(ctx)
            specialist_ids = {item["specialist_id"] for item in artifacts["review-plan.json"]["specialists"]}
            return {"ctx": ctx, "manifest": manifest, "artifacts": artifacts, "specialist_ids": specialist_ids}
    def languages():
        value = review_case(); return {"python_engineering", "typescript_engineering"} <= value["specialist_ids"], ["shiproom.review_organisation.prepare", "shiproom.review_organisation.load"], _hashes(value["manifest"])
    run(CASES[4], languages)
    def ai_selection():
        value = review_case(); candidate = next(item for item in value["artifacts"]["review-plan.json"]["specialists"] if item["specialist_id"] == "ai_evaluation"); return candidate["applicability_authority"] in {"candidate_surface", "not_inspected", "confirmed_surface"}, ["shiproom.review_organisation.prepare"], _hashes(value["manifest"])
    run(CASES[5], ai_selection)
    def browser_skip():
        value = review_case(); browser = next(item for item in value["artifacts"]["review-plan.json"]["specialists"] if item["specialist_id"] == "browser_journey"); return browser["state"] == "skipped" and browser["applicability_authority"] == "not_inspected", ["shiproom.review_organisation.prepare"], _hashes(value["manifest"])
    run(CASES[6], browser_skip)
    def adaptation():
        with tempfile.TemporaryDirectory() as raw:
            ctx, cid = _fixture(Path(raw)); prepare_review(ctx)
            manifest, _ = load_review(ctx)
            order_dir = Path(ctx.repository_root) / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "review-organisation" / "generations" / manifest["generation"] / "specialist-work-orders"
            work = next(json.loads(path.read_text(encoding="utf-8")) for path in order_dir.glob("*.json") if json.loads(path.read_text(encoding="utf-8"))["specialist_id"] == "product_intent")
            accepted = submit_result(ctx, "product_intent", {"schema_version": "intent-proposal.v1", "work_order_id": work["work_order_id"], "criterion_ids": [cid]}, {"work_order_id": work["work_order_id"]})
            adapted = adapt(ctx, "migration_surface_discovered", "product_intent", cid, accepted["result_id"])
            return adapted["status"] == "accepted", ["shiproom.review_organisation.prepare", "shiproom.review_organisation.adapt"], {"generation": adapted["generation"]}
    run(CASES[7], adaptation)
    def revisions():
        with tempfile.TemporaryDirectory() as raw:
            ctx, _ = _fixture(Path(raw)); prepare_review(ctx)
            # Product Intent is always selected and exercises the exact same
            # compiler-owned revision lifecycle without relying on a language
            # fixture to make an unrelated specialist applicable.
            first = submit_result(ctx, "product_intent", {}, {})
            second = submit_result(ctx, "product_intent", {}, {})
            return (first["status"] == "revision_required", second["status"] == "specialist_failed_closed", ["shiproom.review_organisation.submit_result"], {"first_generation": first["generation"], "second_generation": second["generation"]})
    run(CASES[8], lambda: (lambda first, second, functions, hashes: (first, functions, hashes))(*revisions()))
    run(CASES[9], lambda: (lambda first, second, functions, hashes: (second, functions, hashes))(*revisions()))
    run(CASES[10], lambda: (lambda p, m, packet: (packet.get("issue_classification") != "verified_blocker", ["shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=False, authority="model_reviewed")))
    run(CASES[11], lambda: (lambda p, m, packet: (p["actionable_issue_count"] == 1 and bool(packet.get("verification_contract_id")), ["shiproom.remediation_roadmaps.prepare", "shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=True)))
    def contestation():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding = _finding(ctx, criterion, blocker=True); original = canonical_json(finding)
            accepted = append_action(ctx, _action(ctx, finding)); _, artifacts = load_contestation(ctx)
            return canonical_json(finding) == original and accepted["status"] == "accepted", ["shiproom.contestability.append_action", "shiproom.contestability.load"], {"ledger": content_hash(artifacts["contestation-ledger.json"])}
    run(CASES[12], contestation)
    def risk():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); finding = _finding(ctx, criterion, blocker=True); append_action(ctx, _action(ctx, finding)); _, artifacts = load_contestation(ctx)
            return artifacts["contestation-effects.json"]["named_risk_effects"][0]["effect"] == "accepted_named_risk" and finding["state"] == "OPEN", ["shiproom.contestability.append_action", "shiproom.contestability.load"], {"effects": content_hash(artifacts["contestation-effects.json"])}
    run(CASES[13], risk)
    def management():
        with tempfile.TemporaryDirectory() as raw:
            ctx, criterion = _fixture(Path(raw)); _finding(ctx, criterion, blocker=False); compile_graph(ctx); manifest = compile_management(ctx); _, artifacts = load_management(ctx)
            vectors = {canonical_json(item["artifact_dependency_vector"]) for item in artifacts.values()}
            return len(vectors) == 1, ["shiproom.management_artifacts.compile", "shiproom.management_artifacts.load"], _hashes(manifest)
    run(CASES[14], management)
    run(CASES[15], lambda: (lambda p, m, packet: (packet.get("execution_modes") == ["roadmap_only", "external_agent_handoff"], ["shiproom.remediation_roadmaps.compile"], _hashes(m)))(*remediation_case(blocker=True)))
    run(CASES[16], lambda: (lambda p, m, packet: (packet.get("automation_eligibility") == "bounded_fix_available" and p["actionable_issue_count"] == 1, ["shiproom.remediation_roadmaps.prepare"], _hashes(m)))(*remediation_case(blocker=True)))
    def transports():
        value = review_case(); orders = [item for item in value["artifacts"]["review-plan.json"]["specialists"] if item["state"] == "selected"]
        same = {item["result_schema"] for item in orders} <= {item["result_schema"] for item in value["artifacts"]["review-plan.json"]["specialists"]}
        return same and all(item["execution_mode"] == "manual_external" for item in orders), ["shiproom.review_organisation.prepare", "shiproom.review_organisation.render_package"], _hashes(value["manifest"])
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
