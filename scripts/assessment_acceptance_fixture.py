from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def snapshot_read_only_state(ctx) -> dict:
    root = ctx.repository_root
    graph_pointer = root / ".shiproom/local/releases" / ctx.release["release_id"] / "requirement-evidence-graph/current-generation.json"
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=no"], cwd=root, text=True, capture_output=True, check=True).stdout
    return {
        "release": json.dumps(ctx.release, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "graph_pointer": graph_pointer.read_bytes(),
        "tracked_status": status,
        "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip(),
    }


def assert_read_only_state(ctx, before: dict) -> None:
    after = snapshot_read_only_state(ctx)
    if after != before:
        raise AssertionError("assessment changed canonical release, graph, commit, or tracked repository state")


def write_browser_submission(ctx, preparation: dict, *, corrupt_artifact_hash: bool = False, corrupt_receipt_hash: bool = False) -> Path:
    work = preparation["work_orders"]["browser_journey"]
    if not work["permissions"]["browser"]["allowed_targets"]:
        raise ValueError("browser fixture requires an issued authorized target")
    criterion_id = work["inputs"]["criterion_ids"][0]; target = work["permissions"]["browser"]["allowed_targets"][0]; timestamp = "2026-07-15T10:00:00+00:00"
    inbox = ctx.repository_root / ".shiproom/local/releases" / ctx.release["release_id"] / "assessment/inbox" / work["preparation_id"] / work["work_order_id"]
    evidence_path = inbox / "evidence/observation.json"
    evidence = json.dumps({"url": target["url"], "loaded": True}, sort_keys=True).encode("utf-8")
    evidence_path.parent.mkdir(parents=True, exist_ok=True); evidence_path.write_bytes(evidence)
    evidence_hash = "sha256:" + hashlib.sha256(evidence).hexdigest()
    if corrupt_artifact_hash: evidence_hash = "sha256:" + "0" * 64
    result = {
        "schema_version": "browser-journey-result.v2", "role_id": "browser_journey", "role_version": work["role_version"],
        "preparation_id": work["preparation_id"], "preparation_semantic_hash": work["preparation_semantic_hash"], "work_order_id": work["work_order_id"], "work_order_hash": work["work_order_hash"],
        "base_graph_generation": work["inputs"]["base_graph_generation"], "base_graph_semantic_hash": work["inputs"]["base_graph_semantic_hash"],
        "payload": {
            "criteria": [{"local_id": "criterion_result", "criterion_id": criterion_id, "disposition": "assessed", "uncertainty": "bounded", "rationale": "Observed only the exact granted target."}],
            "observations": [{"local_id": "observation", "criterion_id": criterion_id, "url": target["url"], "action": "Navigate to the exact granted URL.", "observed_outcome": "The authorized page loaded.", "redirect_chain": [target["url"]], "capture_timestamp": timestamp, "evidence_local_ids": ["evidence"], "evidence_class": "browser_observed"}],
            "judgments": [{"local_id": "judgment", "criterion_id": criterion_id, "observation_local_ids": ["observation"], "conclusion": "The bounded browser observation succeeded; implementation and test adequacy remain unproven.", "uncertainty": "bounded", "evidence_class": "model_reviewed"}],
            "evidence": [{"local_id": "evidence", "observation_local_id": "observation", "path": "observation.json", "media_type": "application/json", "byte_length": len(evidence), "sha256": evidence_hash, "capture_timestamp": timestamp}],
        }, "assumptions": [], "limitations": ["Only the exact granted target was observed."]
    }
    result_path = inbox / "result.json"; _write(result_path, result)
    result_hash = "sha256:" + hashlib.sha256(result_path.read_bytes()).hexdigest()
    if corrupt_receipt_hash: result_hash = "sha256:" + "f" * 64
    receipt = {"schema_version": "shiproom.assessment-completion-receipt.v2", "executor": {"executor_type": "human", "reviewer_label": "Portable manual reviewer"}, "work_order_id": work["work_order_id"], "work_order_hash": work["work_order_hash"], "result_snapshot_hash": result_hash, "started_at": timestamp, "completed_at": "2026-07-15T10:05:00+00:00"}
    _write(inbox / "completion-receipt.json", receipt)
    return result_path


def write_core_results(ctx, preparation: dict) -> None:
    def common(local_id: str, field: str, item: dict) -> dict:
        return {"local_id":local_id,field:item[field],"disposition":"assessed","scope_status":item["scope_status"],"evidence_class":"model_reviewed","uncertainty":"bounded","rationale":"Manual packet-only assessment.","basis_node_ids":[item[field]],"basis_edge_ids":[],"basis_gap_ids":[],"basis_source_refs":[]}
    for role in ("product_assessment","engineering_assessment","test_adequacy","targeted_test_planning"):
        work=preparation["work_orders"][role]; context=preparation["contexts"][role]
        if role=="product_assessment":
            payload={"requirements":[{**common(f"req_{i}","requirement_id",item),"intended_user_outcome":"Preserve the declared outcome.","partial_or_missing":"Boundary evidence remains limited."} for i,item in enumerate(context["assigned_requirements"])],"journeys":[{**common(f"journey_{i}","journey_id",item),"journey_completeness":"Not established end to end.","declared_vs_evidence_assessed_scope":"Only prepared evidence was assessed."} for i,item in enumerate(context["assigned_journeys"])],"criteria":[{**common(f"product_{i}","criterion_id",item),"implementation_status":"plausibly_present","honest_success_state":"Not independently established.","honest_failure_state":"Failure remains possible.","evidence_required_after_launch":["Bounded runtime observation."]} for i,item in enumerate(context["assigned_criteria"])],"gaps":[],"decision_candidates":[]}
            schema="product-assessment-result.v2"
        elif role=="engineering_assessment":
            payload={"criteria":[{**common(f"engineering_{i}","criterion_id",item),"probable_component_node_ids":[],"existing_test_node_ids":[],"test_layer":"unit","assertion_adequacy":"partial","boundary_adequacy":"inadequate","overall_adequacy":"inadequate","mocks_or_bypasses":[],"negative_cases":[],"recovery_cases":[],"state_transition_cases":[],"runtime_evidence_node_ids":[],"dependency_isolation":"Not inspected.","rollback_concern":"Not inspected.","migration_concern":"Not inspected.","remaining_gap":"Passing commands would not establish boundary coverage.","required_closure_evidence":["Boundary-level evidence."]} for i,item in enumerate(context["assigned_criteria"])],"gaps":[]}; schema="engineering-assessment-result.v2"
        elif role=="test_adequacy":
            payload={"criteria":[{**common(f"adequacy_{i}","criterion_id",item),"existing_test_node_ids":[],"test_layer":"unit","assertion_adequacy":"adequate","boundary_adequacy":"inadequate","overall_adequacy":"partial","negative_cases":[],"recovery_cases":[],"state_transition_cases":[],"mock_boundaries":[]} for i,item in enumerate(context["assigned_criteria"])],"gaps":[]}; schema="test-adequacy-result.v2"
        else:
            payload={"criteria":[{**common(f"planning_{i}","criterion_id",item),"recommendation_summary":"A boundary-level test is recommended."} for i,item in enumerate(context["assigned_criteria"])],"specifications":[]}; schema="targeted-test-result.v2"
        result={"schema_version":schema,"role_id":role,"role_version":work["role_version"],"preparation_id":work["preparation_id"],"preparation_semantic_hash":work["preparation_semantic_hash"],"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"base_graph_generation":work["inputs"]["base_graph_generation"],"base_graph_semantic_hash":work["inputs"]["base_graph_semantic_hash"],"payload":payload,"assumptions":[],"limitations":["No new project command was executed."]}
        inbox=ctx.repository_root/".shiproom/local/releases"/ctx.release["release_id"]/"assessment/inbox"/work["preparation_id"]/work["work_order_id"]; result_path=inbox/"result.json"; _write(result_path,result)
        receipt={"schema_version":"shiproom.assessment-completion-receipt.v2","executor":{"executor_type":"human","reviewer_label":"Portable manual reviewer"},"work_order_id":work["work_order_id"],"work_order_hash":work["work_order_hash"],"result_snapshot_hash":"sha256:"+hashlib.sha256(result_path.read_bytes()).hexdigest(),"started_at":"2026-07-15T09:00:00+00:00","completed_at":"2026-07-15T09:05:00+00:00"}; _write(inbox/"completion-receipt.json",receipt)
