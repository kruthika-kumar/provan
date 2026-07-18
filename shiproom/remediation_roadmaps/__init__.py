"""Packet-only remediation roadmaps; private alpha never edits reviewed code."""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from shiproom.assessment import load_assessment
from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.measurement_ai.persistence import load_generation as load_measurement_ai
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import ensure_directory, exact_children, replace_bytes, safe_entry, write_bytes


PREPARATION_VERSION = "remediation-roadmap-preparation.v1"
COMPILER_VERSION = "portable-remediation-roadmap.v1"
PLANNER_ROLE_SCHEMA = "remediation-planner-role.v1"
PLANNER_WORK_ORDER_SCHEMA = "remediation-planner-work-order.v1"
PLANNER_RESULT_SCHEMA = "remediation-planner-result.v1"
PLANNER_RECEIPT_SCHEMA = "remediation-planner-completion-receipt.v1"
GENERATION_MANIFEST_SCHEMA = "remediation-generation-manifest.v1"
POINTER_SCHEMA = "current-remediation-generation.v1"
ACTIONABLE = {"verified_blocker", "condition_candidate", "owner_decision_required", "model_reviewed_recommendation", "roadmap_opportunity"}
PLANNER_FIELDS = ("root_cause_hypotheses", "recommended_changes", "test_proposals", "instrumentation_implications", "rollback_suggestions", "complexity", "risk", "suggested_owner")
AUTOMATION_CLASSES = {"exact_route_mismatch", "broken_internal_link", "simple_configuration_mismatch", "missing_narrow_regression_test", "clearly_false_success_state_copy"}


def root(ctx: LocalExecutionContext) -> Path:
    return ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "remediation"


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _stable(prefix: str, value: object) -> str:
    return prefix + "_" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:24]


def _dependency(state: str, generation: str | None = None, semantic_hash: str | None = None) -> dict:
    if state not in {"required_present", "not_applicable", "not_used", "unavailable"}:
        raise ValueError("invalid_dependency_state")
    if state == "required_present":
        if not isinstance(generation, str) or not isinstance(semantic_hash, str):
            raise ValueError("required_dependency_missing_binding")
    elif generation is not None or semantic_hash is not None:
        raise ValueError("optional_dependency_must_be_null")
    return {"state": state, "generation": generation, "semantic_hash": semantic_hash}


def _optional_assessment(ctx: LocalExecutionContext) -> tuple[dict, dict] | None:
    pointer = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "assessment" / "current-assessment.json"
    if not pointer.exists():
        return None
    return load_assessment(ctx)


def _optional_measurement(ctx: LocalExecutionContext) -> tuple[dict, dict] | None:
    pointer = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "measurement-ai-readiness" / "current-generation.json"
    if not pointer.exists():
        return None
    return load_measurement_ai(ctx)


def _authority(ctx: LocalExecutionContext) -> dict:
    graph = load_assessment_input(ctx)
    assessment = _optional_assessment(ctx)
    measurement = _optional_measurement(ctx)
    return {
        "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"],
        "product_intent": _dependency("required_present", graph["intent_manifest"].get("generation", graph["graph_generation"]), graph["intent_manifest"]["semantic_bundle_hash"]),
        "graph": _dependency("required_present", graph["graph_generation"], graph["graph_manifest"]["semantic_bundle_hash"]),
        "assessment": _dependency("required_present", assessment[0].get("generation", "current"), assessment[0]["semantic_bundle_hash"]) if assessment else _dependency("not_used"),
        "measurement_ai": _dependency("required_present", measurement[0]["generation"], measurement[0]["semantic_bundle_hash"]) if measurement else _dependency("not_used"),
    }


def _issue_records(ctx: LocalExecutionContext, authority: dict) -> list[dict]:
    records: list[dict] = []
    for finding in ctx.release.get("findings", []):
        if finding.get("state") == "CLOSED":
            continue
        classification = "verified_blocker" if finding.get("blocker") else "condition_candidate"
        evidence = [{"kind": "canonical_finding", "id": finding.get("id"), "authority": "deterministically_established"}]
        seed = {"source_issue_type": "finding", "source_issue_id": finding.get("id"), "criterion_id": finding.get("criterion_id"), "requirement_id": finding.get("requirement_id"), "journey_ids": finding.get("journey_ids", [])}
        records.append({**seed, "issue_classification": classification, "issue_authority": "deterministically_established", "evidence_refs": evidence, "automation_class": finding.get("automation_class") if finding.get("automation_class") in AUTOMATION_CLASSES else None})
    assessment = _optional_assessment(ctx)
    if assessment:
        _, artifacts = assessment
        for item in artifacts.get("assessment-graph-overlay.json", {}).get("nodes", []):
            if item.get("node_type") != "assessment_gap":
                continue
            seed = {"source_issue_type": "assessment_gap", "source_issue_id": item["node_id"], "criterion_id": item.get("criterion_id"), "requirement_id": None, "journey_ids": []}
            records.append({**seed, "issue_classification": "model_reviewed_recommendation", "issue_authority": "model_reviewed", "evidence_refs": [{"kind": "assessment_gap", "id": item["node_id"], "authority": "model_reviewed"}], "automation_class": None})
    measurement = _optional_measurement(ctx)
    if measurement:
        _, artifacts = measurement
        for check in artifacts.get("measurement-ai-readiness.json", {}).get("checks", []):
            if check.get("status") != "gap":
                continue
            seed = {"source_issue_type": "measurement_ai_check", "source_issue_id": check["check_id"], "criterion_id": None, "requirement_id": None, "journey_ids": []}
            records.append({**seed, "issue_classification": "model_reviewed_recommendation", "issue_authority": "model_reviewed", "evidence_refs": [{"kind": "measurement_ai_check", "id": check["check_id"], "authority": check.get("check_authority", "model_reviewed")}], "automation_class": None})
    seen = set(); result = []
    for item in records:
        key = (item["source_issue_type"], item["source_issue_id"])
        if key not in seen:
            seen.add(key); result.append(item)
    return sorted(result, key=lambda item: (item["source_issue_type"], item["source_issue_id"]))


def _minimal_packet(issue: dict, planner: dict | None) -> dict:
    remediation_id = _stable("remediation", {key: issue[key] for key in ("source_issue_type", "source_issue_id", "criterion_id", "requirement_id")})
    closure_id = _stable("closure", {"remediation_id": remediation_id, "evidence": issue["evidence_refs"]})
    semantic = {name: {"authority": "not_inspected", "value": None} for name in PLANNER_FIELDS}
    semantic.update({"assumptions": [], "limitations": ["No remediation planner result was supplied."]})
    if planner is not None:
        semantic = planner["records_by_issue"][issue["source_issue_id"]]
    eligibility = "bounded_fix_available" if issue.get("automation_class") in AUTOMATION_CLASSES and issue["issue_classification"] == "verified_blocker" else "roadmap_only"
    packet = {"remediation_id": remediation_id, **issue, "user_or_business_impact": {"authority": "not_inspected", "value": None}, "automation_eligibility": eligibility, "execution_modes": ["roadmap_only", "external_agent_handoff"], "verification_contract_id": closure_id, "protected_invariants": ["canonical_findings_unchanged", "canonical_verdict_unchanged", "no_automatic_merge"], "allowed_closure_evidence_classes": ["deterministically_established"], **semantic}
    contract = {"closure_contract_id": closure_id, "remediation_id": remediation_id, "original_issue_id": issue["source_issue_id"], "original_criterion_id": issue["criterion_id"], "original_failure_evidence": issue["evidence_refs"], "required_before_state": "preserved", "required_after_evidence": "independent exact rerun bound to original issue", "exact_checks_to_rerun": [issue["source_issue_id"]], "test_requirements": [], "instrumentation_requirements": [], "protected_invariants": packet["protected_invariants"], "allowed_repository_commit_or_branch": None, "independent_verifier_requirement": True, "owner_decision_requirement": issue["issue_classification"] == "owner_decision_required", "evidence_classes_allowed_to_close": packet["allowed_closure_evidence_classes"], "expiry_or_stale_bindings": {"release_commit": None}}
    return {"packet": packet, "contract": contract}


def prepare(ctx: LocalExecutionContext) -> dict:
    authority = _authority(ctx); issues = _issue_records(ctx, authority); preparation_id = "prep_" + uuid.uuid4().hex
    directory = ensure_directory(ctx.repository_root, root(ctx) / "preparations" / preparation_id, label="remediation_preparation")
    actionable = [item for item in issues if item["issue_classification"] in ACTIONABLE]
    work_order = None
    if actionable:
        work_order = {"schema_version": PLANNER_WORK_ORDER_SCHEMA, "work_order_id": _stable("wo_remediation_planner", {"authority": authority, "issues": [item["source_issue_id"] for item in actionable]}), "preparation_id": preparation_id, "release_id": ctx.release["release_id"], "assigned_issue_ids": [item["source_issue_id"] for item in actionable], "forbidden_fields": ["issue_classification", "issue_authority", "evidence_refs", "criterion_id", "requirement_id", "journey_ids", "automation_eligibility", "closure_status", "protected_invariants"]}
    source = {"schema_version": "remediation-source-packet.v1", "preparation_id": preparation_id, "authority": authority, "issues": issues}
    manifest = {"schema_version": "remediation-work-orders.v1", "compiler_version": PREPARATION_VERSION, "preparation_id": preparation_id, "authority": authority, "source_packet_hash": content_hash(source), "planner_work_order": work_order, "manifest_hash": ""}
    manifest["manifest_hash"] = content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    write_bytes(ctx.repository_root, directory / "remediation-source-packet.json", _json(source), label="remediation_source_packet")
    write_bytes(ctx.repository_root, directory / "remediation-work-orders.json", _json(manifest), label="remediation_manifest")
    if work_order:
        write_bytes(ctx.repository_root, directory / "work-orders" / (work_order["work_order_id"] + ".json"), _json(work_order), label="remediation_work_order")
    replace_bytes(ctx.repository_root, root(ctx) / "active-preparation.json", _json({"schema_version": "active-remediation-preparation.v1", "preparation_id": preparation_id, "manifest_hash": _sha(_json(manifest))}), label="remediation_pointer")
    return {"preparation_id": preparation_id, "actionable_issue_count": len(actionable), "planner_work_order": work_order}


def _planner_result(ctx: LocalExecutionContext, preparation: Path, manifest: dict) -> dict | None:
    work = manifest.get("planner_work_order")
    if not work:
        return None
    path = root(ctx) / "inbox" / manifest["preparation_id"] / work["work_order_id"] / "result.json"
    if not path.exists():
        return None
    safe_entry(path, directory=False, label="remediation_planner_result")
    receipt_path = path.with_name("completion-receipt.json")
    if not receipt_path.exists():
        raise ValueError("planner_completion_receipt_missing")
    safe_entry(receipt_path, directory=False, label="remediation_planner_receipt")
    value = json.loads(path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    fields = {"schema_version", "work_order_id", "preparation_id", "records", "assumptions", "limitations"}
    if set(value) != fields or value["schema_version"] != PLANNER_RESULT_SCHEMA or value["work_order_id"] != work["work_order_id"] or value["preparation_id"] != manifest["preparation_id"]:
        raise ValueError("planner_result_binding_mismatch")
    if set(receipt) != {"schema_version", "work_order_id", "result_snapshot_hash", "executor"} or receipt["schema_version"] != PLANNER_RECEIPT_SCHEMA or receipt["work_order_id"] != work["work_order_id"] or receipt["result_snapshot_hash"] != _sha(path.read_bytes()):
        raise ValueError("planner_completion_receipt_invalid")
    executor = receipt["executor"]
    if not isinstance(executor, dict) or executor.get("executor_type") not in {"human", "agent_harness"}:
        raise ValueError("planner_executor_invalid")
    authority = "model_reviewed" if executor["executor_type"] == "agent_harness" else "human_reviewed"
    owner_ref = executor.get("owner_authority_ref")
    if owner_ref is not None:
        valid = [item for item in ctx.release.get("owner_authorities", []) if item.get("authority_id") == owner_ref and item.get("release_id") == ctx.release["release_id"] and item.get("snapshot_hash") == executor.get("owner_authority_snapshot_hash")]
        if not valid:
            raise ValueError("planner_owner_authority_invalid")
        authority = "owner_declared"
    if not isinstance(value["records"], list) or len(value["records"]) != len(work["assigned_issue_ids"]):
        raise ValueError("planner_coverage_incomplete")
    records = {}
    for record in value["records"]:
        if set(record) != {"source_issue_id", *PLANNER_FIELDS} or record["source_issue_id"] not in work["assigned_issue_ids"] or record["source_issue_id"] in records:
            raise ValueError("planner_authority_field_forbidden")
        records[record["source_issue_id"]] = {name: {"authority": authority, "value": record[name]} for name in PLANNER_FIELDS} | {"assumptions": value["assumptions"], "limitations": value["limitations"]}
    return {"records_by_issue": records}


def compile(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    active = root(ctx) / "active-preparation.json"
    if preparation_id is None:
        value = json.loads(active.read_text(encoding="utf-8")); preparation_id = value["preparation_id"]
    directory = root(ctx) / "preparations" / preparation_id
    safe_entry(directory, directory=True, label="remediation_preparation")
    manifest = json.loads((directory / "remediation-work-orders.json").read_text(encoding="utf-8"))
    if manifest["compiler_version"] != PREPARATION_VERSION or manifest["manifest_hash"] != content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"}):
        raise ValueError("stale_remediation_preparation")
    planner = _planner_result(ctx, directory, manifest)
    source = json.loads((directory / "remediation-source-packet.json").read_text(encoding="utf-8"))
    if content_hash(source) != manifest["source_packet_hash"]:
        raise ValueError("remediation_source_packet_tampered")
    items = [_minimal_packet(issue, planner) for issue in source["issues"] if issue["issue_classification"] in ACTIONABLE]
    packets = [item["packet"] for item in items]; contracts = [item["contract"] for item in items]
    if len({item["remediation_id"] for item in packets}) != len(packets) or len({item["remediation_id"] for item in contracts}) != len(contracts):
        raise ValueError("remediation_cardinality_invalid")
    generation = "gen_" + uuid.uuid4().hex; output = ensure_directory(ctx.repository_root, root(ctx) / "generations" / generation, label="remediation_generation")
    artifacts = {"remediation-index.json": {"schema_version": "remediation-index.v1", "release_id": ctx.release["release_id"], "authority": source["authority"], "remediation_ids": [item["remediation_id"] for item in packets]}, "remediation-plan.json": {"schema_version": "remediation-plan.v1", "release_id": ctx.release["release_id"], "packets": packets}, "remediation-overlay.json": {"schema_version": "remediation-overlay.v1", "nodes": [{"node_id": item["remediation_id"], "node_type": "remediation_packet", "authority": item["issue_authority"]} for item in packets]}}
    for name, value in artifacts.items():
        write_bytes(ctx.repository_root, output / name, _json(value), label="remediation_artifact")
    for item in packets:
        write_bytes(ctx.repository_root, output / "remediation-packets" / (item["remediation_id"] + ".json"), _json(item), label="remediation_packet")
    for item in contracts:
        write_bytes(ctx.repository_root, output / "closure-contracts" / (item["closure_contract_id"] + ".json"), _json(item), label="closure_contract")
    hashes = {name: _sha(_json(value)) for name, value in artifacts.items()}
    generated = {"schema_version": GENERATION_MANIFEST_SCHEMA, "compiler_version": COMPILER_VERSION, "generation": generation, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "authority": source["authority"], "preparation_id": preparation_id, "artifact_hashes": hashes, "semantic_bundle_hash": content_hash({"authority": source["authority"], "packets": packets, "contracts": contracts}), "bundle_hash": ""}
    generated["bundle_hash"] = content_hash({key: value for key, value in generated.items() if key != "bundle_hash"})
    write_bytes(ctx.repository_root, output / "manifest.json", _json(generated), label="remediation_manifest")
    load_generation(ctx, output)
    replace_bytes(ctx.repository_root, root(ctx) / "current-remediation-generation.json", _json({"schema_version": POINTER_SCHEMA, "generation": generation, "manifest_hash": _sha(_json(generated)), "semantic_bundle_hash": generated["semantic_bundle_hash"]}), label="remediation_current_pointer")
    return generated


def load_generation(ctx: LocalExecutionContext, directory: Path | None = None) -> tuple[dict, dict]:
    if directory is None:
        pointer = json.loads((root(ctx) / "current-remediation-generation.json").read_text(encoding="utf-8")); directory = root(ctx) / "generations" / pointer["generation"]
    safe_entry(directory, directory=True, label="remediation_generation")
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("compiler_version") != COMPILER_VERSION or manifest.get("release_commit") != ctx.authority_binding["repository_commit"]:
        raise ValueError("stale_dependency")
    artifacts = {name: json.loads((directory / name).read_text(encoding="utf-8")) for name in ("remediation-index.json", "remediation-plan.json", "remediation-overlay.json")}
    if any(_sha(_json(artifacts[name])) != manifest["artifact_hashes"].get(name) for name in artifacts):
        raise ValueError("remediation_artifact_tampered")
    return manifest, artifacts


def closure_verify(ctx: LocalExecutionContext, closure_contract_id: str, evidence: dict) -> dict:
    manifest, _ = load_generation(ctx); path = root(ctx) / "generations" / manifest["generation"] / "closure-contracts" / (closure_contract_id + ".json")
    contract = json.loads(path.read_text(encoding="utf-8"))
    if evidence.get("release_commit") != ctx.authority_binding["repository_commit"]:
        return {"status": "stale", "closure_contract_id": closure_contract_id}
    if evidence.get("executor_id") == evidence.get("fixer_id"):
        raise ValueError("closure_verifier_not_independent")
    expected = set(contract["exact_checks_to_rerun"])
    actual = set(evidence.get("rerun_of", []))
    if not expected.issubset(actual):
        return {"status": "unsatisfied", "closure_contract_id": closure_contract_id}
    return {"status": "satisfied_candidate", "closure_contract_id": closure_contract_id}
