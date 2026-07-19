"""Packet-only remediation roadmaps; private alpha never edits reviewed code."""
from __future__ import annotations

import hashlib
import json
import uuid
from importlib import resources
from pathlib import Path

from shiproom.assessment import load_assessment
from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.measurement_ai.persistence import load_generation as load_measurement_ai
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import ensure_directory, exact_children, read_bytes, read_json, replace_bytes, safe_entry, write_bytes


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
CLOSURE_EVIDENCE_SCHEMA = "remediation-closure-evidence.v1"
CLOSURE_RECEIPT_SCHEMA = "remediation-closure-verifier-receipt.v1"
CLOSURE_VERIFICATION_SCHEMA = "remediation-closure-verification.v1"


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


def authority_policy() -> dict:
    value = json.loads(resources.files("shiproom.remediation_schemas").joinpath("remediation-issue-authority-policy.v1.json").read_text(encoding="utf-8"))
    required = {"rule_id", "finding_state", "blocker", "criterion_authority", "evidence_class", "open_state", "owner_decision_state", "freshness", "issue_class", "actionable", "automation_classes", "closure_evidence_classes"}
    if value.get("schema_version") != "remediation-issue-authority-policy.v1" or not isinstance(value.get("rules"), list):
        raise ValueError("remediation_issue_authority_policy_invalid")
    seen = set()
    for rule in value["rules"]:
        if set(rule) != required or rule["rule_id"] in seen:
            raise ValueError("remediation_issue_authority_policy_invalid")
        seen.add(rule["rule_id"])
        if rule["issue_class"] not in ACTIONABLE | {"not_inspected"} or not isinstance(rule["actionable"], bool):
            raise ValueError("remediation_issue_authority_policy_invalid")
        if not set(rule["automation_classes"]) <= AUTOMATION_CLASSES or not set(rule["closure_evidence_classes"]) <= {"deterministically_established", "source_verified"}:
            raise ValueError("remediation_issue_authority_policy_invalid")
    return value


def _policy_decision(*, blocker: bool, criterion_authority: str, evidence_class: str, open_state: str, owner_required: bool, fresh: bool, finding_state: str | None = None) -> dict:
    """Single authority policy evaluator; rules are intentionally ordered by specificity."""
    for rule in authority_policy()["rules"]:
        expected = {"finding_state": finding_state or open_state, "blocker": blocker, "criterion_authority": criterion_authority, "evidence_class": evidence_class,
                    "open_state": open_state, "owner_decision_state": "required" if owner_required else "not_required",
                    "freshness": "fresh" if fresh else "stale"}
        if all(rule[key] == "any" or rule[key] == value for key, value in expected.items()):
            return {"issue_classification": rule["issue_class"], "actionable": rule["actionable"],
                    "permitted_automation_classes": rule["automation_classes"],
                    "allowed_closure_evidence_classes": rule["closure_evidence_classes"]}
    raise ValueError("remediation_issue_authority_policy_no_match")


def _optional_assessment(ctx: LocalExecutionContext) -> tuple[dict, dict] | None:
    pointer = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "assessment" / "current-assessment.json"
    try:
        safe_entry(pointer, directory=False, label="assessment_pointer")
    except FileNotFoundError:
        return None
    return load_assessment(ctx)


def _optional_measurement(ctx: LocalExecutionContext) -> tuple[dict, dict] | None:
    pointer = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "measurement-ai-readiness" / "current-generation.json"
    try:
        safe_entry(pointer, directory=False, label="measurement_ai_pointer")
    except FileNotFoundError:
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
        state = "closed" if finding.get("state") == "CLOSED" else "open"
        evidence_class = finding.get("evidence_class", "not_inspected")
        criterion_authority = finding.get("criterion_authority", evidence_class)
        policy = _policy_decision(blocker=bool(finding.get("blocker")), criterion_authority=criterion_authority,
                                  evidence_class=evidence_class, open_state=state,
                                  owner_required=bool(finding.get("owner_decision_required")), fresh=True, finding_state=state)
        evidence = [{"kind": "canonical_finding", "id": finding.get("id"), "authority": evidence_class}]
        seed = {"source_issue_type": "finding", "source_issue_id": finding.get("id"), "criterion_id": finding.get("criterion_id"), "requirement_id": finding.get("requirement_id"), "journey_ids": finding.get("journey_ids", [])}
        records.append({**seed, **policy, "issue_authority": evidence_class, "evidence_refs": evidence,
                        "automation_class": finding.get("automation_class") if finding.get("automation_class") in policy["permitted_automation_classes"] else None})
    assessment = _optional_assessment(ctx)
    if assessment:
        _, artifacts = assessment
        for item in artifacts.get("assessment-graph-overlay.json", {}).get("nodes", []):
            if item.get("node_type") != "assessment_gap":
                continue
            seed = {"source_issue_type": "assessment_gap", "source_issue_id": item["node_id"], "criterion_id": item.get("criterion_id"), "requirement_id": None, "journey_ids": []}
            policy = _policy_decision(blocker=False, criterion_authority="model_reviewed", evidence_class="model_reviewed", open_state="open", owner_required=False, fresh=True)
            records.append({**seed, **policy, "issue_authority": "model_reviewed", "evidence_refs": [{"kind": "assessment_gap", "id": item["node_id"], "authority": "model_reviewed"}], "automation_class": None})
    measurement = _optional_measurement(ctx)
    if measurement:
        _, artifacts = measurement
        for check in artifacts.get("measurement-ai-readiness.json", {}).get("checks", []):
            if check.get("status") != "gap":
                continue
            seed = {"source_issue_type": "measurement_ai_check", "source_issue_id": check["check_id"], "criterion_id": None, "requirement_id": None, "journey_ids": []}
            evidence_class = check.get("check_authority", "model_reviewed")
            policy = _policy_decision(blocker=False, criterion_authority=evidence_class, evidence_class=evidence_class, open_state="open", owner_required=False, fresh=True)
            records.append({**seed, **policy, "issue_authority": evidence_class, "evidence_refs": [{"kind": "measurement_ai_check", "id": check["check_id"], "authority": evidence_class}], "automation_class": None})
    seen = set(); result = []
    for item in records:
        key = (item["source_issue_type"], item["source_issue_id"])
        if key not in seen:
            seen.add(key); result.append(item)
    return sorted(result, key=lambda item: (item["source_issue_type"], item["source_issue_id"]))


def _minimal_packet(issue: dict, planner: dict | None, ctx: LocalExecutionContext) -> dict:
    remediation_id = _stable("remediation", {key: issue[key] for key in ("source_issue_type", "source_issue_id", "criterion_id", "requirement_id")})
    closure_id = _stable("closure", {"remediation_id": remediation_id, "evidence": issue["evidence_refs"]})
    semantic = {name: {"authority": "not_inspected", "value": None} for name in PLANNER_FIELDS}
    semantic.update({"assumptions": [], "limitations": ["No remediation planner result was supplied."]})
    if planner is not None:
        semantic = planner["records_by_issue"][issue["source_issue_id"]]
    permitted = issue.get("permitted_automation_classes")
    if permitted is None and issue.get("issue_classification") == "verified_blocker":
        permitted = list(AUTOMATION_CLASSES)
    eligibility = "bounded_fix_available" if issue.get("automation_class") in (permitted or []) else "roadmap_only"
    packet = {"remediation_id": remediation_id, **issue, "user_or_business_impact": {"authority": "not_inspected", "value": None}, "automation_eligibility": eligibility, "execution_modes": ["roadmap_only", "external_agent_handoff"], "verification_contract_id": closure_id, "protected_invariants": ["canonical_findings_unchanged", "canonical_verdict_unchanged", "no_automatic_merge"], "allowed_closure_evidence_classes": ["deterministically_established"], **semantic}
    commit = ctx.authority_binding["repository_commit"]
    branch = ctx.release.get("repository", {}).get("branch") or ctx.release.get("branch") or "owner_action_required"
    contract = {"closure_contract_id": closure_id, "remediation_id": remediation_id, "original_issue_id": issue["source_issue_id"], "original_criterion_id": issue["criterion_id"], "original_failure_evidence": issue["evidence_refs"], "required_before_state": "preserved", "required_after_evidence": "independent exact rerun bound to original issue", "exact_checks_to_rerun": [issue["source_issue_id"]], "regression_checks": [], "test_requirements": [], "instrumentation_requirements": [], "protected_invariants": packet["protected_invariants"], "allowed_repository_commit": commit, "allowed_branch": branch, "independent_verifier_requirement": True, "owner_decision_requirement": issue["issue_classification"] == "owner_decision_required", "evidence_classes_allowed_to_close": issue.get("allowed_closure_evidence_classes", ["deterministically_established"]), "source_generation": issue.get("source_generation", "current"), "release_commit": commit, "expiry_or_stale_bindings": {"release_commit": commit}}
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
    try:
        safe_entry(path, directory=False, label="remediation_planner_result")
    except FileNotFoundError:
        return None
    receipt_path = path.with_name("completion-receipt.json")
    try:
        safe_entry(receipt_path, directory=False, label="remediation_planner_receipt")
    except FileNotFoundError:
        raise ValueError("planner_completion_receipt_missing")
    value = read_json(ctx.repository_root, path, label="remediation_planner_result")
    receipt = read_json(ctx.repository_root, receipt_path, label="remediation_planner_receipt")
    fields = {"schema_version", "work_order_id", "preparation_id", "records", "assumptions", "limitations"}
    if set(value) != fields or value["schema_version"] != PLANNER_RESULT_SCHEMA or value["work_order_id"] != work["work_order_id"] or value["preparation_id"] != manifest["preparation_id"]:
        raise ValueError("planner_result_binding_mismatch")
    if set(receipt) != {"schema_version", "work_order_id", "result_snapshot_hash", "executor"} or receipt["schema_version"] != PLANNER_RECEIPT_SCHEMA or receipt["work_order_id"] != work["work_order_id"] or receipt["result_snapshot_hash"] != _sha(read_bytes(ctx.repository_root, path, label="remediation_planner_result")):
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
        list_fields = ("root_cause_hypotheses", "recommended_changes", "test_proposals", "instrumentation_implications", "rollback_suggestions")
        if (any(not isinstance(record[field], list) or len(record[field]) > 64 or any(not isinstance(item, str) or not item or len(item) > 4096 for item in record[field]) for field in list_fields) or
                record["complexity"] not in {"low", "medium", "high", "unknown"} or record["risk"] not in {"low", "medium", "high", "unknown"} or
                (record["suggested_owner"] is not None and (not isinstance(record["suggested_owner"], str) or len(record["suggested_owner"]) > 512))):
            raise ValueError("planner_result_record_invalid")
        if (not isinstance(value["assumptions"], list) or not isinstance(value["limitations"], list) or
                any(not isinstance(item, str) or not item or len(item) > 4096 for item in value["assumptions"] + value["limitations"])):
            raise ValueError("planner_result_narrative_invalid")
        records[record["source_issue_id"]] = {name: {"authority": authority, "value": record[name]} for name in PLANNER_FIELDS} | {"assumptions": value["assumptions"], "limitations": value["limitations"]}
    return {"records_by_issue": records}


def compile(ctx: LocalExecutionContext, preparation_id: str | None = None) -> dict:
    active = root(ctx) / "active-preparation.json"
    if preparation_id is None:
        value = read_json(ctx.repository_root, active, label="remediation_active_preparation"); preparation_id = value["preparation_id"]
    directory = root(ctx) / "preparations" / preparation_id
    safe_entry(directory, directory=True, label="remediation_preparation")
    manifest = read_json(ctx.repository_root, directory / "remediation-work-orders.json", label="remediation_work_orders")
    if manifest["compiler_version"] != PREPARATION_VERSION or manifest["manifest_hash"] != content_hash({key: value for key, value in manifest.items() if key != "manifest_hash"}):
        raise ValueError("stale_remediation_preparation")
    planner = _planner_result(ctx, directory, manifest)
    source = read_json(ctx.repository_root, directory / "remediation-source-packet.json", label="remediation_source_packet")
    if content_hash(source) != manifest["source_packet_hash"]:
        raise ValueError("remediation_source_packet_tampered")
    items = [_minimal_packet(issue, planner, ctx) for issue in source["issues"] if issue["issue_classification"] in ACTIONABLE]
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
    hashes.update({"remediation-packets/" + item["remediation_id"] + ".json": _sha(_json(item)) for item in packets})
    hashes.update({"closure-contracts/" + item["closure_contract_id"] + ".json": _sha(_json(item)) for item in contracts})
    generated = {"schema_version": GENERATION_MANIFEST_SCHEMA, "compiler_version": COMPILER_VERSION, "generation": generation, "release_id": ctx.release["release_id"], "release_commit": ctx.authority_binding["repository_commit"], "authority": source["authority"], "preparation_id": preparation_id, "artifact_hashes": hashes, "semantic_bundle_hash": content_hash({"authority": source["authority"], "packets": packets, "contracts": contracts}), "bundle_hash": ""}
    generated["bundle_hash"] = content_hash({key: value for key, value in generated.items() if key != "bundle_hash"})
    write_bytes(ctx.repository_root, output / "manifest.json", _json(generated), label="remediation_manifest")
    load_generation(ctx, output)
    replace_bytes(ctx.repository_root, root(ctx) / "current-remediation-generation.json", _json({"schema_version": POINTER_SCHEMA, "generation": generation, "manifest_hash": _sha(_json(generated)), "semantic_bundle_hash": generated["semantic_bundle_hash"]}), label="remediation_current_pointer")
    return generated


def load_generation(ctx: LocalExecutionContext, directory: Path | None = None) -> tuple[dict, dict]:
    if directory is None:
        pointer = read_json(ctx.repository_root, root(ctx) / "current-remediation-generation.json", label="remediation_pointer"); directory = root(ctx) / "generations" / pointer["generation"]
    safe_entry(directory, directory=True, label="remediation_generation")
    manifest = read_json(ctx.repository_root, directory / "manifest.json", label="remediation_manifest")
    if manifest.get("compiler_version") != COMPILER_VERSION or manifest.get("release_commit") != ctx.authority_binding["repository_commit"]:
        raise ValueError("stale_dependency")
    artifacts = {name: read_json(ctx.repository_root, directory / name, label="remediation_artifact") for name in ("remediation-index.json", "remediation-plan.json", "remediation-overlay.json")}
    if any(_sha(_json(artifacts[name])) != manifest["artifact_hashes"].get(name) for name in artifacts):
        raise ValueError("remediation_artifact_tampered")
    packets = artifacts["remediation-plan.json"].get("packets", [])
    expected_packets = {item["remediation_id"] + ".json" for item in packets}
    expected_contracts = {item["verification_contract_id"] + ".json" for item in packets}
    exact_children(directory / "remediation-packets", expected_packets, label="remediation_packets")
    exact_children(directory / "closure-contracts", expected_contracts, label="closure_contracts")
    for item in packets:
        packet_path = directory / "remediation-packets" / (item["remediation_id"] + ".json")
        contract_path = directory / "closure-contracts" / (item["verification_contract_id"] + ".json")
        packet = read_json(ctx.repository_root, packet_path, label="remediation_packet")
        contract = read_json(ctx.repository_root, contract_path, label="closure_contract")
        if packet != item or contract.get("remediation_id") != item["remediation_id"]:
            raise ValueError("remediation_packet_contract_link_invalid")
        if _sha(_json(packet)) != manifest["artifact_hashes"].get("remediation-packets/" + item["remediation_id"] + ".json") or _sha(_json(contract)) != manifest["artifact_hashes"].get("closure-contracts/" + item["verification_contract_id"] + ".json"):
            raise ValueError("remediation_packet_contract_tampered")
    return manifest, artifacts


def _closure_inbox(ctx: LocalExecutionContext, closure_contract_id: str) -> tuple[dict, dict]:
    inbox = root(ctx) / "closure-inbox" / closure_contract_id
    exact_children(inbox, {"evidence.json", "verifier-receipt.json"}, label="closure_inbox")
    evidence = read_json(ctx.repository_root, inbox / "evidence.json", label="closure_evidence")
    receipt = read_json(ctx.repository_root, inbox / "verifier-receipt.json", label="closure_verifier_receipt")
    evidence_fields = {"schema_version", "closure_contract_id", "release_id", "release_commit", "branch", "fixer_id", "reruns", "regression_results", "test_results", "instrumentation_results", "protected_invariant_outcomes"}
    receipt_fields = {"schema_version", "closure_contract_id", "evidence_snapshot_hash", "verifier_id", "executor_type"}
    if not isinstance(evidence, dict) or set(evidence) != evidence_fields or evidence.get("schema_version") != CLOSURE_EVIDENCE_SCHEMA:
        raise ValueError("closure_evidence_contract_invalid")
    outcome_fields = ("reruns", "regression_results", "test_results", "instrumentation_results")
    if (not isinstance(evidence.get("reruns"), list) or not evidence["reruns"] or
            any(not isinstance(evidence[name], list) or len(evidence[name]) > 2048 or any(not isinstance(item, dict) or set(item) != {"check_id", "passed", "evidence_class"} or not isinstance(item["check_id"], str) or not item["check_id"] or not isinstance(item["passed"], bool) or item["evidence_class"] not in {"deterministically_established", "source_verified"} for item in evidence[name]) for name in outcome_fields) or
            not isinstance(evidence["protected_invariant_outcomes"], list) or
            any(not isinstance(item, dict) or set(item) != {"invariant", "passed"} or not isinstance(item["invariant"], str) or not isinstance(item["passed"], bool) for item in evidence["protected_invariant_outcomes"])):
        raise ValueError("closure_evidence_contract_invalid")
    if (not isinstance(receipt, dict) or set(receipt) != receipt_fields or receipt.get("schema_version") != CLOSURE_RECEIPT_SCHEMA or
            receipt.get("executor_type") not in {"human", "agent_harness"} or not isinstance(receipt.get("verifier_id"), str) or not receipt["verifier_id"]):
        raise ValueError("closure_verifier_receipt_invalid")
    raw = _json(evidence)
    if receipt.get("closure_contract_id") != closure_contract_id or receipt.get("evidence_snapshot_hash") != _sha(raw):
        raise ValueError("closure_evidence_receipt_binding_invalid")
    return evidence, receipt


def closure_verify(ctx: LocalExecutionContext, closure_contract_id: str, evidence: dict | None = None) -> dict:
    """Validate only the portable closure inbox; arbitrary evidence objects are forbidden."""
    manifest, _ = load_generation(ctx)
    path = root(ctx) / "generations" / manifest["generation"] / "closure-contracts" / (closure_contract_id + ".json")
    contract = read_json(ctx.repository_root, path, label="closure_contract")
    if not isinstance(contract, dict) or contract.get("closure_contract_id") != closure_contract_id:
        raise ValueError("closure_contract_invalid")
    if evidence is not None:
        raise ValueError("closure_evidence_must_use_inbox")
    try:
        submitted, receipt = _closure_inbox(ctx, closure_contract_id)
    except ValueError as exc:
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "not_evaluated", "reason_codes": [str(exc)]}
    expected_branch = ctx.release.get("repository", {}).get("branch") or ctx.release.get("branch") or "owner_action_required"
    if (submitted.get("release_id") != ctx.release["release_id"] or submitted.get("release_commit") != ctx.authority_binding["repository_commit"] or submitted.get("branch") != expected_branch):
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "stale", "reason_codes": ["release_commit_mismatch"]}
    if receipt.get("verifier_id") == submitted.get("fixer_id"):
        raise ValueError("closure_verifier_not_independent")
    expected = set(contract["exact_checks_to_rerun"])
    reruns = submitted.get("reruns")
    if not isinstance(reruns, list) or {item.get("check_id") for item in reruns} != expected:
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "unsatisfied", "reason_codes": ["exact_rerun_identity_missing"]}
    if any(not item.get("passed") or item.get("evidence_class") not in contract["evidence_classes_allowed_to_close"] for item in reruns):
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "unsatisfied", "reason_codes": ["closure_evidence_not_permitted"]}
    requirement_groups = (("regression_results", "regression_checks"), ("test_results", "test_requirements"), ("instrumentation_results", "instrumentation_requirements"))
    for submitted_key, contract_key in requirement_groups:
        expected_checks = set(contract.get(contract_key, []))
        submitted_checks = {item["check_id"] for item in submitted[submitted_key]}
        if submitted_checks != expected_checks:
            return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "unsatisfied", "reason_codes": ["closure_required_outcome_missing"]}
        if any(not item["passed"] or item["evidence_class"] not in contract["evidence_classes_allowed_to_close"] for item in submitted[submitted_key]):
            return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "unsatisfied", "reason_codes": ["closure_evidence_not_permitted"]}
    if any(not item.get("passed") for item in submitted.get("protected_invariant_outcomes", [])):
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "unsatisfied", "reason_codes": ["protected_invariant_failed"]}
    if contract.get("owner_decision_requirement"):
        return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "owner_action_required", "reason_codes": ["owner_decision_required"]}
    return {"schema_version": CLOSURE_VERIFICATION_SCHEMA, "closure_contract_id": closure_contract_id, "status": "satisfied_candidate", "reason_codes": ["independent_exact_rerun_passed"]}
