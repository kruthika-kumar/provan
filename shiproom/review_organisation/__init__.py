"""Deterministic, harness-neutral specialist planning."""
from __future__ import annotations

import hashlib
import importlib
import json
import uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import checked_children, ensure_directory, read_bytes, read_json, replace_bytes, safe_entry, write_bytes


COMPILER_VERSION="portable-review-plan.v1"
STATES={"selected","skipped","unavailable"}
AUTHORITIES={"confirmed_surface","candidate_surface","explicitly_not_applicable","not_inspected"}
TRIGGERS={"migration_surface_discovered","ai_surface_discovered","browser_surface_disproven"}
REVISION_CODES={"MISSING_CRITERION_LINK","MISSING_EVIDENCE_LINK","AUTHORITY_UPGRADE","OUT_OF_SCOPE_RECORD","INCOMPLETE_COVERAGE","MISSING_CLOSURE_REQUIREMENT"}


def root(ctx:LocalExecutionContext)->Path:
    return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"review-organisation"


def _json(value:object)->bytes:return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _hash(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _stable(prefix:str,value:object)->str:return prefix+"_"+hashlib.sha256(canonical_json(value).encode()).hexdigest()[:24]
def _dep(state:str,generation:str|None=None,semantic_hash:str|None=None)->dict:
    if state not in {"required_present","not_applicable","not_used","unavailable"}:raise ValueError("invalid_dependency_state")
    if state=="required_present" and (not generation or not semantic_hash):raise ValueError("required_dependency_missing_binding")
    if state!="required_present" and (generation is not None or semantic_hash is not None):raise ValueError("optional_dependency_must_be_null")
    return {"state":state,"generation":generation,"semantic_hash":semantic_hash}


def registry()->dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("specialist-result-registry.v1.json").read_text(encoding="utf-8"))


def native_boundaries() -> dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("specialist-native-boundary-registry.v1.json").read_text(encoding="utf-8"))


def surface_policy() -> dict:
    return json.loads(resources.files("shiproom.review_organisation").joinpath("review-surface-policy.v1.json").read_text(encoding="utf-8"))


def _resolve_symbol(value: str) -> object:
    """Resolve a published native boundary without treating a prose name as proof.

    The registry is part of the compiler's authority surface.  A typo, a removed
    native validator, or a cross-specialist contract is an unavailable boundary,
    never an invitation for the planner to synthesize a weaker substitute.
    """
    module_name, separator, attribute = value.rpartition(".")
    if not separator:
        raise ValueError("specialist_native_boundary_symbol_invalid")
    module = importlib.import_module(module_name)
    target = getattr(module, attribute, None)
    if not callable(target):
        raise ValueError("specialist_native_boundary_symbol_invalid")
    return target


def validate_specialist_registries() -> dict:
    """Validate the fixed specialist/result/native/surface contract matrix."""
    result = registry()
    boundaries = native_boundaries()
    policy = surface_policy()
    specialists = result.get("specialists")
    native = boundaries.get("specialists")
    signals = policy.get("signals")
    if not isinstance(specialists, list) or not isinstance(native, list) or not isinstance(signals, list):
        raise ValueError("specialist_registry_invalid")
    ids = [item.get("specialist_id") for item in specialists]
    native_ids = [item.get("specialist_id") for item in native]
    if not ids or len(ids) != len(set(ids)) or set(ids) != set(native_ids):
        raise ValueError("specialist_registry_cardinality_invalid")
    by_id = {item["specialist_id"]: item for item in specialists}
    required_native = {"specialist_id", "native_prepare_function", "native_work_order_contract", "native_context_contract", "native_result_contract", "native_result_validator", "native_completion_receipt_contract", "accepted_result_projection"}
    for boundary in native:
        if set(boundary) != required_native:
            raise ValueError("specialist_native_boundary_invalid")
        specialist = by_id[boundary["specialist_id"]]
        if specialist.get("result_schema") != boundary["native_result_contract"]:
            raise ValueError("specialist_result_contract_mismatch")
        _resolve_symbol(boundary["native_prepare_function"])
        _resolve_symbol(boundary["native_result_validator"])
    seen_signals = set()
    required_signal = {"signal_type", "source_domain", "source_authority", "surface", "maximum_applicability_authority", "permitted_selection_effect", "permitted_adaptation_effect"}
    for signal in signals:
        if set(signal) != required_signal or signal["signal_type"] in seen_signals or signal["surface"] not in by_id:
            raise ValueError("review_surface_policy_invalid")
        seen_signals.add(signal["signal_type"])
        if signal["maximum_applicability_authority"] not in AUTHORITIES:
            raise ValueError("review_surface_policy_invalid")
    return {"registry": result, "native_boundaries": boundaries, "surface_policy": policy}


def validate_migration_result(value: dict) -> dict:
    """Native closed validator for the only Session 7-specific specialist result.

    It deliberately does not accept a generic ``details`` bag: the planner can
    transport this result but cannot turn an arbitrary specialist payload into a
    migration authority.
    """
    required = {"schema_version", "work_order_id", "criterion_ids", "evidence_refs", "rollback_required", "limitations"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("migration_result_shape_invalid")
    if value["schema_version"] != "migration-and-rollback-result.v1" or not isinstance(value["work_order_id"], str) or not value["work_order_id"]:
        raise ValueError("migration_result_binding_invalid")
    if not isinstance(value["criterion_ids"], list) or not value["criterion_ids"] or any(not isinstance(item, str) or not item for item in value["criterion_ids"]):
        raise ValueError("migration_result_criteria_invalid")
    if not isinstance(value["evidence_refs"], list) or not isinstance(value["rollback_required"], bool) or not isinstance(value["limitations"], list):
        raise ValueError("migration_result_shape_invalid")
    return value


def _vector(ctx:LocalExecutionContext)->dict:
    graph=load_assessment_input(ctx); nodes=graph["graph_artifacts"]["requirement-evidence-graph.json"].get("nodes",[])
    paths=sorted({node.get("path") for node in nodes if isinstance(node.get("path"),str)})
    languages={"python":any(path.endswith(".py") for path in paths),"typescript":any(path.endswith((".ts",".tsx")) for path in paths)}
    criteria=graph["intent_artifacts"]["acceptance-criteria.json"].get("criteria",[])
    browser=any("browser_or_http" in item.get("required_evidence_categories",[]) for item in criteria)
    # A filename-like hint is a candidate surface only. It cannot establish selection.
    ai_candidates=[path for path in paths if "ai" in path.lower() or "prompt" in path.lower()]
    migration_candidates=[path for path in paths if "migration" in path.lower()]
    change_impact = ctx.release.get("change_impact", {})
    migration_confirmed = bool(change_impact.get("migration_surface"))
    return {"schema_version":"review-plan-input-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",graph["graph_generation"],graph["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",graph["graph_generation"],graph["graph_manifest"]["semantic_bundle_hash"]),"assessment":_dep("not_used"),"measurement_ai":_dep("not_used"),"remediation":_dep("not_used"),"browser_applicability":{"authority":"confirmed_surface" if browser else "not_inspected","criterion_ids":[item["criterion_id"] for item in criteria if "browser_or_http" in item.get("required_evidence_categories",[])]},"language_framework_signals":languages,"migration_signal":{"authority":"confirmed_surface" if migration_confirmed else "candidate_surface" if migration_candidates else "not_inspected","evidence_paths":migration_candidates,"change_impact_binding":"release_change_impact" if migration_confirmed else None},"ai_surface_signal":{"authority":"candidate_surface" if ai_candidates else "not_inspected","evidence_paths":ai_candidates},"harness":{"declared_capability":"manual_external","granted_permission":"prepared_packet_only","observed_execution":"not_observed","independence_limitation":"declared capability is not proof of isolation"}}


def _native_preparation(ctx: LocalExecutionContext, specialist_id: str) -> tuple[dict | None, str | None]:
    """Resolve an *existing* native preparation for a wrapped specialist.

    Review Organisation is intentionally not a second assessment compiler.  A
    selected specialist must be able to point at an already validated native
    packet and exact native work order.  The absence of that packet is an
    ``unavailable`` boundary, not a license to mint a look-alike work order.
    A malformed current native pointer is deliberately allowed to fail closed.
    """
    if specialist_id in {"browser_journey", "python_engineering", "typescript_engineering", "test_adequacy"}:
        from shiproom import assessment
        role = {"browser_journey": "browser_journey", "python_engineering": "engineering_assessment", "typescript_engineering": "engineering_assessment", "test_adequacy": "test_adequacy"}[specialist_id]
        try:
            preparation = assessment.load_preparation(ctx)
        except ValueError as exc:
            if str(exc) == "active assessment preparation unavailable":
                return None, "native_assessment_preparation_unavailable"
            raise
        work = preparation["work_orders"].get(role)
        if work is None:
            return None, "native_assessment_work_order_unavailable"
        return {"domain": "assessment", "role_id": role, "preparation_id": preparation["manifest"]["preparation_id"],
                "preparation_semantic_hash": preparation["manifest"]["preparation_semantic_hash"],
                "work_order_id": work["work_order_id"], "work_order_hash": work["work_order_hash"],
                "context_hash": preparation["contexts"][role]["packet_hash"],
                "result_schema": work["required_output"]["schema_version"]}, None
    if specialist_id in {"instrumentation", "ai_evaluation"}:
        from shiproom.measurement_ai.preparation import load_preparation
        role = "measurement" if specialist_id == "instrumentation" else "ai_evaluation"
        try:
            preparation = load_preparation(ctx)
        except ValueError as exc:
            if str(exc) == "active measurement AI preparation unavailable":
                return None, "native_measurement_ai_preparation_unavailable"
            raise
        work = preparation["work_orders"].get(role)
        if work is None:
            return None, "native_measurement_ai_work_order_unavailable"
        return {"domain": "measurement_ai", "role_id": role, "preparation_id": preparation["manifest"]["preparation_id"],
                "preparation_semantic_hash": preparation["manifest"]["preparation_semantic_hash"],
                "work_order_id": work["work_order_id"], "work_order_hash": work["work_order_hash"],
                "context_hash": preparation["contexts"][role]["packet_hash"],
                "result_schema": work["required_output"]["schema_version"]}, None
    if specialist_id == "product_intent":
        # The native Product Intent workflow has a proposal packet but no
        # independent work-order/receipt lifecycle.  It therefore cannot be
        # represented honestly by this specialist wrapper yet.
        return None, "native_product_intent_work_order_unavailable"
    if specialist_id == "migration_and_rollback":
        return {"domain": "review_organisation", "role_id": specialist_id, "preparation_id": None,
                "preparation_semantic_hash": None, "work_order_id": None, "work_order_hash": None,
                "context_hash": content_hash({"release": ctx.release["release_id"]}), "result_schema": "migration-and-rollback-result.v1"}, None
    raise ValueError("specialist_native_boundary_invalid")


def _selection(ctx: LocalExecutionContext | dict, vector:dict | None = None)->list[dict]:
    # Retain a pure vector-only form for registry tests; real preparation always
    # supplies a context and therefore resolves native boundaries.
    if vector is None:
        vector = ctx  # type: ignore[assignment]
        ctx = None  # type: ignore[assignment]
    active_signals = {
        "python_source": vector["language_framework_signals"]["python"],
        "typescript_source": vector["language_framework_signals"]["typescript"],
        "browser_requirement": vector["browser_applicability"]["authority"] == "confirmed_surface",
        "ai_keyword_candidate": vector["ai_surface_signal"]["authority"] == "candidate_surface",
        "migration_keyword_candidate": vector["migration_signal"]["authority"] in {"candidate_surface", "confirmed_surface"},
        # Product Intent's fixed evidence taxonomy is the only canonical
        # source for these specialist surfaces; implementation omissions do
        # not manufacture either signal.
        "test_requirement": False,
        "instrumentation_requirement": False,
    }
    policy_by_surface = {item["surface"]: item for item in surface_policy()["signals"]}
    result=[]
    for entry in registry()["specialists"]:
        sid=entry["specialist_id"]; selected=False; authority="not_inspected"; reasons=[]
        rule = policy_by_surface.get(sid)
        if rule is not None:
            signal_active = active_signals.get(rule["signal_type"], False)
            authority = rule["maximum_applicability_authority"] if signal_active else "not_inspected"
            selected = signal_active and rule["permitted_selection_effect"] in {"select", "candidate_review"}
            reasons = [rule["signal_type"] if signal_active else "no_registered_surface_signal"]
            if sid == "browser_journey" and vector["browser_applicability"]["authority"] == "explicitly_not_applicable":
                authority, selected, reasons = "explicitly_not_applicable", False, ["browser_explicitly_not_applicable"]
        elif sid == "product_intent":
            # See _native_preparation: the legacy proposal path has no native
            # receipt-bound work order, so it is honestly unavailable here.
            authority, reasons = "not_inspected", ["native_product_intent_work_order_unavailable"]
        native=next(item for item in native_boundaries()["specialists"] if item["specialist_id"]==sid)
        binding, unavailable_reason = (None, None) if ctx is None or not selected else _native_preparation(ctx, sid)
        if selected and ctx is not None and binding is None:
            selected = False
            authority = "not_inspected" if authority != "explicitly_not_applicable" else authority
            reasons = reasons + [unavailable_reason]
        result.append({"specialist_id":sid,"state":"selected" if selected else "unavailable" if unavailable_reason and authority != "explicitly_not_applicable" else "skipped","applicability_authority":authority,"reason_codes":reasons,"evidence_refs":[],"required_capabilities":["prepared_packet_read"],"execution_mode":"manual_external","independence_limitations":["declared capability is not proof of isolation"],"result_schema":entry["result_schema"],"role_version":entry["role_version"],"native_boundary":native,"native_binding":binding})
    return result


def _bind_consumed_dependencies(vector: dict, selected: list[dict]) -> dict:
    """Bind only native generations actually consumed by selected work."""
    result = json.loads(canonical_json(vector))
    assessment = [item["native_binding"] for item in selected if item["state"] == "selected" and item["native_binding"] and item["native_binding"]["domain"] == "assessment"]
    measurement = [item["native_binding"] for item in selected if item["state"] == "selected" and item["native_binding"] and item["native_binding"]["domain"] == "measurement_ai"]
    if assessment:
        identities = {(item["preparation_id"], item["preparation_semantic_hash"]) for item in assessment}
        if len(identities) != 1:
            raise ValueError("mixed_native_assessment_preparations")
        generation, semantic_hash = next(iter(identities)); result["assessment"] = _dep("required_present", generation, semantic_hash)
    if measurement:
        identities = {(item["preparation_id"], item["preparation_semantic_hash"]) for item in measurement}
        if len(identities) != 1:
            raise ValueError("mixed_native_measurement_ai_preparations")
        generation, semantic_hash = next(iter(identities)); result["measurement_ai"] = _dep("required_present", generation, semantic_hash)
    return result


def _validate_consumed_dependencies(ctx: LocalExecutionContext, vector: dict) -> None:
    """Fail closed only for generations that actually consumed a native input.

    This deliberately does not discover a later optional preparation: a plan
    that consumed no assessment or Measurement/AI material remains portable
    when one is issued later.
    """
    assessment_dependency = vector["assessment"]
    if assessment_dependency["state"] == "required_present":
        from shiproom import assessment
        preparation = assessment.load_preparation(ctx)
        if (preparation["manifest"]["preparation_id"] != assessment_dependency["generation"] or
                preparation["manifest"]["preparation_semantic_hash"] != assessment_dependency["semantic_hash"]):
            raise ValueError("stale_consumed_assessment_dependency")
    measurement_dependency = vector["measurement_ai"]
    if measurement_dependency["state"] == "required_present":
        from shiproom.measurement_ai.preparation import load_preparation
        preparation = load_preparation(ctx)
        if (preparation["manifest"]["preparation_id"] != measurement_dependency["generation"] or
                preparation["manifest"]["preparation_semantic_hash"] != measurement_dependency["semantic_hash"]):
            raise ValueError("stale_consumed_measurement_ai_dependency")


def _validate_plan_native_bindings(ctx: LocalExecutionContext, plan: dict) -> None:
    """Re-resolve every selected native boundary from current trusted inputs."""
    for item in plan.get("specialists", []):
        if item.get("state") != "selected":
            continue
        binding = item.get("native_binding")
        if not isinstance(binding, dict):
            raise ValueError("review_plan_native_binding_tampered")
        resolved, reason = _native_preparation(ctx, item.get("specialist_id"))
        if reason is not None or resolved != binding:
            raise ValueError("stale_native_specialist_boundary")


def prepare(ctx:LocalExecutionContext)->dict:
    validate_specialist_registries()
    vector=_vector(ctx); selected=_selection(ctx, vector); vector=_bind_consumed_dependencies(vector, selected); plan_id=_stable("review_plan",vector); generation="plan_"+uuid.uuid4().hex; directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="review_plan_generation")
    work_orders=[]
    for item in selected:
        if item["state"]!="selected":continue
        work_orders.append({"schema_version":"specialist-work-order.v1","work_order_id":_stable("wo",{"plan":plan_id,"specialist":item["specialist_id"]}),"plan_id":plan_id,"specialist_id":item["specialist_id"],"role_version":item["role_version"],"result_schema":item["result_schema"],"input_vector_hash":content_hash(vector),"allowed_files":[],"execution_mode":item["execution_mode"],"revision_policy":{"maximum_invalid_submissions":2,"codes":sorted(REVISION_CODES)},"native_boundary":item["native_boundary"],"native_binding":item["native_binding"]})
    plan={"schema_version":"review-plan.v1","plan_id":plan_id,"input_vector":vector,"specialists":selected,"adaptation_depth":0,"supersedes":None}
    artifacts={"review-plan.json":plan,"plan-events.json":{"schema_version":"plan-events.v1","events":[]},"revision-ledger.json":{"schema_version":"revision-ledger.v1","entries":[]},"accepted-results.json":{"schema_version":"accepted-specialist-results.v1","results":[]},"execution-summary.json":{"schema_version":"execution-summary.v1","execution_modes":[item["execution_mode"] for item in selected if item["state"]=="selected"]}}
    for name,value in artifacts.items():write_bytes(ctx.repository_root,directory/name,_json(value),label="review_plan_artifact")
    ensure_directory(ctx.repository_root, directory/"specialist-work-orders", label="review_plan_work_order_directory")
    for work in work_orders:write_bytes(ctx.repository_root,directory/"specialist-work-orders"/(work["work_order_id"]+".json"),_json(work),label="specialist_work_order")
    manifest={"schema_version":"review-plan-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"plan_id":plan_id,"input_vector":vector,"artifact_hashes":{name:_hash(_json(value)) for name,value in artifacts.items()},"semantic_bundle_hash":content_hash({"plan":plan,"work_orders":work_orders}),"bundle_hash":""};manifest["bundle_hash"]=content_hash({key:value for key,value in manifest.items() if key!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="review_plan_manifest")
    replace_bytes(ctx.repository_root,root(ctx)/"current-review-plan.json",_json({"schema_version":"current-review-plan.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="review_plan_pointer")
    return manifest


def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=read_json(ctx.repository_root, root(ctx)/"current-review-plan.json",label="review_plan_pointer");directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="review_plan_generation");manifest=read_json(ctx.repository_root,directory/"manifest.json",label="review_plan_manifest")
    if manifest.get("compiler_version")!=COMPILER_VERSION or manifest["input_vector"]["release_commit"]!=ctx.authority_binding["repository_commit"]:raise ValueError("stale_dependency")
    _validate_consumed_dependencies(ctx, manifest["input_vector"])
    if pointer.get("manifest_hash") != _hash(_json(manifest)) or pointer.get("semantic_bundle_hash") != manifest.get("semantic_bundle_hash"):
        raise ValueError("review_plan_pointer_tampered")
    names=("review-plan.json","plan-events.json","revision-ledger.json","accepted-results.json","execution-summary.json")
    expected=set(names)|{"manifest.json","specialist-work-orders"}
    if {path.name for path in checked_children(ctx.repository_root,directory,label="review_plan_generation")} != expected:
        raise ValueError("review_plan_generation_file_set_mismatch")
    artifacts={name:read_json(ctx.repository_root,directory/name,label="review_plan_artifact") for name in names}
    if any(_hash(_json(value)) != manifest["artifact_hashes"].get(name) for name,value in artifacts.items()):
        raise ValueError("review_plan_artifact_tampered")
    plan = artifacts["review-plan.json"]
    if plan.get("input_vector") != manifest["input_vector"] or any(item.get("state") == "selected" and not isinstance(item.get("native_binding"), dict) for item in plan.get("specialists", [])):
        raise ValueError("review_plan_native_binding_tampered")
    _validate_plan_native_bindings(ctx, plan)
    return manifest,artifacts


def _publish_successor(ctx: LocalExecutionContext, manifest: dict, artifacts: dict, *, label: str) -> dict:
    """Publish an immutable review-plan successor and replace the pointer last."""
    new_generation = "plan_" + uuid.uuid4().hex
    output = ensure_directory(ctx.repository_root, root(ctx) / "generations" / new_generation, label=label)
    for name, value in artifacts.items():
        write_bytes(ctx.repository_root, output / name, _json(value), label=label + "_artifact")
    prior_orders = root(ctx) / "generations" / manifest["generation"] / "specialist-work-orders"
    ensure_directory(ctx.repository_root, output / "specialist-work-orders", label=label + "_work_order_directory")
    for path in checked_children(ctx.repository_root, prior_orders, label="prior_specialist_work_orders"):
        if path.suffix != ".json":
            raise ValueError("specialist_work_order_file_invalid")
        read_json(ctx.repository_root, path, label="prior_specialist_work_order")
        write_bytes(ctx.repository_root, output / "specialist-work-orders" / path.name, read_bytes(ctx.repository_root, path, label="prior_specialist_work_order"), label=label + "_work_order")
    new_manifest = {"schema_version": "review-plan-generation-manifest.v1", "compiler_version": COMPILER_VERSION,
                    "generation": new_generation, "plan_id": manifest["plan_id"], "input_vector": manifest["input_vector"],
                    "artifact_hashes": {name: _hash(_json(value)) for name, value in artifacts.items()},
                    "semantic_bundle_hash": content_hash({"plan": artifacts["review-plan.json"], "events": artifacts["plan-events.json"]}),
                    "bundle_hash": ""}
    new_manifest["bundle_hash"] = content_hash({key: value for key, value in new_manifest.items() if key != "bundle_hash"})
    write_bytes(ctx.repository_root, output / "manifest.json", _json(new_manifest), label=label + "_manifest")
    # The pointer is deliberately the final write: a failed successor leaves the
    # previously readable plan authoritative.
    replace_bytes(ctx.repository_root, root(ctx) / "current-review-plan.json", _json({"schema_version": "current-review-plan.v1", "generation": new_generation, "manifest_hash": _hash(_json(new_manifest)), "semantic_bundle_hash": new_manifest["semantic_bundle_hash"]}), label="review_plan_pointer")
    return new_manifest


def adapt(ctx:LocalExecutionContext,trigger:str,source_specialist:str,criterion_id:str,evidence_id:str)->dict:
    if trigger not in TRIGGERS:raise ValueError("adaptation_trigger_invalid")
    manifest,artifacts=load(ctx);events=artifacts["plan-events.json"]["events"]
    identity=_stable("plan_event",{"trigger":trigger,"source":source_specialist,"criterion":criterion_id,"evidence":evidence_id})
    if any(item["event_id"]==identity for item in events):return {"status":"duplicate_trigger","event_id":identity}
    if manifest["input_vector"].get("release_commit")!=ctx.authority_binding["repository_commit"]:raise ValueError("adaptation_evidence_unlinked")
    if artifacts["review-plan.json"]["adaptation_depth"]>=3:raise ValueError("adaptation_depth_exceeded")
    if source_specialist not in {item["specialist_id"] for item in artifacts["review-plan.json"]["specialists"]}:
        raise ValueError("adaptation_evidence_unlinked")
    accepted = [item for item in artifacts["accepted-results.json"]["results"] if item["result_id"] == evidence_id and item["specialist_id"] == source_specialist and item["status"] == "accepted"]
    if len(accepted) != 1 or accepted[0]["criterion_id"] != criterion_id:
        raise ValueError("adaptation_evidence_unlinked")
    event={"event_id":identity,"trigger":trigger,"source_specialist":source_specialist,"criterion_id":criterion_id,"evidence_id":evidence_id}
    plan=dict(artifacts["review-plan.json"]);plan["adaptation_depth"]+=1;plan["supersedes"]=manifest["generation"]
    new_events={"schema_version":"plan-events.v1","events":events+[event]}
    new_artifacts={"review-plan.json":plan,"plan-events.json":new_events,"revision-ledger.json":artifacts["revision-ledger.json"],"accepted-results.json":artifacts["accepted-results.json"],"execution-summary.json":artifacts["execution-summary.json"]}
    new_manifest = _publish_successor(ctx, manifest, new_artifacts, label="review_plan_adaptation")
    return {"status":"accepted","event":event,"prior_generation":manifest["generation"],"generation":new_manifest["generation"]}


def render_package(ctx: LocalExecutionContext, specialist_id: str) -> dict:
    manifest, _ = load(ctx)
    directory = root(ctx) / "generations" / manifest["generation"] / "specialist-work-orders"
    matches = [path for path in checked_children(ctx.repository_root, directory, label="specialist_work_orders") if path.suffix == ".json" and read_json(ctx.repository_root, path, label="specialist_work_order").get("specialist_id") == specialist_id]
    if len(matches) != 1:
        raise ValueError("specialist_work_order_unavailable")
    order = read_json(ctx.repository_root, matches[0], label="specialist_work_order")
    return {"schema_version": "codex-execution-package.v1", "work_order": order, "allowed_files": order["allowed_files"], "forbidden_operations": ["model_execution", "network", "project_command", "sql"], "expected_result_path": "result.json", "expected_receipt_path": "completion-receipt.json"}


def _validate_native_submission(ctx: LocalExecutionContext, specialist_id: str, binding: dict, raw: bytes, receipt_raw: bytes) -> tuple[dict, list[str], str]:
    """Invoke the registered native validator; never emulate it locally."""
    result = json.loads(raw.decode("utf-8"))
    receipt = json.loads(receipt_raw.decode("utf-8"))
    if binding["domain"] == "review_organisation":
        validate_migration_result(result)
        if receipt.get("work_order_id") != result["work_order_id"]:
            raise ValueError("native_completion_receipt_binding_invalid")
        return result, result["criterion_ids"], content_hash(result)
    if binding["domain"] == "assessment":
        from shiproom import assessment
        preparation = assessment.load_preparation(ctx, binding["preparation_id"])
        role = binding["role_id"]
        definitions = assessment.load_role_definitions()
        if role == "browser_journey":
            evidence_root = ctx.repository_root / ".shiproom" / "local" / "releases" / ctx.release["release_id"] / "assessment" / "inbox" / binding["preparation_id"] / binding["work_order_id"] / "evidence"
            normalized = assessment._validate_browser_result(raw, receipt_raw, evidence_root, preparation, definitions[role]["value"])
            return result, list(preparation["contexts"][role]["assigned"]["criterion_ids"]), normalized["hashes"]["result_semantic_hash"]
        _submitted, _receipt, normalized = assessment._validate_role_result(raw, receipt_raw, role, preparation, definitions[role]["value"])
        return result, list(preparation["contexts"][role]["assigned"]["criterion_ids"]), content_hash(normalized)
    if binding["domain"] == "measurement_ai":
        from shiproom.measurement_ai.preparation import load_preparation
        from shiproom.measurement_ai.results import normalize_result
        preparation = load_preparation(ctx, binding["preparation_id"])
        role = binding["role_id"]
        normalized = normalize_result(raw, receipt_raw, preparation["work_orders"][role], preparation["contexts"][role], preparation["guidance"])
        return result, list(preparation["contexts"][role]["assigned"]["criterion_ids"]), normalized["result_semantic_hash"]
    raise ValueError("specialist_native_boundary_invalid")


def _submit_result(ctx: LocalExecutionContext, specialist_id: str, result: dict, receipt: dict, raw: bytes, receipt_raw: bytes) -> dict:
    manifest, artifacts = load(ctx)
    specialist = next((item for item in artifacts["review-plan.json"]["specialists"] if item["specialist_id"] == specialist_id), None)
    if specialist is None or specialist["state"] != "selected":
        raise ValueError("specialist_not_issued")
    invalid = None
    if result.get("work_order_id") is None or receipt.get("work_order_id") != result.get("work_order_id"):
        invalid = ("MISSING_EVIDENCE_LINK", ["/work_order_id"])
    elif result.get("authority") in {"deterministically_established", "source_verified"}:
        invalid = ("AUTHORITY_UPGRADE", ["/authority"])
    if invalid:
        prior = [item for item in artifacts["revision-ledger.json"]["entries"] if item["specialist_id"] == specialist_id]
        attempt = len(prior) + 1
        entry = {"revision_id": _stable("revision", {"generation": manifest["generation"], "specialist": specialist_id, "attempt": attempt, "reason": invalid[0], "pointers": invalid[1]}), "specialist_id": specialist_id, "attempt": attempt, "reason": invalid[0], "json_pointers": invalid[1], "status": "revision_required" if attempt == 1 else "specialist_failed_closed"}
        ledger = {"schema_version": "revision-ledger.v1", "entries": artifacts["revision-ledger.json"]["entries"] + [entry]}
        successor = dict(artifacts)
        successor["revision-ledger.json"] = ledger
        new_manifest = _publish_successor(ctx, manifest, successor, label="review_plan_revision")
        return {"status": entry["status"], "reason": invalid[0], "json_pointers": invalid[1], "revision_id": entry["revision_id"], "generation": new_manifest["generation"]}
    order_dir = root(ctx) / "generations" / manifest["generation"] / "specialist-work-orders"
    orders = [read_json(ctx.repository_root, path, label="specialist_work_order") for path in checked_children(ctx.repository_root, order_dir, label="specialist_work_orders") if path.suffix == ".json"]
    work = next((item for item in orders if item.get("specialist_id") == specialist_id), None)
    binding = work.get("native_binding") if work else None
    expected_work_order = binding.get("work_order_id") if binding and binding.get("work_order_id") else work.get("work_order_id") if work else None
    if work is None or not isinstance(binding, dict) or result.get("work_order_id") != expected_work_order or result.get("schema_version") != specialist.get("result_schema"):
        # A bound but cross-specialist result is a closed revision reason, not
        # an accepted source of future adaptation.
        invalid = ("OUT_OF_SCOPE_RECORD", ["/schema_version"])
        prior = [item for item in artifacts["revision-ledger.json"]["entries"] if item["specialist_id"] == specialist_id]
        attempt = len(prior) + 1
        entry = {"revision_id": _stable("revision", {"generation": manifest["generation"], "specialist": specialist_id, "attempt": attempt, "reason": invalid[0], "pointers": invalid[1]}), "specialist_id": specialist_id, "attempt": attempt, "reason": invalid[0], "json_pointers": invalid[1], "status": "revision_required" if attempt == 1 else "specialist_failed_closed"}
        successor = dict(artifacts)
        successor["revision-ledger.json"] = {"schema_version": "revision-ledger.v1", "entries": artifacts["revision-ledger.json"]["entries"] + [entry]}
        new_manifest = _publish_successor(ctx, manifest, successor, label="review_plan_revision")
        return {"status": entry["status"], "reason": invalid[0], "json_pointers": invalid[1], "revision_id": entry["revision_id"], "generation": new_manifest["generation"]}
    _validated, criterion_ids, native_semantic_hash = _validate_native_submission(ctx, specialist_id, binding, raw, receipt_raw)
    if not isinstance(criterion_ids, list) or not criterion_ids or any(not isinstance(item, str) or not item for item in criterion_ids):
        raise ValueError("accepted_result_criterion_link_missing")
    result_id = _stable("accepted_result", {"specialist_id": specialist_id, "criteria": sorted(criterion_ids), "native_result_semantic_hash": native_semantic_hash})
    existing = artifacts["accepted-results.json"]["results"]
    if any(item["result_id"] == result_id for item in existing):
        return {"status": "idempotent_replay", "specialist_id": specialist_id, "work_order_id": result["work_order_id"], "result_id": result_id}
    accepted_records = [{"result_id": _stable("accepted_result", {"parent": result_id, "criterion": criterion_id}), "parent_result_id": result_id, "specialist_id": specialist_id, "criterion_id": criterion_id, "work_order_id": expected_work_order, "result_schema": specialist["result_schema"], "result_semantic_hash": native_semantic_hash, "native_preparation_id": binding.get("preparation_id"), "native_preparation_semantic_hash": binding.get("preparation_semantic_hash"), "status": "accepted"} for criterion_id in sorted(set(criterion_ids))]
    successor = dict(artifacts)
    if any(item["result_id"] == accepted["result_id"] for item in existing for accepted in accepted_records):
        return {"status": "idempotent_replay", "specialist_id": specialist_id, "work_order_id": expected_work_order, "result_ids": [item["result_id"] for item in accepted_records]}
    successor["accepted-results.json"] = {"schema_version": "accepted-specialist-results.v1", "results": existing + accepted_records}
    new_manifest = _publish_successor(ctx, manifest, successor, label="review_plan_accepted_result")
    return {"status": "accepted", "specialist_id": specialist_id, "work_order_id": expected_work_order, "result_id": accepted_records[0]["result_id"], "result_ids": [item["result_id"] for item in accepted_records], "generation": new_manifest["generation"]}


def submit_result(ctx: LocalExecutionContext, specialist_id: str, result: dict, receipt: dict) -> dict:
    """Compatibility API for canonical in-memory manual submissions."""
    return _submit_result(ctx, specialist_id, result, receipt, _json(result), _json(receipt))


def submit_result_bytes(ctx: LocalExecutionContext, specialist_id: str, raw: bytes, receipt_raw: bytes) -> dict:
    """Receipt-sensitive API used by the CLI for byte-exact native results."""
    try:
        result = json.loads(raw.decode("utf-8")); receipt = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("specialist_result_json_invalid") from exc
    if not isinstance(result, dict) or not isinstance(receipt, dict):
        raise ValueError("specialist_result_shape_invalid")
    return _submit_result(ctx, specialist_id, result, receipt, raw, receipt_raw)
