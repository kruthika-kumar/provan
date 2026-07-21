"""Canonical management-artifact compilation and escaped local rendering."""
from __future__ import annotations

import hashlib, html, json, uuid
from importlib import resources
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.graph import load_assessment_input
from shiproom.assessment import load_assessment
from shiproom.measurement_ai.persistence import load_generation as load_measurement_ai
from shiproom.remediation_roadmaps import load_generation as load_remediation
from shiproom.review_organisation import load as load_review_plan
from shiproom.contestability import load as load_contestation
from shiproom.project import canonical_json, content_hash
from shiproom.workflow_trust import checked_children, ensure_directory, read_bytes, read_json, replace_bytes, safe_entry, write_bytes, reject_private_alpha_operation
from shiproom.workflow_audit import observed_boundary
from shiproom.session6_8_contract_validation import validate_canonical_contract

COMPILER_VERSION="portable-management-artifacts.v1"
JSON_ARTIFACTS=("executive-release-brief","product-release-review","engineering-release-assessment","measurement-ai-readiness","remediation-overview","release-packet-index","release-recommendation-view")


def guard_prohibited_operation(operation: str) -> None:
    """Reporting is deterministic local rendering, never an adapter surface."""
    reject_private_alpha_operation(operation)

def root(ctx:LocalExecutionContext)->Path:return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"management-artifacts"
def _json(v:object)->bytes:return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def _hash(raw:bytes)->str:return "sha256:"+hashlib.sha256(raw).hexdigest()
def _dep(s:str,g:str|None=None,h:str|None=None)->dict:
    if s not in {"required_present","not_applicable","not_used","unavailable"}:raise ValueError("invalid_dependency_state")
    if s=="required_present" and (not g or not h):raise ValueError("required_dependency_missing_binding")
    if s!="required_present" and (g is not None or h is not None):raise ValueError("optional_dependency_must_be_null")
    return {"state":s,"generation":g,"semantic_hash":h}

def dependency_vector(ctx:LocalExecutionContext)->dict:
    upstream=load_assessment_input(ctx)
    release_root=ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]
    def optional(pointer:str, loader):
        try:
            safe_entry(release_root / pointer, directory=False, label="optional_dependency_pointer")
        except FileNotFoundError:
            return _dep("not_used"), None
        try:
            manifest, artifacts=loader(ctx)
        except ValueError as exc:
            raise ValueError("stale_dependency") from exc
        return _dep("required_present",manifest.get("generation"),manifest["semantic_bundle_hash"]), artifacts
    assessment_state, assessment=optional("assessment/current-assessment.json",load_assessment)
    measurement_state, measurement=optional("measurement-ai-readiness/current-generation.json",load_measurement_ai)
    remediation_state, remediation=optional("remediation/current-remediation-generation.json",load_remediation)
    review_state, review=optional("review-organisation/current-review-plan.json",load_review_plan)
    contest_state, contest=optional("contestability/current-contestation-generation.json",load_contestation)
    return {"schema_version":"artifact-dependency-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",upstream["graph_generation"],upstream["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",upstream["graph_generation"],upstream["graph_manifest"]["semantic_bundle_hash"]),"assessment":assessment_state,"measurement_ai":measurement_state,"remediation":remediation_state,"review_plan":review_state,"contestability":contest_state,"_loaded":{"upstream":upstream,"assessment":assessment,"measurement":measurement,"remediation":remediation,"review":review,"contest":contest}}

def _section_specs(name: str, registry_value: dict | None = None) -> list[dict]:
    value = json.loads(resources.files("shiproom.management_artifacts").joinpath("management-artifact-section-registry.v1.json").read_text()) if registry_value is None else registry_value
    specs = value.get("artifacts", {}).get(name)
    required = {"section_id", "source_dependencies", "required_when", "record_source", "minimum_records", "typed_empty_state", "authority_passthrough"}
    if value.get("schema_version") != "management-artifact-section-registry.v1" or not isinstance(specs, list) or not specs:
        raise ValueError("management_section_registry_invalid")
    ids = []
    for spec in specs:
        if set(spec) != required or not isinstance(spec["section_id"], str) or not spec["section_id"] or not isinstance(spec["source_dependencies"], list) or not spec["source_dependencies"] or not isinstance(spec["minimum_records"], int) or spec["minimum_records"] < 0 or not isinstance(spec["authority_passthrough"], bool):
            raise ValueError("management_section_registry_invalid")
        ids.append(spec["section_id"])
    if len(ids) != len(set(ids)):
        raise ValueError("management_section_registry_invalid")
    return specs


def validate_section_registry(value: dict) -> dict:
    artifacts=value.get("artifacts") if isinstance(value,dict) else None
    if set(value)!={"schema_version","artifacts"} or value.get("schema_version")!="management-artifact-section-registry.v1" or not isinstance(artifacts,dict) or not artifacts:
        raise ValueError("management_section_registry_invalid")
    for name in artifacts:
        _section_specs(name,value)
    return value


def validate_recommendation_policy(value: dict) -> dict:
    return _recommendation_policy(value)


def _sections(name: str) -> list[str]:
    return [item["section_id"] for item in _section_specs(name)]


def _section_contracts(name: str) -> list[dict]:
    """Return the packaged exact sections; artifacts may not invent their own."""
    return _section_specs(name)


def _section_records(name: str, specs: list[dict], *, ctx: LocalExecutionContext, loaded: dict, vector: dict) -> list[dict]:
    """Materialize every registered report section from canonical inputs.

    The renderer consumes these records verbatim.  It does not infer authority
    or recompute Measurement/AI state; an unavailable dependency gets its
    registry-defined typed empty state instead of a fabricated narrative.
    """
    upstream = loaded.get("upstream", {"intent_artifacts": {}, "graph_artifacts": {}})
    intent = upstream["intent_artifacts"]
    graph = upstream["graph_artifacts"]
    graph_nodes = graph.get("requirement-evidence-graph.json", {}).get("nodes", [])
    requirements = intent.get("requirements.json", {}).get("requirements", [])
    criteria = intent.get("acceptance-criteria.json", {}).get("criteria", [])
    journeys = [item for item in graph_nodes if item.get("node_type") == "critical_journey"]
    assessment = loaded["assessment"] or {}
    measurement = loaded["measurement"] or {}
    remediation = loaded["remediation"] or {}
    review = loaded["review"] or {}
    contest = loaded["contest"] or {}
    activation = getattr(ctx, "activation", {}) or {}
    sources = {
        "requirements": requirements, "criteria": criteria, "critical_journeys": journeys,
        "repository_map": [ctx.release.get("repository", {})] if ctx.release.get("repository") else [],
        "components": graph_nodes, "implementation_state": graph_nodes,
        "test_evidence": assessment.get("test-adequacy.json", {}).get("payload", {}).get("criteria", []),
        "instrumentation": measurement.get("instrumentation-coverage.json", {}).get("signals", []),
        "runtime_evidence": assessment.get("effective-assessment-view.json", {}).get("criteria", []),
        "measurement_contract": measurement.get("measurement-contract.json", {}).get("contracts", []),
        "event_property_coverage": measurement.get("instrumentation-coverage.json", {}).get("signals", []),
        "ai_maturity": measurement.get("measurement-ai-readiness.json", {}).get("checks", []),
        "claim_honesty": measurement.get("measurement-ai-readiness.json", {}).get("checks", []),
        "issues": remediation.get("remediation-plan.json", {}).get("packets", []),
        "packets": remediation.get("remediation-plan.json", {}).get("packets", []),
        "closure_contracts": remediation.get("remediation-plan.json", {}).get("packets", []),
        "contestation": contest.get("contestation-ledger.json", {}).get("actions", []),
        "owner_decisions": ctx.release.get("owner_decisions", []),
        "verified_blockers": [item for item in ctx.release.get("findings", []) if item.get("blocker")],
        "recommendation": [{"record_id": "derived_recommendation", "source": "release_recommendation_policy"}],
        "what_was_promised": requirements + criteria + journeys,
        "what_was_proven": graph_nodes,
        "unknowns": [{"dependency": key, **value} for key, value in vector.items() if isinstance(value, dict) and value.get("state") in {"not_used", "unavailable"}],
        "accepted_conditions": contest.get("contestation-effects.json", {}).get("named_risk_effects", []),
        "residual_risk": [item for item in ctx.release.get("findings", []) if item.get("state") != "CLOSED"],
        "post_release_watch": measurement.get("launch-measurement-plan.json", {}).get("recommendations", []),
        "execution_substrate": [activation.get("contract", {}).get("execution_policy", {})],
        "execution_mode": review.get("execution-summary.json", {}).get("execution_modes", []),
        "independence_limitations": [item.get("independence_limitations", []) for item in review.get("review-plan.json", {}).get("specialists", []) if item.get("independence_limitations")],
        "target_user": requirements, "outcomes": requirements, "scope": requirements,
        "non_goals": [], "source_conflicts": intent.get("ambiguities.json", {}).get("ambiguities", []),
        "product_decisions": ctx.release.get("owner_decisions", []),
        "post_release_plan": measurement.get("launch-measurement-plan.json", {}).get("recommendations", []),
        "requirement_criterion_matrix": [{"requirement_id": item.get("requirement_id"), "criterion_ids": sorted({criterion.get("criterion_id") for criterion in criteria if criterion.get("requirement_id")==item.get("requirement_id")})} for item in requirements],
        "change_map": graph_nodes, "approved_commands": [activation.get("contract", {}).get("execution_policy", {}).get("approved_commands", [])],
        "requirement_test_matrix": assessment.get("effective-assessment-view.json", {}).get("criteria", []),
        "test_adequacy": assessment.get("test-adequacy.json", {}).get("payload", {}).get("criteria", []),
        "negative_recovery": assessment.get("engineering-assessment.json", {}).get("payload", {}).get("criteria", []),
        "runtime": assessment.get("effective-assessment-view.json", {}).get("criteria", []),
        "rollback": remediation.get("remediation-plan.json", {}).get("packets", []),
        "migration": remediation.get("remediation-plan.json", {}).get("packets", []),
        "dependencies": graph_nodes, "remediation": remediation.get("remediation-plan.json", {}).get("packets", []),
        "closure_contracts": remediation.get("remediation-plan.json", {}).get("packets", []),
        "success_failure": measurement.get("measurement-contract.json", {}).get("contracts", []),
        "definition_execution_accuracy": measurement.get("measurement-contract.json", {}).get("downstream_definitions", []),
        "verifier_dispositions": measurement.get("measurement-ai-readiness.json", {}).get("verifier_dispositions", []),
        "launch_monitoring": measurement.get("launch-measurement-plan.json", {}).get("recommendations", []),
        "limitations": measurement.get("launch-measurement-plan.json", {}).get("limitations", []),
        "automation_eligibility": remediation.get("remediation-plan.json", {}).get("packets", []),
        "owners": remediation.get("remediation-plan.json", {}).get("packets", []),
        "execution_modes": review.get("execution-summary.json", {}).get("execution_modes", []),
        "state": remediation.get("remediation-plan.json", {}).get("packets", []),
        "verification": remediation.get("closure-verifications.json", {}).get("verifications", []),
        "dependency_vector": [{key: value for key, value in vector.items() if key != "schema_version"}],
        "artifact_index": [{"artifact": value} for value in JSON_ARTIFACTS],
        "source_generations": [{key: value for key, value in vector.items() if isinstance(value, dict) and "state" in value}],
    }
    result = []
    for spec in specs:
        records = sources.get(spec["section_id"], [])
        if not isinstance(records, list):
            records = [records]
        dependencies = ["contestability" if dep == "contestation" else dep for dep in spec["source_dependencies"]]
        unavailable = all(vector.get(dep, {}).get("state") in {"not_used", "unavailable", "not_applicable"} for dep in dependencies)
        # A consumed Measurement & AI generation can canonically establish that
        # the release has no applicable measurement/AI surface.  Its six
        # compiler-derived checks are the source records for that state; an
        # empty contract list is not missing upstream material.
        if (not records and spec["record_source"] == "measurement_ai_canonical_projection"
                and vector.get("measurement_ai", {}).get("state") == "required_present"):
            readiness = measurement.get("measurement-ai-readiness.json", {})
            if readiness.get("skip_reason") == "no_applicable_measurement_or_ai_surface":
                records = [{"record_id": item["check_id"], "status": item["status"],
                            "check_authority": item["check_authority"],
                            "semantic_review_authority": item["semantic_review_authority"],
                            "coverage_boundary": item["coverage_boundary"]}
                           for item in readiness.get("checks", [])]
        if not records and not unavailable and spec["record_source"] == "canonical_dependency_vector":
            # The vector itself is canonical and makes an honest, bounded
            # status record for a section whose specialised upstream material
            # has no records yet.  It is not a semantic finding.
            records = [{"record_id": "dependency_" + dep, "source_dependency": dep, **vector[dep]} for dep in dependencies]
        state = spec["typed_empty_state"] if unavailable and not records else "populated" if records else "empty_no_canonical_records"
        if state != spec["typed_empty_state"] and len(records) < spec["minimum_records"]:
            raise ValueError("management_section_minimum_records_missing:" + spec["section_id"])
        result.append({"section_id": spec["section_id"], "state": state, "records": records, "authority_passthrough": spec["authority_passthrough"]})
    return result
def _recommendation_policy(value: dict | None = None) -> dict:
    value = json.loads(resources.files("shiproom.management_artifacts").joinpath("release-recommendation-policy.v1.json").read_text()) if value is None else value
    required = {"schema_version", "statuses", "required_inputs", "rules", "unknown_dependency_states", "rule"}
    if set(value) != required or value["schema_version"] != "release-recommendation-policy.v1":
        raise ValueError("release_recommendation_policy_invalid")
    expected = {"rule_id", "precedence", "when", "status", "reason_codes"}
    if (not isinstance(value["rules"], list) or not value["rules"] or
            any(set(rule) != expected or rule["status"] not in value["statuses"] or not isinstance(rule["reason_codes"], list) or not rule["reason_codes"] for rule in value["rules"]) or
            [rule["precedence"] for rule in value["rules"]] != sorted(rule["precedence"] for rule in value["rules"])):
        raise ValueError("release_recommendation_policy_invalid")
    return value


def validate_generation_manifest(value: dict) -> dict:
    required={"schema_version","compiler_version","generation","release_id","artifact_dependency_vector","artifact_hashes","semantic_bundle_hash","bundle_hash"}
    if not isinstance(value,dict) or set(value)!=required or value.get("schema_version")!="management-generation-manifest.v1" or value.get("compiler_version")!="portable-management-artifacts.v1":
        raise ValueError("management_generation_manifest_invalid")
    if not isinstance(value.get("artifact_hashes"),dict) or not value["artifact_hashes"] or not all(isinstance(item,str) and item.startswith("sha256:") for item in value["artifact_hashes"].values()):
        raise ValueError("management_generation_manifest_hashes_invalid")
    return value


def _policy(ctx:LocalExecutionContext,vector:dict, contestation:dict | None)->dict:
    """Apply the sole packaged recommendation policy to canonical facts only."""
    policy = _recommendation_policy()
    blockers = [item for item in ctx.release.get("findings", []) if item.get("blocker") and item.get("state") != "CLOSED"]
    actions = (contestation or {}).get("contestation-ledger.json", {}).get("actions", [])
    owner_decision = any(item.get("action_type") in {"accept_named_risk", "defer"} for item in actions)
    unavailable = any(isinstance(item, dict) and item.get("state") in policy["unknown_dependency_states"] for item in vector.values())
    predicates = {"verified_blocker_present": bool(blockers), "accepted_condition_or_named_risk": owner_decision,
                  "required_dependency_unavailable": unavailable, "no_verified_blocker_in_canonical_release": not bool(blockers)}
    rule = next(item for item in policy["rules"] if predicates.get(item["when"], False))
    unknowns = [key for key, item in vector.items() if isinstance(item, dict) and item.get("state") in {"not_used", "unavailable"}]
    return {"status": rule["status"], "reason_codes": rule["reason_codes"], "unknowns": unknowns,
            "policy_rule_id": rule["rule_id"], "canonical_input_summary": {"open_verified_blockers": len(blockers), "owner_decision_present": owner_decision}}
def _html(name:str,value:dict)->bytes:
    meta=html.escape(canonical_json(value["artifact_dependency_vector"]),quote=True);body=html.escape(json.dumps(value,ensure_ascii=False,indent=2));return ("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"artifact-dependency-vector\" content=\""+meta+"\"><style>body{font-family:system-ui;margin:2rem}pre{white-space:pre-wrap}</style></head><body><h1>"+html.escape(name)+"</h1><pre>"+body+"</pre></body></html>").encode()


def _verify_html_vector(raw: bytes, vector: dict) -> None:
    """HTML is an escaped, local rendering; its metadata must match JSON."""
    try:
        rendered = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("management_html_utf8_invalid") from exc
    prefix = '<meta name="artifact-dependency-vector" content="'
    if not rendered.startswith("<!doctype html>") or "<script" in rendered.lower() or "<iframe" in rendered.lower() or "http://" in rendered.lower() or "https://" in rendered.lower() or prefix not in rendered:
        raise ValueError("management_html_resource_policy_invalid")
    encoded = rendered.split(prefix, 1)[1].split('">', 1)[0]
    try:
        parsed = json.loads(html.unescape(encoded))
    except json.JSONDecodeError as exc:
        raise ValueError("management_html_vector_invalid") from exc
    if canonical_json(parsed) != canonical_json(vector):
        raise ValueError("management_html_dependency_vector_mismatch")

@observed_boundary
def compile(ctx:LocalExecutionContext)->dict:
    vector=dependency_vector(ctx); loaded=vector.pop("_loaded");policy=_policy(ctx,vector,loaded["contest"]);generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="management_generation")
    base={"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector}
    def report(name: str, **extra: object) -> dict:
        contracts = _section_contracts(name)
        return {**base, "sections": _sections(name), "section_contracts": contracts, "section_records": _section_records(name, contracts, ctx=ctx, loaded=loaded, vector=vector), **extra}
    artifacts={
      "executive-release-brief":report("executive-release-brief",recommendation=policy,verified_blockers=[i for i in ctx.release.get("findings",[]) if i.get("blocker")],unknowns=policy["unknowns"]),
      "product-release-review":report("product-release-review",matrix=[{"requirement_id": item.get("requirement_id"), "criterion_ids": sorted({criterion.get("criterion_id") for criterion in loaded.get("upstream", {"intent_artifacts": {}})["intent_artifacts"].get("acceptance-criteria.json", {}).get("criteria", []) if criterion.get("requirement_id")==item.get("requirement_id")})} for item in loaded.get("upstream", {"intent_artifacts": {}})["intent_artifacts"].get("requirements.json", {}).get("requirements", [])]),
      "engineering-release-assessment":report("engineering-release-assessment",repository=ctx.release.get("repository",{})),
      "measurement-ai-readiness":report("measurement-ai-readiness",authority_note="Canonical Measurement & AI authority is not recalculated by reporting.",canonical_artifacts=loaded["measurement"] or {}),
      "remediation-overview":report("remediation-overview",remediation_dependency=vector["remediation"],canonical_artifacts=loaded["remediation"] or {}),
      "release-packet-index":report("release-packet-index",artifacts=list(JSON_ARTIFACTS)),
      "release-recommendation-view":{**base,"sections":["computed_recommendation","canonical_finding_state","owner_decision_state","accepted_conditions","unknowns","source_generations"],"section_contracts":[{"section_id":s,"source_dependencies":["product_intent","graph"],"required_when":"always","record_source":"canonical_dependency_vector","minimum_records":1,"typed_empty_state":"not_used_or_unavailable","authority_passthrough":True} for s in ["computed_recommendation","canonical_finding_state","owner_decision_state","accepted_conditions","unknowns","source_generations"]],"computed_recommendation":policy,"canonical_finding_state":ctx.release.get("findings",[]),"owner_decision_state":ctx.release.get("owner_decisions",[]),"contestation":loaded["contest"] or {}}}
    for name,value in artifacts.items():
        write_bytes(ctx.repository_root,directory/(name+".json"),_json(value),label="management_json")
        if name!="release-recommendation-view":write_bytes(ctx.repository_root,directory/(name+".html"),_html(name,value),label="management_html")
    github_contracts = _section_contracts("github-summary-payload")
    github={**base,"sections":_sections("github-summary-payload"),"section_contracts":github_contracts,
            "section_records":_section_records("github-summary-payload", github_contracts, ctx=ctx, loaded=loaded, vector=vector),
            "recommendation":policy,"local_references":[name+".json" for name in JSON_ARTIFACTS]}
    markdown_sections = "\n".join("- " + section["section_id"].replace("_", " ") + ": " + section["state"] for section in github["section_records"])
    write_bytes(ctx.repository_root,directory/"github-summary-payload.json",_json(github),label="github_payload");write_bytes(ctx.repository_root,directory/"github-summary.md",("# Shiproom release summary\n\nRecommendation: `"+policy["status"]+"`\n\n"+markdown_sections+"\n").encode(),label="github_markdown")
    hashes={path.name:_hash(read_bytes(ctx.repository_root,path,label="management_generated_artifact",max_bytes=2*1024*1024)) for path in checked_children(ctx.repository_root,directory,label="management_generation") if path.is_file()};manifest={"schema_version":"management-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector,"artifact_hashes":hashes,"semantic_bundle_hash":content_hash(artifacts),"bundle_hash":""};manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="management_manifest");replace_bytes(ctx.repository_root,root(ctx)/"current-management-generation.json",_json({"schema_version":"current-management-generation.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="management_pointer");return manifest

@observed_boundary
def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=read_json(ctx.repository_root,root(ctx)/"current-management-generation.json",label="management_pointer");validate_canonical_contract("management_current_pointer",pointer);directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="management_generation");manifest=read_json(ctx.repository_root,directory/"manifest.json",label="management_manifest")
    validate_canonical_contract("management_generation_manifest", manifest)
    validate_generation_manifest(manifest)
    if manifest["compiler_version"]!=COMPILER_VERSION or manifest["release_id"]!=ctx.release["release_id"]:raise ValueError("stale_dependency")
    if pointer.get("manifest_hash") != _hash(_json(manifest)) or pointer.get("semantic_bundle_hash") != manifest.get("semantic_bundle_hash"):
        raise ValueError("management_pointer_tampered")
    artifacts={name:read_json(ctx.repository_root,directory/(name+".json"),label="management_artifact") for name in JSON_ARTIFACTS};github=read_json(ctx.repository_root,directory/"github-summary-payload.json",label="github_payload")
    report_contracts={
      "executive-release-brief":"management_executive_release_brief",
      "product-release-review":"management_product_release_review",
      "engineering-release-assessment":"management_engineering_release_assessment",
      "measurement-ai-readiness":"management_measurement_ai_readiness",
      "remediation-overview":"management_remediation_overview",
      "release-packet-index":"management_release_packet_index",
      "release-recommendation-view":"management_release_recommendation_view",
    }
    for name,value in artifacts.items(): validate_canonical_contract(report_contracts[name], value)
    validate_canonical_contract("management_github_payload", github)
    vectors=[canonical_json(v["artifact_dependency_vector"]) for v in artifacts.values()]+[canonical_json(github["artifact_dependency_vector"])]
    if len(set(vectors))!=1 or vectors[0]!=canonical_json(manifest["artifact_dependency_vector"]):raise ValueError("artifact_dependency_vector_mismatch")
    expected = {name + ".json" for name in JSON_ARTIFACTS} | {name + ".html" for name in JSON_ARTIFACTS if name != "release-recommendation-view"} | {"github-summary-payload.json", "github-summary.md", "manifest.json"}
    actual = {path.name for path in checked_children(ctx.repository_root, directory, label="management_generation")}
    if actual != expected: raise ValueError("management_generation_file_set_mismatch")
    for name, digest in manifest["artifact_hashes"].items():
        if _hash(read_bytes(ctx.repository_root, directory / name, label="management_artifact_hash", max_bytes=2*1024*1024)) != digest:
            raise ValueError("management_artifact_tampered")
    for name in JSON_ARTIFACTS:
        if name == "release-recommendation-view":
            continue
        _verify_html_vector(read_bytes(ctx.repository_root, directory / (name + ".html"), label="management_html", max_bytes=2 * 1024 * 1024), manifest["artifact_dependency_vector"])
    current = dependency_vector(ctx); current_loaded=current.pop("_loaded")
    if canonical_json(current) != canonical_json(manifest["artifact_dependency_vector"]):
        raise ValueError("stale_dependency")
    for name in JSON_ARTIFACTS:
        if name == "release-recommendation-view":
            continue
        contracts=_section_contracts(name)
        expected_records=_section_records(name,contracts,ctx=ctx,loaded=current_loaded,vector=current)
        if canonical_json(artifacts[name].get("section_records")) != canonical_json(expected_records):
            raise ValueError("management_canonical_projection_tampered")
    if canonical_json(artifacts["measurement-ai-readiness"].get("canonical_artifacts")) != canonical_json(current_loaded["measurement"] or {}):
        raise ValueError("management_measurement_ai_passthrough_tampered")
    if canonical_json(artifacts["remediation-overview"].get("canonical_artifacts")) != canonical_json(current_loaded["remediation"] or {}):
        raise ValueError("management_remediation_passthrough_tampered")
    if canonical_json(artifacts["release-recommendation-view"].get("computed_recommendation")) != canonical_json(_policy(ctx,current,current_loaded["contest"])):
        raise ValueError("management_recommendation_view_tampered")
    github_contracts=_section_contracts("github-summary-payload")
    expected_github_records=_section_records("github-summary-payload",github_contracts,ctx=ctx,loaded=current_loaded,vector=current)
    if canonical_json(github.get("section_records")) != canonical_json(expected_github_records):
        raise ValueError("management_github_projection_tampered")
    return manifest,artifacts
