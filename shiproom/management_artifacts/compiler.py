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
from shiproom.workflow_trust import checked_children, ensure_directory, read_bytes, read_json, replace_bytes, safe_entry, write_bytes

COMPILER_VERSION="portable-management-artifacts.v1"
JSON_ARTIFACTS=("executive-release-brief","product-release-review","engineering-release-assessment","measurement-ai-readiness","remediation-overview","release-packet-index","release-recommendation-view")

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
        manifest, artifacts=loader(ctx)
        return _dep("required_present",manifest.get("generation"),manifest["semantic_bundle_hash"]), artifacts
    assessment_state, assessment=optional("assessment/current-assessment.json",load_assessment)
    measurement_state, measurement=optional("measurement-ai-readiness/current-generation.json",load_measurement_ai)
    remediation_state, remediation=optional("remediation/current-remediation-generation.json",load_remediation)
    review_state, review=optional("review-organisation/current-review-plan.json",load_review_plan)
    contest_state, contest=optional("contestability/current-contestation-generation.json",load_contestation)
    return {"schema_version":"artifact-dependency-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",upstream["graph_generation"],upstream["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",upstream["graph_generation"],upstream["graph_manifest"]["semantic_bundle_hash"]),"assessment":assessment_state,"measurement_ai":measurement_state,"remediation":remediation_state,"review_plan":review_state,"contestability":contest_state,"_loaded":{"assessment":assessment,"measurement":measurement,"remediation":remediation,"review":review,"contest":contest}}

def _section_specs(name: str) -> list[dict]:
    value = json.loads(resources.files("shiproom.management_artifacts").joinpath("management-artifact-section-registry.v1.json").read_text())
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


def _sections(name: str) -> list[str]:
    return [item["section_id"] for item in _section_specs(name)]


def _section_contracts(name: str) -> list[dict]:
    """Return the packaged exact sections; artifacts may not invent their own."""
    return _section_specs(name)
def _recommendation_policy() -> dict:
    value = json.loads(resources.files("shiproom.management_artifacts").joinpath("release-recommendation-policy.v1.json").read_text())
    required = {"schema_version", "statuses", "required_inputs", "rules", "unknown_dependency_states", "rule"}
    if set(value) != required or value["schema_version"] != "release-recommendation-policy.v1":
        raise ValueError("release_recommendation_policy_invalid")
    expected = {"rule_id", "precedence", "when", "status", "reason_codes"}
    if (not isinstance(value["rules"], list) or not value["rules"] or
            any(set(rule) != expected or rule["status"] not in value["statuses"] or not isinstance(rule["reason_codes"], list) or not rule["reason_codes"] for rule in value["rules"]) or
            [rule["precedence"] for rule in value["rules"]] != sorted(rule["precedence"] for rule in value["rules"])):
        raise ValueError("release_recommendation_policy_invalid")
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

def compile(ctx:LocalExecutionContext)->dict:
    vector=dependency_vector(ctx); loaded=vector.pop("_loaded");policy=_policy(ctx,vector,loaded["contest"]);generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="management_generation")
    base={"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector}
    artifacts={
      "executive-release-brief":{**base,"sections":_sections("executive-release-brief"),"section_contracts":_section_contracts("executive-release-brief"),"recommendation":policy,"verified_blockers":[i for i in ctx.release.get("findings",[]) if i.get("blocker")],"unknowns":policy["unknowns"]},
      "product-release-review":{**base,"sections":_sections("product-release-review"),"section_contracts":_section_contracts("product-release-review"),"matrix":[]},
      "engineering-release-assessment":{**base,"sections":_sections("engineering-release-assessment"),"section_contracts":_section_contracts("engineering-release-assessment"),"repository":ctx.release.get("repository",{})},
      "measurement-ai-readiness":{**base,"sections":_sections("measurement-ai-readiness"),"section_contracts":_section_contracts("measurement-ai-readiness"),"authority_note":"Canonical Measurement & AI authority is not recalculated by reporting.","canonical_artifacts":loaded["measurement"] or {}},
      "remediation-overview":{**base,"sections":_sections("remediation-overview"),"section_contracts":_section_contracts("remediation-overview"),"remediation_dependency":vector["remediation"],"canonical_artifacts":loaded["remediation"] or {}},
      "release-packet-index":{**base,"sections":_sections("release-packet-index"),"section_contracts":_section_contracts("release-packet-index"),"artifacts":list(JSON_ARTIFACTS)},
      "release-recommendation-view":{**base,"sections":["computed_recommendation","canonical_finding_state","owner_decision_state","accepted_conditions","unknowns","source_generations"],"section_contracts":[{"section_id":s,"source_dependencies":["product_intent","graph"],"required_when":"always","record_source":"canonical_dependency_vector","minimum_records":1,"typed_empty_state":"not_used_or_unavailable","authority_passthrough":True} for s in ["computed_recommendation","canonical_finding_state","owner_decision_state","accepted_conditions","unknowns","source_generations"]],"computed_recommendation":policy,"canonical_finding_state":ctx.release.get("findings",[]),"owner_decision_state":ctx.release.get("owner_decisions",[]),"contestation":loaded["contest"] or {}}}
    for name,value in artifacts.items():
        write_bytes(ctx.repository_root,directory/(name+".json"),_json(value),label="management_json")
        if name!="release-recommendation-view":write_bytes(ctx.repository_root,directory/(name+".html"),_html(name,value),label="management_html")
    github={**base,"sections":_sections("github-summary-payload"),"recommendation":policy,"local_references":[name+".json" for name in JSON_ARTIFACTS]}
    write_bytes(ctx.repository_root,directory/"github-summary-payload.json",_json(github),label="github_payload");write_bytes(ctx.repository_root,directory/"github-summary.md",("# Shiproom release summary\n\nRecommendation: `"+policy["status"]+"`\n").encode(),label="github_markdown")
    hashes={path.name:_hash(read_bytes(ctx.repository_root,path,label="management_generated_artifact",max_bytes=2*1024*1024)) for path in checked_children(ctx.repository_root,directory,label="management_generation") if path.is_file()};manifest={"schema_version":"management-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector,"artifact_hashes":hashes,"semantic_bundle_hash":content_hash(artifacts),"bundle_hash":""};manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="management_manifest");replace_bytes(ctx.repository_root,root(ctx)/"current-management-generation.json",_json({"schema_version":"current-management-generation.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="management_pointer");return manifest

def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=read_json(ctx.repository_root,root(ctx)/"current-management-generation.json",label="management_pointer");directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="management_generation");manifest=read_json(ctx.repository_root,directory/"manifest.json",label="management_manifest")
    if manifest["compiler_version"]!=COMPILER_VERSION or manifest["release_id"]!=ctx.release["release_id"]:raise ValueError("stale_dependency")
    if pointer.get("manifest_hash") != _hash(_json(manifest)) or pointer.get("semantic_bundle_hash") != manifest.get("semantic_bundle_hash"):
        raise ValueError("management_pointer_tampered")
    artifacts={name:read_json(ctx.repository_root,directory/(name+".json"),label="management_artifact") for name in JSON_ARTIFACTS};github=read_json(ctx.repository_root,directory/"github-summary-payload.json",label="github_payload");vectors=[canonical_json(v["artifact_dependency_vector"]) for v in artifacts.values()]+[canonical_json(github["artifact_dependency_vector"])]
    if len(set(vectors))!=1 or vectors[0]!=canonical_json(manifest["artifact_dependency_vector"]):raise ValueError("artifact_dependency_vector_mismatch")
    expected = {name + ".json" for name in JSON_ARTIFACTS} | {name + ".html" for name in JSON_ARTIFACTS if name != "release-recommendation-view"} | {"github-summary-payload.json", "github-summary.md", "manifest.json"}
    actual = {path.name for path in checked_children(ctx.repository_root, directory, label="management_generation")}
    if actual != expected: raise ValueError("management_generation_file_set_mismatch")
    for name, digest in manifest["artifact_hashes"].items():
        if _hash(read_bytes(ctx.repository_root, directory / name, label="management_artifact_hash", max_bytes=2*1024*1024)) != digest:
            raise ValueError("management_artifact_tampered")
    current = dependency_vector(ctx); current.pop("_loaded")
    if canonical_json(current) != canonical_json(manifest["artifact_dependency_vector"]):
        raise ValueError("stale_dependency")
    return manifest,artifacts
