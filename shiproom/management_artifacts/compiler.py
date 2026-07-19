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
from shiproom.workflow_trust import ensure_directory, replace_bytes, safe_entry, write_bytes

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
        if not (release_root/pointer).exists(): return _dep("not_used"), None
        manifest, artifacts=loader(ctx)
        return _dep("required_present",manifest.get("generation"),manifest["semantic_bundle_hash"]), artifacts
    assessment_state, assessment=optional("assessment/current-assessment.json",load_assessment)
    measurement_state, measurement=optional("measurement-ai-readiness/current-generation.json",load_measurement_ai)
    remediation_state, remediation=optional("remediation/current-remediation-generation.json",load_remediation)
    review_state, review=optional("review-organisation/current-review-plan.json",load_review_plan)
    contest_state, contest=optional("contestability/current-contestation-generation.json",load_contestation)
    return {"schema_version":"artifact-dependency-vector.v1","release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"product_intent":_dep("required_present",upstream["graph_generation"],upstream["intent_manifest"]["semantic_bundle_hash"]),"graph":_dep("required_present",upstream["graph_generation"],upstream["graph_manifest"]["semantic_bundle_hash"]),"assessment":assessment_state,"measurement_ai":measurement_state,"remediation":remediation_state,"review_plan":review_state,"contestability":contest_state,"_loaded":{"assessment":assessment,"measurement":measurement,"remediation":remediation,"review":review,"contest":contest}}

def _sections(name:str)->list[str]:return json.loads(resources.files("shiproom.management_artifacts").joinpath("management-artifact-section-registry.v1.json").read_text())["artifacts"][name]
def _policy(ctx:LocalExecutionContext,vector:dict)->dict:
    blockers=[item for item in ctx.release.get("findings",[]) if item.get("blocker") and item.get("state")!="CLOSED"]
    return {"status":"do_not_recommend" if blockers else "recommend_with_conditions","reason_codes":["verified_blocker_present"] if blockers else ["no_verified_blocker_in_canonical_release"],"unknowns":[key for key,item in vector.items() if isinstance(item,dict) and item.get("state") in {"not_used","unavailable"}]}
def _html(name:str,value:dict)->bytes:
    meta=html.escape(canonical_json(value["artifact_dependency_vector"]),quote=True);body=html.escape(json.dumps(value,ensure_ascii=False,indent=2));return ("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"artifact-dependency-vector\" content=\""+meta+"\"><style>body{font-family:system-ui;margin:2rem}pre{white-space:pre-wrap}</style></head><body><h1>"+html.escape(name)+"</h1><pre>"+body+"</pre></body></html>").encode()

def compile(ctx:LocalExecutionContext)->dict:
    vector=dependency_vector(ctx); loaded=vector.pop("_loaded");policy=_policy(ctx,vector);generation="gen_"+uuid.uuid4().hex;directory=ensure_directory(ctx.repository_root,root(ctx)/"generations"/generation,label="management_generation")
    base={"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector}
    artifacts={
      "executive-release-brief":{**base,"sections":_sections("executive-release-brief"),"recommendation":policy,"verified_blockers":[i for i in ctx.release.get("findings",[]) if i.get("blocker")],"unknowns":policy["unknowns"]},
      "product-release-review":{**base,"sections":_sections("product-release-review"),"matrix":[]},
      "engineering-release-assessment":{**base,"sections":_sections("engineering-release-assessment"),"repository":ctx.release.get("repository",{})},
      "measurement-ai-readiness":{**base,"sections":_sections("measurement-ai-readiness"),"authority_note":"Canonical Measurement & AI authority is not recalculated by reporting.","canonical_artifacts":loaded["measurement"] or {}},
      "remediation-overview":{**base,"sections":_sections("remediation-overview"),"remediation_dependency":vector["remediation"],"canonical_artifacts":loaded["remediation"] or {}},
      "release-packet-index":{**base,"sections":_sections("release-packet-index"),"artifacts":list(JSON_ARTIFACTS)},
      "release-recommendation-view":{**base,"sections":["computed_recommendation","canonical_finding_state","owner_decision_state","accepted_conditions","unknowns","source_generations"],"computed_recommendation":policy,"canonical_finding_state":ctx.release.get("findings",[]),"owner_decision_state":ctx.release.get("owner_decisions",[]),"contestation":loaded["contest"] or {}}}
    for name,value in artifacts.items():
        write_bytes(ctx.repository_root,directory/(name+".json"),_json(value),label="management_json")
        if name!="release-recommendation-view":write_bytes(ctx.repository_root,directory/(name+".html"),_html(name,value),label="management_html")
    github={**base,"sections":_sections("github-summary-payload"),"recommendation":policy,"local_references":[name+".json" for name in JSON_ARTIFACTS]}
    write_bytes(ctx.repository_root,directory/"github-summary-payload.json",_json(github),label="github_payload");write_bytes(ctx.repository_root,directory/"github-summary.md",("# Shiproom release summary\n\nRecommendation: `"+policy["status"]+"`\n").encode(),label="github_markdown")
    hashes={path.name:_hash(path.read_bytes()) for path in directory.iterdir() if path.is_file()};manifest={"schema_version":"management-generation-manifest.v1","compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"artifact_dependency_vector":vector,"artifact_hashes":hashes,"semantic_bundle_hash":content_hash(artifacts),"bundle_hash":""};manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"})
    write_bytes(ctx.repository_root,directory/"manifest.json",_json(manifest),label="management_manifest");replace_bytes(ctx.repository_root,root(ctx)/"current-management-generation.json",_json({"schema_version":"current-management-generation.v1","generation":generation,"manifest_hash":_hash(_json(manifest)),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}),label="management_pointer");return manifest

def load(ctx:LocalExecutionContext)->tuple[dict,dict]:
    pointer=json.loads((root(ctx)/"current-management-generation.json").read_text());directory=root(ctx)/"generations"/pointer["generation"];safe_entry(directory,directory=True,label="management_generation");manifest=json.loads((directory/"manifest.json").read_text())
    if manifest["compiler_version"]!=COMPILER_VERSION or manifest["release_id"]!=ctx.release["release_id"]:raise ValueError("stale_dependency")
    artifacts={name:json.loads((directory/(name+".json")).read_text()) for name in JSON_ARTIFACTS};github=json.loads((directory/"github-summary-payload.json").read_text());vectors=[canonical_json(v["artifact_dependency_vector"]) for v in artifacts.values()]+[canonical_json(github["artifact_dependency_vector"])]
    if len(set(vectors))!=1 or vectors[0]!=canonical_json(manifest["artifact_dependency_vector"]):raise ValueError("artifact_dependency_vector_mismatch")
    return manifest,artifacts
