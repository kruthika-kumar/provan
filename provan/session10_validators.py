from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from .errors import ProvanError

HEX = re.compile(r"sha256:[0-9a-f]{64}$")


def _digest(value: Any) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_change_brief_serialized(raw: bytes) -> None:
    value = json.loads(raw)
    if value.get("schema_id") != "provan.change_brief.v1":
        raise ProvanError("CHANGE_BRIEF_SCHEMA_ID_INVALID", "wrong contract")
    candidate = value.get("candidate", {})
    mode=candidate.get("mode");base=candidate.get("base");head=candidate.get("head");working_digest=candidate.get("working_tree_digest")
    if mode=="immutable" and (not re.fullmatch(r"[0-9a-f]{40}",str(base or "")) or not re.fullmatch(r"[0-9a-f]{40}",str(head or "")) or working_digest is not None):
        raise ProvanError("PINNED_COMMIT_REQUIRED","immutable candidates require exact full base and head commits")
    if mode=="mutable" and (not re.fullmatch(r"[0-9a-f]{40}",str(base or "")) or head is not None or not HEX.fullmatch(str(working_digest or ""))):
        raise ProvanError("MUTABLE_CANDIDATE_BINDING_INVALID","mutable candidates require committed HEAD plus a working-tree digest")
    recomputed = _digest({k: candidate.get(k) for k in ("repository_identity", "mode", "base", "head", "working_tree_digest")})
    if candidate.get("candidate_digest") != recomputed:
        raise ProvanError("CHANGE_BRIEF_CANDIDATE_DIGEST_MISMATCH", "candidate digest was not independently recomputed")
    classes = {"agent_reported", "source_attributed_product_intent", "source_established", "model_reviewed_implications", "unresolved"}
    if set(value.get("claims", {})) != classes:
        raise ProvanError("CHANGE_BRIEF_CLAIM_CLASS_CONFLATION", "claim authority classes are incomplete")
    if value.get("acceptance_seed", {}).get("status") != "proposed":
        raise ProvanError("ACCEPTANCE_SEED_NOT_PROPOSED", "seed cannot be confirmed")
    if candidate.get("mode") == "mutable" and value.get("acceptance_seed", {}).get("acceptance_eligible") is not False:
        raise ProvanError("MUTABLE_BRIEF_NOT_PROMOTABLE", "mutable candidate cannot be Acceptance-eligible")
    case_id=value.get("case_id");binding=value.get("case_binding",{});claims=value.get("claims",{});request=value.get("context_request",{});usage=value.get("model_usage",{});promotion=value.get("promotion_decision",{})
    context_binding={"file_digests":request.get("file_digests"),"aliases":request.get("aliases"),"journey_digests":request.get("journey_digests")}
    intent=claims.get("source_attributed_product_intent",[]);agent=claims.get("agent_reported",[])
    model_expected={"mode":"NO_MODEL" if usage.get("mode")=="NO_MODEL" else "DETERMINISTIC_FALLBACK" if usage.get("calls")==0 else "CONFIGURED","provider":usage.get("provider"),"model":usage.get("model"),"provider_version":binding.get("model",{}).get("provider_version"),"prompt_id":usage.get("prompt_id") or "change-brief-synthesis","prompt_version":usage.get("prompt_version") or "1","instructions_digest":binding.get("model",{}).get("instructions_digest")}
    provenance=value.get("case_provenance",{});pr_provenance=provenance.get("pr");previous_provenance=provenance.get("previous");comparison=value.get("previous_comparison",{})
    if pr_provenance is None:
        if binding.get("pr") is not None:raise ProvanError("CHANGE_BRIEF_PR_BINDING_INVALID","PR binding lacks canonical provenance")
    else:
        pr_core={key:pr_provenance.get(key) for key in ("repository_identity","number","base","head")}
        if pr_provenance.get("metadata_digest")!=_digest(pr_core) or pr_core.get("repository_identity")!=candidate.get("repository_identity") or pr_core.get("base")!=candidate.get("base") or pr_core.get("head")!=candidate.get("head") or binding.get("pr")!=pr_core.get("number"):
            raise ProvanError("CHANGE_BRIEF_PR_BINDING_INVALID","PR provenance does not recompute from the serialized candidate")
    if previous_provenance is None:
        if binding.get("previous") is not None or comparison.get("status")!="NOT_SUPPLIED":raise ProvanError("CHANGE_BRIEF_PREVIOUS_BINDING_INVALID","previous-Brief binding lacks canonical provenance")
    else:
        previous_core={key:value for key,value in previous_provenance.items() if key!="binding_digest"}
        manifest=previous_core.get("manifest");closure=previous_core.get("artifact_closure")
        if not isinstance(manifest,dict) or not isinstance(closure,dict) or previous_core.get("manifest_digest")!=_digest(manifest):
            raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","previous-Brief manifest does not independently resolve")
        prior_briefs=[]
        if previous_core.get("kind")=="canonical_id":
            refs=manifest.get("artifacts",{})
            if manifest.get("schema_id")!="provan.change_brief_manifest.v1" or set(refs)!=set(closure):raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","canonical previous manifest closure is incomplete")
            for name,expected in refs.items():
                text=closure.get(name)
                if not isinstance(text,str) or _digest_bytes(text.encode())!=expected:raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","canonical previous artifact digest does not resolve")
                artifact=json.loads(text)
                if artifact.get("schema_id")=="provan.change_brief.v1":prior_briefs.append(artifact)
        elif previous_core.get("kind")=="manifest_export":
            refs=manifest.get("artifacts",[])
            if manifest.get("schema_id")!="provan.change_brief_export_manifest.v1" or {row.get("path") for row in refs}!=set(closure):raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","export previous manifest closure is incomplete")
            for ref in refs:
                text=closure.get(ref.get("path"))
                if not isinstance(text,str) or len(text.encode())!=ref.get("size") or _digest_bytes(text.encode())!=ref.get("sha256"):raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","export previous artifact digest does not resolve")
                artifact=json.loads(text)
                if ref.get("role")=="change_brief" and artifact.get("schema_id")=="provan.change_brief.v1":prior_briefs.append(artifact)
        else:raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","previous-Brief provenance kind is unsupported")
        if len(prior_briefs)!=1:raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","previous-Brief closure does not contain exactly one canonical Brief")
        prior=prior_briefs[0];validate_change_brief_serialized(canonical_semantic(prior))
        if prior.get("brief_id")!=previous_core.get("brief_id") or prior.get("candidate",{}).get("candidate_digest")!=previous_core.get("candidate_digest"):
            raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_UNRESOLVED","previous-Brief identity does not resolve from the closure")
        prior_candidate=prior.get("candidate",{});previous_ref=prior_candidate.get("head") or prior_candidate.get("base");current_ref=candidate.get("head") or candidate.get("base")
        if previous_core.get("kind")=="manifest_export" and (manifest.get("repository_identity")!=prior_candidate.get("repository_identity") or manifest.get("previous_head")!=previous_ref):
            raise ProvanError("CHANGE_BRIEF_PREVIOUS_PROVENANCE_MISMATCH","export manifest identity or head does not bind the enclosed Brief")
        if previous_core.get("repository_identity")!=prior_candidate.get("repository_identity") or previous_core.get("repository_identity")!=candidate.get("repository_identity") or previous_core.get("previous_head")!=previous_ref or previous_core.get("current_head")!=current_ref or previous_core.get("lineage_status")!="ANCESTOR":
            raise ProvanError("CHANGE_BRIEF_PREVIOUS_LINEAGE_UNRESOLVED","serialized lineage binding does not match the previous and current candidates")
        if previous_provenance.get("binding_digest")!=_digest(previous_core) or binding.get("previous")!=previous_core or comparison.get("status")!="COMPARABLE" or comparison.get("previous_brief_id")!=previous_core.get("brief_id"):
            raise ProvanError("CHANGE_BRIEF_PREVIOUS_BINDING_INVALID","previous-Brief provenance does not bind the serialized comparison")
    if case_id!=_digest(binding) or binding.get("candidate")!=candidate.get("candidate_digest") or binding.get("brief")!=_digest_text(intent[0] if intent else "") or binding.get("agent")!=_digest_text(agent[0] if agent else "") or binding.get("context_request")!=_digest(context_binding) or binding.get("policy")!={"id":promotion.get("policy_id"),"version":promotion.get("policy_version")} or binding.get("model")!=model_expected:
        raise ProvanError("CHANGE_BRIEF_CASE_DERIVATION_INVALID","case identity does not independently recompute from serialized inputs")
    analysis=value.get("analysis_evidence",[])
    expected_claims,allowed_entities,allowed_relationships=_recompute_analysis_authority(analysis)
    if claims.get("source_established",[])!=expected_claims:
        raise ProvanError("SOURCE_FACT_EVIDENCE_MISMATCH","source-established claims do not independently recompute from serialized analysis evidence")
    entities=value.get("entities",[]);relationships=value.get("relationships",[])
    for entity in entities:validate_affected_entity_serialized(canonical_semantic(entity),allowed_entities)
    entity_ids={entity.get("entity_id") for entity in entities}
    for relationship in relationships:validate_affected_relationship_serialized(canonical_semantic(relationship),entity_ids,allowed_relationships)
    bundle=value.get("context_bundle",{});validate_context_bundle_serialized(canonical_semantic(bundle))
    validate_context_request_serialized(canonical_semantic(value.get("context_request",{})),value.get("context_bundle",{}))
    validate_promotion_serialized(canonical_semantic(promotion),case_id,claims.get("source_established",[]),analysis)
    if bundle.get("case_id")!=case_id or value.get("context_request",{}).get("case_id")!=case_id:raise ProvanError("CHANGE_BRIEF_CASE_BINDING_INVALID","context artifacts do not bind the Brief case")
    validate_acceptance_seed_serialized(canonical_semantic(value.get("acceptance_seed",{})),candidate,case_id,promotion,entity_ids,bundle)
    validate_model_usage_serialized(canonical_semantic(value.get("model_usage",{})),value.get("model_input_envelope_digest"))


def canonical_semantic(value: Any) -> bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def _digest_text(value: str) -> str:
    return "sha256:"+hashlib.sha256(value.encode()).hexdigest()


def _recompute_analysis_authority(rows: list[dict[str,Any]]) -> tuple[list[dict[str,Any]],dict[tuple[str,str],set[str]],set[tuple[str,str,str,str]]]:
    added_digests={row.get("static_details",{}).get("content_digest") for row in rows if row.get("status")=="A" and row.get("static_details",{}).get("content_digest")}
    claims=[];entities:dict[tuple[str,str],set[str]]={};relationships=set()
    for row in rows:
        path=row.get("path");status=row.get("status");classes=row.get("surface_classes");current=row.get("static_details");old=row.get("baseline_static_details")
        if not isinstance(path,str) or not path or Path(path).is_absolute() or ".." in Path(path).parts or status not in {"A","M","D","R","C","T","U","?"} or not isinstance(classes,list) or not isinstance(current,dict) or not isinstance(old,dict):
            raise ProvanError("ANALYSIS_EVIDENCE_INVALID","serialized analysis evidence is incomplete or unsafe")
        expected=[]
        public_delta=(old.get("exports")!=current.get("exports") and bool(old.get("exports") or current.get("exports"))) or old.get("routes")!=current.get("routes") or old.get("schema_contract")!=current.get("schema_contract")
        manifest_delta=Path(path).name.lower() in {"pyproject.toml","package.json"} and (old.get("dependencies")!=current.get("dependencies") or old.get("symbols")!=current.get("symbols"))
        if public_delta or manifest_delta:expected.append("PUBLIC_CONTRACT_CHANGED")
        old_digest=old.get("content_digest")
        if status=="D" and "test_or_fixture" in classes and old_digest and old_digest not in added_digests:expected.append("VERIFICATION_SURFACE_WEAKENED")
        if sorted(set(row.get("verified_triggers",[])))!=sorted(expected):
            raise ProvanError("ANALYSIS_TRIGGER_DERIVATION_INVALID","serialized trigger does not recompute from structural evidence")
        core={"changed_file":path,"status":status,"verified_triggers":sorted(expected)};claims.append({**core,"fact_digest":_digest(core)})
        entities.setdefault(("file",path),set()).add(path)
        targets=[("symbol",name,"declares") for name in current.get("symbols",[])]+[("module",name,"imports") for name in current.get("imports",[])]+[("dependency",name,"declares_dependency") for name in current.get("dependencies",[])]+[("route",item.get("method","")+" "+item.get("path",""),"declares_route") for item in current.get("routes",[]) if isinstance(item,dict)]
        file_id=_digest({"kind":"file","scope":path})
        for kind,scope,relation in targets[:256]:
            if not scope:continue
            entities.setdefault((kind,scope),set()).add(path);target_id=_digest({"kind":kind,"scope":scope});relationships.add((file_id,target_id,relation,path))
    return claims,entities,relationships


def validate_affected_entity_serialized(raw: bytes, allowed_entities: dict[tuple[str,str],set[str]] | None = None) -> None:
    value=json.loads(raw);expected=_digest({"kind":value.get("kind"),"scope":value.get("scope")});key=(value.get("kind"),value.get("scope"));refs=set(value.get("evidence_refs",[]))
    grounded=allowed_entities is not None and key in allowed_entities and bool(refs) and refs.issubset(allowed_entities[key])
    if value.get("entity_id")!=expected or value.get("authority") not in {"source_established","unresolved"} or not grounded:
        raise ProvanError("AFFECTED_ENTITY_PROVENANCE_INVALID","entity identity or evidence authority is invalid")


def validate_affected_relationship_serialized(raw: bytes, entity_ids: set[str], allowed_relationships: set[tuple[str,str,str,str]] | None = None) -> None:
    value=json.loads(raw);source=value.get("source_entity_id");target=value.get("target_entity_id");expected=_digest({"source":source,"target":target,"relation":value.get("relation")})
    refs=value.get("evidence_refs",[]);grounded=allowed_relationships is not None and bool(refs) and all((source,target,value.get("relation"),ref) in allowed_relationships for ref in refs)
    if value.get("relationship_id")!=expected or source not in entity_ids or target not in entity_ids or value.get("authority") not in {"source_established","unresolved"} or not grounded:
        raise ProvanError("AFFECTED_RELATIONSHIP_PROVENANCE_INVALID","relationship endpoint, identity, or authority is invalid")


def validate_context_request_serialized(raw: bytes, bundle: dict[str,Any]) -> None:
    value=json.loads(raw)
    expected_files=[row.get("content_digest") for row in bundle.get("records",[])]
    expected_journeys=[_digest(row) for row in bundle.get("journeys",[])]
    expected_aliases=[row.get("proposal") for row in bundle.get("aliases",[])]
    if value.get("case_id")!=bundle.get("case_id") or value.get("file_digests")!=expected_files or value.get("journey_digests")!=expected_journeys or value.get("aliases")!=expected_aliases:
        raise ProvanError("CONTEXT_REQUEST_BINDING_INVALID","context request does not recompute from its bundle")


def validate_context_record_serialized(raw: bytes, expected_case_id: str | None = None) -> None:
    row=json.loads(raw)
    forbidden = {"owner_confirmed", "approved_policy", "runtime_verified", "execution_verified"}
    if row.get("authority") in forbidden:
        raise ProvanError("CONTEXT_AUTHORITY_CEILING_EXCEEDED", "case-local files cannot self-confer authority")
    if row.get("schema_id")!="provan.context_record.v1" or row.get("source_type")!="case_local_file" or row.get("lifecycle")!="ephemeral" or row.get("scope")!="case" or not row.get("source_reference") or not row.get("citation"):
        raise ProvanError("CONTEXT_RECORD_SEMANTICS_INVALID","context record is incomplete or unsupported")
    if expected_case_id is not None and row.get("case_id")!=expected_case_id:
        raise ProvanError("CONTEXT_CASE_BINDING_INVALID","context record crosses the case boundary")
    if not HEX.fullmatch(row.get("content_digest", "")):
        raise ProvanError("CONTEXT_PROVENANCE_INVALID", "context digest missing")


def validate_context_bundle_serialized(raw: bytes) -> None:
    value = json.loads(raw); case = value.get("case_id")
    if value.get("schema_id")!="provan.case_context_bundle.v1" or not case:
        raise ProvanError("CONTEXT_CASE_BINDING_INVALID", "context bundle lacks one case identity")
    for row in value.get("records",[]):validate_context_record_serialized(canonical_semantic(row),case)
    if any(row.get("authority")!="case_local_identity_proposal" or not row.get("proposal") for row in value.get("aliases",[])) or any(row.get("authority")!="source_attributed_proposal" or not row.get("text") for row in value.get("journeys",[])):
        raise ProvanError("CONTEXT_AUTHORITY_CEILING_EXCEEDED","aliases and journeys must remain bounded proposals")


def validate_promotion_serialized(raw: bytes, expected_case_id: str | None = None, source_claims: list[dict[str,Any]] | None = None, analysis_evidence: list[dict[str,Any]] | None = None) -> None:
    value = json.loads(raw)
    supported = {"PUBLIC_CONTRACT_CHANGED", "VERIFICATION_SURFACE_WEAKENED", "EXTERNAL_BOUNDARY_ADDED", "AUTH_PERMISSION_SURFACE", "PAYMENT_SURFACE", "PRIVACY_SURFACE", "DESTRUCTIVE_SURFACE", "MIGRATION_SURFACE", "SHARED_SERVICE_IMPACT", "PRODUCT_INTENT_AMBIGUOUS"}
    applied = value.get("applied_triggers", [])
    if any(row.get("reason") not in supported or row.get("authority") not in {"source_verified", "configuration_verified"} or not HEX.fullmatch(row.get("source_fact_digest","")) for row in applied):
        raise ProvanError("PROMOTION_TRIGGER_AUTHORITY_INVALID", "trigger lacks deterministic supported authority")
    if source_claims is not None:
        if analysis_evidence is None:raise ProvanError("PROMOTION_SOURCE_AUTHORITY_UNRESOLVED","promotion facts require serialized structural analysis evidence")
        grounded_claims,_,_=_recompute_analysis_authority(analysis_evidence)
        if source_claims!=grounded_claims:raise ProvanError("SOURCE_FACT_EVIDENCE_MISMATCH","promotion facts do not recompute from structural analysis evidence")
        expected=[]
        for claim in source_claims:
            core={"changed_file":claim.get("changed_file"),"status":claim.get("status"),"verified_triggers":sorted(set(claim.get("verified_triggers",[])))};fact=_digest(core)
            if claim.get("fact_digest")!=fact:raise ProvanError("SOURCE_FACT_DIGEST_INVALID","source-established claim digest is invalid")
            for reason in core["verified_triggers"]:
                if reason not in supported:raise ProvanError("PROMOTION_TRIGGER_AUTHORITY_INVALID","source fact contains unsupported trigger")
                expected.append({"reason":reason,"authority":"configuration_verified" if reason=="VERIFICATION_SURFACE_WEAKENED" else "source_verified","evidence_ref":core["changed_file"],"source_fact_digest":fact})
        normalize=lambda rows:sorted(rows,key=lambda row:(row.get("reason",""),row.get("evidence_ref","")))
        if normalize(applied)!=normalize(expected):raise ProvanError("PROMOTION_TRIGGER_EVIDENCE_MISMATCH","promotion triggers do not derive from canonical source facts")
    if any(row.get("authority")!="unresolved_proposal" or row.get("reason") in supported for row in value.get("unresolved_proposals",[])):
        raise ProvanError("PROMOTION_UNRESOLVED_PROPOSAL_INVALID","unsupported proposals must remain explicitly unresolved")
    expected = "acceptance_recommended" if applied else "explain_only"
    if value.get("schema_id")!="provan.promotion_decision.v1" or value.get("policy_id")!="community.default.v1" or not value.get("policy_version") or (expected_case_id is not None and value.get("case_id")!=expected_case_id) or value.get("decision") != expected or value.get("decision") == "acceptance_required_by_policy":
        raise ProvanError("PROMOTION_DECISION_INVALID", "decision does not follow pure policy")


def validate_acceptance_seed_serialized(raw: bytes,candidate: dict[str,Any],case_id: str,promotion: dict[str,Any],entity_ids: set[str],bundle: dict[str,Any] | None = None) -> None:
    value=json.loads(raw)
    context_ok=bundle is None or value.get("context_digest")==_digest(bundle)
    if value.get("status")!="proposed" or value.get("case_id")!=case_id or value.get("candidate_digest")!=candidate.get("candidate_digest") or value.get("policy_id")!=promotion.get("policy_id") or value.get("policy_version")!=promotion.get("policy_version") or value.get("decision")!=promotion.get("decision") or value.get("trigger_refs")!=promotion.get("applied_triggers") or not context_ok or not set(value.get("evidence_refs",[])).issubset(entity_ids):
        raise ProvanError("ACCEPTANCE_SEED_PROVENANCE_INVALID","proposed Seed does not preserve candidate, policy, and evidence bindings")
    if value.get("acceptance_eligible")!=(candidate.get("mode")=="immutable"):
        raise ProvanError("ACCEPTANCE_SEED_ELIGIBILITY_INVALID","Seed eligibility does not follow candidate mode")


def validate_model_usage_serialized(raw: bytes,envelope_digest: str|None) -> None:
    value=json.loads(raw);calls=value.get("calls");latency=value.get("latency_ms");source=value.get("latency_source")
    if calls==0:
        if any(value.get(field) is not None for field in ("provider","model","prompt_id","prompt_version","envelope_digest","latency_ms")) or envelope_digest is not None or source!="not-applicable":raise ProvanError("MODEL_ZERO_CALL_RECEIPT_INVALID","zero-call receipt contains execution binding")
    elif calls==1:
        if not all(value.get(field) for field in ("provider","model","prompt_id","prompt_version")) or not HEX.fullmatch(value.get("envelope_digest","")) or value.get("envelope_digest")!=envelope_digest:raise ProvanError("MODEL_USAGE_BINDING_INVALID","executed model receipt lacks exact envelope binding")
        if latency is None:
            if source!="unavailable" or value.get("cost_status")!="unavailable":raise ProvanError("MODEL_USAGE_LATENCY_INVALID","unavailable execution latency lacks honest provenance")
        elif not isinstance(latency,(int,float)) or isinstance(latency,bool) or not math.isfinite(latency) or not 0<=latency<=3_600_000 or source!="provan_monotonic_elapsed":
            raise ProvanError("MODEL_USAGE_LATENCY_INVALID","execution latency is not a bounded Provan monotonic measurement")
    else:raise ProvanError("MODEL_CALL_COUNT_INVALID","at most one model call is permitted")


def validate_topology_serialized(raw: bytes,entities: list[dict[str,Any]],relationships: list[dict[str,Any]]) -> None:
    value=json.loads(raw);expected=len(entities)>=8 or len(relationships)>=6
    if value.get("rendered")!=expected or not value.get("text_fallback") or (expected and (value.get("nodes")!=entities or value.get("edges")!=relationships)) or (not expected and (value.get("nodes") or value.get("edges"))):
        raise ProvanError("CHANGE_TOPOLOGY_DERIVATION_INVALID","topology does not follow canonical complexity and edge authority")


def validate_provider_result_serialized(raw: bytes,bundle: dict[str,Any]) -> None:
    value=json.loads(raw)
    if value.get("provider_id")!="CaseLocalContextProvider" or value.get("case_id")!=bundle.get("case_id") or value.get("records")!=bundle.get("records") or value.get("canonical_proof") is not False:
        raise ProvanError("CONTEXT_PROVIDER_RESULT_AUTHORITY_INVALID","provider result exceeds or diverges from its case bundle")


def validate_manifest_serialized(raw: bytes,artifacts: dict[str,bytes]) -> None:
    value=json.loads(raw);declared=value.get("artifacts",{})
    if set(declared)!=set(artifacts) or any(declared[name]!="sha256:"+hashlib.sha256(content).hexdigest() for name,content in artifacts.items()):
        raise ProvanError("CHANGE_BRIEF_MANIFEST_DIGEST_MISMATCH","manifest does not resolve every canonical artifact")


def validate_public_render_text(text: str) -> None:
    normalized=re.sub(r"[^a-z0-9]+","_",text.lower())
    forbidden=("future_challenge_input","challenge_seed","selector_weight","private_oracle","private_eval","grading_answer","challenge_sibling")
    if any(token in normalized for token in forbidden):
        raise ProvanError("PUBLIC_PROJECTION_CHALLENGE_MATERIAL_FORBIDDEN","public rendering contains challenge or private-evaluation material")
    private_reference=re.compile(
        r"(?:(?<![A-Za-z0-9])[A-Za-z]:[\\/]|/(?:home|Users|var|etc|tmp)/|\\\\[?.]\\|"
        r"https?://[^/\s:@]+:[^/\s@]+@|Authorization\s*:|"
        r"BEGIN [A-Z ]*PRIVATE KEY|\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*\S+|"
        r"\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b|provan-(?:evals|enterprise))",
        re.I,
    )
    if private_reference.search(text):
        raise ProvanError("PUBLIC_PROJECTION_PRIVATE_REFERENCE","public rendering contains a private path, credential, or private reference")


def validate_public_projection_serialized(raw: bytes) -> None:
    value=json.loads(raw);text=json.dumps(value,sort_keys=True)
    user_home="/"+"home/"
    if value.get("sensitivity")!="PUBLIC_SAFE" or value.get("summary","").lower().find("sanitised")<0 or user_home in text or re.search(r"(?:[A-Za-z]:\\\\Users\\\\|Authorization:|BEGIN [A-Z ]*PRIVATE KEY)",text,re.I):
        raise ProvanError("PUBLIC_PROJECTION_SENSITIVITY_INVALID","public projection is not deterministically sanitised")
    validate_public_render_text(text)


def validate_dogfood_ledger_serialized(raw: bytes, expected_changed_paths: set[str], expected_binding: dict[str,Any], brief_raw: bytes, projection_raw: bytes) -> None:
    value=json.loads(raw);changed=value.get("changed_paths",[]);replay=value.get("replay",{})
    if value.get("schema_id")!="provan.session10_consequential_range_dogfood_ledger.v1" or value.get("sensitivity")!="PUBLIC_SAFE":
        raise ProvanError("SESSION10_DOGFOOD_LEDGER_INVALID","dogfood ledger identity is invalid")
    if len(changed)!=len(set(changed)) or set(changed)!=expected_changed_paths:
        raise ProvanError("SESSION10_DOGFOOD_RANGE_INCOMPLETE","dogfood ledger does not cover the exact consequential implementation range")
    if value.get("implementation_commit")!=expected_binding.get("implementation_commit") or value.get("implementation_tree")!=expected_binding.get("implementation_tree"):
        raise ProvanError("SESSION10_DOGFOOD_BINDING_INVALID","dogfood ledger is not bound to the implementation")
    if value.get("consequential_range")!=value.get("baseline_commit")+".."+value.get("implementation_commit"):
        raise ProvanError("SESSION10_DOGFOOD_RANGE_INVALID","dogfood range does not resolve from its endpoints")
    brief=json.loads(brief_raw);candidate=brief.get("candidate",{});projection=json.loads(projection_raw)
    candidate_core={key:candidate.get(key) for key in ("repository_identity","mode","base","head","working_tree_digest")}
    if brief.get("schema_id")!="provan.change_brief.v1" or candidate.get("mode")!="immutable" or candidate.get("base")!=value.get("baseline_commit") or candidate.get("head")!=value.get("implementation_commit") or candidate.get("candidate_digest")!=_digest(candidate_core):
        raise ProvanError("SESSION10_DOGFOOD_CANDIDATE_INVALID","dogfood Brief candidate does not resolve the consequential range")
    brief_changed=[row.get("changed_file") for row in brief.get("claims",{}).get("source_established",[])]
    if len(brief_changed)!=len(set(brief_changed)) or set(brief_changed)!=expected_changed_paths:
        raise ProvanError("SESSION10_DOGFOOD_BRIEF_RANGE_MISMATCH","dogfood Brief does not establish the exact changed-path inventory")
    if replay.get("case")!="SESSION10_SELF_DOGFOOD" or replay.get("brief_id")!=brief.get("brief_id") or replay.get("candidate_digest")!=candidate.get("candidate_digest") or replay.get("brief_digest")!=_digest_bytes(brief_raw) or replay.get("public_projection_sha256")!=_digest_bytes(projection_raw) or projection.get("brief_id")!=brief.get("brief_id"):
        raise ProvanError("SESSION10_DOGFOOD_ARTIFACT_BINDING_INVALID","dogfood replay does not resolve its Brief and public projection")
    if replay.get("status")!="PASS" or replay.get("production_changed_after_run") is not False:
        raise ProvanError("SESSION10_DOGFOOD_REPLAY_INVALID","dogfood replay is incomplete or stale")


def validate_model_envelope_serialized(raw: bytes, expected_binding: dict[str, Any] | None = None) -> None:
    value = json.loads(raw)
    required = {"schema_id","envelope_id","case_id","instructions","selected_blocks","candidate_digest","provider","model","provider_version","prompt_id","prompt_version","limits","permitted_output_classes"}
    uuid4=r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    limits=value.get("limits",{});strings=("provider","model","provider_version","prompt_id","prompt_version","instructions")
    if not required.issubset(value) or value.get("schema_id")!="provan.model_input_envelope.v1" or not re.fullmatch(uuid4,str(value.get("envelope_id",""))) or not HEX.fullmatch(str(value.get("case_id",""))) or not HEX.fullmatch(str(value.get("candidate_digest",""))) or any(not isinstance(value.get(field),str) or not value.get(field) for field in strings) or set(limits)!={"max_input_bytes","max_output_tokens"} or not isinstance(limits.get("max_input_bytes"),int) or not 1<=limits["max_input_bytes"]<=1048576 or not isinstance(limits.get("max_output_tokens"),int) or not 1<=limits["max_output_tokens"]<=8192 or value.get("permitted_output_classes")!=["model_reviewed_implications","unresolved"]:
        raise ProvanError("MODEL_ENVELOPE_INCOMPLETE", "semantic payload is not fully bound")
    blocks=value.get("selected_blocks",[]);categories=[]
    if not isinstance(blocks,list) or len(blocks)>64:raise ProvanError("MODEL_ENVELOPE_INCOMPLETE","selected model blocks exceed the semantic bound")
    for block in blocks:
        if set(block)!={"category","content","sha256"} or not isinstance(block.get("category"),str) or not block.get("category") or not isinstance(block.get("content"),str):raise ProvanError("MODEL_ENVELOPE_INCOMPLETE","selected model block is not canonical")
        categories.append(block["category"])
        digest = "sha256:" + hashlib.sha256(str(block.get("content", "")).encode()).hexdigest()
        if block.get("sha256") != digest:
            raise ProvanError("MODEL_ENVELOPE_BLOCK_DIGEST_MISMATCH", "selected block digest mismatch")
    if len(categories)!=len(set(categories)) or len(raw)>limits["max_input_bytes"]:raise ProvanError("MODEL_ENVELOPE_INCOMPLETE","model block identities or byte limit are invalid")
    if expected_binding is not None and any(value.get(field)!=expected for field,expected in expected_binding.items()):
        raise ProvanError("MODEL_ENVELOPE_CROSS_BINDING_INVALID","model envelope diverges from the canonical case/provider/prompt binding")


def validate_session_handoff_serialized(raw: bytes, artifacts: dict[str, bytes]) -> None:
    value = json.loads(raw)
    required = {"candidate", "brief", "analysis_evidence", "entities", "relationships", "context_bundle", "promotion_decision", "acceptance_seed", "addressing_rules", "projection_rules", "limitations", "session11_prerequisites", "layer4_matrix", "proof_root", "reviewer_receipt", "implementation_binding"}
    if not required.issubset(value):
        raise ProvanError("SESSION11_HANDOFF_INCOMPLETE", "semantic handoff dependency missing")
    for name, reference in value.get("artifact_references", {}).items():
        if name not in artifacts or not HEX.fullmatch(reference.get("sha256", "")) or "sha256:" + hashlib.sha256(artifacts[name]).hexdigest() != reference["sha256"]:
            raise ProvanError("SESSION11_HANDOFF_UNRESOLVABLE", "handoff artifact cannot be resolved by digest")
    candidate=value.get("candidate",{});candidate_core={key:candidate.get(key) for key in ("repository_identity","mode","base","head","working_tree_digest")}
    if candidate.get("candidate_digest")!=_digest(candidate_core):raise ProvanError("SESSION11_HANDOFF_CANDIDATE_MISMATCH","handoff candidate digest does not resolve")
    analysis=value.get("analysis_evidence",[]);grounded_claims,allowed_entities,allowed_relationships=_recompute_analysis_authority(analysis)
    if value.get("source_established_claims",[])!=grounded_claims:raise ProvanError("SOURCE_FACT_EVIDENCE_MISMATCH","handoff source claims do not recompute")
    entities=value.get("entities",[]);entity_ids={row.get("entity_id") for row in entities}
    for entity in entities:validate_affected_entity_serialized(canonical_semantic(entity),allowed_entities)
    for relationship in value.get("relationships",[]):validate_affected_relationship_serialized(canonical_semantic(relationship),entity_ids,allowed_relationships)
    bundle=value.get("context_bundle",{});validate_context_bundle_serialized(canonical_semantic(bundle));case_id=bundle.get("case_id")
    promotion=value.get("promotion_decision",{});validate_promotion_serialized(canonical_semantic(promotion),case_id,value.get("source_established_claims",[]),analysis)
    validate_acceptance_seed_serialized(canonical_semantic(value.get("acceptance_seed",{})),candidate,case_id,promotion,entity_ids,bundle)
    validate_implementation_binding_serialized(canonical_semantic(value.get("implementation_binding",{})))
    refs=value.get("artifact_references",{});component=[{"name":name,"sha256":row["sha256"]} for name,row in sorted(refs.items())]
    review_state=value.get("reviewer_receipt",{}).get("state")
    if review_state=="PENDING_EXTERNAL_NON_RECURSIVE":root_ok=value.get("proof_root")==_digest(component)
    elif review_state=="BOUND_REVIEWED_PRE_ROOT":
        pre=json.loads(artifacts.get("pre_review_manifest",b"{}"));root_ok=value.get("proof_root")==pre.get("proof_root") and bool(value.get("reviewer_receipt",{}).get("receipts"))
        for receipt in value.get("reviewer_receipt",{}).get("receipts",[]):
            name=Path(receipt.get("path","")).stem.split(".")[0]
            if name not in artifacts or receipt.get("sha256")!="sha256:"+hashlib.sha256(artifacts[name]).hexdigest():root_ok=False
    else:root_ok=False
    if not root_ok or value.get("layer4_matrix")!=refs.get("layer4_matrix") or value.get("brief",{}).get("public_projection")!=refs.get("public_projection"):
        raise ProvanError("SESSION11_HANDOFF_PROOF_BINDING_MISMATCH","handoff proof or projection reference does not resolve")
    projection=json.loads(artifacts["public_projection"]);real_use=json.loads(artifacts["real_use"]);binding=json.loads(artifacts["implementation_binding"]);matrix=json.loads(artifacts["layer4_matrix"]);registry=json.loads(artifacts["proof_registry"]);canonical_brief=json.loads(artifacts["canonical_brief"]);schema_registry=json.loads(artifacts["schema_registry"])
    validate_public_projection_serialized(artifacts["public_projection"])
    if projection.get("candidate_digest")!=candidate.get("candidate_digest") or projection.get("brief_id")!=value.get("brief",{}).get("brief_id") or canonical_brief.get("brief_id")!=value.get("brief",{}).get("brief_id") or canonical_brief.get("candidate")!=candidate or real_use.get("brief_digest")!=value.get("brief",{}).get("sha256") or real_use.get("implementation_binding")!=binding or value.get("implementation_binding")!=binding:
        raise ProvanError("SESSION11_HANDOFF_CROSS_ARTIFACT_MISMATCH","handoff artifacts disagree")
    expected_ids={f"G10-{index:02d}" for index in range(1,72)};matrix_ids={row.get("Claim","").split(" ",1)[0] for row in matrix.get("claims",[])};registry_ids={entry.get("proof_id") for entry in registry.get("entries",[])}
    matrix_proofs={row.get(field) for row in matrix.get("claims",[]) for field in ("Positive proof","Near-valid proof","Negative proof")}
    if matrix.get("schema_id")!="provan.session10_layer4_matrix.v1" or matrix_ids!=expected_ids or registry.get("schema_id")!="provan.session10_proof_registry.v1" or registry.get("implementation_commit")!=binding.get("implementation_commit") or registry.get("implementation_tree")!=binding.get("implementation_tree") or not matrix_proofs.issubset(registry_ids):
        raise ProvanError("SESSION11_HANDOFF_PROOF_SET_INCOMPLETE","handoff claim or proof set is incomplete")
    if value.get("schema_registry",{}).get("registry_digest")!=schema_registry.get("registry_digest") or schema_registry.get("registry_digest")!=binding.get("schema_registry_digest") or value.get("wheel",{}).get("sha256")!=binding.get("wheel_sha256") or "sha256:"+hashlib.sha256(artifacts["authoritative_wheel"]).hexdigest()!=binding.get("wheel_sha256"):
        raise ProvanError("SESSION11_HANDOFF_IMPLEMENTATION_ARTIFACT_MISMATCH","wheel or schema registry does not resolve")
    provider=value.get("provider_binding",{})
    if provider.get("status")=="NOT_APPLICABLE" and (not provider.get("reason") or not provider.get("authority")):raise ProvanError("SESSION11_HANDOFF_PROVIDER_BINDING_INVALID","provider N/A lacks typed authority")
    if len(value.get("session11_prerequisites",[]))<5 or set(value.get("projection_rules",{}))!={"internal","public","client_safe"}:raise ProvanError("SESSION11_HANDOFF_INCOMPLETE","handoff prerequisites or projections are incomplete")


def validate_cache_fragment_serialized(raw: bytes, key_inputs: dict[str, Any], expected_analysis: dict[str,Any]) -> None:
    value = json.loads(raw)
    if value.get("schema_id") != "provan.repository_analysis_cache_fragment.v1" or value.get("case_id") is not None or value.get("cache_key") != _digest(key_inputs) or value.get("key_inputs") != key_inputs or value.get("analysis_digest")!=_digest(value.get("analysis")) or value.get("analysis")!=expected_analysis:
        raise ProvanError("CACHE_FRAGMENT_BINDING_INVALID", "cache fragment is not case-neutral or input-complete")


def validate_reviewer_receipt_serialized(raw: bytes, expected_claim_ids: set[str]) -> None:
    value=json.loads(raw);rows=value.get("claim_dispositions",[]);ids=[row.get("claim_id") for row in rows]
    if len(ids)!=len(set(ids)) or set(ids)!=expected_claim_ids:raise ProvanError("REVIEWER_CLAIM_DISPOSITIONS_INCOMPLETE","reviewer dispositions are not unique and complete")
    counts={severity:sum(row.get("severity")==severity for row in value.get("findings",[])) for severity in ("P0","P1","P2")}
    if any(value.get(f"open_{severity.lower()}_count")!=count for severity,count in counts.items()):raise ProvanError("REVIEWER_FINDING_COUNT_MISMATCH","reviewer finding counts do not recompute")
    expected="GO" if counts["P0"]==counts["P1"]==counts["P2"]==0 and all(row.get("disposition")=="ACCEPTED" for row in rows) else "NO_GO"
    if value.get("verdict")!=expected:raise ProvanError("REVIEWER_VERDICT_INVALID","reviewer verdict does not follow findings and dispositions")


def validate_acceptance_preparation_serialized(raw: bytes) -> None:
    value = json.loads(raw)
    if value.get("status") != "preparation_only" or value.get("confirmed") is not False or value.get("executed") is not False or value.get("verdict") is not None:
        raise ProvanError("ACCEPTANCE_PREPARATION_AUTHORITY_EXCEEDED", "preparation cannot become a contract, execution, or verdict")
    if not value.get("candidate_digest") or not value.get("policy_id") or not value.get("policy_version"):
        raise ProvanError("ACCEPTANCE_PREPARATION_PROVENANCE_MISSING", "candidate and policy bindings are required")


def validate_error_serialized(raw: bytes) -> None:
    value = json.loads(raw)
    if not re.fullmatch(r"[A-Z0-9_]+", value.get("error", "")):
        raise ProvanError("ERROR_CODE_INVALID", "typed error code required")
    message = value.get("message", "")
    absolute_home = "/" + "home/"
    if re.search(r"(?:[A-Za-z]:\\\\Users\\\\|Authorization:|TOKEN=|BEGIN [A-Z ]*PRIVATE KEY)", message, re.I) or absolute_home in message:
        raise ProvanError("ERROR_MESSAGE_SENSITIVE", "error message is not public-safe")


def validate_previous_export_manifest_serialized(raw: bytes) -> None:
    value = json.loads(raw)
    seen: set[str] = set(); total = 0
    role_schemas={"change_brief":"provan.change_brief.v1","context_bundle":"provan.case_context_bundle.v1","context_request":"provan.context_request.v1","context_provider_result":"provan.context_provider_result.v1","promotion_decision":"provan.promotion_decision.v1","acceptance_seed":"provan.acceptance_seed.v1","change_topology":"provan.change_topology.v1","model_usage_receipt":"provan.model_usage_receipt.v1","model_input_envelope":"provan.model_input_envelope.v1","public_projection":"provan.change_brief_public_projection.v1"}
    for row in value.get("artifacts", []):
        path = row.get("path", ""); pure = Path(path)
        if pure.is_absolute() or ".." in pure.parts or path in seen or "\\" in path or pure.suffix.lower()!=".json":
            raise ProvanError("PREVIOUS_BRIEF_EXPORT_PATH_UNSAFE", "artifact path is not unique, relative, and contained")
        if role_schemas.get(row.get("role"))!=row.get("schema_id") or row.get("sensitivity") not in ({"PUBLIC_SAFE"} if row.get("role")=="public_projection" else {"LOCAL_NON_PUBLIC"}):
            raise ProvanError("PREVIOUS_BRIEF_EXPORT_AUTHORITY_INVALID","artifact role, schema, and sensitivity are not canonically bound")
        seen.add(path); total += row.get("size", 0)
        if total > 32 * 1024 * 1024:
            raise ProvanError("PREVIOUS_BRIEF_EXPORT_TOO_LARGE", "export aggregate exceeds bound")
    if not seen:
        raise ProvanError("PREVIOUS_BRIEF_EXPORT_EMPTY", "manifest must resolve artifacts")


def validate_implementation_binding_serialized(raw: bytes) -> None:
    value = json.loads(raw)
    if value.get("package_version") != "0.3.0" or value.get("maturity") != "QUALIFIED_BOUNDED" or value.get("published") is not False or value.get("implementation_commit")==value.get("implementation_tree"):
        raise ProvanError("SESSION10_MATURITY_BINDING_INVALID", "Session 10 is unpublished and bounded")
    for field in ("wheel_sha256", "schema_registry_digest"):
        candidate = value.get(field, "")
        if not HEX.fullmatch(candidate) or candidate == "sha256:" + "0" * 64:
            raise ProvanError("SESSION10_IMPLEMENTATION_DIGEST_INVALID", "implementation binding digest invalid")


def validate_authentic_comparator_serialized(raw: bytes) -> None:
    comparator=json.loads(raw);pr=comparator.get("pr",{});review=comparator.get("review",{});core={"case":comparator.get("case"),"pr":pr,"review":review}
    if comparator.get("schema_id")!="provan.session10_authentic_comparator.v1" or comparator.get("sensitivity")!="PUBLIC_SAFE":raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","comparator identity is invalid")
    if pr.get("title_sha256")!=_digest_bytes(str(pr.get("title","")).encode()) or pr.get("body_sha256")!=_digest_bytes(str(pr.get("body","")).encode()) or review.get("body_sha256")!=_digest_bytes(str(review.get("body","")).encode()):raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","comparator component digests do not resolve")
    if comparator.get("aggregate_digest")!=_digest(core):raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","comparator aggregate digest does not resolve")
    if not re.fullmatch(r"https://github[.]com/[^/]+/[^/]+/pull/[0-9]+",str(pr.get("url",""))) or not re.fullmatch(r"https://github[.]com/[^/]+/[^/]+/pull/[0-9]+#pullrequestreview-[0-9]+",str(review.get("url",""))) or review.get("state") not in {"APPROVED","CHANGES_REQUESTED","COMMENTED"}:
        raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","comparator public source identity is not resolvable")


def validate_real_use_serialized(raw: bytes, predeclared_cases: set[str], comparator_raw: bytes | None = None, brief_raw: bytes | None = None, expected_binding: dict[str,Any] | None = None) -> None:
    value = json.loads(raw)
    if value.get("case") not in predeclared_cases or value.get("predeclared") is not True:
        raise ProvanError("REAL_USE_COMPARATOR_NOT_PREDECLARED", "real-use case was not predeclared")
    binding = value.get("implementation_binding", {})
    brief_digest = value.get("brief_digest", "")
    if value.get("production_changed_after_run") is not False or not HEX.fullmatch(brief_digest) or brief_digest == "sha256:" + "0" * 64 or not binding.get("implementation_commit"):
        raise ProvanError("REAL_USE_FINAL_TREE_BINDING_INVALID", "real-use evidence is not bound to the final implementation")
    if expected_binding is not None and binding != expected_binding:
        raise ProvanError("REAL_USE_FINAL_TREE_BINDING_INVALID","real-use implementation binding does not match the qualified artifact")
    if brief_raw is not None and brief_digest != _digest_bytes(brief_raw):
        raise ProvanError("REAL_USE_FINAL_TREE_BINDING_INVALID","real-use Brief digest does not resolve")
    if comparator_raw is not None:
        validate_authentic_comparator_serialized(comparator_raw);comparator=json.loads(comparator_raw);review=comparator.get("review",{})
        if comparator.get("case")!=value.get("case"):raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","comparator case does not bind the real-use receipt")
        ref=value.get("comparator",{})
        if ref.get("digest")!=comparator.get("aggregate_digest") or ref.get("artifact_sha256")!=_digest_bytes(comparator_raw) or ref.get("review_id")!=review.get("id") or ref.get("review_url")!=review.get("url"):
            raise ProvanError("REAL_USE_COMPARATOR_UNRESOLVED","real-use evidence does not bind the canonical comparator")


def _validate_local_reference(reference: dict[str, Any], artifacts: dict[str, bytes]) -> None:
    path=str(reference.get("path", ""));pure=Path(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path or path not in artifacts:
        raise ProvanError("SESSION10_FINAL_REFERENCE_UNRESOLVED", "final reference is not a contained canonical artifact")
    if reference.get("sha256") != _digest_bytes(artifacts[path]):
        raise ProvanError("SESSION10_FINAL_REFERENCE_DIGEST_MISMATCH", "final reference digest does not resolve")


def validate_handoff_finalization_serialized(raw: bytes, artifacts: dict[str, bytes], expected_pre_root: str) -> None:
    value=json.loads(raw)
    if value.get("state")!="BOUND_REVIEWED_PRE_ROOT" or value.get("reviewed_handoff_unchanged") is not True or value.get("reviewed_pre_review_root")!=expected_pre_root:
        raise ProvanError("SESSION10_HANDOFF_FINALIZATION_BINDING_INVALID","handoff finalization does not bind the reviewed pre-root")
    expected_paths={"artifacts/session10/session11_handoff.v1.public.json","artifacts/session10/layer4_claim_matrix.final.v1.public.json","artifacts/session10/proofs/reviewer_receipt_a.v1.public.json","artifacts/session10/proofs/reviewer_receipt_b.v1.public.json"}
    references=[value.get("reviewed_handoff",{}),value.get("final_layer4_matrix",{}),*value.get("reviewer_receipts",[])]
    if {item.get("path") for item in references}!=expected_paths or len(references)!=4:
        raise ProvanError("SESSION10_HANDOFF_FINALIZATION_REFERENCE_SET_INVALID","handoff finalization reference set is incomplete")
    for reference in references:_validate_local_reference(reference,artifacts)
    matrix=json.loads(artifacts["artifacts/session10/layer4_claim_matrix.final.v1.public.json"])
    if not matrix.get("claims") or any(row.get("Reviewer result")!="ACCEPTED" or row.get("Status")!="CLOSED" for row in matrix["claims"]):
        raise ProvanError("SESSION10_FINAL_LAYER4_INCOMPLETE","final Layer 4 matrix is not individually closed")


def validate_session10_proof_manifest_serialized(raw: bytes, artifacts: dict[str, bytes], expected_commit: str, expected_tree: str, expected_pre_root: str) -> None:
    value=json.loads(raw);entries=value.get("entries",[])
    if value.get("implementation_commit")!=expected_commit or value.get("implementation_tree")!=expected_tree or value.get("reviewed_pre_review_root")!=expected_pre_root:
        raise ProvanError("SESSION10_FINAL_PROOF_BINDING_INVALID","final proof manifest implementation or reviewed-root binding changed")
    expected=[{"path":path,"sha256":_digest_bytes(content)} for path,content in sorted(artifacts.items())]
    if entries!=expected or len({row.get("path") for row in entries})!=len(entries):
        raise ProvanError("SESSION10_FINAL_PROOF_INVENTORY_INVALID","final proof manifest is not the exact canonical artifact inventory")
    if value.get("proof_root")!=_digest(entries):
        raise ProvanError("SESSION10_FINAL_PROOF_ROOT_MISMATCH","final proof root does not independently recompute")


def validate_session10_closeout_serialized(raw: bytes, expected_binding: dict[str, Any], expected_pre_root: str, proof_manifest_raw: bytes, reviewer_artifacts: dict[str, bytes]) -> None:
    value=json.loads(raw);manifest=json.loads(proof_manifest_raw)
    if value.get("status")!="CLOSED" or value.get("implementation_binding")!=expected_binding or value.get("reviewed_pre_review_root")!=expected_pre_root or value.get("final_proof_root")!=manifest.get("proof_root"):
        raise ProvanError("SESSION10_CLOSEOUT_BINDING_INVALID","closeout does not bind the qualified implementation and proof roots")
    if any(value.get(name) is not False for name in ("session11_implemented","release_created","tag_created","package_published","production_changed_after_review")):
        raise ProvanError("SESSION10_CLOSEOUT_BOUNDARY_EXCEEDED","closeout exceeds the Session 10 publication boundary")
    receipts=value.get("reviewer_receipts",[])
    expected_paths={"artifacts/session10/proofs/reviewer_receipt_a.v1.public.json","artifacts/session10/proofs/reviewer_receipt_b.v1.public.json"}
    if len(receipts)!=2 or {row.get("path") for row in receipts}!=expected_paths:
        raise ProvanError("SESSION10_CLOSEOUT_REVIEW_BINDING_INVALID","closeout reviewer reference set is incomplete")
    for reference in receipts:_validate_local_reference(reference,reviewer_artifacts)


def validate_runtime_invariant_evidence_serialized(raw: bytes) -> None:
    value=json.loads(raw);transcript=value.get("transcript","");tests=value.get("production_test_ids",[])
    if value.get("exit_code")!=0 or value.get("transcript_sha256")!=_digest_bytes(transcript.encode("utf-8")):
        raise ProvanError("RUNTIME_INVARIANT_EVIDENCE_INVALID","runtime transcript result or digest does not recompute")
    if not tests or any(test_id not in value.get("command","") and test_id not in transcript for test_id in tests):
        raise ProvanError("RUNTIME_INVARIANT_EVIDENCE_INVALID","runtime evidence does not bind its production checks")
    if "FAILED" in transcript or "ERROR" in transcript or not any(marker in transcript for marker in ("PASSED","_PASS","_VALID","_OK","passed")):
        raise ProvanError("RUNTIME_INVARIANT_EVIDENCE_INVALID","runtime transcript does not establish successful execution")
    expected_scenario={"valid":"supported_success","near-valid":"bounded_limitation","adversarial":"prohibited_or_invalid_input_rejected","schema-valid-python-invalid":"supported_success"}.get(value.get("fixture_class"))
    if value.get("scenario")!=expected_scenario or (value.get("fixture_class")=="near-valid") != bool(value.get("limitations")):
        raise ProvanError("RUNTIME_INVARIANT_SCENARIO_INVALID","runtime fixture class, scenario, and limitation do not agree")
    if value.get("fixture_class")=="near-valid":
        match=re.search(rf"NEAR_VALID_OBSERVED:{re.escape(str(value.get('invariant')))}:([A-Z0-9_]+)",transcript)
        if not match or value.get("limitations")!=[match.group(1)]:
            raise ProvanError("RUNTIME_NEAR_VALID_OBSERVATION_UNRESOLVED","near-valid bounded condition is not independently present in the transcript")
    expected_error=value.get("expected_error");observed_error=value.get("observed_error");operation=value.get("adversarial_operation")
    if value.get("fixture_class")=="adversarial":
        marker=f"ADVERSARIAL_REJECTION_OBSERVED:{value.get('invariant')}:{expected_error}"
        marker_ok=marker in transcript
        if not operation or not expected_error or observed_error!=expected_error or not marker_ok:
            raise ProvanError("RUNTIME_ADVERSARIAL_REJECTION_UNRESOLVED","adversarial operation and observed rejection are not independently present in the transcript")
    elif any(item is not None for item in (operation,expected_error,observed_error)):
        raise ProvanError("RUNTIME_INVARIANT_SCENARIO_INVALID","non-adversarial evidence cannot declare an adversarial rejection")
    for artifact in value.get("artifact_evidence",[]):
        if artifact.get("sha256")!=_digest_bytes(artifact.get("content","").encode("utf-8")):
            raise ProvanError("RUNTIME_INVARIANT_ARTIFACT_DIGEST_MISMATCH","bound runtime artifact digest does not recompute")
