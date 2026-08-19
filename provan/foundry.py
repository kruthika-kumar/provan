from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .modeling import (FROZEN_PUBLIC_MODEL_EGRESS, ModelProvider,
                       build_envelope, invoke_frozen_public_openai_responses)
from .safe_input import read_bounded_file
from .state import secure_read, secure_write


PACKAGE_VERSION = "0.5.0"
POLICY_VERSION = "community.contract-foundry.v1"
ROLE_REGISTRY_VERSION = "community.foundry-roles.v1"
ROUTER_VERSION = "community.foundry-router.v1"
PROVIDERS = {
    "openai-responses-primary":{"origin":"https://api.openai.com","tier_1_model":"gpt-5.6-luna","tier_2_3_model":"gpt-5.6-sol","qualified_roles":["semantic_interpreter","strong_reasoner","independent_critic"],"store_requested":False,"retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED"},
    "scripted-test":{"origin":"local-scripted","model":"deterministic-scripted-v1","qualified_roles":[],"store_requested":False,"retention":"not_applicable"},
}
RUN_STAGES = {
    "fast": ["blind_intent", "contract_proposal", "verification_patterns", "readiness"],
    "standard": ["blind_intent", "goal_obstacle", "pre_mortem", "contract_proposal", "adversarial_audit", "revision", "witnesses", "verification_patterns", "readiness"],
    "deep": ["blind_path_a", "blind_path_b", "freeze_blind_paths", "synthesis", "goal_obstacle", "pre_mortem", "adversarial_audit", "witnesses", "mutation_checks", "final_audit", "revisions", "verification_patterns", "readiness"],
}
PATTERN_FAMILIES = (
    "event_response", "state_transition", "invariant_property", "metamorphic_relation", "pairwise_combinatorial",
    "retry_idempotency_concurrency", "timeout_restart_persistence", "dependency_failure", "api_schema_backward_compatibility",
    "permission_privilege_boundary", "browser_journey_recovery", "mobile_lifecycle_future", "migration_rollback",
    "ai_structured_output", "ai_fallback", "ai_prompt_injection", "ai_identity_tool_authority",
    "test_adequacy_contract_mutation", "false_success_durable_state",
)
ROUTING_ENUMS = {
    "risk": {"low", "medium", "high", "unresolved"},
    "ambiguity": {"low", "material", "unresolved"},
    "blast_radius": {"bounded", "public_contract", "shared", "unresolved"},
    "reversibility": {"easy", "bounded", "difficult", "unresolved"},
    "oracle": {"adequate", "missing", "unresolved"},
    "actor_autonomy": {"low", "high", "unresolved"},
}
PATTERN_RESEARCH_REFS = {
    "event_response": "https://www.rfc-editor.org/rfc/rfc9110",
    "state_transition": "https://www.rfc-editor.org/rfc/rfc9110",
    "invariant_property": "https://docs.python.org/3/library/unittest.html",
    "metamorphic_relation": "https://dl.acm.org/doi/10.1145/347324.383796",
    "pairwise_combinatorial": "https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software",
    "retry_idempotency_concurrency": "https://www.rfc-editor.org/rfc/rfc9110",
    "timeout_restart_persistence": "https://www.rfc-editor.org/rfc/rfc9110",
    "dependency_failure": "https://sre.google/sre-book/handling-overload/",
    "api_schema_backward_compatibility": "https://json-schema.org/draft/2020-12/json-schema-core",
    "permission_privilege_boundary": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    "browser_journey_recovery": "https://www.w3.org/TR/webdriver2/",
    "mobile_lifecycle_future": "https://developer.android.com/topic/libraries/architecture/lifecycle",
    "migration_rollback": "https://sre.google/workbook/canarying-releases/",
    "ai_structured_output": "https://platform.openai.com/docs/guides/structured-outputs",
    "ai_fallback": "https://platform.openai.com/docs/guides/production-best-practices",
    "ai_prompt_injection": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "ai_identity_tool_authority": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    "test_adequacy_contract_mutation": "https://mutation-testing.org/",
    "false_success_durable_state": "https://sre.google/sre-book/monitoring-distributed-systems/",
}
PUBLIC_PROMPTS = {
    "blind_intent": "Derive only proposed intent, ambiguity, non-goals, and unresolved questions from the selected intent sources. Do not infer implementation facts or authority.",
    "contract_candidate": "Propose bounded criteria, evidence classes, source-only checks, future capability requirements, limitations, and owner questions. Do not claim acceptance or verification.",
    "adversarial_critic": "Identify ambiguity, over-specification, missing oracles, false-success risks, and unsafe authority promotion. Return proposals only.",
    "synthesis": "Reconcile two frozen independent paths while preserving disagreements and provenance. Do not invent authority or runtime evidence.",
}
OUTPUT_PROTOCOL = "Return exactly one JSON object with keys model_reviewed_implications and unresolved; each value must be a bounded array of strings. Return no other keys or prose."
PUBLIC_PROMPTS["output_protocol"] = OUTPUT_PROTOCOL


def _schema(filename: str, value: dict[str, Any]) -> None:
    path = Path(__file__).with_name("schemas") / filename
    jsonschema.validate(value, json.loads(path.read_text(encoding="utf-8")))


def _load_brief(brief_id: str) -> tuple[dict[str, Any], bytes]:
    if not re.fullmatch(r"[0-9a-f-]{36}", brief_id):
        raise ProvanError("FOUNDRY_BRIEF_ID_INVALID", "Foundry requires a canonical Change Brief ID")
    relative = Path("outputs/change-brief") / brief_id / "change-brief.json"
    try:
        raw = secure_read(relative)
    except FileNotFoundError as exc:
        raise ProvanError("FOUNDRY_BRIEF_NOT_FOUND", brief_id) from exc
    value = json.loads(raw)
    if value.get("schema_id") != "provan.change_brief.v1" or value.get("brief_id") != brief_id or canonical_bytes(value) != raw:
        raise ProvanError("FOUNDRY_BRIEF_INVALID", brief_id)
    return value, raw


def _contained_sources(manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _, manifest = read_bounded_file(manifest_path, limit=1024 * 1024, structured=True)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        raise ProvanError("FOUNDRY_SOURCE_MANIFEST_INVALID", "source manifest requires a sources array")
    if len(manifest["sources"]) > 32:
        raise ProvanError("FOUNDRY_SOURCE_COUNT_EXCEEDED", "at most 32 source files are accepted")
    root = Path(os.path.abspath(manifest_path)).parent
    rows: list[dict[str, Any]] = []
    total = 0
    nodes = 0
    for index, spec in enumerate(manifest["sources"]):
        if not isinstance(spec, dict) or spec.get("role") not in {"intent", "formal_contract", "context"}:
            raise ProvanError("FOUNDRY_SOURCE_ROLE_INVALID", f"source {index} has an unsupported role")
        pure = PurePosixPath(str(spec.get("path", "")).translate({92: 47}))
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise ProvanError("FOUNDRY_SOURCE_PATH_UNSAFE", "source paths must be normalized and manifest-relative")
        candidate = root.joinpath(*pure.parts)
        if root != candidate.parent and root not in candidate.parents:
            raise ProvanError("FOUNDRY_SOURCE_PATH_UNSAFE", "source escaped the manifest root")
        suffix = candidate.suffix.lower()
        if suffix not in {".txt", ".md", ".json", ".yaml", ".yml"}:
            raise ProvanError("FOUNDRY_SOURCE_FORMAT_UNSUPPORTED", "Session 12 accepts only text, Markdown, JSON, and YAML")
        limit = 512 * 1024 if suffix in {".txt", ".md"} else 1024 * 1024
        text, parsed = read_bounded_file(candidate, limit=limit, structured=suffix in {".json", ".yaml", ".yml"})
        raw = text.encode("utf-8"); total += len(raw)
        if total > 8 * 1024 * 1024:
            raise ProvanError("FOUNDRY_SOURCE_AGGREGATE_EXCEEDED", "source aggregate exceeds 8 MiB")
        if parsed is not None:
            stack = [(parsed, 0)]
            while stack:
                item, depth = stack.pop(); nodes += 1
                if depth > 32 or nodes > 50_000:
                    raise ProvanError("FOUNDRY_STRUCTURED_LIMIT_EXCEEDED", "structured source exceeds depth or node limits")
                if isinstance(item, dict): stack.extend((value, depth + 1) for value in item.values())
                elif isinstance(item, list): stack.extend((value, depth + 1) for value in item)
        rows.append({"source_id": f"source-{index + 1}", "role": spec["role"], "media_type": suffix.lstrip("."), "bytes": len(raw), "sha256": sha256_bytes(raw), "content": text})
    if not any(row["role"] == "intent" for row in rows):
        raise ProvanError("FOUNDRY_INTENT_SOURCE_REQUIRED", "at least one intent source is required")
    return manifest, rows


def _require_model_egress_authorization(manifest: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Require an exact operator-confirmed PUBLIC_SAFE digest closure before model egress."""
    authorization = manifest.get("model_egress_authorization")
    selected = [{"source_id": row["source_id"], "sha256": row["sha256"]} for row in sources if row["role"] in {"intent", "formal_contract"}]
    expected = FROZEN_PUBLIC_MODEL_EGRESS.get(authorization.get("case_id")) if isinstance(authorization, dict) else None
    if not isinstance(authorization, dict) or authorization.get("classification") != "PUBLIC_SAFE" or authorization.get("operator_confirmed") is not True or authorization.get("selected_sources") != selected or tuple(row["sha256"] for row in selected) != expected:
        raise ProvanError("FOUNDRY_MODEL_EGRESS_NOT_AUTHORIZED", "model egress requires an exact operator-confirmed PUBLIC_SAFE source digest closure")
    return authorization


def route(risk: dict[str, Any]) -> dict[str, Any]:
    if set(risk) != set(ROUTING_ENUMS) or any(risk.get(key) not in values for key, values in ROUTING_ENUMS.items()):
        raise ProvanError("FOUNDRY_ROUTING_INPUT_INVALID", "routing inputs must use the exact versioned enums")
    if any(value == "unresolved" for value in risk.values()): tier = 3
    elif risk["risk"] == "low" and risk["ambiguity"] == "low" and risk["blast_radius"] == "bounded" and risk["reversibility"] == "easy" and risk["oracle"] == "adequate" and risk["actor_autonomy"] == "low": tier = 0
    elif risk["risk"] == "high" and (risk["ambiguity"] == "material" or risk["oracle"] == "missing" or risk["reversibility"] == "difficult" or risk["actor_autonomy"] == "high" or risk["blast_radius"] == "shared"): tier = 3
    elif risk["risk"] in {"medium", "high"} or risk["ambiguity"] == "material" or risk["oracle"] == "missing" or risk["blast_radius"] in {"public_contract", "shared"}: tier = 2
    else: tier = 1
    return {"schema_id": "provan.model_routing_receipt.v1", "router_id": ROUTER_VERSION, "inputs": risk, "tier": tier, "roles": {0: [], 1: ["semantic_interpreter"], 2: ["strong_reasoner"], 3: ["strong_reasoner", "independent_critic"]}[tier], "authority": "deterministic_inputs_only"}


def pattern_library() -> dict[str, Any]:
    patterns = []
    for family in PATTERN_FAMILIES:
        future = []
        if family.startswith("browser_"): future = ["qualified_browser_verifier"]
        elif family.startswith("mobile_"): future = ["qualified_mobile_verifier"]
        elif family.startswith("ai_"): future = ["qualified_model_test_harness"]
        else: future = ["qualified_read_only_verifier"]
        patterns.append({"pattern_id": f"community.pattern.{family}.v1", "version": 1, "family": family, "applicability": [" ".join(family.split("_"))], "preconditions": ["owner-confirmed criterion", "candidate freeze"], "required_oracle": "typed criterion-specific oracle", "dimensions": ["valid", "near_valid", "adversarial"], "capability_requirements": future, "limitations": ["SESSION12_SELECTION_ONLY", "NO_EXECUTION"], "false_inference_risks": ["selection mistaken for execution", "weak oracle mistaken for evidence"], "cost_class": "future_bounded", "research_refs": [PATTERN_RESEARCH_REFS[family]], "publication": "PUBLIC_SAFE"})
    return {"schema_id": "provan.verification_pattern_library.v1", "library_id": "community.verification-patterns.v1", "version": 1, "patterns": patterns, "execution_available": False, "challenge_available": False}


def _source_outcome(sources: list[dict[str, Any]]) -> str:
    intent = [row["content"].strip() for row in sources if row["role"] == "intent"]
    return intent[0][:4096] if intent else "INTENDED_OUTCOME_UNRESOLVED"


def _proposal(brief: dict[str, Any], sources: list[dict[str, Any]], interpretation: str, model_proposals: list[str]) -> dict[str, Any]:
    source_refs = [row["source_id"] for row in sources if row["role"] == "intent"]
    outcome = _source_outcome(sources)
    criterion = {"criterion_id": "foundry-criterion-1", "statement": f"The case operator confirms the intended outcome and exact closure semantics for: {outcome[:512]}", "class": "mandatory", "material": True, "required_evidence_classes": ["owner_confirmed"], "challenge_requirement": "not_required", "closure_requirement": {"check_mode": "human_confirmation", "required_evidence_class": "owner_confirmed", "check": {"type":"canonical_case_operator_action"}, "subject_refs": source_refs, "limitations": ["OWNER_CONFIRMATION_REQUIRED","RUNTIME_BEHAVIOR_NOT_ESTABLISHED"]}}
    conditions = [{"statement": text[:1024], "authority": "model_reviewed_proposal", "owner_confirmation_required": True} for text in model_proposals[:16]]
    return {"intended_outcome": outcome, "target_user": None, "journeys": [], "criteria": [criterion], "protected_invariants": [], "allowed_evidence_classes": ["source_verified", "owner_confirmed", "trusted_imported_receipt"], "future_verifier_requirements": [], "network_policy": "none", "challenge_budget": {"class": "not_required", "max_instances": 0, "max_wall_seconds": 0, "max_network_requests": 0}, "risk": {"tier": {"value": "unresolved", "authority": "unresolved", "provenance_refs": source_refs}, "reversibility": {"value": "unresolved", "authority": "unresolved", "provenance_refs": source_refs}}, "conditions": conditions, "reinspection_triggers": ["candidate_changed", "expiry_reached"], "interpretation": interpretation}


def _render(run: dict[str, Any], format_name: str) -> str:
    if format_name == "json": return json.dumps(run, sort_keys=True, indent=2)
    if format_name == "terminal": return f"Contract Foundry {run['run_id']}\nEligibility: {run['run_eligibility']}\nReadiness: {run['contract_readiness']}\nProjection: {run['owner_projection_ref']['id']}\n"
    lines = [f"# Contract Foundry {run['run_id']}", f"Eligibility: `{run['run_eligibility']}`", f"Readiness: `{run['contract_readiness']}`", f"Projection: `{run['owner_projection_ref']['id']}`"]
    body = "\n\n".join(lines) + "\n"
    if format_name == "markdown": return body
    import html
    return "<!doctype html><html><body><pre>" + html.escape(body) + "</pre></body></html>"


def _stage(root: Path, name: str, value: dict[str, Any], schema_file: str, id_key: str) -> tuple[dict[str, Any], bytes]:
    _schema(schema_file, value); raw = canonical_bytes(value); secure_write(root / f"{name}.json", raw)
    return {"id": value[id_key], "schema_id": value["schema_id"], "path": f"{name}.json", "sha256": sha256_bytes(raw)}, raw


def foundry(*, brief_id: str, source_manifest: Path, interpretation: str = "faithful", depth: str = "standard", provider_id: str | None = None, no_model: bool = False, format_name: str = "terminal") -> tuple[dict[str, Any], str]:
    brief, brief_raw = _load_brief(brief_id); manifest, sources = _contained_sources(source_manifest)
    run_id = str(uuid.uuid4()); case_id = brief["case_id"]; root = Path("outputs/contract-foundry") / run_id
    risk_inputs = manifest.get("routing_inputs", {"risk": "unresolved", "ambiguity": "unresolved", "blast_radius": "unresolved", "reversibility": "unresolved", "oracle": "unresolved", "actor_autonomy": "unresolved"})
    routing = route(risk_inputs)
    if provider_id is None and not no_model: provider_id = os.environ.get("PROVAN_FOUNDRY_PROVIDER") or None
    if provider_id is not None and provider_id not in PROVIDERS: raise ProvanError("FOUNDRY_PROVIDER_NOT_ALLOWLISTED", provider_id)
    required_calls = 0 if routing["tier"] == 0 else (2 if depth == "deep" or routing["tier"] == 3 else 1)
    egress_authorization = _require_model_egress_authorization(manifest, sources) if provider_id == "openai-responses-primary" and required_calls else None
    scripted = provider_id == "scripted-test" and os.environ.get("PROVAN_ALLOW_SCRIPTED_PROVIDER") == "1"
    configured={item.strip() for item in os.environ.get("PROVAN_MODEL_ALLOWLIST","").split(",") if item.strip()};hosts={item.strip().lower() for item in os.environ.get("PROVAN_MODEL_HOST_ALLOWLIST","").split(",") if item.strip()}
    live=provider_id=="openai-responses-primary" and provider_id in configured and "api.openai.com" in hosts and bool(os.environ.get("OPENAI_API_KEY"))
    semantic_available = scripted or live
    eligibility = "ELIGIBLE"
    limitations = ["SOURCE_ONLY", "TARGET_READ_ONLY", "EXECUTION_UNAVAILABLE", "CHALLENGE_UNAVAILABLE"]
    if no_model and required_calls: eligibility = "NOT_ELIGIBLE"; limitations.append("REQUIRED_MODEL_ROLE_UNAVAILABLE_NO_MODEL")
    elif required_calls and not semantic_available: eligibility = "NOT_ELIGIBLE"; limitations.append("REQUIRED_CONFIGURED_MODEL_UNAVAILABLE")
    if required_calls and scripted: eligibility = "NOT_ELIGIBLE"; limitations.append("SCRIPTED_PROVIDER_SEMANTICALLY_UNQUALIFIED")
    if depth == "deep" and not semantic_available: eligibility = "NOT_ELIGIBLE"; limitations.append("DEEP_DUAL_PATH_NOT_EXECUTED")
    ledger_id=str(uuid.uuid4());ledger={"schema_id":"provan.source_authority_ledger.v1","ledger_id":ledger_id,"case_id":case_id,"candidate_digest":brief["candidate"]["candidate_digest"],"sources":[{key:row[key] for key in ("source_id","role","media_type","bytes","sha256")} for row in sources],"limits":{"manifest_bytes":1024*1024,"text_bytes":512*1024,"structured_bytes":1024*1024,"aggregate_bytes":8*1024*1024,"files":32,"depth":32,"nodes":50000},"blind_input_digest":sha256_bytes(canonical_bytes([{"source_id":row["source_id"],"role":row["role"],"sha256":row["sha256"]} for row in sources if row["role"] in {"intent","formal_contract"}])),"limitations":["CONTENT_REMAINS_INTERNAL"]};ledger_ref,_=_stage(root,"source-authority-ledger",ledger,"source-authority-ledger.v1.json","ledger_id")
    spend_control=manifest.get("spend_control",{})
    if not isinstance(spend_control,dict) or set(spend_control)-{"spent","in_flight","minimum_mandatory_remaining","per_call_reservation"}:raise ProvanError("FOUNDRY_SPEND_CONTROL_INVALID","spend_control")
    spent=spend_control.get("spent",0);in_flight=spend_control.get("in_flight",0);minimum_remaining=spend_control.get("minimum_mandatory_remaining",0);reservation=spend_control.get("per_call_reservation",10)
    if any(not isinstance(item,(int,float)) or isinstance(item,bool) or item<0 for item in (spent,in_flight,minimum_remaining,reservation)):raise ProvanError("FOUNDRY_SPEND_CONTROL_INVALID","values")
    blind_paths = [];envelope_refs=[];usage_receipts=[];pre_call_reservations=[];reserved_total=0
    semantic_path_count=2 if depth=="deep" or routing["tier"]==3 else (1 if required_calls else 0)
    if semantic_available and semantic_path_count:
        for label in (("A","B") if semantic_path_count==2 else ("A",)):
            projected=spent+in_flight+reserved_total+reservation+minimum_remaining
            if projected>75:raise ProvanError("FOUNDRY_SPEND_RESERVATION_EXCEEDED",f"call {label} would reserve {projected} USD")
            pre_call_reservations.append({"call":label,"spent":spent,"in_flight":in_flight,"reserved_before":reserved_total,"reservation":reservation,"minimum_mandatory_remaining":minimum_remaining,"projected_total":projected,"authorized":True});reserved_total+=reservation
            instructions=PUBLIC_PROMPTS["blind_intent"]+"\n\n"+PUBLIC_PROMPTS["contract_candidate" if label=="A" else "adversarial_critic"]+"\n\n"+OUTPUT_PROTOCOL
            model_id = PROVIDERS[provider_id].get("model") or (PROVIDERS[provider_id]["tier_1_model"] if routing["tier"] == 1 else PROVIDERS[provider_id]["tier_2_3_model"])
            reasoning_effort = "xhigh" if depth == "deep" else ("medium" if routing["tier"] == 1 else "high")
            provider=ModelProvider(provider_id,model_id,"pinned-work-order-v2",PROVIDERS[provider_id]["origin"],reasoning_effort)
            blocks=[{"category":f"blind_{row['role']}","content":row["content"]} for row in sources if row["role"] in {"intent","formal_contract"}]
            envelope=build_envelope(case_id=case_id,candidate_digest=brief["candidate"]["candidate_digest"],provider=provider,instructions=instructions,blocks=blocks);envelope["prompt_id"]=f"foundry-deep-path-{label.lower()}";envelope["limits"]["max_output_tokens"]=8192 if reasoning_effort=="xhigh" else 4096;envelope_raw=canonical_bytes(envelope);_schema("model-input-envelope.v1.json",envelope);path=f"model-input-envelope-{label.lower()}.json";secure_write(root/path,envelope_raw);envelope_ref={"id":envelope["envelope_id"],"path":path,"sha256":sha256_bytes(envelope_raw),"prompt_id":envelope["prompt_id"]};envelope_refs.append(envelope_ref)
            if live:result,usage=invoke_frozen_public_openai_responses(provider,envelope,os.environ["OPENAI_API_KEY"],egress_authorization)
            else:result={"model_reviewed_implications":[_source_outcome(sources)],"unresolved":["SCRIPTED_PROVIDER_SEMANTICALLY_UNQUALIFIED"]};usage={"mode":"SCRIPTED_TEST","calls":1,"latency_ms":0,"cost_status":"not_applicable","envelope_digest":sha256_bytes(envelope_raw)}
            usage_receipts.append(usage);output={"kind":"candidate" if label=="A" else "structured_critique","model_reviewed_implications":result["model_reviewed_implications"],"unresolved":result["unresolved"]}
            blind_paths.append({"path": label, "conversation_state": None, "previous_response_id": None, "background": False, "input_digest": sha256_bytes(canonical_bytes([{"source_id": row["source_id"], "sha256": row["sha256"]} for row in sources if row["role"] in {"intent", "formal_contract"}])), "model_envelope_ref":envelope_ref,"intent_model": {"proposals": result["model_reviewed_implications"], "authority": "model_reviewed_proposal"}, "contract_output": {**output,"digest": sha256_bytes(canonical_bytes(output))}})
    path_digests=[row["contract_output"]["digest"] for row in blind_paths]
    model_proposals=[text for row in blind_paths for text in row["contract_output"]["model_reviewed_implications"]]
    synthesized_outcome=(model_proposals[0][:1024] if model_proposals else _source_outcome(sources))
    library=pattern_library();pattern_rows=[row for row in library["patterns"] if row["family"] in {"api_schema_backward_compatibility", "test_adequacy_contract_mutation", "false_success_durable_state"}];pattern_ids = [row["pattern_id"] for row in pattern_rows]
    synthesis_method="deterministic_source_only" if not blind_paths else ("frozen_dual_path_reconciliation_v1" if len(blind_paths)==2 else "single_blind_path")
    intent_id=str(uuid.uuid4());intent={"schema_id":"provan.intent_model.v1","intent_id":intent_id,"path_id":"deterministic" if not blind_paths else "synthesis","source_ledger_ref":ledger_ref,"input_path_digests":path_digests,"synthesis_method":synthesis_method,"outcomes":[synthesized_outcome],"users":[],"journeys":[],"ambiguities":["TARGET_USER_UNRESOLVED","EXACT_ORACLE_REQUIRES_OWNER_CONFIRMATION"]+[text[:1024] for row in blind_paths for text in row["contract_output"]["unresolved"][:8]],"non_goals":["runtime verification","challenge execution"],"authority":"model_reviewed_proposal" if blind_paths else "source_attributed_proposal","limitations":limitations};intent_ref,_=_stage(root,"intent-model",intent,"intent-model.v1.json","intent_id")
    goal_id=str(uuid.uuid4());goal={"schema_id":"provan.goal_obstacle_model.v1","model_id":goal_id,"intent_ref":intent_ref,"goals":list(intent["outcomes"]),"obstacles":["owner confirmation outstanding","runtime evidence unavailable"],"unknowns":["target user","final oracle"],"authority":"proposal_only","limitations":limitations};goal_ref,_=_stage(root,"goal-obstacle-model",goal,"goal-obstacle-model.v1.json","model_id")
    premortem_id=str(uuid.uuid4());premortem={"schema_id":"provan.premortem_analysis.v1","analysis_id":premortem_id,"goal_model_ref":goal_ref,"failure_modes":["criterion overfits implementation","missing oracle permits false success"],"false_success_risks":["artifact exists without durable intended behavior"],"mitigation_proposals":["owner-confirm exact typed closure","future qualified verifier"],"limitations":limitations};premortem_ref,_=_stage(root,"premortem-analysis",premortem,"premortem-analysis.v1.json","analysis_id")
    proposal = _proposal(brief, sources, interpretation, model_proposals)
    readiness = "NOT_READY" if eligibility == "NOT_ELIGIBLE" else ("READY_WITH_MATERIAL_QUESTIONS" if proposal["risk"]["tier"]["value"] == "unresolved" else "READY_FOR_OWNER_CONFIRMATION")
    candidate_id=str(uuid.uuid4());candidate_artifact={"schema_id":"provan.contract_candidate.v1","candidate_id":candidate_id,"path_id":"synthesized" if blind_paths else "deterministic","case_id":case_id,"intent_ref":intent_ref,"goal_obstacle_ref":goal_ref,"premortem_ref":premortem_ref,"derivation_input_digests":[intent_ref["sha256"],goal_ref["sha256"],premortem_ref["sha256"]],"proposed_terms":proposal,"evidence_plan":[{"criterion_id":row["criterion_id"],"required":row["required_evidence_classes"]} for row in proposal["criteria"]],"oracle_plan":[{"criterion_id":row["criterion_id"],"closure":row["closure_requirement"]} for row in proposal["criteria"]],"authority":"proposal_only","limitations":limitations};candidate_ref,_=_stage(root,"contract-candidate",candidate_artifact,"contract-candidate.v1.json","candidate_id")
    audit_id=str(uuid.uuid4());audit={"schema_id":"provan.contract_audit.v1","audit_id":audit_id,"candidate_ref":candidate_ref,"findings":[{"code":"OWNER_CONFIRMATION_REQUIRED","severity":"material"},{"code":"RUNTIME_EVIDENCE_UNAVAILABLE","severity":"limitation"}],"finding_coverage":{"total":2,"addressed":0,"preserved_unresolved":2},"authority":"advisory","limitations":limitations};audit_ref,_=_stage(root,"contract-audit",audit,"contract-audit.v1.json","audit_id")
    witness_id=str(uuid.uuid4());witnesses={"schema_id":"provan.contract_witness_set.v1","witness_set_id":witness_id,"candidate_ref":candidate_ref,"valid":["owner-confirmed exact source predicate holds"],"near_valid":["artifact exists but expected canonical value differs"],"adversarial":["runtime-only claim presented as source evidence"],"ambiguity":["target user unspecified"],"overspecification":["implementation-specific mechanism required without source authority"],"limitations":limitations};witness_ref,_=_stage(root,"contract-witness-set",witnesses,"contract-witness-set.v1.json","witness_set_id")
    selection_id=str(uuid.uuid4());selection={"schema_id":"provan.verification_pattern_selection.v1","selection_id":selection_id,"contract_candidate_ref":candidate_ref,"items":[{"pattern_ref":{"id":row["pattern_id"],"version":row["version"]},"status":"proposed","reason_codes":["OWNER_CONFIRMATION_REQUIRED"]} for row in pattern_rows],"execution_implied":False,"challenge_implied":False,"limitations":["SESSION12_SELECTION_ONLY"]};selection_ref,_=_stage(root,"verification-pattern-selection",selection,"verification-pattern-selection.v1.json","selection_id")
    readiness_id=str(uuid.uuid4());readiness_artifact={"schema_id":"provan.contract_readiness.v1","readiness_id":readiness_id,"contract_candidate_ref":candidate_ref,"contract_readiness":readiness,"run_eligibility":eligibility,"reason_codes":limitations,"evidence_plan_complete":True,"oracle_plan_complete":False,"runtime_evidence_established":False,"limitations":limitations};readiness_ref,_=_stage(root,"contract-readiness",readiness_artifact,"contract-readiness.v1.json","readiness_id")
    projection_id = str(uuid.uuid4())
    projection = {"schema_id": "provan.foundry_acceptance_projection.v1", "projection_id": projection_id, "sensitivity": "PUBLIC_SAFE", "run_id": run_id, "brief_ref": {"id": brief_id, "sha256": sha256_bytes(brief_raw)}, "case_id": case_id, "candidate_digest": brief["candidate"]["candidate_digest"], "proposed_contract_terms": proposal, "contract_readiness": readiness, "run_eligibility": eligibility, "owner_confirmation_required": True, "creates_authority": False, "execution_available": False, "challenge_available": False, "limitations": limitations}
    _schema("foundry-acceptance-projection.v1.json", projection)
    projection_raw = canonical_bytes(projection)
    provider_config=PROVIDERS.get(provider_id) if provider_id else None
    selected_model = None if not provider_id else (provider_config.get("tier_1_model") if routing["tier"] == 1 else provider_config.get("tier_2_3_model", provider_config.get("model")))
    stage_outputs={"blind_intent":[intent_ref["sha256"]],"blind_path_a":path_digests[:1],"blind_path_b":path_digests[1:2],"freeze_blind_paths":[sha256_bytes(canonical_bytes(path_digests))] if path_digests else [],"synthesis":[intent_ref["sha256"]],"goal_obstacle":[goal_ref["sha256"]],"pre_mortem":[premortem_ref["sha256"]],"contract_proposal":[candidate_ref["sha256"]],"adversarial_audit":[audit_ref["sha256"]],"revision":[],"witnesses":[witness_ref["sha256"]],"mutation_checks":[witness_ref["sha256"]],"final_audit":[audit_ref["sha256"]],"revisions":[],"verification_patterns":[selection_ref["sha256"]],"readiness":[readiness_ref["sha256"]]}
    stage_execution=[];previous=[ledger_ref["sha256"]]
    for stage_name in RUN_STAGES[depth]:
        outputs=stage_outputs[stage_name];status="EXECUTED" if outputs else "NOT_APPLICABLE"
        stage_execution.append({"stage":stage_name,"input_digests":previous,"output_digests":outputs,"status":status})
        if outputs:previous=outputs
    run = {"schema_id": "provan.contract_foundry_run.v1", "run_id": run_id, "sensitivity": "LOCAL_NON_PUBLIC", "package_version": PACKAGE_VERSION, "case_id": case_id, "candidate": brief["candidate"], "brief_ref": projection["brief_ref"], "source_ledger": ledger_ref, "blind_boundary": {"implementation_material_included": False, "source_ids": [row["source_id"] for row in sources],"blind_input_digest":ledger["blind_input_digest"]}, "blind_paths": blind_paths, "model_envelope_refs":envelope_refs,"stages": RUN_STAGES[depth],"stage_execution":stage_execution, "stage_artifacts": {"intent":intent_ref,"goal_obstacle":goal_ref,"pre_mortem":premortem_ref,"contract_candidate":candidate_ref,"audit":audit_ref,"witnesses":witness_ref,"pattern_selection":selection_ref,"readiness":readiness_ref,"revisions":[]}, "pattern_selection": {"status": "proposed", "pattern_ids": pattern_ids, "execution_implied": False}, "routing_receipt": routing, "role_registry": ROLE_REGISTRY_VERSION, "provider_receipts": [{"provider": provider_id,"origin":provider_config["origin"],"model":selected_model,"kind": "deterministic_scripted_provider" if scripted else ("openai_responses_stateless" if live else "configured_provider_unavailable"), "semantic_qualification": live, "calls": len(usage_receipts), "usage_receipts":usage_receipts,"store_requested": provider_config["store_requested"], "provider_retention": provider_config["retention"]}] if provider_id else [], "interpretation": interpretation, "depth": depth, "run_eligibility": eligibility, "contract_readiness": readiness, "mode_qualification": "IMPLEMENTED_UNQUALIFIED", "owner_projection_ref": {"id": projection_id, "sha256": sha256_bytes(projection_raw)}, "spend": {"currency": "USD", "hard_cap": 75, "spent": spent, "in_flight": in_flight, "minimum_mandatory_remaining":minimum_remaining,"per_call_reservation":reservation,"reserved":reserved_total,"pre_call_reservations":pre_call_reservations,"cost_status": "unavailable" if live else ("not_applicable" if not semantic_available else "scripted_not_billable")}, "execution_available": False, "challenge_available": False, "limitations": limitations}
    _schema("contract-foundry-run.v1.json", run)
    secure_write(root / "foundry-acceptance-projection.json", projection_raw)
    secure_write(root / "contract-foundry-run.json", canonical_bytes(run))
    return run, _render(run, format_name)


def load_projection(projection_id: str) -> tuple[dict[str, Any], bytes]:
    root = Path("outputs/contract-foundry")
    # Canonical UUID identity is a locator only; every candidate is revalidated.
    if not re.fullmatch(r"[0-9a-f-]{36}", projection_id): raise ProvanError("FOUNDRY_PROJECTION_ID_INVALID", projection_id)
    state = __import__("provan.state", fromlist=["state_root"]).state_root()
    base = state / root
    if base.is_dir():
        for child in sorted(base.iterdir(), key=lambda item: item.name):
            if not child.is_dir() or child.is_symlink(): continue
            relative = root / child.name / "foundry-acceptance-projection.json"
            try: raw = secure_read(relative)
            except FileNotFoundError: continue
            value = json.loads(raw)
            if value.get("projection_id") == projection_id:
                _schema("foundry-acceptance-projection.v1.json", value)
                if canonical_bytes(value) != raw: raise ProvanError("FOUNDRY_PROJECTION_CANONICAL_BYTES_INVALID", projection_id)
                return value, raw
    raise ProvanError("FOUNDRY_PROJECTION_NOT_FOUND", projection_id)
