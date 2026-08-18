from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .foundry import PATTERN_FAMILIES, PROVIDERS, PUBLIC_PROMPTS, RUN_STAGES, route
from .modeling import FROZEN_PUBLIC_MODEL_EGRESS

SHA = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


def _load(raw: bytes, schema_id: str) -> dict[str, Any]:
    try: value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ProvanError("SESSION12_CANONICAL_JSON_INVALID", schema_id) from exc
    if canonical_bytes(value) != raw or value.get("schema_id") != schema_id: raise ProvanError("SESSION12_CANONICAL_ARTIFACT_INVALID", schema_id)
    return value


def validate_projection_serialized(raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.foundry_acceptance_projection.v1")
    if value["contract_readiness"] not in {"READY_FOR_OWNER_CONFIRMATION", "READY_WITH_MATERIAL_QUESTIONS", "NOT_READY"}: raise ProvanError("FOUNDRY_READINESS_INVALID", "readiness")
    if value["run_eligibility"] not in {"ELIGIBLE", "NOT_ELIGIBLE"}: raise ProvanError("FOUNDRY_ELIGIBILITY_INVALID", "eligibility")
    if value["creates_authority"] or value["execution_available"] or value["challenge_available"] or not value["owner_confirmation_required"]: raise ProvanError("FOUNDRY_PROJECTION_AUTHORITY_INVALID", "projection")
    return value


def validate_run_serialized(raw: bytes, projection_raw: bytes, stage_artifacts: dict[str, bytes] | None = None) -> dict[str, Any]:
    value = _load(raw, "provan.contract_foundry_run.v1"); projection = validate_projection_serialized(projection_raw)
    if value["owner_projection_ref"] != {"id": projection["projection_id"], "sha256": sha256_bytes(projection_raw)}: raise ProvanError("FOUNDRY_PROJECTION_BINDING_MISMATCH", "projection")
    if value["run_id"] != projection["run_id"] or value["case_id"] != projection["case_id"] or value["candidate"]["candidate_digest"] != projection["candidate_digest"]: raise ProvanError("FOUNDRY_CASE_BINDING_MISMATCH", "case")
    if value["stages"] != RUN_STAGES[value["depth"]]: raise ProvanError("FOUNDRY_STAGE_ORDER_INVALID", value["depth"])
    if value["routing_receipt"] != route(value["routing_receipt"]["inputs"]): raise ProvanError("FOUNDRY_ROUTING_MISMATCH", "router")
    if value["run_eligibility"] != projection["run_eligibility"] or value["contract_readiness"] != projection["contract_readiness"]: raise ProvanError("FOUNDRY_STATUS_BINDING_MISMATCH", "status")
    if value["execution_available"] or value["challenge_available"] or value["mode_qualification"] != "IMPLEMENTED_UNQUALIFIED": raise ProvanError("FOUNDRY_CAPABILITY_OR_MATURITY_INVALID", "run")
    tier=value["routing_receipt"]["tier"];required_calls=0 if tier==0 else (2 if value["depth"]=="deep" or tier==3 else 1)
    receipts=value["provider_receipts"]
    if len(receipts)>1:raise ProvanError("FOUNDRY_PROVIDER_RECEIPT_INVALID","multiple providers")
    if receipts:
        receipt=receipts[0];config=PROVIDERS.get(receipt.get("provider"))
        if config is None or receipt.get("origin")!=config["origin"] or receipt.get("model")!=config["model"] or receipt.get("store_requested")!=config["store_requested"] or receipt.get("provider_retention")!=config["retention"]:raise ProvanError("FOUNDRY_PROVIDER_BINDING_INVALID",str(receipt.get("provider")))
        if receipt.get("provider")=="scripted-test" and receipt.get("semantic_qualification") is not False:raise ProvanError("FOUNDRY_SCRIPTED_PROVIDER_QUALIFICATION_FORBIDDEN","scripted-test")
    if value["spend"].get("currency")!="USD" or value["spend"].get("hard_cap")!=75 or value["spend"].get("spent",0)+value["spend"].get("in_flight",0)>75:raise ProvanError("FOUNDRY_SPEND_CAP_INVALID","spend")
    if required_calls and value["run_eligibility"]=="ELIGIBLE" and (not receipts or receipts[0].get("calls")!=required_calls or receipts[0].get("semantic_qualification") is not True):raise ProvanError("FOUNDRY_REQUIRED_ROLE_NOT_QUALIFIED","provider")
    if value["depth"] == "deep":
        paths = value["blind_paths"]
        if value["run_eligibility"] == "ELIGIBLE" and (len(paths) != 2 or {row["path"] for row in paths} != {"A", "B"} or any(row["conversation_state"] is not None or row["previous_response_id"] is not None or row["background"] for row in paths) or any(row["contract_output"]["kind"] not in {"candidate", "structured_critique"} for row in paths)): raise ProvanError("FOUNDRY_DEEP_ISOLATION_INVALID", "deep")
    if stage_artifacts is not None:
        required={"intent","goal_obstacle","pre_mortem","contract_candidate","audit","witnesses","pattern_selection","readiness"}
        if set(value["stage_artifacts"])-{"revisions"}!=required:raise ProvanError("FOUNDRY_STAGE_ARTIFACT_SET_INVALID","stages")
        loaded={}
        ledger_ref=value["source_ledger"];ledger_raw=stage_artifacts.get(ledger_ref["path"])
        if ledger_raw is None or sha256_bytes(ledger_raw)!=ledger_ref["sha256"]:raise ProvanError("FOUNDRY_SOURCE_LEDGER_BINDING_MISMATCH","ledger")
        ledger=_load(ledger_raw,"provan.source_authority_ledger.v1")
        if ledger.get("ledger_id")!=ledger_ref["id"] or ledger.get("case_id")!=value["case_id"] or ledger.get("candidate_digest")!=value["candidate"]["candidate_digest"] or ledger.get("blind_input_digest")!=value["blind_boundary"]["blind_input_digest"] or [row["source_id"] for row in ledger["sources"]]!=value["blind_boundary"]["source_ids"]:raise ProvanError("FOUNDRY_SOURCE_LEDGER_SEMANTICS_INVALID","ledger")
        envelope_refs=value.get("model_envelope_refs",[])
        if value["blind_paths"] and len(envelope_refs)!=len(value["blind_paths"]):raise ProvanError("FOUNDRY_MODEL_ENVELOPE_COVERAGE_INVALID","envelopes")
        for ref in envelope_refs:
            envelope_raw=stage_artifacts.get(ref.get("path"));
            if envelope_raw is None or sha256_bytes(envelope_raw)!=ref.get("sha256"):raise ProvanError("FOUNDRY_MODEL_ENVELOPE_BINDING_MISMATCH",str(ref.get("id")))
            envelope=_load(envelope_raw,"provan.model_input_envelope.v1")
            if envelope.get("envelope_id")!=ref.get("id") or envelope.get("case_id")!=value["case_id"] or envelope.get("candidate_digest")!=value["candidate"]["candidate_digest"]:raise ProvanError("FOUNDRY_MODEL_ENVELOPE_SEMANTICS_INVALID",str(ref.get("id")))
            config=PROVIDERS.get(envelope.get("provider"));expected_prompt={"foundry-deep-path-a":PUBLIC_PROMPTS["blind_intent"]+"\n\n"+PUBLIC_PROMPTS["contract_candidate"]+"\n\n"+PUBLIC_PROMPTS["output_protocol"],"foundry-deep-path-b":PUBLIC_PROMPTS["blind_intent"]+"\n\n"+PUBLIC_PROMPTS["adversarial_critic"]+"\n\n"+PUBLIC_PROMPTS["output_protocol"]}.get(envelope.get("prompt_id"))
            if config is None or envelope.get("model")!=config["model"] or expected_prompt is None or envelope.get("instructions")!=expected_prompt or any(row.get("sha256")!=sha256_bytes(str(row.get("content","")).encode("utf-8")) for row in envelope.get("selected_blocks",[])):raise ProvanError("FOUNDRY_MODEL_ENVELOPE_SEMANTICS_INVALID",str(ref.get("id")))
        for path in value["blind_paths"]:
            if path.get("model_envelope_ref") not in envelope_refs:raise ProvanError("FOUNDRY_MODEL_ENVELOPE_PATH_MISMATCH",path.get("path","?"))
        for name in required:
            ref=value["stage_artifacts"][name];artifact_raw=stage_artifacts.get(ref["path"])
            if artifact_raw is None or sha256_bytes(artifact_raw)!=ref["sha256"]:raise ProvanError("FOUNDRY_STAGE_ARTIFACT_BINDING_MISMATCH",name)
            artifact=json.loads(artifact_raw)
            if artifact.get("schema_id")!=ref["schema_id"] or ref["id"] not in artifact.values() or canonical_bytes(artifact)!=artifact_raw:raise ProvanError("FOUNDRY_STAGE_ARTIFACT_SEMANTICS_INVALID",name)
            loaded[name]=artifact
        candidate=loaded["contract_candidate"];readiness=loaded["readiness"];selection=loaded["pattern_selection"]
        if candidate["proposed_terms"]!=projection["proposed_contract_terms"] or readiness["contract_candidate_ref"]!=value["stage_artifacts"]["contract_candidate"] or readiness["contract_readiness"]!=value["contract_readiness"] or readiness["run_eligibility"]!=value["run_eligibility"] or readiness["runtime_evidence_established"] is not False:raise ProvanError("FOUNDRY_STAGE_CROSS_BINDING_MISMATCH","candidate/readiness")
        if selection["contract_candidate_ref"]!=value["stage_artifacts"]["contract_candidate"] or selection["execution_implied"] or selection["challenge_implied"]:raise ProvanError("FOUNDRY_PATTERN_SELECTION_BINDING_INVALID","selection")
        revisions=value["stage_artifacts"].get("revisions",[]);cap=2 if value["depth"]=="deep" else 1 if value["depth"]=="standard" else 0
        if len(revisions)>cap:raise ProvanError("FOUNDRY_REVISION_CAP_EXCEEDED",value["depth"])
        audit=loaded["audit"];coverage=audit.get("finding_coverage",{})
        if coverage.get("total")!=len(audit.get("findings",[])) or coverage.get("addressed",0)+coverage.get("preserved_unresolved",0)!=coverage.get("total"):raise ProvanError("FOUNDRY_AUDIT_COVERAGE_INVALID","audit")
    return value


def validate_pattern_library_serialized(raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.verification_pattern_library.v1"); rows = value.get("patterns", [])
    if {row.get("family") for row in rows} != set(PATTERN_FAMILIES) or len(rows) != len(PATTERN_FAMILIES): raise ProvanError("FOUNDRY_PATTERN_LIBRARY_INCOMPLETE", "families")
    required = {"pattern_id", "version", "family", "applicability", "preconditions", "required_oracle", "dimensions", "capability_requirements", "limitations", "false_inference_risks", "cost_class", "research_refs", "publication"}
    if any(set(row) != required or not row["preconditions"] or not row["required_oracle"] or not row["limitations"] or not row["false_inference_risks"] for row in rows): raise ProvanError("FOUNDRY_PATTERN_CONTRACT_INCOMPLETE", "pattern")
    if value.get("execution_available") or value.get("challenge_available"): raise ProvanError("FOUNDRY_PATTERN_EXECUTION_FALSE_CLAIM", "library")
    return value


def validate_claim_registry_serialized(raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session12_claim_registry.v1"); claims = value.get("claims", []); ids = [row.get("claim_id") for row in claims]
    required = [f"G12-{index:02d}" for index in range(1, 95)]
    if ids[:94] != required or len(ids) != len(set(ids)): raise ProvanError("SESSION12_FROZEN_CLAIMS_INVALID", "claims")
    for index, claim_id in enumerate(ids[94:], 95):
        if claim_id != f"G12-{index:02d}": raise ProvanError("SESSION12_ADDITIVE_CLAIM_GAP", claim_id)
    expected = "sha256:" + hashlib.sha256(canonical_bytes(claims)).hexdigest()
    if value.get("registry_digest") != expected: raise ProvanError("SESSION12_CLAIM_REGISTRY_DIGEST_MISMATCH", "claims")
    return value


def validate_adjudication_projection_serialized(raw: bytes) -> dict[str,Any]:
    value=_load(raw,"provan.session12_adjudication_projection.v1");core=dict(value);declared=core.pop("projection_digest",None)
    if declared!=sha256_bytes(canonical_bytes(core)):raise ProvanError("SESSION12_ADJUDICATION_PROJECTION_DIGEST_MISMATCH","projection")
    if value.get("disposition")!="GO" or value.get("findings")!={"P0":0,"P1":0,"P2":0}:raise ProvanError("SESSION12_ADJUDICATION_REVIEW_NOT_GO","review")
    summary=value.get("case_summary",{});cases=summary.get("cases",[])
    if summary.get("headline_cases")!=len(cases) or summary.get("reserve_cases")!=2 or {row.get("case_id") for row in cases}!={"httpx-pr-3699-control","click-pr-3721-control","httpcore-pr-880-consequential","provan-public-control","session11-controlled-patient"}:raise ProvanError("SESSION12_ADJUDICATION_CASE_SET_INVALID","cases")
    if not value.get("independence",{}).get("review_completed_before_outcome_runs") or not value["independence"].get("evaluation_driven_changes_invalidate_comparisons"):raise ProvanError("SESSION12_ADJUDICATION_ORDER_INVALID","independence")
    if any(not str(item).startswith("sha256:") for item in value.get("authority_bindings",{}).values()):raise ProvanError("SESSION12_ADJUDICATION_BINDING_INVALID","bindings")
    return value


def validate_work_order_serialized(raw:bytes)->dict[str,Any]:
    value=_load(raw,"provan.session12_work_order.v1");boundaries=value.get("boundaries",{});provider=value.get("provider_pin",{})
    if value.get("baseline_commit")!="6c1006c7fe546805aaefd0bc2b47a40317c19c88" or value.get("package_version_expected")!="0.5.0" or value.get("extension_api_major")!=1:raise ProvanError("SESSION12_START_AUTHORITY_INVALID","baseline")
    if boundaries!={"source_only":True,"target_read_only":True,"execution_available":False,"challenge_available":False,"session13_implemented":False,"private_planning_authority":"EXTERNAL_NOT_COPIED"}:raise ProvanError("SESSION12_BOUNDARY_INVALID","boundaries")
    if provider!={"provider_id":"openai-responses-primary","origin":"https://api.openai.com","model":"gpt-5.2","availability_endpoint_use":"VALIDATION_ONLY_NOT_SELECTION","store_requested":False,"retention":"NOT_ZERO_OR_ESTABLISHED"}:raise ProvanError("SESSION12_PROVIDER_PIN_INVALID","provider")
    if value.get("budget")!={"currency":"USD","hard_cap":75} or value.get("qualification")!={"development":"IMPLEMENTED_UNQUALIFIED","gate_only_promotion":True}:raise ProvanError("SESSION12_WORK_ORDER_POLICY_INVALID","policy")
    return value


def validate_model_egress_allowlist_serialized(raw:bytes)->dict[str,Any]:
    value=_load(raw,"provan.foundry_model_egress_allowlist.v1")
    expected=[{"case_id":case_id,"selected_source_digests":list(digests)} for case_id,digests in sorted(FROZEN_PUBLIC_MODEL_EGRESS.items())]
    if value.get("cases")!=expected or value.get("arbitrary_manifest_egress") is not False or value.get("operator_confirmation_required") is not True:raise ProvanError("FOUNDRY_MODEL_EGRESS_ALLOWLIST_INVALID","cases")
    if value.get("provider")!="openai-responses-primary" or value.get("origin")!="https://api.openai.com" or value.get("model")!="gpt-5.2" or value.get("store_requested") is not False or value.get("provider_retention")!="PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED":raise ProvanError("FOUNDRY_MODEL_EGRESS_PROVIDER_INVALID","provider")
    return value


def validate_implementation_binding_serialized(raw: bytes, schema_registry_raw: bytes, claim_registry_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session12_implementation_binding.v1")
    registry = json.loads(schema_registry_raw); claims = validate_claim_registry_serialized(claim_registry_raw)
    if not COMMIT.fullmatch(str(value.get("implementation_commit", ""))) or not COMMIT.fullmatch(str(value.get("implementation_tree", ""))) or not SHA.fullmatch(str(value.get("wheel_sha256", ""))):
        raise ProvanError("SESSION12_IMPLEMENTATION_IDENTITY_INVALID", "binding")
    if value.get("package_version") != "0.5.0" or value.get("extension_api_major") != 1 or value.get("published") is not False:
        raise ProvanError("SESSION12_PACKAGE_BINDING_INVALID", "binding")
    if value.get("schema_registry_digest") != registry.get("registry_digest") or value.get("claim_registry_digest") != claims.get("registry_digest"):
        raise ProvanError("SESSION12_REGISTRY_BINDING_MISMATCH", "binding")
    if value.get("execution_available") is not False or value.get("challenge_available") is not False:
        raise ProvanError("SESSION12_CAPABILITY_BINDING_INVALID", "binding")
    return value


def validate_real_use_qualification_serialized(raw: bytes, binding_raw: bytes, adjudication_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.foundry_real_use_qualification.v1"); binding = json.loads(binding_raw); adjudication = validate_adjudication_projection_serialized(adjudication_raw)
    if value.get("implementation_binding") != binding or value.get("adjudication_root") != adjudication["authority_bindings"]["review_root"]:
        raise ProvanError("SESSION12_REAL_USE_BINDING_MISMATCH", "qualification")
    cases = value.get("cases", []); expected = {"httpx-pr-3699-control", "click-pr-3721-control", "httpcore-pr-880-consequential", "provan-public-control", "session11-controlled-patient", "session12-final-dogfood"}
    if {row.get("case_id") for row in cases} != expected or any(not row.get("predeclared") for row in cases):
        raise ProvanError("SESSION12_REAL_USE_CASE_SET_INVALID", "cases")
    if value.get("evaluation_driven_adjudication_change") is not False or value.get("coding_harness_sanity", {}).get("claim_scope") != "SINGLE_BLIND_SANITY_NOT_HEADLINE_COMPARISON":
        raise ProvanError("SESSION12_REAL_USE_AUTHORITY_INVALID", "qualification")
    if value.get("outcome_bearing_runs_completed"):
        if not value.get("arms") or any(row.get("label") not in {"FRONTIER_PROMPT_BASELINE", "FOUNDRY_STANDARD", "FOUNDRY_DEEP"} for row in value["arms"]):
            raise ProvanError("SESSION12_REAL_USE_ARM_BINDING_INVALID", "arms")
    return value


def validate_pre_review_manifest_serialized(raw: bytes, artifacts: dict[str, bytes], binding_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session11_proof_manifest.v1"); binding = json.loads(binding_raw)
    if value.get("phase") != "PRE_REVIEW" or value.get("reviewer_outputs_excluded") is not True or value.get("reviewed_pre_review_root") is not None:
        raise ProvanError("SESSION12_PRE_REVIEW_PHASE_INVALID", "manifest")
    if any(value.get(key) != binding.get(key) for key in ("implementation_commit", "implementation_tree", "wheel_sha256")):
        raise ProvanError("SESSION12_PRE_REVIEW_BINDING_MISMATCH", "manifest")
    entries = value.get("entries", []); paths = [row.get("path") for row in entries]
    forbidden = {"reviewer_receipt_a.v1.public.json", "reviewer_receipt_b.v1.public.json", "final_proof_manifest.v1.public.json", "closeout.v1.public.json"}
    if len(paths) != len(set(paths)) or any(str(path).replace("\\", "/").split("/")[-1] in forbidden for path in paths):
        raise ProvanError("SESSION12_PRE_REVIEW_RECURSION_FORBIDDEN", "manifest")
    for row in entries:
        artifact = artifacts.get(row["path"])
        if artifact is None or sha256_bytes(artifact) != row["sha256"]:
            raise ProvanError("SESSION12_PRE_REVIEW_ARTIFACT_MISMATCH", row["path"])
    if value.get("proof_root") != sha256_bytes(canonical_bytes(entries)):
        raise ProvanError("SESSION12_PRE_REVIEW_ROOT_MISMATCH", "manifest")
    return value


def validate_session13_handoff_serialized(raw: bytes, artifacts: dict[str, bytes], binding_raw: bytes, proof_registry_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session_handoff.v2"); binding = json.loads(binding_raw); registry = json.loads(proof_registry_raw)
    if value.get("session") != 12 or value.get("implementation_binding") != binding or value.get("execution_available") is not False or value.get("challenge_available") is not False:
        raise ProvanError("SESSION13_HANDOFF_BINDING_INVALID", "handoff")
    for name in ("wheel", "schema_registry", "claim_registry", "foundry_run", "owner_projection", "pattern_library"):
        reference = value.get(name, {}); raw_artifact = artifacts.get(reference.get("path"))
        if raw_artifact is None or sha256_bytes(raw_artifact) != reference.get("sha256"):
            raise ProvanError("SESSION13_HANDOFF_ARTIFACT_UNRESOLVED", name)
    if value.get("proof_root") != sha256_bytes(canonical_bytes(registry.get("entries", []))) or len(value.get("session13_prerequisites", [])) < 5 or not value.get("limitations"):
        raise ProvanError("SESSION13_HANDOFF_SEMANTIC_INCOMPLETE", "handoff")
    if value.get("mode_qualification") != {"standard": binding["standard_maturity"], "deep": binding["deep_maturity"]}:
        raise ProvanError("SESSION13_HANDOFF_MATURITY_MISMATCH", "handoff")
    return value


def validate_generic_absence_receipt_serialized(raw: bytes, binding_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session10_generic_absence_receipt.v1"); binding = json.loads(binding_raw)
    if any(value.get(key) != binding.get(key) for key in ("implementation_commit", "implementation_tree", "wheel_sha256")):
        raise ProvanError("SESSION12_ABSENCE_BINDING_MISMATCH", "absence")
    scopes = [row.get("scope") for row in value.get("checks", [])]
    if scopes != ["history_delta", "working_tree", "package", "proofs_examples", "controlled_ci"] or any(row.get("generic_violation_count") != 0 for row in value["checks"]):
        raise ProvanError("SESSION12_ABSENCE_SCOPE_INVALID", "absence")
    if value.get("result") != "PRIVATE_PLANNING_AUTHORITY_ABSENT" or value.get("confidential_fingerprint_known") is not False:
        raise ProvanError("SESSION12_ABSENCE_RESULT_INVALID", "absence")
    return value


def validate_validation_summary_serialized(raw: bytes, binding_raw: bytes) -> dict[str, Any]:
    value = _load(raw, "provan.session12_validation_summary.v1"); binding = json.loads(binding_raw)
    if value.get("implementation_binding") != binding or value.get("authoritative_full_gate") != "SUCCESS" or value.get("target_mutation_detected") is not False:
        raise ProvanError("SESSION12_VALIDATION_SUMMARY_INVALID", "summary")
    if value.get("execution_available") is not False or value.get("challenge_available") is not False or value.get("session13_implemented") is not False:
        raise ProvanError("SESSION12_VALIDATION_CAPABILITY_INVALID", "summary")
    checks = value.get("checks", [])
    if not checks or any(row.get("exit_code") != 0 or not SHA.fullmatch(str(row.get("transcript_sha256", ""))) for row in checks):
        raise ProvanError("SESSION12_VALIDATION_CHECK_INVALID", "summary")
    return value
