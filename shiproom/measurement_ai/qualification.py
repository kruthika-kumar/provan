from __future__ import annotations

from pathlib import Path

from shiproom.project import content_hash

from .contracts import load_json_bytes, require_exact, require_string_list, require_text, sha256_bytes, stable_id


QUALIFICATION_SCHEMA = "measurement-reviewer-qualification.v1"
QUALIFICATION_RESULT_SCHEMA = "measurement-reviewer-qualification-result.v1"
QUALIFIED_CAPABILITIES = {
    "contract_structure", "metric_decision_alignment", "absolute_count_opportunity_review",
    "ratio_denominator_review", "population_review", "window_delay_review", "proxy_outcome_review",
    "guardrail_review", "causal_claim_review", "ai_eval_structure", "ai_claim_authority_review",
    "skeptical_material_review",
}


def qualification_store(repository_root: Path) -> Path:
    return repository_root / ".shiproom" / "local" / "measurement-reviewer-qualifications"


def grade_qualification_result(value: dict, guidance: dict) -> dict:
    require_exact(value, {"schema_version", "provider_id", "model_id", "role_prompt_version", "guidance_pack_hash", "recommendation_policy_hash", "result_schema_version", "qualification_suite_version", "qualification_suite_hash", "case_results"}, "qualification result")
    if value["schema_version"] != QUALIFICATION_RESULT_SCHEMA or value["guidance_pack_hash"] != guidance["pack_hash"]:
        raise ValueError("qualification result binding mismatch")
    for field in ("provider_id", "model_id", "role_prompt_version", "result_schema_version", "qualification_suite_version"):
        require_text(value[field], field, 200)
    expected_cases = {item["case_id"]: item for item in guidance["qualification_suite"]["cases"]}
    submitted = value["case_results"]
    if not isinstance(submitted, list) or {item.get("case_id") for item in submitted if isinstance(item, dict)} != set(expected_cases) or len(submitted) != len(expected_cases):
        raise ValueError("qualification case coverage is incomplete")
    capabilities = set()
    for item in submitted:
        require_exact(item, {"case_id", "semantic_assessment", "recommendation_classes", "guidance_rule_ids", "exceptions_considered", "effect", "abstained", "claims", "authority_labels"}, "qualification case result")
        expected = expected_cases[item["case_id"]]["expected_constraints"]
        recommendations = set(require_string_list(item["recommendation_classes"], "recommendation_classes"))
        rules = set(require_string_list(item["guidance_rule_ids"], "guidance_rule_ids"))
        exceptions = set(require_string_list(item["exceptions_considered"], "exceptions_considered"))
        claims = set(require_string_list(item["claims"], "claims"))
        authorities = set(require_string_list(item["authority_labels"], "authority_labels"))
        if item["semantic_assessment"] not in expected["allowed_semantic_assessments"] or item["semantic_assessment"] in expected["forbidden_semantic_assessments"] or not set(expected["required_recommendation_classes"]).issubset(recommendations) or recommendations & set(expected["forbidden_recommendation_classes"]) or not set(expected["required_guidance_rules"]).issubset(rules) or not set(expected["required_exceptions"]).issubset(exceptions) or item["effect"] != expected["maximum_effect"] or bool(item["abstained"]) != bool(expected["abstention_required"]) or claims & set(expected["forbidden_claims"]) or not set(expected["required_authority_labels"]).issubset(authorities):
            raise ValueError(f"qualification case failed: {item['case_id']}")
        capabilities.update(expected["qualified_capabilities"])
    receipt = {
        "schema_version": QUALIFICATION_SCHEMA,
        "qualification_id": stable_id("qualification", {key: value[key] for key in value if key != "case_results"}),
        "provider_id": value["provider_id"], "model_id": value["model_id"],
        "role_prompt_version": value["role_prompt_version"], "guidance_pack_hash": guidance["pack_hash"],
        "recommendation_policy_hash": value["recommendation_policy_hash"],
        "result_schema_version": value["result_schema_version"],
        "qualification_suite_version": value["qualification_suite_version"],
        "qualification_suite_hash": value["qualification_suite_hash"],
        "qualified_capabilities": sorted(capabilities), "case_ids": sorted(expected_cases),
        "result_semantic_hash": content_hash(value),
    }
    return receipt


def load_qualification_receipt(path: Path, guidance: dict) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("qualification receipt must be a regular file")
    raw = path.read_bytes(); value = load_json_bytes(raw)
    expected = {"schema_version", "qualification_id", "provider_id", "model_id", "role_prompt_version", "guidance_pack_hash", "recommendation_policy_hash", "result_schema_version", "qualification_suite_version", "qualification_suite_hash", "qualified_capabilities", "case_ids", "result_semantic_hash"}
    require_exact(value, expected, "qualification receipt")
    if value["schema_version"] != QUALIFICATION_SCHEMA or value["guidance_pack_hash"] != guidance["pack_hash"] or not set(value["qualified_capabilities"]).issubset(QUALIFIED_CAPABILITIES):
        raise ValueError("qualification receipt is stale or invalid")
    return {"value": value, "bytes": raw, "snapshot_hash": sha256_bytes(raw)}
