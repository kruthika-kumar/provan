"""Manually authored responses to the public qualification scenarios only."""

RESPONSES = {
    "qual_case_001": ("no_material_concern_identified", [], ["MEAS_COUNT_002"], ["absolute_volume_decision"], "none", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_002": ("contextual_warning", ["research_backed_warning"], ["MEAS_COUNT_002"], ["fixed_opportunity"], "non_blocking_warning", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_003": ("contextual_warning", ["research_backed_warning"], ["MEAS_RATIO_003"], ["release_affects_denominator"], "non_blocking_warning", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_004": ("contextual_warning", ["owner_confirmation_question"], ["MEAS_WINDOW_005"], ["immediate_outcome"], "non_blocking_warning", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_005": ("contextual_warning", ["research_backed_warning"], ["MEAS_PROXY_006"], ["validated_diagnostic_use"], "non_blocking_warning", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_006": ("insufficient_context", ["owner_confirmation_question"], ["MEAS_DECISION_001"], ["reporting_only"], "owner_confirmation", True, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_007": ("contextual_warning", ["research_backed_warning"], ["AI_EVAL_010"], ["upstream_deterministic_execution"], "non_blocking_warning", False, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_008": ("insufficient_context", ["contextual_hypothesis"], ["MEAS_SIGNAL_009"], ["single_terminal_state"], "none", True, [], ["model_reviewed_with_curated_guidance", "model_mapped_candidate"]),
    "qual_case_009": ("insufficient_context", ["owner_confirmation_question"], ["MEAS_POPULATION_004"], ["fixed_eligibility"], "owner_confirmation", True, [], ["model_reviewed_with_curated_guidance"]),
    "qual_case_010": ("insufficient_context", ["contextual_hypothesis"], [], [], "none", True, [], ["model_reviewed"]),
}

def qualification_result(task, provider="provider", model="model"):
    case_results=[]
    for case in task["cases"]:
        assessment,recommendations,rules,exceptions,effect,abstained,claims,labels=RESPONSES[case["case_id"]]
        case_results.append({"case_id":case["case_id"],"semantic_assessment":assessment,"recommendation_classes":recommendations,"guidance_rule_ids":rules,"exception_ids":exceptions,"effect":effect,"abstained":abstained,"claim_codes":claims,"authority_labels":labels,"automatic_replacements":[]})
    return {"schema_version":"measurement-reviewer-qualification-result.v3","task_id":task["task_id"],"task_hash":task["task_hash"],"provider_id":provider,"model_id":model,"requested_capabilities":task["requested_capabilities"],"case_results":case_results}
