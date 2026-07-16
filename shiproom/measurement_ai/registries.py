"""Closed development-time registries for Measurement & AI Readiness v3.

The checked-in role and JSON Schema resources are generated from these values.
Release preparation snapshots those static resources; it never generates a
contract dynamically.
"""
from __future__ import annotations


METRIC_ROLES = ("outcome", "diagnostic", "guardrail", "operational_or_data_quality")
METRIC_DIMENSIONS = (
    "decision_use_case_alignment", "metric_role", "outcome_alignment", "population",
    "opportunity_exposure", "denominator", "window", "attribution",
    "interpretation_rule", "guardrails", "inference_intent_alignment",
)
AI_MATURITY_RUNGS = (
    "case_candidate", "fixed_input", "oracle_or_rubric", "pass_condition",
    "journey_or_criterion_linkage", "prompt_or_model_binding", "known_failure",
    "fallback", "malformed_output", "unavailable_model", "supplied_execution_result",
    "deterministically_validated_result", "production_trace_linkage",
)

MEASUREMENT_GAP_KINDS = (
    "outcome_event_definition_gap", "success_failure_distinction_gap",
    "critical_property_gap", "metric_decision_gap", "instrumentation_mapping_gap",
)
AI_GAP_KINDS = (
    "fixed_eval_gap", "claim_authority_gap", "failure_case_gap",
    "version_traceability_gap", "observability_gap",
)
ROLE_RESULT_SCHEMAS = {
    "measurement": "measurement-result.v3",
    "ai_evaluation": "ai-evaluation-result.v3",
}

DECISION_USE_CASES = (
    "launch_monitoring", "ongoing_kpi", "product_diagnosis",
    "comparative_noncausal_review", "causal_experiment", "operational_health",
    "safety_or_quality_guardrail",
)
INFERENCE_INTENTS = ("descriptive", "comparative_noncausal", "causal_experiment", "not_specified")
DENOMINATOR_STATES = ("not_required", "required_and_defined", "required_but_unresolved", "not_inspected")
DEFINITION_STATES = ("supplied_and_inspected", "declared_external", "not_supplied", "not_inspected")
EXECUTION_STATES = ("established", "not_established", "not_inspected")
DATA_ACCURACY_STATES = EXECUTION_STATES
EXPECTED_DIRECTIONS = ("increase", "decrease", "maintain", "not_specified")
UNIT_KINDS = ("count", "duration", "currency", "ratio", "percentage", "score", "boolean", "other")
DURATION_UNITS = ("seconds", "minutes", "hours", "days", "weeks")
AGGREGATION_METHODS = ("count", "sum", "mean", "median", "rate", "ratio", "percentage", "percentile", "distribution", "other")
GUARDRAIL_APPLICABILITY = ("applicable", "not_applicable", "owner_confirmation_required")

# ``kind`` is consumed by both the Python validator and schema generator.
MEASUREMENT_FIELD_SPECS = {
    "decision_question": {"kind": "text"},
    "decision_use_case": {"kind": "enum", "values": DECISION_USE_CASES},
    "decision_owner": {"kind": "text"},
    "decision_timing": {"kind": "text"},
    "decision_rule_or_interpretation": {"kind": "text"},
    "intended_outcome": {"kind": "text"},
    "unit": {"kind": "unit"},
    "unit_of_observation": {"kind": "text"},
    "eligible_population": {"kind": "text"},
    "exposure_or_opportunity_definition": {"kind": "exposure"},
    "numerator": {"kind": "estimand_component"},
    "denominator": {"kind": "estimand_component"},
    "denominator_state": {"kind": "enum", "values": DENOMINATOR_STATES},
    "eligible_denominator_population": {"kind": "text"},
    "zero_denominator_handling": {"kind": "text"},
    "release_can_affect_denominator": {"kind": "boolean"},
    "aggregation_level": {"kind": "aggregation"},
    "observation_window": {"kind": "duration"},
    "attribution_rule": {"kind": "text"},
    "expected_direction": {"kind": "enum", "values": EXPECTED_DIRECTIONS},
    "decision_threshold_or_interpretation": {"kind": "text"},
    "journey_start": {"kind": "text"},
    "success_condition": {"kind": "text"},
    "failure_condition": {"kind": "text"},
    "guardrails": {"kind": "guardrails"},
    "experiment_exposure": {"kind": "experiment_exposure"},
    "inference_intent": {"kind": "enum", "values": INFERENCE_INTENTS},
    "outcome_delay": {"kind": "duration"},
    "minimum_maturity_window": {"kind": "duration"},
    "incomplete_observation_possible": {"kind": "boolean"},
    "censoring_limitation": {"kind": "text"},
    "definition_state": {"kind": "enum", "values": DEFINITION_STATES},
    "execution_state": {"kind": "enum", "values": EXECUTION_STATES},
    "data_accuracy_state": {"kind": "enum", "values": DATA_ACCURACY_STATES},
}

TYPED_SOURCE_SUBTYPES = (
    "instrumentation_event_definition", "instrumentation_property_definition",
    "ai_fixed_input_definition", "ai_oracle_or_rubric_definition",
    "ai_pass_condition_definition", "ai_prompt_model_binding_definition",
    "ai_known_failure_case_definition", "ai_fallback_case_definition",
    "ai_malformed_output_case_definition", "ai_unavailable_model_case_definition",
)

RUNG_BASIS_TYPES = {
    "case_candidate": {"ai_fixed_input_definition", "test_reference"},
    "fixed_input": {"ai_fixed_input_definition"},
    "oracle_or_rubric": {"ai_oracle_or_rubric_definition"},
    "pass_condition": {"ai_pass_condition_definition"},
    "journey_or_criterion_linkage": set(TYPED_SOURCE_SUBTYPES),
    "prompt_or_model_binding": {"ai_prompt_model_binding_definition"},
    "known_failure": {"ai_known_failure_case_definition"},
    "fallback": {"ai_fallback_case_definition"},
    "malformed_output": {"ai_malformed_output_case_definition"},
    "unavailable_model": {"ai_unavailable_model_case_definition"},
    "supplied_execution_result": {"ai_execution", "runtime_evidence"},
    "deterministically_validated_result": {"ai_execution", "runtime_evidence"},
    "production_trace_linkage": {"production_trace", "runtime_evidence"},
}

PROJECTION_REGISTRY = {
    "measurement.contract_updates": ("measurement-contract.json", "measurement-ai-overlay.json"),
    "measurement.signal_assessments.event_candidates": ("instrumentation-coverage.json", "measurement-ai-overlay.json"),
    "measurement.signal_assessments.property_results": ("instrumentation-coverage.json", "measurement-ai-overlay.json"),
    "measurement.signal_assessments.tests": ("instrumentation-coverage.json", "measurement-ai-overlay.json"),
    "measurement.signal_assessments.runtime_evidence": ("instrumentation-coverage.json", "measurement-ai-overlay.json"),
    "measurement.metric_dimensions": ("measurement-ai-readiness.json",),
    "ai_evaluation.maturity_rungs": ("measurement-ai-readiness.json", "measurement-ai-overlay.json"),
    "ai_evaluation.judge_assessments": ("measurement-ai-readiness.json", "measurement-ai-overlay.json"),
    "ai_evaluation.claims": ("measurement-ai-readiness.json", "measurement-ai-overlay.json"),
    "ai_evaluation.observability_candidates": ("measurement-ai-readiness.json", "measurement-ai-overlay.json"),
    "common.gaps": ("launch-measurement-plan.json", "measurement-ai-overlay.json"),
    "common.recommendations": ("launch-measurement-plan.json", "measurement-ai-overlay.json"),
    "common.verifier_dispositions": ("measurement-ai-readiness.json", "launch-measurement-plan.json", "measurement-ai-overlay.json"),
    "common.owner_confirmation_proposals": ("launch-measurement-plan.json", "measurement-ai-overlay.json"),
    "common.assumptions": ("launch-measurement-plan.json", "measurement-ai-compiler-receipts.json"),
    "common.limitations": ("launch-measurement-plan.json", "measurement-ai-compiler-receipts.json"),
    "common.bases": ("owning_artifact", "measurement-ai-overlay.json"),
}
