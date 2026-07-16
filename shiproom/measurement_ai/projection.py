from __future__ import annotations


# Every substantive reviewer field accepted by a v3 result has a closed
# canonical destination.  The compiler records the destinations it actually
# consumed and rejects any accepted path without a handler.
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


def projection_destinations(field_path: str) -> tuple[str, ...]:
    try:
        return PROJECTION_REGISTRY[field_path]
    except KeyError as exc:
        raise ValueError(f"accepted reviewer field has no canonical projection: {field_path}") from exc


def validate_projection_coverage(accepted: set[str], projected: dict[str, set[str]]) -> None:
    unknown = accepted - set(PROJECTION_REGISTRY)
    if unknown:
        raise ValueError("accepted reviewer fields lack projection handlers: " + ",".join(sorted(unknown)))
    for field in sorted(accepted):
        expected = set(PROJECTION_REGISTRY[field])
        actual = projected.get(field, set())
        if actual != expected:
            raise ValueError(f"canonical projection mismatch for {field}")
