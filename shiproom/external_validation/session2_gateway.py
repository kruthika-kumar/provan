"""The only approved Session 2 model-call gateway.

Selection, qualification, mutation and reviewer workers receive neither an API
key nor this object.  The gateway reserves budget before an outbound call and
records enough provider authority to stop on drift, without treating a probe
as evaluated output.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from typing import Any, Callable

from .session2 import BudgetLedger, Session2ValidationError


TERRA_REQUEST = {
    "model": "gpt-5.6-terra", "reasoning": {"effort": "high"}, "max_output_tokens": 16384,
    "store": False, "service_tier": "standard", "tools": [],
}
FORBIDDEN_WORKER_ENV = {"OPENAI_API_KEY", "OPENAI_BASE_URL", "SHIPROOM_MODEL_GATEWAY"}


class ModelGatewayError(RuntimeError):
    pass


def assert_non_observation_worker_environment(environment: dict[str, str] | None = None) -> None:
    values = os.environ if environment is None else environment
    if any(values.get(key) for key in FORBIDDEN_WORKER_ENV):
        raise ModelGatewayError("session2_non_observation_capability_violation")


@dataclass(frozen=True)
class ModelProbe:
    requested_model_id: str
    returned_model_id: str
    request_id: str
    timestamp: str
    api_version: str | None
    sdk_version: str | None
    system_fingerprint: str | None
    provider_metadata: dict[str, Any]

    def document(self) -> dict[str, Any]:
        return {"schema_id": "external_validation.session2_model_probe.v1", "schema_version": "1", "requested_model_id": self.requested_model_id, "returned_model_id": self.returned_model_id, "request_id": self.request_id, "timestamp": self.timestamp, "api_version": self.api_version, "sdk_version": self.sdk_version, "system_fingerprint": self.system_fingerprint, "provider_metadata": self.provider_metadata, "request": TERRA_REQUEST}


class OpenAIResponsesGateway:
    """A small adapter around an injected Responses API sender.

    The injected sender allows the production process to use its pinned SDK
    while unit tests cannot accidentally issue provider calls.
    """
    def __init__(self, ledger: BudgetLedger, sender: Callable[[dict[str, Any]], dict[str, Any]]):
        self.ledger, self._sender = ledger, sender

    @staticmethod
    def _metadata(response: dict[str, Any]) -> ModelProbe:
        if not isinstance(response, dict):
            raise ModelGatewayError("session2_provider_response_invalid")
        requested = TERRA_REQUEST["model"]
        returned = response.get("model")
        request_id = response.get("request_id") or response.get("_request_id")
        if returned != requested:
            raise ModelGatewayError("session2_model_returned_identity_changed")
        if not isinstance(request_id, str) or not request_id:
            raise ModelGatewayError("session2_provider_request_id_missing")
        fingerprint = response.get("system_fingerprint")
        if fingerprint is not None and not isinstance(fingerprint, str):
            raise ModelGatewayError("session2_model_fingerprint_invalid")
        return ModelProbe(requested, returned, request_id, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), response.get("api_version"), response.get("sdk_version"), fingerprint, dict(response.get("provider_metadata") or {}))

    def availability_probe(self) -> ModelProbe:
        """One content-free, reserved Session-2 availability probe."""
        attempt, key = "session2_probe_1", "session2-probe-1"
        self.ledger.reserve(attempt, key, "session2_probes", 1.0, input_tokens=0)
        self.ledger.transition(attempt, "SUBMITTED", provider_request_id="operation_session2_probe_1")
        try:
            # An empty input is intentionally not an evaluated repository or
            # benchmark prompt.  The sender is responsible for the pinned SDK.
            response = self._sender({**TERRA_REQUEST, "input": []})
        except BaseException:
            self.ledger.transition(attempt, "FAILED_MAX_CHARGED")
            raise
        probe = self._metadata(response)
        usage = response.get("usage")
        if not isinstance(usage, dict) or not isinstance(usage.get("cost_usd"), (int, float)):
            self.ledger.transition(attempt, "FAILED_MAX_CHARGED")
            raise ModelGatewayError("session2_provider_usage_unavailable")
        self.ledger.transition(attempt, "SETTLED", provider_request_id=probe.request_id, settled=float(usage["cost_usd"]))
        return probe


def assert_pre_execution_model_drift(session2_probe: ModelProbe, session3_probe: ModelProbe) -> None:
    if session3_probe.requested_model_id != "gpt-5.6-terra" or session3_probe.returned_model_id != session2_probe.returned_model_id:
        raise ModelGatewayError("session2_model_returned_identity_changed")
    if session3_probe.provider_metadata != session2_probe.provider_metadata:
        raise ModelGatewayError("session2_model_provider_metadata_changed")
