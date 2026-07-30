"""Root-only, content-free Session 2 OpenAI model-metadata probe.

This recovery entry point is intentionally fixed to the one explicitly
approved third ledger attempt.  Attempts one and two are immutable terminal
records from the credential and request-shape defects; this process cannot
overwrite or reuse either one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .session2 import BudgetPolicy
from .session2_gateway import (OpenAIResponsesGateway,
                               gateway_credential_from_environment,
                               responses_api_sender_from_environment,
                               seal_availability_probe)
from .session2_storage import open_budget_ledger

RECOVERY_ATTEMPT_ID = "session2_probe_3"
RECOVERY_IDEMPOTENCY_KEY = "session2-probe-3"


def run() -> dict[str, str]:
    """Execute the one approved metadata lookup from an immutable stage."""
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("root_required")
    stage = Path(__file__).resolve().parents[2]
    ledger = open_budget_ledger(stage, BudgetPolicy())
    gateway = OpenAIResponsesGateway(ledger, responses_api_sender_from_environment,
                                     preflight=gateway_credential_from_environment)
    return seal_availability_probe(stage, gateway, attempt_id=RECOVERY_ATTEMPT_ID,
                                   idempotency_key=RECOVERY_IDEMPOTENCY_KEY)


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
