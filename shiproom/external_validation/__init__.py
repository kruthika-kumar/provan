"""Fail-closed control plane for external validation experiments.

Nothing in this package mounts or executes a patient repository without the
Docker qualification gate.  It intentionally has no dependency on Shiproom's
legacy local command runner.
"""

from .identity import case_id, observation_key, schedule_id, attempt_id, receipt_id, cost_view_id
from .validators import ValidationError, validate_artifact

__all__ = ["ValidationError", "attempt_id", "case_id", "cost_view_id", "observation_key", "receipt_id", "schedule_id", "validate_artifact"]
