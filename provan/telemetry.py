from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .state import secure_replace, state_root, write_pending
from .validators import validate_pending_envelope_semantics


def home() -> Path:
    return state_root()


def _settings() -> dict:
    path = home() / "telemetry.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"enabled": False}


def status() -> dict:
    settings = _settings()
    endpoint = os.environ.get("PROVAN_TELEMETRY_ENDPOINT")
    return {"schema_id": "provan.telemetry_status.v1", "enabled": bool(settings.get("enabled")), "transport": "CONFIGURED" if endpoint else "NOT_CONFIGURED", "identifier_policy": "per_envelope_pseudonymous_non_persistent", "installation_identity_collected": False, "cross_run_correlation": "UNSUPPORTED", "timed_rotation": "NOT_APPLICABLE", "recurring_installation_usage_measurement": "UNSUPPORTED"}


def configure(enabled: bool) -> dict:
    secure_replace(Path("telemetry.json"), (json.dumps({"enabled": enabled}, sort_keys=True) + "\n").encode("utf-8"))
    return status()


def clear_pending() -> dict:
    pending = home() / "pending"
    removed = 0
    if pending.exists():
        if pending.is_symlink() or not pending.is_dir():
            raise ProvanError("TELEMETRY_RETENTION_BOUNDARY_VIOLATION", "pending store is not a real directory")
        entries = list(pending.iterdir())
        if any(p.is_symlink() or not p.is_file() or p.suffix != ".json" for p in entries):
            raise ProvanError("TELEMETRY_RETENTION_BOUNDARY_VIOLATION", "pending store contains a non-envelope entry")
        removed = len(entries)
        shutil.rmtree(pending)
    return {"schema_id": "provan.telemetry_clear_pending.v1", "pending_envelopes_invalidated": removed, "timed_rotation": "NOT_APPLICABLE"}


def reset_id() -> dict:
    """Untimed compatibility alias; the CLI supplies the migration notice."""
    return clear_pending()


def preview(event: str = "doctor_completed") -> dict:
    envelope = {
        "schema_id": "provan.telemetry_pending_envelope.v1", "event": event,
        "event_id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
        "product_version": __version__,
    }
    validate_pending_envelope_semantics(envelope)
    data = canonical_bytes(envelope); digest = sha256_bytes(data)
    path = home() / "pending" / (digest.removeprefix("sha256:") + ".json")
    write_pending(path, data)
    return {"schema_id": "provan.telemetry_preview.v1", "envelope_digest": digest, "canonical_bytes_utf8": data.decode("utf-8"), "transport_metadata": {"endpoint_configured": bool(os.environ.get("PROVAN_TELEMETRY_ENDPOINT")), "ip_visible_to_transport": True, "headers": ["Content-Type", "Provan-Envelope-Digest"]}}


def send(digest: str, transport: Callable[[bytes, str], None]) -> dict:
    if not _settings().get("enabled"):
        raise ProvanError("TELEMETRY_DISABLED", "telemetry must be explicitly enabled")
    if not os.environ.get("PROVAN_TELEMETRY_ENDPOINT"):
        raise ProvanError("TELEMETRY_TRANSPORT_NOT_CONFIGURED", "no collector endpoint is configured")
    path = home() / "pending" / (digest.removeprefix("sha256:") + ".json")
    if not path.is_file():
        raise ProvanError("TELEMETRY_PREVIEW_PAYLOAD_MISMATCH", "send must reference an existing preview digest")
    data = path.read_bytes()
    if sha256_bytes(data) != digest:
        raise ProvanError("TELEMETRY_PREVIEW_PAYLOAD_MISMATCH", "pending envelope changed")
    transport(data, digest)
    return {"schema_id": "provan.telemetry_send_receipt.v1", "envelope_digest": digest, "bytes_sent": len(data)}
