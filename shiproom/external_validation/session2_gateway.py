"""The only approved Session 2 model-call gateway.

Selection, qualification, mutation and reviewer workers receive neither an API
key nor this object.  The gateway reserves budget before an outbound call and
records enough provider authority to stop on drift, without treating a probe
as evaluated output.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import platform
import stat
from typing import Any, Callable
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .identity import canonical_json
from .security import _is_reparse, external_root
from .session2 import BudgetLedger, Session2ValidationError


TERRA_REQUEST = {
    "model": "gpt-5.6-terra", "reasoning": {"effort": "high"}, "max_output_tokens": 16384,
    "store": False, "service_tier": "standard", "tools": [],
}
FORBIDDEN_WORKER_ENV = {"OPENAI_API_KEY", "OPENAI_BASE_URL", "SHIPROOM_MODEL_GATEWAY"}
GATEWAY_CREDENTIAL_FILE = Path("/etc/shiproom-external-validation/gateway.env")
_MAX_GATEWAY_CREDENTIAL_FILE_BYTES = 8192


class ModelGatewayError(RuntimeError):
    pass


def responses_api_sender_from_environment(request: dict[str, Any]) -> dict[str, Any]:
    """Perform the sole production Responses request without exposing its key.

    This function is intentionally only usable by the root-owned gateway
    process.  Selection/mutation workers do not import or receive it.  It
    returns provider bytes as parsed JSON; usage normalization remains the
    gateway's responsibility so an absent provider cost can be max-charged.
    """
    key = gateway_credential_from_environment()
    if not isinstance(request, dict) or request.get("model") != TERRA_REQUEST["model"]:
        raise ModelGatewayError("session2_gateway_request_invalid")
    payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    http_request = Request(
        "https://api.openai.com/v1/responses", data=payload, method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(http_request, timeout=90) as response:  # nosec B310: fixed provider endpoint
            raw = response.read()
            request_id = response.headers.get("x-request-id")
    except HTTPError as exc:
        raise ModelGatewayError("session2_gateway_http_" + str(exc.code)) from exc
    except URLError as exc:
        raise ModelGatewayError("session2_gateway_network_failure") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelGatewayError("session2_gateway_response_invalid") from exc
    if not isinstance(value, dict):
        raise ModelGatewayError("session2_gateway_response_invalid")
    if request_id and "request_id" not in value and "_request_id" not in value:
        value["request_id"] = request_id
    return value


def _read_gateway_credential_file(path: Path) -> str:
    """Read the sole root-owned gateway credential without trusting a shell env.

    The worker-facing process environment never carries the provider key.  The
    root-only gateway opens one fixed file after checking every trusted parent
    and the opened descriptor itself.  This deliberately has no path or
    environment override: selection, mutation, review, and patient workers
    cannot redirect credential authority.
    """
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        raise ModelGatewayError("session2_gateway_credential_unavailable")
    if path != GATEWAY_CREDENTIAL_FILE or not path.is_absolute():
        raise ModelGatewayError("session2_gateway_credential_path_invalid")
    parents = (Path("/"), Path("/etc"), path.parent)
    for parent in parents:
        try:
            parent_stat = os.lstat(parent)
        except OSError as exc:
            raise ModelGatewayError("session2_gateway_credential_parent_invalid") from exc
        if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
            raise ModelGatewayError("session2_gateway_credential_parent_invalid")
        if parent_stat.st_uid != 0 or parent_stat.st_gid != 0 or parent_stat.st_mode & 0o022:
            raise ModelGatewayError("session2_gateway_credential_parent_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ModelGatewayError("session2_gateway_credential_unavailable") from exc
    try:
        file_stat = os.fstat(descriptor)
        if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != 0 or file_stat.st_gid != 0
                or stat.S_IMODE(file_stat.st_mode) != 0o600 or file_stat.st_nlink != 1
                or file_stat.st_size <= 0 or file_stat.st_size > _MAX_GATEWAY_CREDENTIAL_FILE_BYTES):
            raise ModelGatewayError("session2_gateway_credential_file_invalid")
        raw = os.read(descriptor, _MAX_GATEWAY_CREDENTIAL_FILE_BYTES + 1)
        if len(raw) != file_stat.st_size or len(raw) > _MAX_GATEWAY_CREDENTIAL_FILE_BYTES:
            raise ModelGatewayError("session2_gateway_credential_file_invalid")
    finally:
        os.close(descriptor)
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModelGatewayError("session2_gateway_credential_file_invalid") from exc
    prefix = "OPENAI_API_KEY="
    if not content.startswith(prefix) or not content.endswith("\n") or content.count("\n") != 1:
        raise ModelGatewayError("session2_gateway_credential_file_invalid")
    key = content[len(prefix):-1]
    if not key or any(character in key for character in "\x00\r\n"):
        raise ModelGatewayError("session2_gateway_credential_file_invalid")
    return key


def gateway_credential_from_environment() -> str:
    """Return the gateway-only credential before a budget reservation exists.

    Kept under its original public name for the caller contract; production
    authority is the fixed root-owned credential file, never an inherited
    environment variable.
    """
    return _read_gateway_credential_file(GATEWAY_CREDENTIAL_FILE)


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
    def __init__(self, ledger: BudgetLedger, sender: Callable[[dict[str, Any]], dict[str, Any]],
                 *, preflight: Callable[[], None] | None = None):
        self.ledger, self._sender, self._preflight = ledger, sender, preflight

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

    def availability_probe(self, *, attempt_id: str = "session2_probe_1",
                           idempotency_key: str = "session2-probe-1") -> ModelProbe:
        """One content-free, reserved Session-2 availability probe."""
        if (not isinstance(attempt_id, str) or not isinstance(idempotency_key, str)
                or not attempt_id.startswith("session2_probe_")
                or not idempotency_key.startswith("session2-probe-")):
            raise ModelGatewayError("session2_model_probe_attempt_invalid")
        # A missing local credential proves no request can have been sent, so
        # it must fail before creating a reservation.  Provider/network
        # uncertainty is handled only after durable SUBMITTED authority.
        if self._preflight is not None:
            self._preflight()
        self.ledger.reserve(attempt_id, idempotency_key, "session2_probes", 1.0, input_tokens=0)
        self.ledger.transition(attempt_id, "SUBMITTED", provider_request_id="operation_" + attempt_id)
        try:
            # An empty input is intentionally not an evaluated repository or
            # benchmark prompt.  The sender is responsible for the pinned SDK.
            response = self._sender({**TERRA_REQUEST, "input": []})
        except BaseException:
            self.ledger.transition(attempt_id, "FAILED_MAX_CHARGED")
            raise
        probe = self._metadata(response)
        usage = response.get("usage")
        # Responses returns token usage, not a provider dollar charge.  The
        # frozen Session-2 rule therefore max-charges an unavailable/malformed
        # charge rather than fabricating a price or releasing a sent request.
        if not isinstance(usage, dict) or not isinstance(usage.get("cost_usd"), (int, float)):
            self.ledger.transition(attempt_id, "FAILED_MAX_CHARGED")
            return probe
        self.ledger.transition(attempt_id, "SETTLED", provider_request_id=probe.request_id, settled=float(usage["cost_usd"]))
        return probe


def _probe_root(repository_root: Path) -> Path:
    if os.name != "posix" or platform.system() != "Linux" or os.geteuid() != 0:
        raise ModelGatewayError("session2_model_probe_requires_root_linux_wsl")
    try:
        root = external_root(None, repository_root)
    except PermissionError as exc:
        raise ModelGatewayError("session2_model_probe_external_root_invalid") from exc
    if root != Path("/var/lib/shiproom-external-validation") or _is_reparse(root):
        raise ModelGatewayError("session2_model_probe_external_root_invalid")
    target = root / "session2" / "model" / "probes"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    if _is_reparse(target):
        raise ModelGatewayError("session2_model_probe_external_root_invalid")
    return target


def seal_availability_probe(repository_root: Path, gateway: OpenAIResponsesGateway, *,
                            attempt_id: str = "session2_probe_1",
                            idempotency_key: str = "session2-probe-1") -> dict[str, str]:
    """Perform and content-address the sole content-free Session-2 probe.

    The private receipt binds the real provider response and the append-only
    logical ledger checkpoint.  A failed provider request deliberately leaves
    its max-charged ledger authority intact but cannot yield a probe receipt.
    """
    target = _probe_root(repository_root)
    if list(target.glob("*.model-probe.json")):
        raise ModelGatewayError("session2_model_probe_already_attempted")
    probe = gateway.availability_probe(attempt_id=attempt_id, idempotency_key=idempotency_key)
    document = {**probe.document(), "evaluated_model_call_count": 0,
                "shiproom_evaluated_output_count": 0,
                "comparator_evaluated_output_count": 0,
                "budget_ledger_checkpoint": gateway.ledger.checkpoint()}
    raw = canonical_json(document)
    digest = "sha256:" + sha256(raw).hexdigest()
    path = target / (digest[7:] + ".model-probe.json")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400)
    except FileExistsError:
        if _is_reparse(path) or path.read_bytes() != raw:
            raise ModelGatewayError("session2_model_probe_collision")
    else:
        try:
            if os.write(descriptor, raw) != len(raw):
                raise ModelGatewayError("session2_model_probe_short_write")
            os.fsync(descriptor)
            if hasattr(os, "fchown"):
                os.fchown(descriptor, 0, 0)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
    return {"model_probe_hash": digest, "model_probe_opaque_id": path.name}


def assert_pre_execution_model_drift(session2_probe: ModelProbe, session3_probe: ModelProbe) -> None:
    if session3_probe.requested_model_id != "gpt-5.6-terra" or session3_probe.returned_model_id != session2_probe.returned_model_id:
        raise ModelGatewayError("session2_model_returned_identity_changed")
    if session3_probe.provider_metadata != session2_probe.provider_metadata:
        raise ModelGatewayError("session2_model_provider_metadata_changed")
