from __future__ import annotations

import os
import re
import uuid
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError


@dataclass(frozen=True)
class ModelProvider:
    provider_id: str
    model: str
    version: str
    endpoint: str


_PROVIDERS: dict[str, ModelProvider] = {}


def configure_provider(provider: ModelProvider) -> None:
    allow = {item.strip() for item in os.environ.get("PROVAN_MODEL_ALLOWLIST", "").split(",") if item.strip()}
    if provider.provider_id not in allow:
        raise ProvanError("MODEL_PROVIDER_NOT_ALLOWLISTED", "provider is not operator-configured and allowlisted")
    if not isinstance(provider.endpoint, str):
        raise ProvanError("MODEL_PROVIDER_ENDPOINT_INVALID", "provider endpoint must be credential-free HTTPS")
    parsed = urllib.parse.urlsplit(provider.endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ProvanError("MODEL_PROVIDER_ENDPOINT_INVALID", "provider endpoint must be credential-free HTTPS")
    hosts = {item.strip().lower() for item in os.environ.get("PROVAN_MODEL_HOST_ALLOWLIST", "").split(",") if item.strip()}
    if parsed.hostname.lower() not in hosts:
        raise ProvanError("MODEL_PROVIDER_ENDPOINT_NOT_ALLOWLISTED", "provider endpoint host is not operator-allowlisted")
    _PROVIDERS[provider.provider_id] = provider


def selected_provider(provider_id: str | None) -> ModelProvider | None:
    if provider_id:
        if provider_id not in _PROVIDERS:
            raise ProvanError("MODEL_PROVIDER_NOT_CONFIGURED", "requested provider is not configured and allowlisted")
        return _PROVIDERS[provider_id]
    return next(iter(_PROVIDERS.values()), None)


def build_envelope(*, case_id: str, candidate_digest: str, provider: ModelProvider,
                   instructions: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    prohibited = ("password=", "authorization:", "private key", "future challenge", "private eval", "private blueprint")
    combined = instructions + "\n" + "\n".join(str(block.get("content", "")) for block in blocks)
    if any(marker in combined.lower() for marker in prohibited):
        raise ProvanError("MODEL_ENVELOPE_PROHIBITED_CONTENT", "model envelope contains prohibited material")
    if re.search(r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+|https?://[^\s/@]+:[^\s/@]+@|AKIA[0-9A-Z]{16}",combined,re.I):
        raise ProvanError("MODEL_ENVELOPE_PROHIBITED_CONTENT","model envelope resembles credential-bearing material")
    selected = []
    for block in blocks:
        content = str(block["content"])
        selected.append({"category": block["category"], "content": content, "sha256": sha256_bytes(content.encode("utf-8"))})
    envelope = {
        "schema_id": "provan.model_input_envelope.v1",
        "envelope_id": str(uuid.uuid4()),
        "case_id": case_id,
        "candidate_digest": candidate_digest,
        "provider": provider.provider_id,
        "model": provider.model,
        "provider_version": provider.version,
        "prompt_id": "change-brief-synthesis",
        "prompt_version": "1",
        "instructions": instructions,
        "selected_blocks": selected,
        "limits": {"max_input_bytes": 262144, "max_output_tokens": 2048},
        "permitted_output_classes": ["model_reviewed_implications", "unresolved"],
    }
    if len(canonical_bytes(envelope)) > envelope["limits"]["max_input_bytes"]:
        raise ProvanError("MODEL_INPUT_LIMIT_EXCEEDED","canonical model envelope exceeds the declared byte limit")
    return envelope


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProvanError("MODEL_TRANSPORT_REDIRECT_FORBIDDEN", "model transport redirects are forbidden")


def _wire_transport(provider: ModelProvider, semantic_bytes: bytes, envelope_digest: str) -> dict[str, Any]:
    request = urllib.request.Request(
        provider.endpoint,
        data=semantic_bytes,
        method="POST",
        headers={"Content-Type": "application/json", "Provan-Envelope-Digest": envelope_digest},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > 1_048_576:
                raise ProvanError("MODEL_OUTPUT_LIMIT_INVALID", "provider response exceeds the byte limit")
            raw = response.read(1_048_577)
    except ProvanError:
        raise
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise ProvanError("MODEL_TRANSPORT_FAILED", "bounded model transport failed") from exc
    if len(raw) > 1_048_576:
        raise ProvanError("MODEL_OUTPUT_LIMIT_INVALID", "provider response exceeds the byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvanError("MODEL_OUTPUT_INVALID", "provider response is not UTF-8 JSON") from exc
    return value


def invoke(provider: ModelProvider, envelope: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    envelope_digest = sha256_bytes(canonical_bytes(envelope))
    semantic_request = {
        "instructions": envelope["instructions"],
        "selected_blocks": envelope["selected_blocks"],
        "permitted_output_classes": envelope["permitted_output_classes"],
    }
    semantic_bytes = canonical_bytes(semantic_request)
    started = time.perf_counter_ns()
    result = _wire_transport(provider, semantic_bytes, envelope_digest)
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    if not isinstance(result,dict) or set(result)-{"model_reviewed_implications","unresolved","cost_status"}:
        raise ProvanError("MODEL_OUTPUT_AUTHORITY_INVALID","provider returned undeclared semantic fields")
    for field in ("model_reviewed_implications","unresolved"):
        values=result.get(field,[])
        if not isinstance(values,list) or len(values)>128 or any(not isinstance(item,str) for item in values) or sum(len(item.encode()) for item in values)>65536:
            raise ProvanError("MODEL_OUTPUT_LIMIT_INVALID","provider output is not a bounded string list")
    return result, {
        "schema_id": "provan.model_usage_receipt.v1",
        "mode": "EXECUTED",
        "provider": provider.provider_id,
        "model": provider.model,
        "prompt_id": envelope["prompt_id"],
        "prompt_version": envelope["prompt_version"],
        "envelope_digest": envelope_digest,
        "calls": 1,
        "latency_ms": latency_ms,
        "latency_source": "provan_monotonic_elapsed",
        "cost_status": result.get("cost_status", "unavailable"),
    }


def zero_usage(mode: str = "DETERMINISTIC_FALLBACK") -> dict[str, Any]:
    return {"schema_id": "provan.model_usage_receipt.v1", "mode": mode, "provider": None, "model": None,
            "prompt_id": None, "prompt_version": None, "envelope_digest": None, "calls": 0,
            "latency_ms": None, "latency_source": "not-applicable", "cost_status": "not-applicable"}
