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
    reasoning_effort: str = "high"


_PROVIDERS: dict[str, ModelProvider] = {}

FROZEN_PUBLIC_MODEL_EGRESS: dict[str, tuple[str, ...]] = {
    "httpx-pr-3699-control": ("sha256:035e61942c06e5f1876761ee1dae1137dbf6eab1d6a5e7b6de5057594bdf8c0d",),
    "click-pr-3721-control": ("sha256:770ee6899ef381630d4dad60b2761a513aa8fad4425bc209de897a37008ad2a0",),
    "httpcore-pr-880-consequential": (
        "sha256:eab900ea1f679d5bea79c4080425b26b8320082884a83c35016e3868ceee4621",
        "sha256:17b6e4df0f971cc94079de630a151545886729b632c2678823978b78ece3c603",
        "sha256:0f649274796b2bbf3cd9549891965d8c86bb8a36749ec5b364ae560f4af19f27",
        "sha256:0b51599184bc1a4ea8ee93322cf6520a97f617bca7a88c1ae9267bad83171c58",
    ),
}


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


def invoke_frozen_public_openai_responses(provider: ModelProvider, envelope: dict[str, Any], api_key: str,
                                          egress_authorization: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute one stateless call only for a predeclared frozen public case digest set."""
    case_id = egress_authorization.get("case_id")
    selected = tuple(row.get("sha256") for row in envelope["selected_blocks"])
    if any(row.get("sha256") != sha256_bytes(str(row.get("content", "")).encode("utf-8")) for row in envelope["selected_blocks"]):
        raise ProvanError("MODEL_EGRESS_NOT_AUTHORIZED", "selected block digest mismatch")
    if (egress_authorization.get("classification") != "PUBLIC_SAFE" or
            egress_authorization.get("operator_confirmed") is not True or
            case_id not in FROZEN_PUBLIC_MODEL_EGRESS or selected != FROZEN_PUBLIC_MODEL_EGRESS[case_id]):
        raise ProvanError("MODEL_EGRESS_NOT_AUTHORIZED", "only the frozen named public case digest sets may leave the machine")
    if provider.endpoint != "https://api.openai.com":
        raise ProvanError("MODEL_PROVIDER_ENDPOINT_INVALID", "OpenAI origin is not pinned")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    auth = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    request = urllib.request.Request(f"{provider.endpoint}/v1/models/{urllib.parse.quote(provider.model, safe='')}", method="GET", headers=auth)
    try:
        with opener.open(request, timeout=20) as response: model_raw = response.read(262145)
        model_value = json.loads(model_raw.decode("utf-8"))
    except (OSError, urllib.error.URLError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvanError("MODEL_AVAILABILITY_CHECK_FAILED", "pinned model availability could not be validated") from exc
    if len(model_raw) > 262144 or model_value.get("id") != provider.model:
        raise ProvanError("MODEL_PIN_NOT_AVAILABLE", provider.model)
    envelope_digest = sha256_bytes(canonical_bytes(envelope))
    semantic_payload = {key: envelope[key] for key in ("instructions", "selected_blocks", "permitted_output_classes")}
    if provider.reasoning_effort not in {"medium", "high", "xhigh", "max"}:
        raise ProvanError("MODEL_REASONING_EFFORT_INVALID", provider.reasoning_effort)
    body = {"model":provider.model,"store":False,"background":False,"reasoning":{"effort":provider.reasoning_effort,"context":"current_turn"},"max_output_tokens":envelope["limits"]["max_output_tokens"],"input":json.dumps(semantic_payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)}
    request = urllib.request.Request(f"{provider.endpoint}/v1/responses",data=canonical_bytes(body),method="POST",headers={**auth,"Content-Type":"application/json","Provan-Envelope-Digest":envelope_digest})
    started=time.perf_counter_ns()
    try:
        with opener.open(request,timeout=300) as response: raw=response.read(1_048_577)
        wire=json.loads(raw.decode("utf-8"));output_text="".join(part.get("text","") for item in wire.get("output",[]) if item.get("type")=="message" for part in item.get("content",[]) if part.get("type")=="output_text");result=json.loads(output_text)
    except (OSError,urllib.error.URLError,ValueError,UnicodeDecodeError,json.JSONDecodeError,TypeError,AttributeError) as exc:
        raise ProvanError("MODEL_TRANSPORT_FAILED","bounded stateless Responses call failed") from exc
    if len(raw)>1_048_576 or not isinstance(result,dict) or set(result)!={"model_reviewed_implications","unresolved"}:raise ProvanError("MODEL_OUTPUT_AUTHORITY_INVALID","bounded output contract")
    for field in ("model_reviewed_implications","unresolved"):
        rows=result[field]
        if not isinstance(rows,list) or len(rows)>128 or any(not isinstance(row,str) for row in rows) or sum(len(row.encode("utf-8")) for row in rows)>65536:raise ProvanError("MODEL_OUTPUT_LIMIT_INVALID",field)
    usage=wire.get("usage") if isinstance(wire.get("usage"),dict) else {}
    return result,{"mode":"EXECUTED","provider":provider.provider_id,"model":provider.model,"reasoning_effort":provider.reasoning_effort,"reasoning_context":"current_turn","envelope_digest":envelope_digest,"calls":1,"latency_ms":(time.perf_counter_ns()-started)/1_000_000,"cost_status":"unavailable","input_tokens":usage.get("input_tokens"),"output_tokens":usage.get("output_tokens"),"store_requested":False,"provider_retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED","previous_response_id":None,"background":False}


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
