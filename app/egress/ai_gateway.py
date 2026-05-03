"""AI gateway dispatch (ADR-017 Phase 1).

The dispatcher takes an OpenAI-compatible ChatCompletionRequest plus the
trusted agent identity (already reconstructed from the DPoP-bound cert
by the router) and forwards the call to the configured gateway. The
agent identity is injected as both the gateway-native attribution
header (e.g. x-portkey-metadata._user) and a canonical Cullis header
(X-Cullis-Agent) propagated through to the upstream provider, so audit
correlations work whether the dashboard speaks Cullis or gateway-native.

Phase 1 supports Portkey only. LiteLLM and Kong land in Phase 2 once
the smoke test confirms the contract.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.egress.schemas import ChatCompletionRequest, ChatCompletionResponse

_log = logging.getLogger("agent_trust.egress")


CULLIS_FORWARD_HEADERS = "X-Cullis-Agent,X-Cullis-Org,X-Cullis-Trace"


@dataclass
class GatewayResult:
    response: ChatCompletionResponse
    latency_ms: int
    upstream_request_id: str | None
    backend: str
    provider: str


class GatewayError(Exception):
    """Raised on any non-recoverable failure talking to the gateway.

    `status_code` is the HTTP code Mastio should return to its own
    caller; `reason` is a short tag suitable for the audit row.
    """

    def __init__(self, status_code: int, reason: str, *, detail: str | None = None):
        super().__init__(detail or reason)
        self.status_code = status_code
        self.reason = reason
        self.detail = detail


async def dispatch(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
    http_client: httpx.AsyncClient | None = None,
) -> GatewayResult:
    backend = settings.ai_gateway_backend.lower()
    if backend == "portkey":
        return await _call_portkey(
            req=req,
            agent_id=agent_id,
            org_id=org_id,
            trace_id=trace_id,
            settings=settings,
            http_client=http_client,
        )
    raise GatewayError(
        501,
        f"backend_not_implemented:{backend}",
        detail=f"AI gateway backend '{backend}' is not wired in Phase 1.",
    )


async def _call_portkey(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
    http_client: httpx.AsyncClient | None,
) -> GatewayResult:
    provider = settings.ai_gateway_provider.lower()
    if provider != "anthropic":
        raise GatewayError(
            501,
            f"provider_not_implemented:{provider}",
            detail="Phase 1 only validates provider='anthropic' against Portkey.",
        )

    if not settings.anthropic_api_key:
        raise GatewayError(503, "provider_key_missing")

    upstream_url = f"{settings.ai_gateway_url.rstrip('/')}/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.anthropic_api_key}",
        "x-portkey-provider": provider,
        "x-portkey-trace-id": trace_id,
        "x-portkey-forward-headers": CULLIS_FORWARD_HEADERS,
        "x-portkey-metadata": json.dumps(
            {"_user": agent_id, "org_id": org_id, "trace_id": trace_id},
            separators=(",", ":"),
        ),
        "X-Cullis-Agent": agent_id,
        "X-Cullis-Org": org_id,
        "X-Cullis-Trace": trace_id,
    }

    body = req.model_dump(exclude_none=True)

    started = time.perf_counter()
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=settings.ai_gateway_request_timeout_s)
    try:
        try:
            resp = await client.post(upstream_url, headers=headers, json=body)
        except httpx.TimeoutException as exc:
            raise GatewayError(504, "upstream_timeout", detail=str(exc)) from exc
        except httpx.HTTPError as exc:
            raise GatewayError(502, "upstream_unreachable", detail=str(exc)) from exc
    finally:
        if owns_client:
            await client.aclose()

    latency_ms = int((time.perf_counter() - started) * 1000)

    if resp.status_code // 100 != 2:
        # Surface the upstream body in the audit detail (capped) so
        # operators can debug without re-running the call.
        detail = resp.text[:512] if resp.text else None
        raise GatewayError(
            502,
            f"upstream_status_{resp.status_code}",
            detail=detail,
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        raise GatewayError(502, "malformed_upstream_body", detail=str(exc)) from exc

    payload.setdefault("id", f"chatcmpl-{uuid.uuid4().hex[:24]}")
    payload.setdefault("object", "chat.completion")
    payload.setdefault("created", int(time.time()))
    payload.setdefault("model", req.model)
    payload["cullis_trace_id"] = trace_id

    try:
        parsed = ChatCompletionResponse.model_validate(payload)
    except Exception as exc:  # pydantic ValidationError or similar
        raise GatewayError(
            502,
            "schema_mismatch",
            detail=f"Upstream payload failed Mastio schema: {exc}",
        ) from exc

    upstream_request_id = (
        resp.headers.get("x-portkey-request-id")
        or resp.headers.get("x-request-id")
    )

    _log.info(
        "egress.llm dispatched backend=portkey provider=%s agent=%s org=%s "
        "model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
        provider, agent_id, org_id, parsed.model, latency_ms,
        parsed.usage.prompt_tokens, parsed.usage.completion_tokens,
    )

    return GatewayResult(
        response=parsed,
        latency_ms=latency_ms,
        upstream_request_id=upstream_request_id,
        backend="portkey",
        provider=provider,
    )
