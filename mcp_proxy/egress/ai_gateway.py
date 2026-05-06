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

from mcp_proxy.config import ProxySettings as Settings
from mcp_proxy.egress.schemas import ChatCompletionRequest, ChatCompletionResponse


# LiteLLM is imported lazily inside _call_litellm_embedded so deployments
# that pin ai_gateway_backend != "litellm_embedded" do not pay the import
# cost on startup. Spike validated 2026-05-03 against Anthropic Haiku 4.5
# (see imp/sandbox-gateways/test/spike_litellm_acompletion.py).

_log = logging.getLogger("agent_trust.egress")


CULLIS_FORWARD_HEADERS = "X-Cullis-Agent,X-Cullis-Org,X-Cullis-Trace"


@dataclass
class GatewayResult:
    response: ChatCompletionResponse
    latency_ms: int
    upstream_request_id: str | None
    backend: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float | None = None


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
    if backend == "litellm_embedded":
        return await _call_litellm_embedded(
            req=req,
            agent_id=agent_id,
            org_id=org_id,
            trace_id=trace_id,
            settings=settings,
        )
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
        detail=f"AI gateway backend '{backend}' is not wired.",
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
        prompt_tokens=int(parsed.usage.prompt_tokens or 0),
        completion_tokens=int(parsed.usage.completion_tokens or 0),
        cost_usd=None,
    )


# ── LiteLLM embedded backend (ADR-017 Phase 3) ─────────────────────────


# Map LiteLLM exception class names to (status_code, reason) tuples.
# We compare by class name rather than isinstance() so the import of
# litellm stays lazy (the dispatcher must boot in deployments that pin
# a non-LiteLLM backend without litellm installed).
_LITELLM_ERROR_MAP: dict[str, tuple[int, str]] = {
    "AuthenticationError": (401, "provider_auth_failed"),
    "PermissionDeniedError": (403, "provider_permission_denied"),
    "NotFoundError": (404, "provider_not_found"),
    "RateLimitError": (429, "provider_rate_limited"),
    "BadRequestError": (400, "provider_bad_request"),
    "UnprocessableEntityError": (422, "provider_unprocessable"),
    "Timeout": (504, "provider_timeout"),
    "APIConnectionError": (502, "provider_unreachable"),
    "ContextWindowExceededError": (400, "provider_context_too_long"),
    "ContentPolicyViolationError": (400, "provider_content_policy"),
    "InternalServerError": (502, "provider_internal_error"),
    "ServiceUnavailableError": (502, "provider_unavailable"),
    "APIError": (502, "provider_api_error"),
}


def _map_litellm_exception(exc: Exception) -> GatewayError:
    cls = type(exc).__name__
    status, reason = _LITELLM_ERROR_MAP.get(cls, (502, "provider_unknown_error"))
    detail = (str(exc) or cls)[:512]
    return GatewayError(status, reason, detail=detail)


async def _call_litellm_embedded(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
) -> GatewayResult:
    """Call the upstream provider via the LiteLLM library, in-process.

    The model id from the request is forwarded as-is. For Anthropic
    we expect the caller to pass either ``claude-haiku-4-5`` (LiteLLM
    auto-detects the provider from the catalogue) or
    ``anthropic/claude-haiku-4-5`` (explicit). The Mastio metadata is
    attached via the ``metadata`` kwarg so any LiteLLM callback the
    operator wires up (Datadog, Langfuse, Postgres) sees the agent
    identity without us doing extra plumbing.
    """
    provider = settings.ai_gateway_provider.lower()
    if provider != "anthropic":
        raise GatewayError(
            501,
            f"provider_not_implemented:{provider}",
            detail="Phase 3 only validates provider='anthropic' via LiteLLM.",
        )
    if not settings.anthropic_api_key:
        raise GatewayError(503, "provider_key_missing")

    try:
        import litellm
        from litellm import acompletion
    except ImportError as exc:
        raise GatewayError(
            503,
            "litellm_not_installed",
            detail=(
                "ai_gateway_backend='litellm_embedded' requires the litellm "
                "package. Install it via requirements.txt."
            ),
        ) from exc

    # Drop unsupported params silently rather than raising — keeps the
    # OpenAI-compat contract usable across providers that vary on minor
    # fields (e.g. Anthropic does not accept all OpenAI knobs).
    litellm.drop_params = True

    body = req.model_dump(exclude_none=True)
    # LiteLLM uses provider-prefixed model ids when ambiguous; pass
    # through whatever the caller sent.
    model = body.pop("model")

    metadata = {
        "cullis_agent_id": agent_id,
        "cullis_org_id": org_id,
        "cullis_trace_id": trace_id,
    }

    started = time.perf_counter()
    try:
        response = await acompletion(
            model=model,
            api_key=settings.anthropic_api_key,
            metadata=metadata,
            **body,
        )
    except Exception as exc:
        # Only the LiteLLM-shaped exceptions land in the map; anything
        # else (e.g. ValueError on bad input) becomes provider_unknown.
        gw_err = _map_litellm_exception(exc)
        _log.warning(
            "litellm_embedded error agent=%s model=%s reason=%s detail=%s",
            agent_id, model, gw_err.reason, gw_err.detail,
        )
        raise gw_err from exc

    latency_ms = int((time.perf_counter() - started) * 1000)

    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
    completion_tokens = getattr(usage, "completion_tokens", 0) or 0

    # response_cost is not on every LiteLLM build; compute it on demand
    # so we always surface a number in the audit row when the model is
    # in the LiteLLM cost catalogue. Failures here are informational —
    # the call succeeded, the cost is just unknown.
    cost_usd: float | None = None
    try:
        cost_usd = litellm.completion_cost(completion_response=response)
    except Exception as exc:
        _log.debug("litellm.completion_cost failed for model=%s: %s", model, exc)

    payload = response.model_dump() if hasattr(response, "model_dump") else dict(response)
    payload.setdefault("id", f"chatcmpl-{uuid.uuid4().hex[:24]}")
    payload.setdefault("object", "chat.completion")
    payload.setdefault("created", int(time.time()))
    payload.setdefault("model", model)
    payload["cullis_trace_id"] = trace_id
    # Force usage shape so Mastio's schema sees the canonical fields
    # even when LiteLLM adds provider-specific extras (cached_tokens,
    # reasoning_tokens) that our pydantic model would reject.
    payload["usage"] = {
        "prompt_tokens": int(prompt_tokens),
        "completion_tokens": int(completion_tokens),
        "total_tokens": int(prompt_tokens + completion_tokens),
    }

    try:
        parsed = ChatCompletionResponse.model_validate(payload)
    except Exception as exc:
        raise GatewayError(
            502,
            "schema_mismatch",
            detail=f"LiteLLM response failed Mastio schema: {exc}",
        ) from exc

    upstream_request_id = (
        getattr(response, "id", None)
        or (response.get("id") if isinstance(response, dict) else None)
    )

    _log.info(
        "egress.llm dispatched backend=litellm_embedded provider=%s agent=%s "
        "org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d cost_usd=%s",
        provider, agent_id, org_id, model, latency_ms,
        prompt_tokens, completion_tokens,
        f"{cost_usd:.6f}" if cost_usd is not None else "n/a",
    )

    return GatewayResult(
        response=parsed,
        latency_ms=latency_ms,
        upstream_request_id=upstream_request_id,
        backend="litellm_embedded",
        provider=provider,
        prompt_tokens=int(prompt_tokens),
        completion_tokens=int(completion_tokens),
        cost_usd=cost_usd,
    )
