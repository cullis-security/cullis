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
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator

import httpx

from mcp_proxy.config import ProxySettings as Settings
from mcp_proxy.db import get_ai_provider_creds
from mcp_proxy.egress.provider_catalog import (
    PROVIDERS,
    litellm_kwargs,
    parse_provider_from_model,
)
from mcp_proxy.egress.schemas import ChatCompletionRequest, ChatCompletionResponse


# LiteLLM is imported lazily inside _call_litellm_embedded so deployments
# that pin ai_gateway_backend != "litellm_embedded" do not pay the import
# cost on startup. Spike validated 2026-05-03 against Anthropic Haiku 4.5
# (see imp/sandbox-gateways/test/spike_litellm_acompletion.py).

_log = logging.getLogger("agent_trust.egress")


CULLIS_FORWARD_HEADERS = "X-Cullis-Agent,X-Cullis-Org,X-Cullis-Trace"


# Audit Wave A B2 (2026-05-11) — provider error bodies routinely echo
# back the rejected API key prefix (e.g. ``Incorrect API key provided:
# sk-ant-abc...``). Without scrubbing, those keys land in the immutable
# hash-chained Mastio audit log via ``upstream_detail``. Same class of
# leak as the third-party-gateway pattern flagged in
# ``feedback_third_party_ai_gateway_key_leak.md``. Patterns cover the
# common provider key shapes; the substitution preserves the field
# enough for ops debugging (provider, error class) without keeping
# the live secret.
_SECRET_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Anthropic console keys (``sk-ant-api03-...``) and project keys
    # (``sk-ant-...``). Match the prefix + non-whitespace tail.
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    # OpenAI legacy + project keys.
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}"),
    # Google AI Studio (Gemini) API keys.
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    # AWS Access Key IDs (Bedrock callers paste these into provider
    # creds when misconfiguring the secret as the access key).
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Bearer / Authorization headers leaked verbatim into bodies.
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{12,}"),
    # Cullis user API tokens.
    re.compile(r"culk_[A-Za-z0-9_\-]{16,}"),
)


def scrub_secrets(text: str | None) -> str | None:
    """Replace API key shapes with ``[REDACTED]`` before persisting text
    that may contain provider error echoes. Idempotent on already-scrubbed
    or secret-free input. Returns the input unchanged when None / empty
    so callers don't need to re-check."""
    if not text:
        return text
    out = text
    for pat in _SECRET_SCRUB_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


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


@dataclass
class StreamingDispatch:
    """Streaming counterpart of ``GatewayResult``.

    The router drives ``aiter()`` to fan-out chunks as SSE frames; once
    the stream drains, ``prompt_tokens`` / ``completion_tokens`` /
    ``cost_usd`` / ``upstream_request_id`` carry the final values used
    for the audit row and the per-principal token-budget consume. The
    backend implementation populates them while iterating.
    """

    backend: str
    provider: str
    model: str
    trace_id: str
    _aiter_factory: object = None  # async generator factory, set by impl
    started_at: float = field(default_factory=time.perf_counter)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float | None = None
    upstream_request_id: str | None = None
    latency_ms: int = 0

    def aiter(self) -> AsyncIterator[dict]:
        if self._aiter_factory is None:
            raise RuntimeError("StreamingDispatch.aiter called before backend wired it")
        return self._aiter_factory()


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


async def dispatch_stream(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
) -> StreamingDispatch:
    """Open a streaming dispatch.

    Returns a ``StreamingDispatch`` whose ``aiter()`` yields OpenAI-shape
    chunk dicts (``object=chat.completion.chunk``). The router converts
    them to SSE frames. Token usage + cost land on the dispatch object
    once the iterator drains, so the post-stream audit/rate-limit logic
    can read them without inspecting the chunks itself.
    """
    backend = settings.ai_gateway_backend.lower()
    if backend == "litellm_embedded":
        return await _build_litellm_stream(
            req=req,
            agent_id=agent_id,
            org_id=org_id,
            trace_id=trace_id,
            settings=settings,
        )
    raise GatewayError(
        501,
        f"streaming_not_implemented_for_backend:{backend}",
        detail=(
            f"Streaming on backend '{backend}' is not wired. "
            "Set ai_gateway_backend=litellm_embedded for stream=true."
        ),
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
    # Portkey path is Phase 1 (legacy). It only validates provider=anthropic
    # against Portkey's chat-completions shim. The credential is still
    # sourced through the same DB-first resolver so deployments that
    # have already migrated to dashboard-managed keys keep working
    # whichever backend they pin.
    provider, creds = await _resolve_provider_creds(req.model, settings)
    if provider != "anthropic":
        raise GatewayError(
            501,
            f"provider_not_implemented:{provider}",
            detail="The Portkey backend only supports Anthropic. "
                   "Switch ai_gateway_backend to litellm_embedded.",
        )
    api_key = creds.get("api_key", "")
    if not api_key:
        raise GatewayError(503, "provider_key_missing")

    upstream_url = f"{settings.ai_gateway_url.rstrip('/')}/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
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
        # operators can debug without re-running the call. Scrub
        # provider key shapes (B2) so a 401 echo like "Incorrect API
        # key provided: sk-ant-..." doesn't immortalise the rejected
        # key in the hash-chained audit log.
        detail = scrub_secrets(resp.text[:512]) if resp.text else None
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
        # Audit F-B-119 — pydantic ValidationError ``str()`` interpolates
        # the offending input into the message. The input is the raw
        # upstream response — model output, tool args, conversation
        # context — and must not echo back to the OpenAI-shape caller.
        from mcp_proxy._http_safety import safe_http_detail
        raise GatewayError(
            502,
            "schema_mismatch",
            detail=safe_http_detail(
                exc,
                public_hint="upstream payload failed Mastio schema",
                log_context="ai_gateway.portkey.parse_response",
            ),
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
    # B2 — LiteLLM stringifies provider 4xx/5xx into ``str(exc)`` and
    # those bodies frequently echo the rejected API key prefix. Scrub
    # before the detail flows into ``upstream_detail`` on the audit row.
    detail = scrub_secrets((str(exc) or cls)[:512])
    return GatewayError(status, reason, detail=detail)


async def _resolve_provider_creds(
    model: str,
    settings: Settings,
) -> tuple[str, dict[str, str]]:
    """Pick the provider for a model id and return its credentials.

    Resolution:
      1. ``parse_provider_from_model`` maps the request model to a
         provider key (``anthropic``, ``openai``, ...).
      2. ``ai_provider_credentials`` row drives the credential dict.
      3. Backward compat: when the row is missing for ``anthropic`` we
         fall back to ``settings.anthropic_api_key`` so existing
         deployments that have not yet seeded the table keep working.
      4. ``provider_not_configured`` is raised on miss + no fallback;
         ``provider_disabled`` is raised on a row with ``enabled=False``.
    """
    provider = parse_provider_from_model(model)
    if provider not in PROVIDERS:
        raise GatewayError(
            501,
            f"provider_not_implemented:{provider}",
            detail=f"No catalog entry for provider {provider!r}.",
        )

    row = await get_ai_provider_creds(provider)
    if row is None:
        if provider == "anthropic" and settings.anthropic_api_key:
            return provider, {"api_key": settings.anthropic_api_key}
        raise GatewayError(
            503,
            "provider_not_configured",
            detail=(
                f"Provider {provider!r} is not configured. "
                "Add credentials in the Mastio dashboard "
                "(Settings → AI Providers)."
            ),
        )
    if not row["enabled"]:
        raise GatewayError(
            503,
            "provider_disabled",
            detail=f"Provider {provider!r} is configured but disabled.",
        )
    return provider, dict(row["creds"] or {})


async def _call_litellm_embedded(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
) -> GatewayResult:
    """Call the upstream provider via the LiteLLM library, in-process.

    The model id from the request drives provider resolution
    (``parse_provider_from_model``) and the credentials are read from
    the ``ai_provider_credentials`` table populated by the Mastio
    admin dashboard. The Mastio metadata is attached via the
    ``metadata`` kwarg so any LiteLLM callback the operator wires up
    (Datadog, Langfuse, Postgres) sees the agent identity without us
    doing extra plumbing.
    """
    body = req.model_dump(exclude_none=True)
    model = body.pop("model")
    provider, creds = await _resolve_provider_creds(model, settings)

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

    provider_kwargs = litellm_kwargs(provider, creds)

    metadata = {
        "cullis_agent_id": agent_id,
        "cullis_org_id": org_id,
        "cullis_trace_id": trace_id,
    }

    started = time.perf_counter()
    try:
        response = await acompletion(
            model=model,
            metadata=metadata,
            **provider_kwargs,
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
        # Audit F-B-119 — LiteLLM payload echoes through pydantic
        # ValidationError ``str()``. Same redaction posture as the
        # portkey branch above.
        from mcp_proxy._http_safety import safe_http_detail
        raise GatewayError(
            502,
            "schema_mismatch",
            detail=safe_http_detail(
                exc,
                public_hint="LiteLLM response failed Mastio schema",
                log_context="ai_gateway.litellm.parse_response",
            ),
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


async def _build_litellm_stream(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
) -> StreamingDispatch:
    """Build a ``StreamingDispatch`` backed by ``litellm.acompletion(stream=True)``.

    Resolve the provider + credentials before opening the SSE response
    so configuration errors (provider not configured, disabled, litellm
    not installed) are surfaced as a regular non-stream error. The
    underlying ``acompletion`` call still happens lazily on first
    iteration of ``_aiter`` so the SSE headers can flush immediately.
    """
    body = req.model_dump(exclude_none=True)
    model = body.pop("model")
    body.pop("stream", None)
    # Ask the upstream for a final usage chunk so we can audit accurate
    # token + cost numbers after the stream drains. Anthropic + OpenAI +
    # most LiteLLM-routed providers honour this OpenAI-spec field.
    stream_options = body.pop("stream_options", None) or {}
    stream_options.setdefault("include_usage", True)

    provider, creds = await _resolve_provider_creds(model, settings)

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
    litellm.drop_params = True

    provider_kwargs = litellm_kwargs(provider, creds)

    metadata = {
        "cullis_agent_id": agent_id,
        "cullis_org_id": org_id,
        "cullis_trace_id": trace_id,
    }

    dispatch_obj = StreamingDispatch(
        backend="litellm_embedded",
        provider=provider,
        model=model,
        trace_id=trace_id,
    )

    async def _aiter() -> AsyncIterator[dict]:
        try:
            stream = await acompletion(
                model=model,
                metadata=metadata,
                stream=True,
                stream_options=stream_options,
                **provider_kwargs,
                **body,
            )
        except Exception as exc:
            raise _map_litellm_exception(exc) from exc

        try:
            async for chunk in stream:
                payload = (
                    chunk.model_dump() if hasattr(chunk, "model_dump")
                    else dict(chunk)
                )
                payload.setdefault("object", "chat.completion.chunk")
                payload.setdefault("model", model)
                if dispatch_obj.upstream_request_id is None:
                    upstream_id = payload.get("id")
                    if upstream_id:
                        dispatch_obj.upstream_request_id = upstream_id
                # The final usage chunk has empty choices and a populated
                # ``usage`` dict; harvest it for the audit row, normalise
                # the shape so the SSE consumer always sees the canonical
                # OpenAI usage fields.
                usage = payload.get("usage")
                if isinstance(usage, dict):
                    pt = int(usage.get("prompt_tokens") or 0)
                    ct = int(usage.get("completion_tokens") or 0)
                    if pt or ct:
                        dispatch_obj.prompt_tokens = pt
                        dispatch_obj.completion_tokens = ct
                        payload["usage"] = {
                            "prompt_tokens": pt,
                            "completion_tokens": ct,
                            "total_tokens": pt + ct,
                        }
                yield payload
        except GatewayError:
            raise
        except Exception as exc:
            raise _map_litellm_exception(exc) from exc
        finally:
            dispatch_obj.latency_ms = int(
                (time.perf_counter() - dispatch_obj.started_at) * 1000
            )
            if dispatch_obj.prompt_tokens or dispatch_obj.completion_tokens:
                # ``completion_cost`` wants a full response object; in the
                # streaming path we've already drained it, so go through
                # ``cost_per_token`` (returns the (input, output) USD
                # tuple already multiplied by the token counts).
                try:
                    in_cost, out_cost = litellm.cost_per_token(
                        model=model,
                        prompt_tokens=dispatch_obj.prompt_tokens,
                        completion_tokens=dispatch_obj.completion_tokens,
                    )
                    dispatch_obj.cost_usd = float(in_cost) + float(out_cost)
                except Exception as exc:  # pragma: no cover — informational
                    _log.debug(
                        "litellm.cost_per_token (stream) failed model=%s: %s",
                        model, exc,
                    )
            _log.info(
                "egress.llm streamed backend=litellm_embedded provider=%s "
                "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d "
                "tokens_out=%d cost_usd=%s",
                provider, agent_id, org_id, model, dispatch_obj.latency_ms,
                dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens,
                f"{dispatch_obj.cost_usd:.6f}"
                if dispatch_obj.cost_usd is not None else "n/a",
            )

    dispatch_obj._aiter_factory = _aiter
    return dispatch_obj
