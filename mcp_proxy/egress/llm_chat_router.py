"""ADR-017 Phase 4 — native AI gateway on Mastio.

Architecture (post-2026-05-06 fix): the Mastio is the AI gateway egress
point for its agents. No Court round trip:

  agent (mTLS+DPoP) → Mastio /v1/chat/completions
                    → mcp_proxy.egress.ai_gateway.dispatch
                    → litellm_embedded (in-process)
                    → upstream provider (Anthropic Haiku 4.5)

The Mastio authenticates the agent via the same mTLS+DPoP pair used by
the rest of ``mcp_proxy.egress.router`` (ADR-014), looks up the
agent's identity (already trusted from the cert), and dispatches the
chat completion in-process via the LiteLLM library. Mastio writes a
local audit row; cross-org dual-write to Court is a federation concern
(future PR), not a precondition for the gateway to work.

Court is never required for LLM calls. The Mastio runs standalone and
serves AI gateway egress for its agents without federating.
"""
from __future__ import annotations

import json
import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.auth.rate_limit import get_token_sum_limiter
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.ai_gateway import (
    GatewayError,
    StreamingDispatch,
    dispatch,
    dispatch_stream,
)
from mcp_proxy.egress.schemas import ChatCompletionRequest
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.llm_chat")

router = APIRouter(tags=["llm-chat"])


def _token_bucket_key(agent: InternalAgent) -> str:
    return f"principal:{agent.agent_id}:llm_tokens"


@router.post("/v1/chat/completions")
@router.post("/v1/llm/chat")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    settings = get_settings()
    trace_id = f"trace_{uuid.uuid4().hex[:16]}"

    if settings.llm_tokens_per_minute > 0:
        token_limiter = get_token_sum_limiter()
        bucket_key = _token_bucket_key(agent)
        current_sum = await token_limiter.peek(bucket_key)
        if current_sum >= settings.llm_tokens_per_minute:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_llm_chat",
                status="error",
                details={
                    "event": "llm.chat_completion",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "backend": settings.ai_gateway_backend,
                    "provider": settings.ai_gateway_provider,
                    "model": req.model,
                    "trace_id": trace_id,
                    "reason": "local_rate_limited_tokens",
                    "current_window_tokens": current_sum,
                    "limit_tokens_per_minute": settings.llm_tokens_per_minute,
                    "stream": req.stream,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "reason": "local_rate_limited_tokens",
                    "trace_id": trace_id,
                    "current_window_tokens": current_sum,
                    "limit_tokens_per_minute": settings.llm_tokens_per_minute,
                },
            )

    if req.stream:
        return await _handle_stream(
            req=req, agent=agent, settings=settings, trace_id=trace_id,
        )

    started = time.perf_counter()

    try:
        result = await dispatch(
            req=req,
            agent_id=agent.agent_id,
            org_id=settings.org_id,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            details={
                "event": "llm.chat_completion",
                "principal_id": agent.agent_id,
                "principal_type": agent.principal_type,
                "backend": settings.ai_gateway_backend,
                "provider": settings.ai_gateway_provider,
                "model": req.model,
                "trace_id": trace_id,
                "reason": exc.reason,
                "upstream_detail": exc.detail,
            },
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={"reason": exc.reason, "trace_id": trace_id},
        ) from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    payload = result.response.model_dump()
    payload.setdefault("cullis_trace_id", trace_id)

    if settings.llm_tokens_per_minute > 0:
        weight = int(result.prompt_tokens) + int(result.completion_tokens)
        await get_token_sum_limiter().consume(_token_bucket_key(agent), weight)

    await log_audit(
        agent_id=agent.agent_id,
        action="egress_llm_chat",
        status="success",
        duration_ms=float(latency_ms),
        details={
            "event": "llm.chat_completion",
            "principal_id": agent.agent_id,
            "principal_type": agent.principal_type,
            "backend": result.backend,
            "provider": result.provider,
            "model": req.model,
            "trace_id": trace_id,
            "upstream_request_id": result.upstream_request_id,
            "latency_ms": latency_ms,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "cost_usd": result.cost_usd,
            "cache_hit": False,
        },
    )

    logger.info(
        "egress_llm_chat agent=%s backend=%s model=%s latency_ms=%d trace_id=%s",
        agent.agent_id, result.backend, req.model, latency_ms, trace_id,
    )

    return payload


async def _handle_stream(
    *,
    req: ChatCompletionRequest,
    agent: InternalAgent,
    settings,
    trace_id: str,
) -> StreamingResponse:
    """Open the upstream stream and fan it out as Server-Sent Events.

    The handler is split out so the generator below can ``finally``-write
    the audit row and consume the per-principal token budget regardless
    of how the stream ends (success, upstream error mid-stream, client
    disconnect). The ``data: [DONE]`` sentinel is appended only on the
    happy path; on upstream error we emit a single ``data: {"error":...}``
    frame so OpenAI-shaped clients see a terminal event.
    """
    try:
        streamer: StreamingDispatch = await dispatch_stream(
            req=req,
            agent_id=agent.agent_id,
            org_id=settings.org_id,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            details={
                "event": "llm.chat_completion",
                "principal_id": agent.agent_id,
                "principal_type": agent.principal_type,
                "backend": settings.ai_gateway_backend,
                "provider": settings.ai_gateway_provider,
                "model": req.model,
                "trace_id": trace_id,
                "reason": exc.reason,
                "upstream_detail": exc.detail,
                "stream": True,
            },
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={"reason": exc.reason, "trace_id": trace_id},
        ) from exc

    async def sse():
        terminated_with_error: GatewayError | None = None
        try:
            async for chunk in streamer.aiter():
                # Inject the trace id on every chunk so a downstream
                # audit/observability consumer can correlate even on a
                # mid-stream client disconnect. The backend stays
                # trace-id-agnostic.
                chunk.setdefault("cullis_trace_id", trace_id)
                yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"
        except GatewayError as exc:
            terminated_with_error = exc
            # Audit H-IO-2 — ``exc.detail`` comes from str(exc) of the
            # underlying httpx / LiteLLM / pydantic error and would echo
            # provider chatter (timeouts, auth-key fragments, schema
            # mismatch text) back to the SSE consumer. Keep it in the
            # audit row below for ops triage; on the wire emit only the
            # stable reason tag + trace id.
            err_frame = {
                "error": {
                    "type": exc.reason,
                    "message": exc.reason,
                    "trace_id": trace_id,
                },
            }
            yield f"data: {json.dumps(err_frame)}\n\n"
        finally:
            if terminated_with_error is not None:
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_llm_chat",
                    status="error",
                    details={
                        "event": "llm.chat_completion",
                        "principal_id": agent.agent_id,
                        "principal_type": agent.principal_type,
                        "backend": streamer.backend,
                        "provider": streamer.provider,
                        "model": req.model,
                        "trace_id": trace_id,
                        "reason": terminated_with_error.reason,
                        "upstream_detail": terminated_with_error.detail,
                        "stream": True,
                        "prompt_tokens": streamer.prompt_tokens,
                        "completion_tokens": streamer.completion_tokens,
                    },
                )
            else:
                if settings.llm_tokens_per_minute > 0:
                    weight = (
                        int(streamer.prompt_tokens)
                        + int(streamer.completion_tokens)
                    )
                    if weight > 0:
                        await get_token_sum_limiter().consume(
                            _token_bucket_key(agent), weight,
                        )
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_llm_chat",
                    status="success",
                    duration_ms=float(streamer.latency_ms),
                    details={
                        "event": "llm.chat_completion",
                        "principal_id": agent.agent_id,
                        "principal_type": agent.principal_type,
                        "backend": streamer.backend,
                        "provider": streamer.provider,
                        "model": req.model,
                        "trace_id": trace_id,
                        "upstream_request_id": streamer.upstream_request_id,
                        "latency_ms": streamer.latency_ms,
                        "prompt_tokens": streamer.prompt_tokens,
                        "completion_tokens": streamer.completion_tokens,
                        "cost_usd": streamer.cost_usd,
                        "cache_hit": False,
                        "stream": True,
                    },
                )
                logger.info(
                    "egress_llm_chat (stream) agent=%s backend=%s model=%s "
                    "latency_ms=%d trace_id=%s",
                    agent.agent_id, streamer.backend, req.model,
                    streamer.latency_ms, trace_id,
                )

    return StreamingResponse(
        sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disable nginx response buffering so chunks reach the client
            # as they are produced, not at end-of-response.
            "X-Accel-Buffering": "no",
            "X-Cullis-Trace": trace_id,
        },
    )
