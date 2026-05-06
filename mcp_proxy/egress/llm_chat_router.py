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

import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.ai_gateway import GatewayError, dispatch
from mcp_proxy.egress.schemas import ChatCompletionRequest
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.llm_chat")

router = APIRouter(tags=["llm-chat"])


@router.post("/v1/chat/completions")
@router.post("/v1/llm/chat")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> dict:
    if req.stream:
        raise HTTPException(
            status_code=400,
            detail="stream=true is not supported in Phase 2.",
        )

    settings = get_settings()
    trace_id = f"trace_{uuid.uuid4().hex[:16]}"
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

    await log_audit(
        agent_id=agent.agent_id,
        action="egress_llm_chat",
        status="success",
        duration_ms=float(latency_ms),
        details={
            "event": "llm.chat_completion",
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
