"""POST /v1/llm/chat — DPoP-authenticated egress to the AI gateway.

Mastio strips/ignores any client-supplied identity headers and re-stamps
the call with the agent_id reconstructed from the DPoP-bound JWT. This
is the trust boundary: a compromised connector cannot impersonate
another agent on the gateway dashboard, because the gateway only ever
sees the Mastio-injected `X-Cullis-Agent` (the connector's own header
on the same name is overwritten in the dispatcher).
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.config import get_settings
from app.db.audit import log_event
from app.db.database import get_db
from app.egress.ai_gateway import GatewayError, dispatch
from app.egress.schemas import ChatCompletionRequest, ChatCompletionResponse

_log = logging.getLogger("agent_trust.egress")

router = APIRouter(prefix="/llm", tags=["llm-egress"])


@router.post("/chat", response_model=ChatCompletionResponse)
async def chat_completion(
    req: ChatCompletionRequest,
    p: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> ChatCompletionResponse:
    if req.stream:
        # SSE forwarding lands in Phase 2 once the audit chain is wired
        # to record streamed token totals at the end-of-stream marker.
        raise HTTPException(
            status_code=400,
            detail="stream=true is not supported in Phase 1.",
        )

    settings = get_settings()
    trace_id = f"trace_{uuid.uuid4().hex[:16]}"

    try:
        result = await dispatch(
            req=req,
            agent_id=p.agent_id,
            org_id=p.org,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        await log_event(
            db,
            event_type="egress.llm.request",
            result="error",
            agent_id=p.agent_id,
            org_id=p.org,
            details={
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

    await log_event(
        db,
        event_type="egress.llm.request",
        result="ok",
        agent_id=p.agent_id,
        org_id=p.org,
        details={
            "backend": result.backend,
            "provider": result.provider,
            "model": result.response.model,
            "trace_id": trace_id,
            "upstream_request_id": result.upstream_request_id,
            "latency_ms": result.latency_ms,
            "prompt_tokens": result.response.usage.prompt_tokens,
            "completion_tokens": result.response.usage.completion_tokens,
            "total_tokens": result.response.usage.total_tokens,
        },
    )

    return result.response
