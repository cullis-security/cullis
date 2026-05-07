"""``POST /v1/guardian/inspect`` — bidirectional content inspection (ADR-016).

Phase 2 (this module): the endpoint now iterates the fast-path tools
registered in ``mcp_proxy.guardian.registry`` and merges their
verdicts (block > redact > pass), then enqueues a copy of the payload
on the slow-path hook (when the enterprise plugin has set one). The
public core stays adapter-agnostic — slow-path judges live in the
enterprise ``llm_guardian`` plugin and are wired via
``set_slow_path_hook`` at plugin startup.

The wire contract is unchanged from Phase 1: same request body, same
response shape, same audit row. Existing SDK clients (Phase 3) keep
working without any change.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.guardian.audit import record_inspection
from mcp_proxy.guardian.registry import ToolResult, registered_tools
from mcp_proxy.guardian.slow_path import SlowPathPayload, enqueue_slow_path
from mcp_proxy.guardian.ticket import GuardianTicketError, sign_ticket
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.guardian.endpoint")

router = APIRouter(tags=["guardian"])


class InspectRequest(BaseModel):
    direction: Literal["in", "out"]
    peer_agent_id: str = Field(..., min_length=1, max_length=512)
    msg_id: str = Field(..., min_length=1, max_length=128)
    content_type: str = Field(
        default="application/json+a2a-payload",
        max_length=128,
    )
    payload_b64: str = Field(..., min_length=1)


class InspectReason(BaseModel):
    tool: str
    match: str


class InspectResponse(BaseModel):
    decision: Literal["pass", "redact", "block"]
    ticket: str
    ticket_exp: int
    redacted_payload_b64: str | None = None
    audit_id: str
    reasons: list[InspectReason] = Field(default_factory=list)


@router.post("/v1/guardian/inspect", response_model=InspectResponse)
async def inspect(
    req: InspectRequest,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> InspectResponse:
    settings = get_settings()
    if not settings.guardian_ticket_key:
        # Refuse to issue tickets nobody can verify. Surface as 503 so
        # the SDK back-off path is the same as for any infra outage.
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "guardian_ticket_key_not_configured",
                "hint": "Set MCP_PROXY_GUARDIAN_TICKET_KEY (hex or base64url).",
            },
        )

    # Validate the payload encoding now (cheap) so a malformed b64 fails
    # before we write an audit row with garbage bytes attached.
    try:
        payload = base64.urlsafe_b64decode(
            req.payload_b64 + "=" * (-len(req.payload_b64) % 4),
        )
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": "malformed_payload_b64", "error": str(exc)},
        ) from exc

    audit_id = uuid.uuid4().hex

    # ── Fast-path dispatch (Phase 2) ────────────────────────────────
    #
    # Run every registered tool for the request direction (plus the
    # ``both``-direction tools) in parallel. Merge verdicts using a
    # block > redact > pass ordering so the strictest tool wins; on
    # redact, the latest non-None ``redacted_payload`` is forwarded
    # downstream. Reasons accumulate across all firing tools so the
    # audit row carries the full triage signal.
    fast_path_tools = registered_tools(direction=req.direction)
    ctx = {
        "agent_id": agent.agent_id,
        "peer_agent_id": req.peer_agent_id,
        "msg_id": req.msg_id,
        "direction": req.direction,
    }
    decision, redacted_payload, reasons = await _run_fast_path(
        tools=fast_path_tools, payload=payload, ctx=ctx,
    )

    try:
        ticket, ticket_exp = sign_ticket(
            key=settings.guardian_ticket_key,
            agent_id=agent.agent_id,
            peer_agent_id=req.peer_agent_id,
            msg_id=req.msg_id,
            direction=req.direction,
            decision=decision,
            audit_id=audit_id,
            ttl_s=settings.guardian_ticket_ttl_s,
        )
    except GuardianTicketError as exc:
        # Treat as 503 (config issue) rather than 500 — the operator
        # has a known fix (set/rotate the key).
        raise HTTPException(
            status_code=503,
            detail={"reason": exc.reason, "error": exc.detail or exc.reason},
        ) from exc

    try:
        await record_inspection(
            audit_id=audit_id,
            decision=decision,
            direction=req.direction,
            agent_id=agent.agent_id,
            peer_agent_id=req.peer_agent_id,
            msg_id=req.msg_id,
            org_id=settings.org_id,
            reasons=reasons,
            extra={
                "content_type": req.content_type,
                "phase": "fast_path",
                "tools_run": [t.name for t in fast_path_tools],
            },
        )
    except Exception:
        # Audit failure must not silently drop the decision; log loudly,
        # but still return the ticket — the SDK has already paid the
        # round trip. The slow-path queue in the enterprise plugin
        # also writes its own per-judge rows asynchronously.
        _log.exception(
            "guardian audit write failed agent=%s msg_id=%s",
            agent.agent_id, req.msg_id,
        )

    # ── Slow-path enqueue (Phase 4 hook, populated by enterprise plugin) ─
    enqueue_slow_path(SlowPathPayload(
        audit_id=audit_id,
        direction=req.direction,
        agent_id=agent.agent_id,
        peer_agent_id=req.peer_agent_id,
        msg_id=req.msg_id,
        # Pass the redacted form when we have one — the slow-path
        # judges should see the same bytes downstream eventually does.
        payload=redacted_payload if redacted_payload is not None else payload,
    ))

    redacted_b64: str | None = None
    if redacted_payload is not None:
        redacted_b64 = (
            base64.urlsafe_b64encode(redacted_payload).rstrip(b"=").decode("ascii")
        )

    return InspectResponse(
        decision=decision,
        ticket=ticket,
        ticket_exp=ticket_exp,
        redacted_payload_b64=redacted_b64,
        audit_id=audit_id,
        reasons=[InspectReason(**r) for r in reasons if "tool" in r and "match" in r],
    )


async def _run_fast_path(
    *, tools: list, payload: bytes, ctx: dict,
) -> tuple[Literal["pass", "redact", "block"], bytes | None, list[dict]]:
    """Run every fast-path tool concurrently, merge worst-decision-wins.

    Tools that raise are recorded in the reasons list as
    ``tool=<name> match=tool_error:<class>`` so a broken tool does not
    silently swallow the audit signal. The endpoint still returns a
    decision (the strictest seen among the surviving tools).
    """
    if not tools:
        return "pass", None, []

    async def _safe_eval(t):
        try:
            return t, await t.evaluate(payload, ctx), None
        except Exception as exc:
            return t, None, exc

    results = await asyncio.gather(*(_safe_eval(t) for t in tools))

    decision: Literal["pass", "redact", "block"] = "pass"
    redacted_payload: bytes | None = None
    reasons: list[dict] = []
    for tool, result, exc in results:
        if exc is not None:
            reasons.append({
                "tool": getattr(tool, "name", "<unnamed>"),
                "match": f"tool_error:{type(exc).__name__}",
            })
            continue
        if not isinstance(result, ToolResult):
            continue
        for r in result.reasons or []:
            reasons.append(r)
        if result.decision == "block":
            decision = "block"
            # Block wins — clear any redaction the previous tool returned;
            # we never want to deliver redacted bytes when another tool
            # said the whole thing must not pass.
            redacted_payload = None
        elif result.decision == "redact" and decision != "block":
            decision = "redact"
            if result.redacted_payload is not None:
                redacted_payload = result.redacted_payload
    return decision, redacted_payload, reasons
