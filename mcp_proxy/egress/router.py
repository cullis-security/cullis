"""
Egress API endpoints — internal agents authenticate with API keys and
communicate through the Cullis broker without seeing x509 keys, DPoP,
or any cryptography.

All endpoints require X-API-Key authentication (via get_agent_from_api_key).
"""
import logging
import time
import uuid

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.api_key import get_agent_from_api_key
from mcp_proxy.db import log_audit
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.router")

router = APIRouter(prefix="/v1/egress", tags=["egress"])


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────


class OpenSessionRequest(BaseModel):
    target_agent_id: str
    target_org_id: str
    capabilities: list[str]


class OpenSessionResponse(BaseModel):
    session_id: str
    status: str


class SendMessageRequest(BaseModel):
    session_id: str
    payload: dict
    recipient_agent_id: str


class DiscoverRequest(BaseModel):
    capabilities: list[str] | None = None
    q: str | None = None


class InvokeToolRequest(BaseModel):
    """Cross-org tool invocation via broker session."""
    session_id: str
    tool_name: str
    parameters: dict = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — BrokerBridge is injected at app startup via app.state
# ─────────────────────────────────────────────────────────────────────────────


def _get_bridge(request: Request):
    """Retrieve the BrokerBridge instance from app state."""
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is None:
        raise HTTPException(
            status_code=503,
            detail="Egress bridge not initialized — broker_url may be unconfigured",
        )
    return bridge


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/sessions", response_model=OpenSessionResponse)
async def open_session(
    body: OpenSessionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Open a broker session on behalf of internal agent."""
    bridge = _get_bridge(request)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    try:
        session_id = await bridge.open_session(
            agent.agent_id,
            body.target_agent_id,
            body.target_org_id,
            body.capabilities,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_open",
            status="success",
            detail=f"target={body.target_agent_id} session={session_id}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return OpenSessionResponse(session_id=session_id, status="opened")

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_open",
            status="error",
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        logger.error("Failed to open session for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.get("/sessions")
async def list_sessions(
    request: Request,
    status: str | None = None,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """List broker sessions for the authenticated agent."""
    bridge = _get_bridge(request)
    try:
        sessions = await bridge.list_sessions(agent.agent_id, status)
        return {"sessions": sessions}
    except Exception as exc:
        logger.error("Failed to list sessions for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/sessions/{session_id}/accept")
async def accept_session(
    session_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Accept a pending broker session."""
    bridge = _get_bridge(request)
    try:
        await bridge.accept_session(agent.agent_id, session_id)

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_accept",
            status="success",
            detail=f"session={session_id}",
        )

        return {"status": "accepted", "session_id": session_id}

    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_accept",
            status="error",
            detail=str(exc)[:500],
        )
        logger.error("Failed to accept session for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/sessions/{session_id}/close")
async def close_session(
    session_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Close a broker session."""
    bridge = _get_bridge(request)
    try:
        await bridge.close_session(agent.agent_id, session_id)

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_close",
            status="success",
            detail=f"session={session_id}",
        )

        return {"status": "closed", "session_id": session_id}

    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_close",
            status="error",
            detail=str(exc)[:500],
        )
        logger.error("Failed to close session %s: %s", session_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/send")
async def send_message(
    body: SendMessageRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Send E2E encrypted message via broker."""
    bridge = _get_bridge(request)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    try:
        await bridge.send_message(
            agent.agent_id,
            body.session_id,
            body.payload,
            body.recipient_agent_id,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send",
            status="success",
            detail=f"session={body.session_id} recipient={body.recipient_agent_id}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return {"status": "sent", "session_id": body.session_id}

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send",
            status="error",
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        if isinstance(exc, httpx.HTTPStatusError):
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=exc.response.text,
            ) from exc
        logger.error("Failed to send message for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.get("/messages/{session_id}")
async def poll_messages(
    session_id: str,
    request: Request,
    after: int = -1,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Poll for messages in a session."""
    bridge = _get_bridge(request)
    try:
        messages = await bridge.poll_messages(agent.agent_id, session_id, after)
        return {"messages": messages, "count": len(messages)}
    except Exception as exc:
        # Pass through broker HTTP status codes (e.g. 409 session closed)
        if isinstance(exc, httpx.HTTPStatusError):
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=exc.response.text,
            ) from exc
        logger.error("Failed to poll messages for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/discover")
async def discover_agents(
    body: DiscoverRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Discover remote agents on the network."""
    bridge = _get_bridge(request)
    try:
        agents = await bridge.discover_agents(
            agent.agent_id,
            capabilities=body.capabilities,
            q=body.q,
        )

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_discover",
            status="success",
            detail=f"capabilities={body.capabilities} q={body.q} results={len(agents)}",
        )

        return {"agents": agents, "count": len(agents)}

    except Exception as exc:
        logger.error("Failed to discover agents for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/tools/invoke")
async def invoke_remote_tool(
    body: InvokeToolRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Invoke a tool on a remote org via an active broker session.

    Sends a structured MCP tool_call message through the session.
    The remote agent receives the tool_call and should respond with
    a tool_result message in the same session.
    """
    bridge = _get_bridge(request)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    # Build MCP-format tool_call payload
    mcp_payload = {
        "type": "tool_call",
        "tool": body.tool_name,
        "parameters": body.parameters,
        "request_id": request_id,
    }

    try:
        # We need to know the recipient — infer from the session's target
        # For now, send to all participants in the session. The caller should
        # ensure the session is 1:1 with the target agent.
        sessions = await bridge.list_sessions(agent.agent_id)
        target_session = None
        for s in sessions:
            sid = s.get("session_id") or s.get("id")
            if sid == body.session_id:
                target_session = s
                break

        if target_session is None:
            raise HTTPException(
                status_code=404,
                detail=f"Session {body.session_id} not found for agent {agent.agent_id}",
            )

        # Determine recipient from session metadata
        recipient = (
            target_session.get("target_agent_id")
            or target_session.get("initiator_agent_id")
            or target_session.get("peer_agent_id", "")
        )
        # If agent is the initiator, send to target; if target, send to initiator
        initiator = target_session.get("initiator_agent_id", "")
        target = target_session.get("target_agent_id", "")
        if initiator == agent.agent_id:
            recipient = target
        elif target == agent.agent_id:
            recipient = initiator

        if not recipient:
            raise HTTPException(
                status_code=400,
                detail="Cannot determine recipient from session metadata",
            )

        await bridge.send_message(
            agent.agent_id,
            body.session_id,
            mcp_payload,
            recipient,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_tool_invoke",
            status="success",
            tool_name=body.tool_name,
            detail=f"session={body.session_id} recipient={recipient}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return {
            "status": "sent",
            "request_id": request_id,
            "session_id": body.session_id,
            "tool": body.tool_name,
            "recipient": recipient,
        }

    except HTTPException:
        raise
    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_tool_invoke",
            status="error",
            tool_name=body.tool_name,
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        logger.error(
            "Failed to invoke tool %s for %s: %s", body.tool_name, agent.agent_id, exc,
        )
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc
