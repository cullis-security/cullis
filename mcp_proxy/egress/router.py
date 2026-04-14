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
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.routing import decide_route
from mcp_proxy.local.models import SessionCloseReason
from mcp_proxy.local.persistence import save_session as save_local_session
from mcp_proxy.local.session import (
    LocalAgentSessionCapExceeded,
    LocalSession,
    LocalSessionStore,
)
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.router")

router = APIRouter(prefix="/v1/egress", tags=["egress"])

import re as _re
_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)


def _validate_session_id(session_id: str) -> None:
    """Reject non-UUID session IDs to prevent log injection."""
    if not _UUID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")


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


def _get_local_store(request: Request) -> LocalSessionStore | None:
    """Return the local session store when ADR-001 Phase 3 is active."""
    return getattr(request.app.state, "local_session_store", None)


def _should_route_intra(recipient_agent_id: str, target_org_id: str = "") -> bool:
    """Check whether the caller should be routed by the local store.

    Called from each session endpoint before falling through to the
    broker bridge. When PROXY_INTRA_ORG is off, always false (preserves
    the pre-Phase-2 behavior). When on, the session-open path prefers
    the explicit target_org_id (authoritative from the caller's intent);
    other paths fall back to the SPIFFE-driven decide_route helper.
    """
    settings = get_settings()
    if not settings.intra_org_routing:
        return False
    if target_org_id:
        return target_org_id == settings.org_id
    route = decide_route(
        recipient_agent_id,
        local_org=settings.org_id,
        local_trust_domain=settings.trust_domain,
    )
    return route == "intra"


def _local_session_to_dict(session: LocalSession) -> dict:
    return {
        "session_id": session.session_id,
        "initiator_agent_id": session.initiator_agent_id,
        "target_agent_id": session.responder_agent_id,
        "status": session.status.value,
        "requested_capabilities": list(session.requested_capabilities),
        "created_at": session.created_at.isoformat(),
        "last_activity_at": session.last_activity_at.isoformat(),
        "close_reason": session.close_reason.value if session.close_reason else None,
        "scope": "local",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/sessions", response_model=OpenSessionResponse)
async def open_session(
    body: OpenSessionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Open a session on behalf of an internal agent.

    ADR-001 Phase 3a: when `PROXY_INTRA_ORG` is on and the target resolves
    to this proxy's (trust_domain, org), the session is created in the
    local store and never touches the broker. Otherwise the request falls
    through to the broker bridge exactly like before.
    """
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    local_store = _get_local_store(request)
    if local_store is not None and _should_route_intra(body.target_agent_id, body.target_org_id):
        try:
            session = local_store.create(
                initiator_agent_id=agent.agent_id,
                responder_agent_id=body.target_agent_id,
                requested_capabilities=body.capabilities,
            )
            await save_local_session(session)
            duration_ms = (time.monotonic() - t0) * 1000
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_session_open_local",
                status="success",
                detail=f"target={body.target_agent_id} session={session.session_id}",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return OpenSessionResponse(session_id=session.session_id, status="opened")
        except LocalAgentSessionCapExceeded as exc:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_session_open_local",
                status="error",
                detail=str(exc)[:500],
                request_id=request_id,
            )
            raise HTTPException(
                status_code=429,
                detail={"error": "session_cap_exceeded", "current": exc.current, "cap": exc.cap},
            ) from exc

    bridge = _get_bridge(request)
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
    """List sessions for the authenticated agent — local + broker merged."""
    local_store = _get_local_store(request)
    local_sessions: list[dict] = []
    if local_store is not None:
        for s in local_store.list_for_agent(agent.agent_id):
            if status is None or s.status.value == status:
                local_sessions.append(_local_session_to_dict(s))

    broker_sessions: list[dict] = []
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        try:
            broker_sessions = await bridge.list_sessions(agent.agent_id, status)
        except Exception as exc:
            logger.error("Failed to list broker sessions for %s: %s", agent.agent_id, exc)
            # Broker failure degrades to local-only listing rather than 502.
            broker_sessions = []

    return {"sessions": local_sessions + broker_sessions}


@router.post("/sessions/{session_id}/accept")
async def accept_session(
    session_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Accept a pending session (local or broker)."""
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    if local_store is not None:
        async with local_store._lock:
            session = local_store.get(session_id)
            if session is not None:
                if session.responder_agent_id != agent.agent_id:
                    raise HTTPException(status_code=403, detail="not the responder")
                session = local_store.activate(session_id)
                await save_local_session(session)
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_session_accept_local",
                    status="success",
                    detail=f"session={session_id}",
                )
                return {"status": "accepted", "session_id": session_id}

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
    """Close a session (local or broker)."""
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    if local_store is not None:
        async with local_store._lock:
            session = local_store.get(session_id)
            if session is not None:
                if not session.involves(agent.agent_id):
                    raise HTTPException(status_code=403, detail="not a participant")
                session = local_store.close(session_id, SessionCloseReason.normal)
                await save_local_session(session)
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_session_close_local",
                    status="success",
                    detail=f"session={session_id}",
                )
                return {"status": "closed", "session_id": session_id}

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
    _validate_session_id(body.session_id)
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
    _validate_session_id(session_id)
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
