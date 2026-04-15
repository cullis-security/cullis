"""
Egress API endpoints — internal agents authenticate with API keys and
communicate through the Cullis broker without seeing x509 keys, DPoP,
or any cryptography.

All endpoints require X-API-Key authentication (via get_agent_from_api_key).
"""
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.api_key import get_agent_from_api_key
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.routing import decide_route
from mcp_proxy.local import message_queue as local_queue
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
    # ADR-001 Phase 3c — at-least-once fields (mirror broker M3 SDK params).
    # Optional; omitting them keeps pre-3c client behavior.
    ttl_seconds: int = Field(default=local_queue.DEFAULT_TTL_SECONDS, ge=10, le=3600)
    idempotency_key: str | None = None
    # ADR-001 §10 — intra-org mtls-only mode. When omitted or "envelope",
    # payload is opaque ciphertext (legacy behavior). When "mtls-only",
    # payload is plaintext and signature + nonce + timestamp are required
    # so the proxy can verify the sender's signature before enqueueing.
    mode: Literal["envelope", "mtls-only"] = "envelope"
    signature: str | None = None
    nonce: str | None = None
    timestamp: int | None = None
    sender_seq: int | None = None


class DiscoverRequest(BaseModel):
    capabilities: list[str] | None = None
    q: str | None = None


class ResolveRequest(BaseModel):
    """ADR-001 §10 — resolve a recipient and return routing path + metadata.

    The SDK calls this before sending so it can choose the right wire
    format: mtls-only (signed, not encrypted) for intra-org in the
    mtls-only transport mode, or envelope (E2E encrypted) otherwise.
    """
    recipient_id: str


class ResolveResponse(BaseModel):
    path: Literal["intra-org", "cross-org"]
    target_agent_id: str
    target_org_id: str
    target_spiffe: str | None = None
    transport: Literal["envelope", "mtls-only"]
    egress_inspection: bool = False
    target_cert_pem: str | None = None


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
    """Send an E2E-encrypted message.

    ADR-001 Phase 3c: when `body.session_id` refers to a local session,
    the message is enqueued on `local_messages` and pushed over the
    recipient's local WS if connected. Otherwise the request falls
    through to the broker bridge exactly like before.
    """
    _validate_session_id(body.session_id)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    local_store = _get_local_store(request)
    local_session = local_store.get(body.session_id) if local_store else None
    if local_session is not None:
        if not local_session.involves(agent.agent_id):
            raise HTTPException(status_code=403, detail="not a participant")
        if agent.agent_id == local_session.initiator_agent_id:
            recipient = local_session.responder_agent_id
        else:
            recipient = local_session.initiator_agent_id

        # ADR-001 §10 — mtls-only path: sender signs plaintext, proxy verifies
        # the signature before enqueueing. The stored blob carries mode +
        # signature + nonce + timestamp so the recipient SDK can re-verify.
        # Legacy envelope mode stores the opaque ciphertext as-is.
        import json as _json

        if body.mode == "mtls-only":
            from cullis_sdk.crypto import verify_signature

            missing = [
                f for f in ("signature", "nonce", "timestamp")
                if getattr(body, f) is None
            ]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"mtls-only requires fields: {', '.join(missing)}",
                )
            if not agent.cert_pem:
                raise HTTPException(
                    status_code=400,
                    detail="sender has no cert — cannot verify mtls-only signature",
                )
            ok = verify_signature(
                agent.cert_pem,
                body.signature,
                body.session_id,
                agent.agent_id,
                body.nonce,
                body.timestamp,
                body.payload,
                client_seq=body.sender_seq,
            )
            if not ok:
                raise HTTPException(
                    status_code=401,
                    detail="mtls-only signature verification failed",
                )
            stored_blob = _json.dumps(
                {
                    "mode": "mtls-only",
                    "payload": body.payload,
                    "signature": body.signature,
                    "nonce": body.nonce,
                    "timestamp": body.timestamp,
                    "sender_seq": body.sender_seq,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            payload_cipher = stored_blob
        else:
            # Legacy envelope — ciphertext opaque.
            payload_cipher = _json.dumps(body.payload, separators=(",", ":"))

        try:
            msg_id, inserted = await local_queue.enqueue(
                session_id=body.session_id,
                sender_agent_id=agent.agent_id,
                recipient_agent_id=recipient,
                payload_ciphertext=payload_cipher,
                ttl_seconds=body.ttl_seconds,
                idempotency_key=body.idempotency_key,
            )
        except Exception as exc:
            logger.error("Local enqueue failed for %s: %s", agent.agent_id, exc)
            raise HTTPException(status_code=500, detail="enqueue_failed") from exc

        local_session.touch()
        await save_local_session(local_session)

        # Push-vs-queue: if the recipient is connected, deliver immediately.
        # Even when we push, the row stays pending until the recipient ack's
        # so a crash between send_json and ack does not drop the message.
        ws_manager = getattr(request.app.state, "local_ws_manager", None)
        pushed = False
        if ws_manager is not None and ws_manager.is_connected(recipient):
            push_frame = {
                "type": "new_message",
                "session_id": body.session_id,
                "msg_id": msg_id,
                "sender_agent_id": agent.agent_id,
                "payload": body.payload,
                "enqueued_at": datetime.now(timezone.utc).isoformat(),
                "mode": body.mode,
            }
            if body.mode == "mtls-only":
                push_frame["signature"] = body.signature
                push_frame["nonce"] = body.nonce
                push_frame["timestamp"] = body.timestamp
                push_frame["sender_seq"] = body.sender_seq
            pushed = await ws_manager.send_to_agent(recipient, push_frame)

        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send_local",
            status="success",
            detail=(
                f"session={body.session_id} recipient={recipient} "
                f"msg_id={msg_id} inserted={inserted} pushed={pushed}"
            ),
            request_id=request_id,
            duration_ms=duration_ms,
        )
        return {
            "status": "sent",
            "session_id": body.session_id,
            "msg_id": msg_id,
            "delivered_via": "ws" if pushed else "queue",
            "duplicate": not inserted,
        }

    if body.mode == "mtls-only":
        # Cross-org through the broker cannot use mtls-only — broker is a
        # non-trusted hop and must only see ciphertext. Reject early so the
        # SDK caller surfaces a clear error instead of leaking plaintext.
        raise HTTPException(
            status_code=400,
            detail="mtls-only is intra-org only; use envelope for cross-org sessions",
        )

    bridge = _get_bridge(request)
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
    """Poll for messages in a session (local or broker).

    Local path returns pending messages for the caller; the caller must
    still hit the ack endpoint before we flip them to `delivered`. That
    keeps at-least-once semantics even when clients prefer REST polling
    over the WebSocket push.
    """
    _validate_session_id(session_id)

    local_store = _get_local_store(request)
    local_session = local_store.get(session_id) if local_store else None
    if local_session is not None:
        if not local_session.involves(agent.agent_id):
            raise HTTPException(status_code=403, detail="not a participant")
        local_session.touch()
        await save_local_session(local_session)
        pending = await local_queue.fetch_pending_for_recipient(agent.agent_id)
        # Only messages that belong to this session — the queue is global
        # per recipient but the caller asked for a specific session.
        msgs = [m for m in pending if m.session_id == session_id]
        payload = [
            {
                "msg_id": m.msg_id,
                "session_id": m.session_id,
                "sender_agent_id": m.sender_agent_id,
                "payload_ciphertext": m.payload_ciphertext,
                "enqueued_at": m.enqueued_at.isoformat() if m.enqueued_at else None,
            }
            for m in msgs
        ]
        return {"messages": payload, "count": len(payload), "scope": "local"}

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


@router.post("/sessions/{session_id}/messages/{msg_id}/ack")
async def ack_message(
    session_id: str,
    msg_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Acknowledge delivery of a queued local message (ADR-001 Phase 3c).

    Only applies to local sessions. Cross-org ack stays implicit via the
    broker's M3 ack endpoint. Returns 404 when the msg_id doesn't exist,
    is already delivered, or belongs to another recipient (same shape
    across all three to avoid enumeration).
    """
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    local_session = local_store.get(session_id) if local_store else None
    if local_session is None:
        raise HTTPException(status_code=404, detail="session_not_local")
    if not local_session.involves(agent.agent_id):
        raise HTTPException(status_code=403, detail="not a participant")

    ok = await local_queue.mark_delivered(msg_id, agent.agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="message_not_found")
    await log_audit(
        agent_id=agent.agent_id,
        action="egress_ack_local",
        status="success",
        detail=f"session={session_id} msg_id={msg_id}",
    )
    return {"status": "acked", "msg_id": msg_id}


@router.post("/resolve", response_model=ResolveResponse)
async def resolve_recipient(
    body: ResolveRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
):
    """Resolve a recipient and tell the SDK how to send.

    ADR-001 §10: routing decision happens here, before the sender
    encrypts anything. Response tells the SDK which wire format to use
    (envelope vs mtls-only) and whether egress inspection is required.

    Invariants:
      - path == "intra-org" iff SPIFFE trust_domain and org both match local
        (or recipient uses internal `org::agent` form with matching org).
      - transport == "mtls-only" only when path is intra-org AND the proxy
        is configured with transport_intra_org != "envelope".
      - target_cert_pem is populated for intra-org mtls-only so the SDK
        can validate the peer certificate at mTLS handshake time.
    """
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    from mcp_proxy.spiffe import InvalidRecipient, parse_recipient

    settings = get_settings()

    try:
        trust_domain, target_org, target_agent = parse_recipient(body.recipient_id)
    except InvalidRecipient as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    route = decide_route(
        body.recipient_id,
        local_org=settings.org_id,
        local_trust_domain=settings.trust_domain,
    )

    target_spiffe: str | None = None
    if trust_domain is not None:
        target_spiffe = f"spiffe://{trust_domain}/{target_org}/{target_agent}"

    if route == "intra":
        intra_enabled = settings.intra_org_routing
        transport: Literal["envelope", "mtls-only"] = "envelope"
        if intra_enabled and settings.transport_intra_org in ("mtls-only", "hybrid"):
            transport = "mtls-only"

        target_cert_pem: str | None = None
        if transport == "mtls-only":
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT cert_pem, is_active FROM local_agents "
                        "WHERE agent_id = :agent_id"
                    ),
                    {"agent_id": target_agent},
                )
                row = result.mappings().first()
                if row is None or not row["is_active"]:
                    raise HTTPException(
                        status_code=404,
                        detail=f"intra-org target not found: {target_agent}",
                    )
                target_cert_pem = row["cert_pem"]

        return ResolveResponse(
            path="intra-org",
            target_agent_id=target_agent,
            target_org_id=target_org,
            target_spiffe=target_spiffe,
            transport=transport,
            egress_inspection=settings.egress_inspection_enabled,
            target_cert_pem=target_cert_pem,
        )

    return ResolveResponse(
        path="cross-org",
        target_agent_id=target_agent,
        target_org_id=target_org,
        target_spiffe=target_spiffe,
        transport="envelope",
        egress_inspection=settings.egress_inspection_enabled,
        target_cert_pem=None,
    )


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
