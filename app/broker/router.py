"""
Broker router — manages sessions and message routing between agents.

Flow:
  1. Agent A calls POST /broker/sessions  → creates a pending session
  2. Agent B calls POST /broker/sessions/{id}/accept → session becomes active
  3. Both can send messages via POST /broker/sessions/{id}/messages
     (REST polling always available; WebSocket push as an additional channel)
"""
import asyncio
import logging
import re
import time as _time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status

_log = logging.getLogger("agent_trust")
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent, decode_token
from app.auth.models import TokenPayload
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.store import get_agent_by_id
from app.registry.binding_store import get_approved_binding
from app.broker.models import SessionRequest, SessionResponse, SessionStatus, MessageEnvelope, InboxMessage
from app.broker.session import get_session_store, SessionStore
from app.broker.persistence import save_session, save_message
from app.broker.ws_manager import ws_manager
from app.policy.backend import evaluate_session_policy
from app.policy.engine import PolicyEngine
from app.rate_limit.limiter import rate_limiter
from app.auth.message_signer import verify_message_signature
from app.telemetry import tracer
from app.telemetry_metrics import SESSION_CREATED_COUNTER, SESSION_DENIED_COUNTER
from app.registry.store import get_agent_by_id as _get_agent_by_id
from app.registry.org_store import get_org_by_id

router = APIRouter(prefix="/broker", tags=["broker"])

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_session_id(session_id: str) -> None:
    """Reject non-UUID session IDs to prevent log injection (#41)."""
    if not _UUID_RE.match(session_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid session_id format (expected UUID)")


@router.post("/sessions", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
async def request_session(
    body: SessionRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """
    An authenticated agent requests a session with another agent.
    """
    await rate_limiter.check(current_agent.agent_id, "broker.session")

    with tracer.start_as_current_span("broker.create_session") as span:
        span.set_attribute("initiator.agent_id", current_agent.agent_id)
        span.set_attribute("target.agent_id", body.target_agent_id)
        return await _create_session_inner(body, current_agent, store, db, span)


async def _create_session_inner(body, current_agent, store, db, span):
    # Verify that the target exists and is active
    target = await get_agent_by_id(db, body.target_agent_id)
    if not target or not target.is_active:
        SESSION_DENIED_COUNTER.add(1, {"reason": "target_not_found"})
        await log_event(db, "broker.session_request", "denied",
                        agent_id=current_agent.agent_id, org_id=current_agent.org,
                        details={"target": body.target_agent_id, "reason": "target not found"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Target agent not found or inactive")

    if target.org_id != body.target_org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="target_org_id does not match the registered agent")

    # Verify that the target has an approved binding
    target_binding = await get_approved_binding(db, target.org_id, body.target_agent_id)
    if not target_binding:
        await log_event(db, "broker.session_request", "denied",
                        agent_id=current_agent.agent_id, org_id=current_agent.org,
                        details={"target": body.target_agent_id, "reason": "target has no approved binding"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Target has no approved binding")

    # Verify scope: requested capabilities must be in both parties' bindings
    # Skip scope checks when policy enforcement is disabled (demo mode)
    from app.config import get_settings
    settings = get_settings()
    if settings.policy_enforcement:
        initiator_scope = set(current_agent.scope)
        target_scope = set(target_binding.scope)
        for cap in body.requested_capabilities:
            if cap not in initiator_scope:
                await log_event(db, "broker.session_request", "denied",
                                agent_id=current_agent.agent_id, org_id=current_agent.org,
                                details={"cap": cap, "reason": "capability not in initiator scope"})
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=f"Capability '{cap}' not authorized in your scope")
            if cap not in target_scope:
                await log_event(db, "broker.session_request", "denied",
                                agent_id=current_agent.agent_id, org_id=current_agent.org,
                                details={"cap": cap, "reason": "capability not in target scope"})
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=f"Capability '{cap}' not authorized in the target's scope")

        # Verify target actually advertises the requested capabilities
        target_caps = set(target.capabilities)
        for cap in body.requested_capabilities:
            if cap not in target_caps:
                await log_event(db, "broker.session_request", "denied",
                                agent_id=current_agent.agent_id, org_id=current_agent.org,
                                details={"cap": cap, "reason": "target does not advertise capability"})
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"Target does not advertise capability '{cap}'")

    # An agent cannot open a session with itself
    if current_agent.agent_id == body.target_agent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="You cannot open a session with yourself")

    # Federated policy evaluation — call both orgs' PDP webhooks (default-deny)
    initiator_org = await get_org_by_id(db, current_agent.org)
    target_org    = await get_org_by_id(db, body.target_org_id)

    pdp_decision = await evaluate_session_policy(
        initiator_org_id=current_agent.org,
        initiator_webhook_url=initiator_org.webhook_url if initiator_org else None,
        target_org_id=body.target_org_id,
        target_webhook_url=target_org.webhook_url if target_org else None,
        initiator_agent_id=current_agent.agent_id,
        target_agent_id=body.target_agent_id,
        capabilities=body.requested_capabilities,
    )
    if not pdp_decision.allowed:
        SESSION_DENIED_COUNTER.add(1, {"reason": "pdp_denied"})
        await log_event(db, "policy.session_denied", "denied",
                        agent_id=current_agent.agent_id, org_id=current_agent.org,
                        details={"reason": pdp_decision.reason,
                                 "denied_by": pdp_decision.org_id})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Policy: {pdp_decision.reason}")

    try:
        session = store.create(
            initiator_agent_id=current_agent.agent_id,
            initiator_org_id=current_agent.org,
            target_agent_id=body.target_agent_id,
            target_org_id=body.target_org_id,
            requested_capabilities=body.requested_capabilities,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=str(exc))
    await save_session(db, session)

    SESSION_CREATED_COUNTER.add(1, {"initiator_org": current_agent.org})
    await log_event(db, "broker.session_created", "ok",
                    agent_id=current_agent.agent_id, session_id=session.session_id,
                    org_id=current_agent.org,
                    details={"target": body.target_agent_id, "caps": body.requested_capabilities})

    # Persistent notification — survives even if the target is offline
    from app.broker.notifications import create_notification
    await create_notification(
        db,
        recipient_type="agent",
        recipient_id=body.target_agent_id,
        notification_type="session_pending",
        title=f"Session request from {current_agent.agent_id}",
        body=f"Capabilities: {', '.join(body.requested_capabilities)}",
        reference_id=session.session_id,
        org_id=target_binding.org_id,
    )

    # Push WS al target se connesso (real-time delivery on top of persistent notification)
    await ws_manager.send_to_agent(body.target_agent_id, {
        "type": "session_pending",
        "session_id": session.session_id,
        "initiator_agent_id": current_agent.agent_id,
        "initiator_org_id": current_agent.org,
        "capabilities": body.requested_capabilities,
    })

    return SessionResponse(
        session_id=session.session_id,
        status=session.status,
        initiator_agent_id=session.initiator_agent_id,
        target_agent_id=session.target_agent_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        message="Session created — waiting for acceptance from the target",
    )


@router.post("/sessions/{session_id}/accept", response_model=SessionResponse)
async def accept_session(
    session_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """
    The target accepts the pending session.
    Only the agent designated as target can accept.
    """
    _validate_session_id(session_id)

    async with store._lock:
        session = store.get(session_id)
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

        if session.target_agent_id != current_agent.agent_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Only the target can accept this session")

        if session.status != SessionStatus.pending:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Session is in state '{session.status}', cannot be accepted")

        store.activate(session_id)
        await save_session(db, session)

    # Clear the pending notification for this session
    from app.broker.notifications import mark_acted_by_reference
    await mark_acted_by_reference(db, "session_pending", session_id)

    await log_event(db, "broker.session_accepted", "ok",
                    agent_id=current_agent.agent_id, session_id=session_id,
                    org_id=current_agent.org)

    return SessionResponse(
        session_id=session.session_id,
        status=session.status,
        initiator_agent_id=session.initiator_agent_id,
        target_agent_id=session.target_agent_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        message="Session active",
    )


@router.post("/sessions/{session_id}/reject", response_model=SessionResponse)
async def reject_session(
    session_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """
    The target rejects the pending session.
    Only the agent designated as target can reject.
    """
    _validate_session_id(session_id)

    async with store._lock:
        session = store.get(session_id)
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

        if session.target_agent_id != current_agent.agent_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Only the target can reject this session")

        if session.status != SessionStatus.pending:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Session is in state '{session.status}', cannot be rejected")

        store.reject(session_id)
        await save_session(db, session)

    from app.broker.notifications import mark_acted_by_reference
    await mark_acted_by_reference(db, "session_pending", session_id)

    await log_event(db, "broker.session_rejected", "ok",
                    agent_id=current_agent.agent_id, session_id=session_id,
                    org_id=current_agent.org)

    # Notify initiator via WebSocket
    if ws_manager.is_connected(session.initiator_agent_id):
        await ws_manager.send_to_agent(session.initiator_agent_id, {
            "type": "session_rejected",
            "session_id": session.session_id,
            "rejected_by": current_agent.agent_id,
        })

    return SessionResponse(
        session_id=session.session_id,
        status=session.status,
        initiator_agent_id=session.initiator_agent_id,
        target_agent_id=session.target_agent_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        message="Session rejected",
    )


@router.post("/sessions/{session_id}/close", response_model=SessionResponse)
async def close_session(
    session_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """
    A participant explicitly closes an active session.
    Both agents (initiator and target) can call this endpoint.
    """
    _validate_session_id(session_id)

    async with store._lock:
        session = store.get(session_id)
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

        participants = {session.initiator_agent_id, session.target_agent_id}
        if current_agent.agent_id not in participants:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="You are not a participant of this session")

        if session.status == SessionStatus.closed:
            return SessionResponse(
                session_id=session.session_id,
                status=session.status,
                initiator_agent_id=session.initiator_agent_id,
                target_agent_id=session.target_agent_id,
                created_at=session.created_at,
                expires_at=session.expires_at,
                message="Session already closed",
            )

        if session.status != SessionStatus.active:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Session is in state '{session.status}', cannot be closed")

        store.close(session_id)
        await save_session(db, session)

    await log_event(db, "session_closed", "ok",
                    agent_id=current_agent.agent_id, session_id=session_id,
                    org_id=current_agent.org)

    return SessionResponse(
        session_id=session.session_id,
        status=session.status,
        initiator_agent_id=session.initiator_agent_id,
        target_agent_id=session.target_agent_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        message="Session closed",
    )


@router.post("/sessions/{session_id}/messages", status_code=status.HTTP_202_ACCEPTED)
async def send_message(
    session_id: str,
    envelope: MessageEnvelope,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """
    Send a message through an active session.
    The broker validates:
      - session is active and not expired
      - sender is a legitimate participant
      - nonce has not already been used (replay protection)
    After saving, pushes the message via WS to the recipient if connected.
    """
    await rate_limiter.check(current_agent.agent_id, "broker.message")

    # ── Validate session_id format ────────────────────────────────────────
    _validate_session_id(session_id)

    # ── Validate envelope session_id matches URL path ──────────────────────
    if envelope.session_id != session_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="session_id in envelope does not match URL path")

    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    # ── Enforce session expiry even if status was not yet updated ─────────
    if session.is_expired():
        session.status = SessionStatus.closed
        await save_session(db, session)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Session has expired")

    if session.status != SessionStatus.active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Session not active")

    participants = {session.initiator_agent_id, session.target_agent_id}
    if current_agent.agent_id not in participants:
        await log_event(db, "broker.message_send", "denied",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        details={"reason": "not a participant"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not a participant of this session")

    if envelope.sender_agent_id != current_agent.agent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="sender_agent_id does not match the token")

    # Fast-path: in-memory cache rejects obvious replays without a DB hit
    if session.is_nonce_cached(envelope.nonce):
        await log_event(db, "broker.message_send", "denied",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        details={"reason": "replay attack detected", "nonce": envelope.nonce})
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Nonce already used — possible replay attack")

    # ── Freshness check — reject messages older than 60 seconds or in the future ──
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if abs(now_ts - envelope.timestamp) > 60:
        await log_event(db, "broker.message_send", "denied",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        details={"reason": "timestamp out of window", "ts": envelope.timestamp})
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Message timestamp too old or in the future — possible replay attack")

    # ── Verify message signature ──────────────────────────────────────────────
    agent_rec = await _get_agent_by_id(db, current_agent.agent_id)
    if not agent_rec or not agent_rec.cert_pem:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Agent certificate not found — log in before sending messages")
    verify_message_signature(
        agent_rec.cert_pem,
        envelope.signature,
        session_id,
        current_agent.agent_id,
        envelope.nonce,
        envelope.timestamp,
        envelope.payload,
        client_seq=envelope.client_seq,
    )
    _log.info("✔ signature verified  (%s)", current_agent.agent_id)

    # ── Transaction token validation (if applicable) ─────────────────────
    if current_agent.token_type == "transaction":
        from app.auth.transaction_token import validate_and_consume_transaction_token, compute_payload_hash
        actual_hash = compute_payload_hash(envelope.payload)
        try:
            txn_record = await validate_and_consume_transaction_token(
                db, current_agent, actual_hash,
            )
        except ValueError as exc:
            await log_event(db, "broker.transaction_rejected", "denied",
                            agent_id=current_agent.agent_id, session_id=session_id,
                            org_id=current_agent.org,
                            details={"reason": str(exc), "txn_jti": current_agent.jti})
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Transaction token invalid: {exc}")
        await log_event(db, "broker.transaction_executed", "ok",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        org_id=current_agent.org,
                        details={
                            "txn_type": txn_record.txn_type,
                            "resource_id": txn_record.resource_id,
                            "approved_by": txn_record.approved_by,
                            "rfq_id": txn_record.rfq_id,
                            "parent_jti": txn_record.parent_jti,
                        })

    # ── Message policy evaluation ────────────────────────────────────────
    _policy_engine = PolicyEngine()
    policy_decision = await _policy_engine.evaluate_message(
        db,
        sender_org_id=current_agent.org,
        payload=envelope.payload,
        agent_id=current_agent.agent_id,
        session_id=session_id,
    )
    if not policy_decision.allowed:
        await log_event(db, "broker.message_send", "denied",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        org_id=current_agent.org,
                        details={"reason": policy_decision.reason,
                                 "policy_id": policy_decision.policy_id})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Message policy: {policy_decision.reason}")

    _log.info("✔ message accepted  (%s → %s)", current_agent.org, session.target_org_id)

    # Cache the nonce in-memory BEFORE storing the message to close the
    # race window where two concurrent requests both pass is_nonce_cached().
    # If the DB insert fails (duplicate), we leave the nonce in the cache
    # (false-positive is safe — it just blocks a replayed nonce).
    session.cache_nonce(envelope.nonce)

    seq = session.store_message(current_agent.agent_id, envelope.payload, envelope.nonce,
                                envelope.signature, client_seq=envelope.client_seq)

    # Atomic DB insert — source of truth for nonce uniqueness.
    # Rollback in-memory state on ANY failure (nonce conflict or DB error).
    try:
        inserted = await save_message(db, session_id, session._messages[-1])
    except Exception:
        session._messages.pop()
        session._next_seq -= 1
        _log.exception("DB error saving message in session %s", session_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to persist message")
    if not inserted:
        session._messages.pop()
        session._next_seq -= 1
        await log_event(db, "broker.message_send", "denied",
                        agent_id=current_agent.agent_id, session_id=session_id,
                        details={"reason": "replay attack detected (DB)", "nonce": envelope.nonce})
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Nonce already used — possible replay attack")

    import hashlib
    import json as _json
    payload_hash = hashlib.sha256(
        _json.dumps(envelope.payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    await log_event(db, "broker.message_forwarded", "ok",
                    agent_id=current_agent.agent_id, session_id=session_id,
                    org_id=current_agent.org,
                    details={
                        "seq": seq,
                        "nonce": envelope.nonce,
                        "payload_hash": payload_hash,
                        "signature": envelope.signature,
                    })
    _log.info("✔ message accepted + audit logged  (seq=%d, session=%s)", seq, session_id)

    # Push WS to the recipient if connected
    recipient_id = (
        session.target_agent_id
        if current_agent.agent_id == session.initiator_agent_id
        else session.initiator_agent_id
    )
    if ws_manager.is_connected(recipient_id):
        ws_msg = {
            "type": "new_message",
            "session_id": session_id,
            "message": {
                "seq": seq,
                "sender_agent_id": current_agent.agent_id,
                "payload": envelope.payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }
        if envelope.client_seq is not None:
            ws_msg["message"]["client_seq"] = envelope.client_seq
        await ws_manager.send_to_agent(recipient_id, ws_msg)

    return {"status": "accepted", "session_id": session_id}


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    status: SessionStatus | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
):
    """List sessions for the authenticated agent, with optional status filter and pagination."""
    sessions = store.list_for_agent(current_agent.agent_id, limit=limit + offset, offset=0)
    if status is not None:
        sessions = [s for s in sessions if s.status == status]
    # Apply pagination after status filter
    page = sessions[offset:offset + limit]
    return [
        SessionResponse(
            session_id=s.session_id,
            status=s.status,
            initiator_agent_id=s.initiator_agent_id,
            target_agent_id=s.target_agent_id,
            created_at=s.created_at,
            expires_at=s.expires_at,
        )
        for s in page
    ]


@router.get("/sessions/{session_id}/messages", response_model=list[InboxMessage])
async def poll_messages(
    session_id: str,
    after: int = -1,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
):
    """
    Inbox polling: returns received messages (not sent by you) with seq > after.
    The client saves the last seq and passes it to the next poll to receive only new ones.
    Remains available as a fallback when WebSocket is not in use.
    """
    _validate_session_id(session_id)
    await rate_limiter.check(current_agent.agent_id, "broker.poll")

    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    # Allow polling on active and closed sessions (closed = drain unread
    # messages), but block on pending/denied where no messages can exist.
    if session.status not in (SessionStatus.active, SessionStatus.closed):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Session is {session.status.value} — polling not available")

    participants = {session.initiator_agent_id, session.target_agent_id}
    if current_agent.agent_id not in participants:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not a participant of this session")

    messages = session.get_messages_for(current_agent.agent_id, after=after)
    return [
        InboxMessage(
            seq=m.seq,
            sender_agent_id=m.sender_agent_id,
            payload=m.payload,
            nonce=m.nonce,
            timestamp=m.timestamp,
            signature=m.signature,
            client_seq=m.client_seq,
        )
        for m in messages
    ]


@router.get("/notifications")
async def get_notifications(
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Return pending (unacted) notifications for the authenticated agent."""
    from app.broker.notifications import get_pending_notifications
    notifications = await get_pending_notifications(db, "agent", current_agent.agent_id, org_id=current_agent.org)
    return [
        {
            "id": n.id,
            "type": n.notification_type,
            "title": n.title,
            "body": n.body,
            "reference_id": n.reference_id,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in notifications
    ]


# ─────────────────────────────────────────────────────────────────────────────
# RFQ (Request for Quote) endpoints
# ─────────────────────────────────────────────────────────────────────────────

from app.broker.models import RfqRequest, RfqRespondRequest, RfqResponse as RfqResponseModel
from app.broker.rfq import broadcast_rfq, submit_rfq_response, get_rfq


@router.post("/rfq", response_model=RfqResponseModel, status_code=status.HTTP_201_CREATED)
async def create_rfq(
    body: RfqRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Broadcast an RFQ to all agents matching the capability filter."""
    await rate_limiter.check(current_agent.agent_id, "broker.rfq")
    result = await broadcast_rfq(db, current_agent, body)
    return result


@router.post("/rfq/{rfq_id}/respond", status_code=status.HTTP_202_ACCEPTED)
async def respond_to_rfq(
    rfq_id: str,
    body: RfqRespondRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Submit a quote response to an open RFQ."""
    _validate_session_id(rfq_id)  # reuse UUID validation
    await rate_limiter.check(current_agent.agent_id, "broker.rfq_respond")
    accepted = await submit_rfq_response(db, rfq_id, current_agent, body.payload)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="RFQ not found, already closed, not in matched set, or already responded",
        )
    return {"status": "accepted", "rfq_id": rfq_id}


@router.get("/rfq/{rfq_id}", response_model=RfqResponseModel)
async def get_rfq_status(
    rfq_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Get the current status and collected quotes for an RFQ."""
    _validate_session_id(rfq_id)
    result = await get_rfq(db, rfq_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RFQ not found")
    return result


_WS_AUTH_TIMEOUT = 10  # seconds — max time to wait for initial auth message


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    """
    Endpoint WebSocket per ricezione messaggi in tempo reale.

    Protocollo:
      1. Client si connette
      2. Client manda: {"type": "auth", "token": "<JWT>"}
      3. Server risponde: {"type": "auth_ok", "agent_id": "..."}
         oppure:          {"type": "auth_error", "detail": "..."}  e chiude
      4. Server pusha: {"type": "new_message", ...} e {"type": "session_pending", ...}
      5. Client può mandare {"type": "ping"} → server risponde {"type": "pong"}
    """
    # ── Origin validation (#25) — CORSMiddleware does not cover WebSocket ──
    from app.config import get_settings
    _ws_settings = get_settings()
    _ws_origins = [o.strip() for o in _ws_settings.allowed_origins.split(",") if o.strip()]
    if _ws_origins and "*" not in _ws_origins:
        origin = websocket.headers.get("origin", "")
        if origin not in _ws_origins:
            await websocket.close(code=1008)
            return

    await websocket.accept()
    agent_id: str | None = None
    agent_org: str | None = None

    try:
        # Step 1: receive authentication message (with timeout to prevent connection exhaustion)
        try:
            auth_msg = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=_WS_AUTH_TIMEOUT,
            )
        except asyncio.TimeoutError:
            _log.warning("WebSocket auth timeout — closing unauthenticated connection")
            await websocket.close(code=1008, reason="Auth timeout")
            return
        except Exception:
            await websocket.close(code=1003)
            return

        if auth_msg.get("type") != "auth" or not auth_msg.get("token"):
            await websocket.send_json({
                "type": "auth_error",
                "detail": "Missing or malformed auth message",
            })
            await websocket.close()
            return

        # Step 2: validate JWT
        try:
            agent = await decode_token(auth_msg["token"])
        except HTTPException as exc:
            await websocket.send_json({"type": "auth_error", "detail": exc.detail})
            await websocket.close()
            return

        # Step 2b: verify DPoP proof for the WebSocket endpoint
        # htm = "GET" (WebSocket upgrade is an HTTP GET)
        # htu = canonical URL for /broker/ws
        dpop_proof = auth_msg.get("dpop_proof", "")
        if not dpop_proof:
            await websocket.send_json({"type": "auth_error", "detail": "DPoP proof required"})
            await websocket.close()
            return
        if not agent.cnf or "jkt" not in agent.cnf:
            await websocket.send_json({"type": "auth_error", "detail": "Token is not DPoP-bound"})
            await websocket.close()
            return
        try:
            from app.auth.dpop import verify_dpop_proof, _normalize_htu
            from app.config import get_settings as _get_settings
            _settings = _get_settings()
            if _settings.broker_public_url:
                ws_htu = _normalize_htu(_settings.broker_public_url.rstrip("/") + "/v1/broker/ws")
            else:
                ws_htu = _normalize_htu(str(websocket.url).replace("wss://", "https://").replace("ws://", "http://"))
            jkt = await verify_dpop_proof(dpop_proof, htm="GET", htu=ws_htu, access_token=auth_msg["token"])
            if jkt != agent.cnf["jkt"]:
                await websocket.send_json({"type": "auth_error", "detail": "DPoP proof key mismatch"})
                await websocket.close()
                return
        except HTTPException as exc:
            await websocket.send_json({"type": "auth_error", "detail": exc.detail})
            await websocket.close()
            return

        # Step 2c: check token revocation
        agent_rec = await get_agent_by_id(db, agent.agent_id)
        if agent_rec and agent_rec.token_invalidated_at is not None:
            token_iat = datetime.fromtimestamp(agent.iat, tz=timezone.utc)
            invalidated_at = agent_rec.token_invalidated_at
            if invalidated_at.tzinfo is None:  # SQLite returns naive datetimes
                invalidated_at = invalidated_at.replace(tzinfo=timezone.utc)
            if token_iat <= invalidated_at:
                await websocket.send_json({"type": "auth_error", "detail": "Token has been revoked"})
                await websocket.close()
                return

        # Step 2d: verify agent binding is still approved
        binding = await get_approved_binding(db, agent.org, agent.agent_id)
        if not binding:
            await websocket.send_json({"type": "auth_error", "detail": "Agent binding not approved or revoked"})
            await websocket.close()
            return

        # Step 3: register connection and confirm
        agent_id = agent.agent_id
        agent_org = agent.org
        try:
            await ws_manager.connect(agent_id, websocket, org_id=agent_org)
        except ConnectionRefusedError:
            await websocket.send_json({"type": "auth_error", "detail": "Too many connections for this organization"})
            await websocket.close()
            return
        await websocket.send_json({"type": "auth_ok", "agent_id": agent_id})

        # Step 4: keepalive — server pushes; client can send ping
        _WS_IDLE_TIMEOUT = 300   # 5 minutes
        _WS_MSG_LIMIT = 30       # max messages per window
        _WS_MSG_WINDOW = 60      # window in seconds
        _msg_times: list[float] = []

        while True:
            # Check token expiry
            if _time.time() > agent.exp:
                _log.info("Token expired during WebSocket session for agent %s", agent_id)
                await websocket.send_json({"type": "auth_error", "detail": "Token expired"})
                await websocket.close(code=1000, reason="Token expired")
                break

            # Receive with idle timeout
            try:
                msg = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=_WS_IDLE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                _log.info("WebSocket idle timeout for agent %s", agent_id)
                await websocket.close(code=1000, reason="Idle timeout")
                break

            # Rate limit incoming messages
            now = _time.monotonic()
            _msg_times = [t for t in _msg_times if t > now - _WS_MSG_WINDOW]
            if len(_msg_times) >= _WS_MSG_LIMIT:
                _log.warning("WebSocket rate limit exceeded for agent %s", agent_id)
                await websocket.close(code=1008, reason="Rate limit exceeded")
                break
            _msg_times.append(now)

            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    finally:
        if agent_id:
            await ws_manager.disconnect(agent_id, org_id=agent_org)
