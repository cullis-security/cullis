"""Broker router for cross-org sessionless one-shot messages (ADR-008 Phase 1 / PR #2).

Endpoints:

  POST /broker/oneshot/forward          — sender proxy enqueues a one-shot
  GET  /broker/oneshot/inbox            — recipient proxy drains pending
  POST /broker/oneshot/{msg_id}/ack     — recipient proxy acks delivery

The sender's proxy authenticates to the broker as the sender agent
(same DPoP + JWT as session endpoints), signs the envelope with the
agent's private key using ``session_id="oneshot:<correlation_id>"``
for domain separation, and forwards it here. The broker verifies the
signature, applies policy (as a synthetic session with capabilities
``["oneshot.message"]``), and persists the row until the recipient
proxy pulls and acks it.

Dedup is scoped to ``(sender_agent_id, correlation_id)`` so sender
retries collapse to the same row; the recipient never sees a duplicate.
Offline recipients are backstopped by a TTL sweeper that flips
``delivery_status`` 0 → 2 (expired).
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.message_signer import verify_message_signature
from app.auth.models import TokenPayload
from app.broker.db_models import BrokerOneShotMessageRecord
from app.broker.ws_manager import ws_manager
from app.db.audit import log_event, log_event_cross_org
from app.db.database import get_db
from app.policy.backend import evaluate_session_policy
from app.rate_limit.limiter import rate_limiter
from app.registry.binding_store import get_approved_binding
from app.registry.org_store import get_org_by_id
from app.registry.store import get_agent_by_id

_log = logging.getLogger("agent_trust")

router = APIRouter(prefix="/broker/oneshot", tags=["broker-oneshot"])

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_ONESHOT_CAPABILITY = "oneshot.message"


# ── Schemas ────────────────────────────────────────────────────────────

class ForwardOneShotRequest(BaseModel):
    recipient_agent_id: str = Field(
        ..., description="Bare agent_id of the recipient (not SPIFFE form).",
    )
    correlation_id: str = Field(
        ..., description="Sender-generated UUID; unique per sender.",
    )
    reply_to_correlation_id: str | None = Field(
        None,
        description="correlation_id of the message this one is a reply to.",
    )
    payload: dict = Field(..., description="Plaintext application body.")
    signature: str = Field(
        ...,
        description="RSA-PSS/ECDSA signature over the canonical plaintext "
                    "with session_id='oneshot:<correlation_id>' (domain separation).",
    )
    nonce: str = Field(..., description="Globally-unique nonce for this envelope.")
    timestamp: int = Field(..., description="Unix timestamp seconds.")
    mode: Literal["mtls-only", "envelope"] = Field(
        "mtls-only",
        description="mtls-only: payload is plaintext dict; envelope: payload "
                    "is a cipher_blob the broker never decrypts. Signature "
                    "is verified on whichever form is present (outer signature "
                    "for envelope mode).",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description="Requested capabilities — verified against both sender "
                    "and recipient binding scopes. Empty list falls back to "
                    "the sentinel 'oneshot.message'.",
    )
    ttl_seconds: int = Field(
        300, ge=10, le=3600,
        description="Broker-side TTL for offline recipients.",
    )


class ForwardOneShotResponse(BaseModel):
    msg_id: str
    duplicate: bool


class InboxOneShotItem(BaseModel):
    msg_id: str
    correlation_id: str
    reply_to_correlation_id: str | None
    sender_agent_id: str
    sender_org_id: str
    envelope_json: str
    nonce: str
    enqueued_at: str
    ttl_expires_at: str


class InboxOneShotResponse(BaseModel):
    messages: list[InboxOneShotItem]
    count: int


# ── Helpers ────────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _build_envelope_json(body: ForwardOneShotRequest) -> str:
    """Serialize the envelope exactly the shape the proxy's one-shot
    router expects when it lazy-mirrors into ``local_messages``.
    """
    envelope = {
        "mode": body.mode,
        "payload": body.payload,
        "signature": body.signature,
        "nonce": body.nonce,
        "timestamp": body.timestamp,
        "correlation_id": body.correlation_id,
        "reply_to": body.reply_to_correlation_id,
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True)


# ── POST /broker/oneshot/forward ───────────────────────────────────────

@router.post(
    "/forward",
    response_model=ForwardOneShotResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def forward_oneshot(
    body: ForwardOneShotRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> ForwardOneShotResponse:
    """Enqueue a sessionless one-shot for the recipient's proxy to drain.

    Returns 202 with ``{msg_id, duplicate}``. ``duplicate=true`` means a
    prior send with the same ``(sender_agent_id, correlation_id)`` is
    already queued — the returned ``msg_id`` points to that row.
    """
    await rate_limiter.check(current_agent.agent_id, "broker.oneshot")

    # Correlation id format — sender generates a UUID; reject arbitrary
    # strings so log_event details + dedup behave predictably.
    if not _UUID_RE.match(body.correlation_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="correlation_id must be a UUID",
        )

    # ── Resolve recipient ─────────────────────────────────────────────
    recipient = await get_agent_by_id(db, body.recipient_agent_id)
    if recipient is None or not recipient.is_active:
        await log_event(
            db, "broker.oneshot_denied", "denied",
            agent_id=current_agent.agent_id, org_id=current_agent.org,
            details={
                "recipient": body.recipient_agent_id,
                "correlation_id": body.correlation_id,
                "reason": "recipient_not_found",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient agent not found or inactive",
        )

    await rate_limiter.check(body.recipient_agent_id, "broker.oneshot_inbound")

    if recipient.agent_id == current_agent.agent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot send a one-shot to yourself",
        )

    # ── Recipient binding ─────────────────────────────────────────────
    recipient_binding = await get_approved_binding(
        db, recipient.org_id, recipient.agent_id,
    )
    if recipient_binding is None:
        await log_event(
            db, "broker.oneshot_denied", "denied",
            agent_id=current_agent.agent_id, org_id=current_agent.org,
            details={
                "recipient": recipient.agent_id,
                "correlation_id": body.correlation_id,
                "reason": "recipient_binding_missing",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recipient has no approved binding",
        )

    # ── Capability scope check (mirrors session scope verification) ──
    effective_caps = body.capabilities or [_ONESHOT_CAPABILITY]
    from app.config import get_settings as _get_settings
    _settings = _get_settings()
    if _settings.policy_enforcement:
        initiator_scope = set(current_agent.scope)
        target_scope = set(recipient_binding.scope)
        target_caps = set(recipient.capabilities)
        for cap in effective_caps:
            if cap not in initiator_scope:
                await log_event(
                    db, "broker.oneshot_denied", "denied",
                    agent_id=current_agent.agent_id,
                    org_id=current_agent.org,
                    details={
                        "correlation_id": body.correlation_id,
                        "cap": cap,
                        "reason": "capability_not_in_sender_scope",
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Capability '{cap}' not authorized in your scope",
                )
            if cap not in target_scope:
                await log_event(
                    db, "broker.oneshot_denied", "denied",
                    agent_id=current_agent.agent_id,
                    org_id=current_agent.org,
                    details={
                        "correlation_id": body.correlation_id,
                        "cap": cap,
                        "reason": "capability_not_in_recipient_scope",
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Capability '{cap}' not authorized in the recipient's scope",
                )
            if cap not in target_caps:
                await log_event(
                    db, "broker.oneshot_denied", "denied",
                    agent_id=current_agent.agent_id,
                    org_id=current_agent.org,
                    details={
                        "correlation_id": body.correlation_id,
                        "cap": cap,
                        "reason": "recipient_does_not_advertise_capability",
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Recipient does not advertise capability '{cap}'",
                )

    # ── PDP policy ────────────────────────────────────────────────────
    initiator_org = await get_org_by_id(db, current_agent.org)
    target_org = await get_org_by_id(db, recipient.org_id)

    pdp_decision = await evaluate_session_policy(
        initiator_org_id=current_agent.org,
        initiator_webhook_url=initiator_org.webhook_url if initiator_org else None,
        target_org_id=recipient.org_id,
        target_webhook_url=target_org.webhook_url if target_org else None,
        initiator_agent_id=current_agent.agent_id,
        target_agent_id=recipient.agent_id,
        capabilities=effective_caps,
    )
    if not pdp_decision.allowed:
        await log_event(
            db, "broker.oneshot_denied", "denied",
            agent_id=current_agent.agent_id, org_id=current_agent.org,
            details={
                "recipient": recipient.agent_id,
                "correlation_id": body.correlation_id,
                "reason": pdp_decision.reason,
                "denied_by": pdp_decision.org_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Policy: {pdp_decision.reason}",
        )

    # ── Freshness ─────────────────────────────────────────────────────
    now_dt = datetime.now(timezone.utc)
    now_ts = int(now_dt.timestamp())
    if abs(now_ts - body.timestamp) > 60:
        await log_event(
            db, "broker.oneshot_denied", "denied",
            agent_id=current_agent.agent_id, org_id=current_agent.org,
            details={
                "correlation_id": body.correlation_id,
                "reason": "timestamp_out_of_window",
                "ts": body.timestamp,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Timestamp outside freshness window — possible replay",
        )

    # ── Verify signature ──────────────────────────────────────────────
    sender_rec = await get_agent_by_id(db, current_agent.agent_id)
    if sender_rec is None or not sender_rec.cert_pem:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sender certificate not available — log in before sending",
        )
    verify_message_signature(
        sender_rec.cert_pem,
        body.signature,
        f"oneshot:{body.correlation_id}",
        current_agent.agent_id,
        body.nonce,
        body.timestamp,
        body.payload,
        client_seq=0,
    )

    # ── Dedup + insert ────────────────────────────────────────────────
    envelope_json = _build_envelope_json(body)
    ttl_expires_at = now_dt + timedelta(seconds=body.ttl_seconds)

    existing = (
        await db.execute(
            select(BrokerOneShotMessageRecord).where(
                BrokerOneShotMessageRecord.sender_agent_id
                == current_agent.agent_id,
                BrokerOneShotMessageRecord.correlation_id
                == body.correlation_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return ForwardOneShotResponse(msg_id=existing.msg_id, duplicate=True)

    msg_id = str(uuid.uuid4())
    row = BrokerOneShotMessageRecord(
        msg_id=msg_id,
        correlation_id=body.correlation_id,
        reply_to_correlation_id=body.reply_to_correlation_id,
        sender_agent_id=current_agent.agent_id,
        sender_org_id=current_agent.org,
        recipient_agent_id=recipient.agent_id,
        recipient_org_id=recipient.org_id,
        envelope_json=envelope_json,
        nonce=body.nonce,
        enqueued_at=now_dt,
        ttl_expires_at=ttl_expires_at,
        delivery_status=0,
    )
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        # Race: sender retried while the first insert was in-flight. Look
        # up the winning row so both calls return the same msg_id.
        winner = (
            await db.execute(
                select(BrokerOneShotMessageRecord).where(
                    BrokerOneShotMessageRecord.sender_agent_id
                    == current_agent.agent_id,
                    BrokerOneShotMessageRecord.correlation_id
                    == body.correlation_id,
                )
            )
        ).scalar_one_or_none()
        if winner is None:
            raise
        return ForwardOneShotResponse(msg_id=winner.msg_id, duplicate=True)

    # ── Cross-org audit dual-write ────────────────────────────────────
    await log_event_cross_org(
        db, "broker.oneshot_forwarded", "ok",
        org_a=current_agent.org, org_b=recipient.org_id,
        agent_id=current_agent.agent_id,
        details={
            "msg_id": msg_id,
            "correlation_id": body.correlation_id,
            "reply_to_correlation_id": body.reply_to_correlation_id,
            "recipient_agent_id": recipient.agent_id,
            "nonce": body.nonce,
            "mode": body.mode,
        },
    )

    # ── Best-effort nudge if recipient is WS-connected ────────────────
    try:
        if ws_manager.is_connected(recipient.agent_id):
            await ws_manager.send_to_agent(
                recipient.agent_id,
                {
                    "type": "oneshot_pending",
                    "msg_id": msg_id,
                    "correlation_id": body.correlation_id,
                },
            )
    except Exception:  # noqa: BLE001 — nudge is advisory
        _log.debug(
            "oneshot_pending notify failed for %s (msg %s)",
            recipient.agent_id, msg_id,
        )

    return ForwardOneShotResponse(msg_id=msg_id, duplicate=False)


# ── GET /broker/oneshot/inbox ──────────────────────────────────────────

@router.get("/inbox", response_model=InboxOneShotResponse)
async def poll_oneshot_inbox(
    limit: int = 500,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> InboxOneShotResponse:
    """Return pending one-shot messages addressed to the caller.

    The response does NOT flip delivery_status — the recipient acks
    separately after successfully mirroring the envelope locally, so a
    crash between drain and mirror is safe to retry.
    """
    await rate_limiter.check(current_agent.agent_id, "broker.oneshot_inbox")

    limit = max(1, min(limit, 500))
    rows = (
        await db.execute(
            select(BrokerOneShotMessageRecord)
            .where(
                BrokerOneShotMessageRecord.recipient_agent_id
                == current_agent.agent_id,
                BrokerOneShotMessageRecord.delivery_status == 0,
            )
            .order_by(BrokerOneShotMessageRecord.enqueued_at.asc())
            .limit(limit)
        )
    ).scalars().all()

    return InboxOneShotResponse(
        messages=[
            InboxOneShotItem(
                msg_id=r.msg_id,
                correlation_id=r.correlation_id,
                reply_to_correlation_id=r.reply_to_correlation_id,
                sender_agent_id=r.sender_agent_id,
                sender_org_id=r.sender_org_id,
                envelope_json=r.envelope_json,
                nonce=r.nonce,
                enqueued_at=_iso(r.enqueued_at),
                ttl_expires_at=_iso(r.ttl_expires_at),
            )
            for r in rows
        ],
        count=len(rows),
    )


# ── POST /broker/oneshot/{msg_id}/ack ──────────────────────────────────

@router.post(
    "/{msg_id}/ack",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def ack_oneshot(
    msg_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Flip the row to delivered. 404 if not found for this recipient,
    409 if already in a terminal state.
    """
    if not _UUID_RE.match(msg_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="msg_id must be a UUID",
        )

    now_dt = datetime.now(timezone.utc)
    result = await db.execute(
        update(BrokerOneShotMessageRecord)
        .where(
            BrokerOneShotMessageRecord.msg_id == msg_id,
            BrokerOneShotMessageRecord.recipient_agent_id
            == current_agent.agent_id,
            BrokerOneShotMessageRecord.delivery_status == 0,
        )
        .values(delivery_status=1, delivered_at=now_dt)
    )
    await db.commit()
    if result.rowcount and result.rowcount > 0:
        return

    existing = (
        await db.execute(
            select(BrokerOneShotMessageRecord.delivery_status).where(
                BrokerOneShotMessageRecord.msg_id == msg_id,
                BrokerOneShotMessageRecord.recipient_agent_id
                == current_agent.agent_id,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One-shot message not found for this recipient",
        )
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="One-shot already in a terminal state",
    )
