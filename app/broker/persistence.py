"""
Session persistence — write-through to SQLite and restore on startup.

Every state operation (create, activate, close) updates the record
in the DB in addition to the in-memory store. On broker startup, non-expired
sessions are reloaded into memory from the DB.
"""
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import SessionRecord, SessionMessageRecord
from app.broker.models import SessionStatus
from app.broker.session import Session, StoredMessage, SessionStore

logger = logging.getLogger("agent_trust")


async def save_session(db: AsyncSession, session: Session) -> None:
    """Upsert the session record (create or update status/closed_at)."""
    closed_at = None
    if session.status == SessionStatus.closed:
        closed_at = datetime.now(timezone.utc)

    existing = await db.get(SessionRecord, session.session_id)
    if existing:
        existing.status = session.status.value
        existing.closed_at = closed_at
    else:
        db.add(SessionRecord(
            session_id=session.session_id,
            initiator_agent_id=session.initiator_agent_id,
            initiator_org_id=session.initiator_org_id,
            target_agent_id=session.target_agent_id,
            target_org_id=session.target_org_id,
            status=session.status.value,
            requested_capabilities=json.dumps(session.requested_capabilities),
            created_at=session.created_at,
            expires_at=session.expires_at,
            closed_at=closed_at,
        ))
    await db.commit()


async def save_message(
    db: AsyncSession,
    session_id: str,
    msg: StoredMessage,
) -> None:
    """Insert a message into the session_messages table."""
    record = SessionMessageRecord(
        session_id=session_id,
        seq=msg.seq,
        sender_agent_id=msg.sender_agent_id,
        payload=json.dumps(msg.payload),
        nonce=msg.nonce,
        timestamp=msg.timestamp,
        signature=msg.signature,
    )
    db.add(record)
    await db.commit()


async def restore_sessions(db: AsyncSession, store: SessionStore) -> int:
    """
    Load from DB all non-expired, non-closed sessions,
    reconstituting the in-memory store (sessions + messages + nonces).

    Each session is re-validated before restoration:
    - initiator binding must still be approved
    - session policy must still allow the initiator→target org pair

    Sessions failing validation are closed in DB and skipped.
    Returns the number of sessions successfully restored.
    """
    # Deferred imports to avoid circular dependencies at module load time.
    from app.policy.engine import PolicyEngine
    from app.registry.binding_store import get_approved_binding

    now = datetime.now(timezone.utc)
    policy_engine = PolicyEngine()

    result = await db.execute(
        select(SessionRecord).where(
            SessionRecord.status.in_(["pending", "active"]),
        )
    )
    records = result.scalars().all()

    restored = 0
    for rec in records:
        # Skip expired sessions
        if rec.expires_at and rec.expires_at.replace(tzinfo=timezone.utc) < now:
            continue

        # Re-validate initiator binding — must still be approved after restart.
        binding = await get_approved_binding(db, rec.initiator_org_id, rec.initiator_agent_id)
        if not binding:
            logger.warning(
                "Session %s invalidated on restore: binding revoked or missing for agent %s",
                rec.session_id, rec.initiator_agent_id,
            )
            rec.status = "closed"
            rec.closed_at = now
            await db.commit()
            continue

        # Re-validate session policy — may have been deactivated since session was opened.
        capabilities = json.loads(rec.requested_capabilities)
        decision = await policy_engine.evaluate_session(
            db,
            initiator_org_id=rec.initiator_org_id,
            target_org_id=rec.target_org_id,
            capabilities=capabilities,
            session_id=rec.session_id,
        )
        if not decision.allowed:
            logger.warning(
                "Session %s invalidated on restore: policy denied — %s",
                rec.session_id, decision.reason,
            )
            rec.status = "closed"
            rec.closed_at = now
            await db.commit()
            continue

        session = Session(
            session_id=rec.session_id,
            initiator_agent_id=rec.initiator_agent_id,
            initiator_org_id=rec.initiator_org_id,
            target_agent_id=rec.target_agent_id,
            target_org_id=rec.target_org_id,
            requested_capabilities=json.loads(rec.requested_capabilities),
            status=SessionStatus(rec.status),
            created_at=rec.created_at.replace(tzinfo=timezone.utc),
            expires_at=rec.expires_at.replace(tzinfo=timezone.utc) if rec.expires_at else None,
        )

        # Reload messages and rebuild nonce set
        msg_result = await db.execute(
            select(SessionMessageRecord)
            .where(SessionMessageRecord.session_id == rec.session_id)
            .order_by(SessionMessageRecord.seq)
        )
        for msg_rec in msg_result.scalars().all():
            stored = StoredMessage(
                seq=msg_rec.seq,
                sender_agent_id=msg_rec.sender_agent_id,
                payload=json.loads(msg_rec.payload),
                nonce=msg_rec.nonce,
                timestamp=msg_rec.timestamp.replace(tzinfo=timezone.utc),
                signature=msg_rec.signature,
            )
            session._messages.append(stored)
            session.used_nonces.add(msg_rec.nonce)
            session._next_seq = max(session._next_seq, msg_rec.seq + 1)

        store._sessions[session.session_id] = session
        restored += 1

    return restored
