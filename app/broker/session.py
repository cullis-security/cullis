"""
In-memory session store for the MVP.
In production: Redis with TTL, persistence on PostgreSQL.

Each session has a unique ID and tracks:
- who started it (initiator)
- who receives it (target)
- current status
- already used nonces (message-level replay protection)
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from app.broker.models import SessionStatus

_log = logging.getLogger("agent_trust")


@dataclass
class StoredMessage:
    seq: int
    sender_agent_id: str
    payload: dict
    nonce: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str | None = None
    client_seq: int | None = None


@dataclass
class Session:
    session_id: str
    initiator_agent_id: str
    initiator_org_id: str
    target_agent_id: str
    target_org_id: str
    requested_capabilities: list[str]
    status: SessionStatus = SessionStatus.pending
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    used_nonces: set[str] = field(default_factory=set)
    _messages: list[StoredMessage] = field(default_factory=list)
    _next_seq: int = 0
    _MAX_NONCES: int = 100_000  # prevent unbounded memory growth

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_nonce_cached(self, nonce: str) -> bool:
        """Fast-path replay check against the in-memory cache.

        The DB (via ``save_message`` ON CONFLICT) is the source of truth;
        this cache prevents an unnecessary DB round-trip for obvious replays.
        """
        return nonce in self.used_nonces

    def cache_nonce(self, nonce: str) -> None:
        """Record a nonce in the in-memory cache after successful DB insert.

        When the cache is full, an arbitrary entry is evicted.
        The DB UNIQUE constraint remains the authoritative replay guard;
        this cache is only a fast-path optimisation.
        """
        if len(self.used_nonces) >= self._MAX_NONCES:
            self.used_nonces.pop()
        self.used_nonces.add(nonce)

    def store_message(self, sender_agent_id: str, payload: dict, nonce: str,
                      signature: str | None = None, client_seq: int | None = None) -> int:
        """Store the message in the session inbox and return the assigned seq."""
        seq = self._next_seq
        self._messages.append(StoredMessage(
            seq=seq,
            sender_agent_id=sender_agent_id,
            payload=payload,
            nonce=nonce,
            signature=signature,
            client_seq=client_seq,
        ))
        self._next_seq += 1
        return seq

    def get_messages_for(self, agent_id: str, after: int = -1) -> list[StoredMessage]:
        """
        Returns messages intended for agent_id (i.e. NOT sent by them)
        with seq > after. Used for polling.
        """
        return [
            m for m in self._messages
            if m.seq > after and m.sender_agent_id != agent_id
        ]


class SessionStore:
    _MAX_SESSIONS: int = 10_000  # hard cap — prevents unbounded memory growth

    def __init__(self, session_ttl_minutes: int = 60):
        self._sessions: dict[str, Session] = {}
        self._ttl = timedelta(minutes=session_ttl_minutes)
        self._lock = asyncio.Lock()  # protects state transitions (accept/reject/close)

    # ── Eviction ─────────────────────────────────────────────────────────

    def _evict_stale(self) -> int:
        """Remove expired and terminal sessions from the in-memory store.

        Called automatically before creating a new session.  Returns the
        number of sessions evicted.
        """
        now = datetime.now(timezone.utc)
        to_remove = [
            sid for sid, s in self._sessions.items()
            if s.status in (SessionStatus.closed, SessionStatus.denied)
            or (s.expires_at is not None and s.expires_at < now)
        ]
        for sid in to_remove:
            del self._sessions[sid]
        if to_remove:
            _log.info("Evicted %d stale session(s) from in-memory store", len(to_remove))
        return len(to_remove)

    # ── CRUD ─────────────────────────────────────────────────────────────

    def create(
        self,
        initiator_agent_id: str,
        initiator_org_id: str,
        target_agent_id: str,
        target_org_id: str,
        requested_capabilities: list[str],
    ) -> Session:
        # Evict stale sessions before checking the cap
        self._evict_stale()

        if len(self._sessions) >= self._MAX_SESSIONS:
            raise RuntimeError(
                f"Session store full ({self._MAX_SESSIONS} sessions) — "
                "cannot create new session"
            )

        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        session = Session(
            session_id=session_id,
            initiator_agent_id=initiator_agent_id,
            initiator_org_id=initiator_org_id,
            target_agent_id=target_agent_id,
            target_org_id=target_org_id,
            requested_capabilities=requested_capabilities,
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired() and session.status != SessionStatus.closed:
            session.status = SessionStatus.closed
        return session

    def activate(self, session_id: str) -> Session | None:
        session = self.get(session_id)
        if session and session.status == SessionStatus.pending:
            session.status = SessionStatus.active
        return session

    def reject(self, session_id: str) -> Session | None:
        session = self.get(session_id)
        if session and session.status == SessionStatus.pending:
            session.status = SessionStatus.denied
        return session

    def close(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.status = SessionStatus.closed

    def close_all_for_agent(self, agent_id: str) -> list[Session]:
        """Close all active/pending sessions involving the given agent.
        Returns the list of sessions that were closed."""
        closed = []
        for s in self._sessions.values():
            if s.status in (SessionStatus.active, SessionStatus.pending) and (
                s.initiator_agent_id == agent_id or s.target_agent_id == agent_id
            ):
                s.status = SessionStatus.closed
                closed.append(s)
        return closed

    def list_for_agent(self, agent_id: str, *, limit: int = 100, offset: int = 0) -> list[Session]:
        matches = [
            s for s in self._sessions.values()
            if s.initiator_agent_id == agent_id or s.target_agent_id == agent_id
        ]
        return matches[offset:offset + limit]


# Singleton per il MVP
session_store = SessionStore()


def get_session_store() -> SessionStore:
    return session_store
