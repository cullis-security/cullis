"""
In-memory session store for the MVP.
In production: Redis with TTL, persistence on PostgreSQL.

Each session has a unique ID and tracks:
- who started it (initiator)
- who receives it (target)
- current status
- already used nonces (message-level replay protection)
"""
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from app.broker.models import SessionStatus


@dataclass
class StoredMessage:
    seq: int
    sender_agent_id: str
    payload: dict
    nonce: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str | None = None


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

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def consume_nonce(self, nonce: str) -> bool:
        """Returns False if the nonce has already been used (replay attack)."""
        if nonce in self.used_nonces:
            return False
        self.used_nonces.add(nonce)
        return True

    def store_message(self, sender_agent_id: str, payload: dict, nonce: str, signature: str | None = None) -> int:
        """Store the message in the session inbox and return the assigned seq."""
        seq = self._next_seq
        self._messages.append(StoredMessage(
            seq=seq,
            sender_agent_id=sender_agent_id,
            payload=payload,
            nonce=nonce,
            signature=signature,
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
    def __init__(self, session_ttl_minutes: int = 60):
        self._sessions: dict[str, Session] = {}
        self._ttl = timedelta(minutes=session_ttl_minutes)

    def create(
        self,
        initiator_agent_id: str,
        initiator_org_id: str,
        target_agent_id: str,
        target_org_id: str,
        requested_capabilities: list[str],
    ) -> Session:
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
        if session and session.is_expired():
            session.status = SessionStatus.closed
        return session

    def activate(self, session_id: str) -> Session | None:
        session = self.get(session_id)
        if session and session.status == SessionStatus.pending:
            session.status = SessionStatus.active
        return session

    def close(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.status = SessionStatus.closed

    def list_for_agent(self, agent_id: str) -> list[Session]:
        return [
            s for s in self._sessions.values()
            if s.initiator_agent_id == agent_id or s.target_agent_id == agent_id
        ]


# Singleton per il MVP
session_store = SessionStore()


def get_session_store() -> SessionStore:
    return session_store
