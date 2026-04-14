"""In-memory session store for intra-org traffic.

Mirrors the subset of `app/broker/session.py` needed for proxy-side
delivery. Simplifications vs the broker:

  - Single org: both peers are registered in `internal_agents` under the
    proxy's own org_id, so no org_id column and no binding check.
  - No in-memory message buffer: messages live in `local_messages`
    (Phase 3c).
  - No nonce cache: message-level replay protection lands with messages
    (Phase 3c).
  - Capabilities and expires_at are held in memory but NOT persisted
    (the `local_sessions` schema doesn't have those columns). On
    restart, expires_at is reconstructed as created_at + HARD_TTL.

Concurrency: `LocalSessionStore._lock` protects state transitions so
`activate`/`reject`/`close` are atomic against each other. Individual
Session instances are not locked here — that'll come with the message
queue in 3c (per broker pattern).
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from mcp_proxy.local.models import SessionCloseReason, SessionStatus

_log = logging.getLogger("mcp_proxy.local.session")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        _log.warning("Invalid %s=%r, falling back to default %d", name, raw, default)
        return default


LOCAL_SESSION_IDLE_TIMEOUT_SECONDS = _env_int("PROXY_LOCAL_SESSION_IDLE_TIMEOUT_SECONDS", 600)
LOCAL_SESSION_HARD_TTL_MINUTES = _env_int("PROXY_LOCAL_SESSION_HARD_TTL_MINUTES", 60)
LOCAL_SESSION_CAP_ACTIVE_PER_AGENT = _env_int("PROXY_LOCAL_SESSION_CAP_ACTIVE_PER_AGENT", 50)


@dataclass
class LocalSession:
    session_id: str
    initiator_agent_id: str
    responder_agent_id: str
    requested_capabilities: list[str]
    status: SessionStatus = SessionStatus.pending
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    close_reason: SessionCloseReason | None = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_idle(self, timeout_seconds: int = LOCAL_SESSION_IDLE_TIMEOUT_SECONDS) -> bool:
        if self.status not in (SessionStatus.active, SessionStatus.pending):
            return False
        age = (datetime.now(timezone.utc) - self.last_activity_at).total_seconds()
        return age > timeout_seconds

    def touch(self) -> None:
        self.last_activity_at = datetime.now(timezone.utc)

    def involves(self, agent_id: str) -> bool:
        return agent_id in (self.initiator_agent_id, self.responder_agent_id)


class LocalAgentSessionCapExceeded(Exception):
    """Raised when an agent has too many concurrent ACTIVE local sessions."""

    def __init__(self, agent_id: str, current: int, cap: int):
        self.agent_id = agent_id
        self.current = current
        self.cap = cap
        super().__init__(
            f"Agent {agent_id} has {current} ACTIVE local sessions "
            f"(cap {cap}) — cannot open new session"
        )


class LocalSessionStore:
    _MAX_SESSIONS: int = 10_000

    def __init__(
        self,
        session_ttl_minutes: int | None = None,
        active_cap_per_agent: int | None = None,
    ):
        self._sessions: dict[str, LocalSession] = {}
        self._ttl = timedelta(
            minutes=session_ttl_minutes
            if session_ttl_minutes is not None
            else LOCAL_SESSION_HARD_TTL_MINUTES
        )
        self._active_cap_per_agent = (
            active_cap_per_agent
            if active_cap_per_agent is not None
            else LOCAL_SESSION_CAP_ACTIVE_PER_AGENT
        )
        self._lock = asyncio.Lock()

    # ── Eviction ────────────────────────────────────────────────────

    def _evict_terminated(self) -> int:
        to_remove = [
            sid for sid, s in self._sessions.items()
            if s.status in (SessionStatus.closed, SessionStatus.denied)
        ]
        for sid in to_remove:
            del self._sessions[sid]
        if to_remove:
            _log.info("Evicted %d terminated local session(s)", len(to_remove))
        return len(to_remove)

    # ── CRUD ────────────────────────────────────────────────────────

    def count_active_for_agent(self, agent_id: str) -> int:
        return sum(
            1
            for s in self._sessions.values()
            if s.status == SessionStatus.active and s.involves(agent_id)
        )

    def create(
        self,
        initiator_agent_id: str,
        responder_agent_id: str,
        requested_capabilities: list[str],
    ) -> LocalSession:
        self._evict_terminated()

        if len(self._sessions) >= self._MAX_SESSIONS:
            raise RuntimeError(
                f"Local session store full ({self._MAX_SESSIONS}) — cannot create new session"
            )

        active_for_initiator = self.count_active_for_agent(initiator_agent_id)
        if active_for_initiator >= self._active_cap_per_agent:
            raise LocalAgentSessionCapExceeded(
                agent_id=initiator_agent_id,
                current=active_for_initiator,
                cap=self._active_cap_per_agent,
            )

        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        session = LocalSession(
            session_id=session_id,
            initiator_agent_id=initiator_agent_id,
            responder_agent_id=responder_agent_id,
            requested_capabilities=list(requested_capabilities),
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> LocalSession | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired() and session.status != SessionStatus.closed:
            session.status = SessionStatus.closed
            if session.close_reason is None:
                session.close_reason = SessionCloseReason.ttl_expired
        return session

    def activate(self, session_id: str) -> LocalSession | None:
        session = self.get(session_id)
        if session and session.status == SessionStatus.pending:
            session.status = SessionStatus.active
            session.touch()
        return session

    def reject(self, session_id: str) -> LocalSession | None:
        session = self.get(session_id)
        if session and session.status == SessionStatus.pending:
            session.status = SessionStatus.denied
            session.close_reason = SessionCloseReason.rejected
        return session

    def close(
        self,
        session_id: str,
        reason: SessionCloseReason = SessionCloseReason.normal,
    ) -> LocalSession | None:
        session = self._sessions.get(session_id)
        if session and session.status != SessionStatus.closed:
            session.status = SessionStatus.closed
            if session.close_reason is None:
                session.close_reason = reason
        return session

    def find_stale(
        self,
        idle_timeout_seconds: int = LOCAL_SESSION_IDLE_TIMEOUT_SECONDS,
    ) -> list[tuple[LocalSession, SessionCloseReason]]:
        out: list[tuple[LocalSession, SessionCloseReason]] = []
        for s in self._sessions.values():
            if s.status in (SessionStatus.closed, SessionStatus.denied):
                continue
            if s.is_expired():
                out.append((s, SessionCloseReason.ttl_expired))
            elif s.is_idle(idle_timeout_seconds):
                out.append((s, SessionCloseReason.idle_timeout))
        return out

    def list_for_agent(self, agent_id: str) -> list[LocalSession]:
        return [s for s in self._sessions.values() if s.involves(agent_id)]

    def restore(self, session: LocalSession) -> None:
        """Insert a session reconstructed from persistence (startup path)."""
        self._sessions[session.session_id] = session

    @property
    def hard_ttl(self) -> timedelta:
        return self._ttl
