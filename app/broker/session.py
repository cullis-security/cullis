"""
In-memory session store for the MVP.
In production: Redis with TTL, persistence on PostgreSQL.

Each session has a unique ID and tracks:
- who started it (initiator)
- who receives it (target)
- current status
- already used nonces (message-level replay protection)

Concurrency model (audit L4-H1):
The store carries TWO locks with distinct purposes.

- ``_lock`` (``asyncio.Lock``): coarse, transaction-scope lock held by
  callers around "read-validate-mutate-persist" sequences that span an
  ``await`` (typically ``await save_session(db, ...)``). It serializes
  coroutines but is useless against threadpool callers because
  ``asyncio.Lock`` is not thread-safe. Existing routers use this.
- ``_state_lock`` (``threading.RLock``): fine-grained, held internally by
  every mutation method around the in-memory ``self._sessions`` dict and
  ``Session.status`` writes. Reentrant so ``create`` can call
  ``_evict_stale`` while still holding it. Defends against the
  ``RuntimeError: dictionary changed size during iteration`` race that
  would surface if any caller ever ran the store off the event loop
  thread (e.g. FastAPI sync endpoints scheduled to the threadpool, future
  background workers, the dashboard's BackgroundTasks). On the current
  single-threaded asyncio runtime the lock is uncontended.

Mutation methods MUST acquire ``_state_lock``. Iteration over
``self._sessions`` MUST snapshot under the lock (``list(...)``) before
yielding the values to the caller. No ``await`` is performed inside
``_state_lock``: it only guards in-memory transitions.
"""
import asyncio
import logging
import os
import threading
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from app.broker.models import SessionStatus, SessionCloseReason

_log = logging.getLogger("agent_trust")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        _log.warning("Invalid %s=%r, falling back to default %d", name, raw, default)
        return default


# M1 reliability layer defaults (overridable via env for tests / per-org tuning)
SESSION_IDLE_TIMEOUT_SECONDS = _env_int("SESSION_IDLE_TIMEOUT_SECONDS", 600)   # 10 min
SESSION_HARD_TTL_MINUTES     = _env_int("SESSION_HARD_TTL_MINUTES", 60)        # 1 hour
SESSION_CAP_ACTIVE_PER_AGENT = _env_int("SESSION_CAP_ACTIVE_PER_AGENT", 50)    # O4 decision: only ACTIVE capped


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
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    close_reason: SessionCloseReason | None = None
    used_nonces: set[str] = field(default_factory=set)
    _messages: list[StoredMessage] = field(default_factory=list)
    _next_seq: int = 0
    _MAX_NONCES: int = 100_000  # prevent unbounded memory growth
    _msg_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_idle(self, timeout_seconds: int = SESSION_IDLE_TIMEOUT_SECONDS) -> bool:
        """True if no activity has been recorded in the last ``timeout_seconds``.

        Activity is anything that calls :meth:`touch`: send, poll, accept.
        Idle sessions are terminal candidates for the sweeper (M1.1).
        """
        if self.status not in (SessionStatus.active, SessionStatus.pending):
            return False
        age = (datetime.now(timezone.utc) - self.last_activity_at).total_seconds()
        return age > timeout_seconds

    def touch(self) -> None:
        """Record activity on the session. Resets the idle timer.

        Called from the router on every send, poll, and accept. Idempotent.
        """
        self.last_activity_at = datetime.now(timezone.utc)

    def is_nonce_cached(self, nonce: str) -> bool:
        """Fast-path replay check against the in-memory cache.

        The DB (via ``save_message`` ON CONFLICT) is the source of truth;
        this cache prevents an unnecessary DB round-trip for obvious replays.
        At capacity, unknown nonces pass through to the DB check (eviction
        happens in cache_nonce).
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
                      signature: str | None = None, client_seq: int | None = None,
                      timestamp: datetime | None = None) -> int:
        """Store the message in the session inbox and return the assigned seq.

        ``timestamp`` is the *signer's* wire timestamp (seconds since epoch
        is converted to UTC datetime by the caller). When omitted, the
        StoredMessage default_factory falls back to ``datetime.now(utc)``,
        which is broker-side and discards the signer's claim — that mode
        exists only for legacy callers that don't carry a signed timestamp
        (transaction tokens, internal injections). Audit W1.6: the broker
        used to silently overwrite the signed timestamp with its local
        now() for every send, breaking SDK session-poll consumers that
        rely on the signer's clock for ordering inferences."""
        seq = self._next_seq
        msg_kwargs = dict(
            seq=seq,
            sender_agent_id=sender_agent_id,
            payload=payload,
            nonce=nonce,
            signature=signature,
            client_seq=client_seq,
        )
        if timestamp is not None:
            msg_kwargs["timestamp"] = timestamp
        self._messages.append(StoredMessage(**msg_kwargs))
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


class AgentSessionCapExceeded(Exception):
    """Raised when an agent has too many concurrent ACTIVE sessions (O4)."""

    def __init__(self, agent_id: str, current: int, cap: int):
        self.agent_id = agent_id
        self.current = current
        self.cap = cap
        super().__init__(
            f"Agent {agent_id} has {current} ACTIVE sessions "
            f"(cap {cap}) — cannot open new session"
        )


class SessionStore:
    _MAX_SESSIONS: int = 10_000  # hard cap — prevents unbounded memory growth

    def __init__(
        self,
        session_ttl_minutes: int | None = None,
        active_cap_per_agent: int | None = None,
    ):
        self._sessions: dict[str, Session] = {}
        self._ttl = timedelta(
            minutes=session_ttl_minutes
            if session_ttl_minutes is not None
            else SESSION_HARD_TTL_MINUTES
        )
        self._active_cap_per_agent = (
            active_cap_per_agent
            if active_cap_per_agent is not None
            else SESSION_CAP_ACTIVE_PER_AGENT
        )
        # ``_lock`` is the transaction-scope lock for callers that need to
        # straddle an ``await`` (e.g. mutate-then-persist). ``_state_lock`` is
        # the in-memory dict guard acquired by every mutation method below;
        # it is reentrant so ``create`` can call ``_evict_stale`` without
        # deadlock. See the module docstring for the full contract.
        self._lock = asyncio.Lock()
        self._state_lock = threading.RLock()

    # ── Eviction ─────────────────────────────────────────────────────────

    def _evict_stale(self) -> int:
        """Remove already-terminated sessions from the in-memory store.

        Called automatically before creating a new session.  Returns the
        number of sessions evicted.

        Only sessions in CLOSED/DENIED states are evicted here — sessions
        whose ``expires_at`` has passed but are still PENDING/ACTIVE are
        left in place so the background sweeper (M1.1) can transition
        them to CLOSED and emit a ``session.closed`` event with reason
        ``ttl_expired`` before they disappear.
        """
        with self._state_lock:
            to_remove = [
                sid for sid, s in self._sessions.items()
                if s.status in (SessionStatus.closed, SessionStatus.denied)
            ]
            for sid in to_remove:
                del self._sessions[sid]
        if to_remove:
            _log.info("Evicted %d stale session(s) from in-memory store", len(to_remove))
        return len(to_remove)

    # ── CRUD ─────────────────────────────────────────────────────────────

    def count_active_for_agent(self, agent_id: str) -> int:
        """Count ACTIVE sessions involving ``agent_id`` (as initiator or target).

        Used by :meth:`create` to enforce the per-agent cap (O4 decision:
        only ACTIVE is capped; PENDING is rate-limited at the route level
        and auto-swept when it times out).
        """
        with self._state_lock:
            snapshot = list(self._sessions.values())
        return sum(
            1
            for s in snapshot
            if s.status == SessionStatus.active
            and (s.initiator_agent_id == agent_id or s.target_agent_id == agent_id)
        )

    def create(
        self,
        initiator_agent_id: str,
        initiator_org_id: str,
        target_agent_id: str,
        target_org_id: str,
        requested_capabilities: list[str],
    ) -> Session:
        # The whole sequence (evict → cap check → cap-per-agent → insert) must
        # be atomic w.r.t. concurrent mutations, otherwise two creators can
        # both observe ``len < _MAX_SESSIONS`` and overflow the cap. RLock is
        # required so the inner ``_evict_stale`` and ``count_active_for_agent``
        # calls reacquire without deadlock.
        with self._state_lock:
            # Evict stale sessions before checking the cap
            self._evict_stale()

            if len(self._sessions) >= self._MAX_SESSIONS:
                raise RuntimeError(
                    f"Session store full ({self._MAX_SESSIONS} sessions) — "
                    "cannot create new session"
                )

            # M1.4 per-agent ACTIVE cap (applies to the initiator; the target's
            # cap is re-checked when they accept).
            active_for_initiator = self.count_active_for_agent(initiator_agent_id)
            if active_for_initiator >= self._active_cap_per_agent:
                raise AgentSessionCapExceeded(
                    agent_id=initiator_agent_id,
                    current=active_for_initiator,
                    cap=self._active_cap_per_agent,
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
        # The TTL-expiry side-effect mutates ``session.status``, so the read
        # has to happen under the state lock to stay consistent with concurrent
        # ``close`` / ``activate`` callers.
        with self._state_lock:
            session = self._sessions.get(session_id)
            if session and session.is_expired() and session.status != SessionStatus.closed:
                session.status = SessionStatus.closed
            return session

    def activate(self, session_id: str) -> Session | None:
        with self._state_lock:
            session = self.get(session_id)
            if session and session.status == SessionStatus.pending:
                session.status = SessionStatus.active
                session.touch()
            return session

    def reject(self, session_id: str) -> Session | None:
        with self._state_lock:
            session = self.get(session_id)
            if session and session.status == SessionStatus.pending:
                session.status = SessionStatus.denied
                session.close_reason = SessionCloseReason.rejected
            return session

    def close(
        self,
        session_id: str,
        reason: SessionCloseReason = SessionCloseReason.normal,
    ) -> Session | None:
        """Close a session, recording why.

        ``reason`` is attached to the session and propagated to peers via
        the ``session.closed`` event (M1.3). The event emission itself
        lives at the router level — this method only mutates state.
        """
        with self._state_lock:
            session = self._sessions.get(session_id)
            if session and session.status != SessionStatus.closed:
                session.status = SessionStatus.closed
                if session.close_reason is None:
                    session.close_reason = reason
            return session

    def close_all_for_agent(
        self,
        agent_id: str,
        reason: SessionCloseReason = SessionCloseReason.normal,
    ) -> list[Session]:
        """Close all active/pending sessions involving the given agent.
        Returns the list of sessions that were closed.

        Snapshots the current sessions under ``_state_lock`` before iterating,
        so a concurrent ``create`` can never trigger
        ``RuntimeError: dictionary changed size during iteration`` (audit L4-H1).
        Mutation of each session's status also happens under the same lock so
        the close decision is atomic w.r.t. ``activate`` / ``close``.
        """
        closed = []
        with self._state_lock:
            for s in list(self._sessions.values()):
                if s.status in (SessionStatus.active, SessionStatus.pending) and (
                    s.initiator_agent_id == agent_id or s.target_agent_id == agent_id
                ):
                    s.status = SessionStatus.closed
                    if s.close_reason is None:
                        s.close_reason = reason
                    closed.append(s)
        return closed

    def find_stale(
        self,
        idle_timeout_seconds: int = SESSION_IDLE_TIMEOUT_SECONDS,
    ) -> list[tuple[Session, SessionCloseReason]]:
        """Return sessions that should be closed by the sweeper (M1.1).

        A session is stale when:
          - expires_at < now                → ttl_expired
          - status in (active, pending) AND idle > idle_timeout_seconds → idle_timeout

        Returns ``[(session, reason)]`` so the sweeper can emit per-session
        close events with the right reason.
        """
        out: list[tuple[Session, SessionCloseReason]] = []
        with self._state_lock:
            snapshot = list(self._sessions.values())
        for s in snapshot:
            if s.status in (SessionStatus.closed, SessionStatus.denied):
                continue
            if s.is_expired():
                out.append((s, SessionCloseReason.ttl_expired))
            elif s.is_idle(idle_timeout_seconds):
                out.append((s, SessionCloseReason.idle_timeout))
        return out

    def list_for_agent(self, agent_id: str, *, limit: int = 100, offset: int = 0) -> list[Session]:
        with self._state_lock:
            snapshot = list(self._sessions.values())
        matches = [
            s for s in snapshot
            if s.initiator_agent_id == agent_id or s.target_agent_id == agent_id
        ]
        if limit <= 0:
            return matches[offset:]
        return matches[offset:offset + limit]


# Singleton per il MVP
session_store = SessionStore()


def get_session_store() -> SessionStore:
    return session_store
