"""Append-only audit log for the Connector local-auth subsystem.

ADR-025 Phase 4 — records login attempts, password changes, lockout
triggers and admin actions into a co-resident SQLite database
(``<config_dir>/users.db``) with row-level append-only enforced by SQL
triggers (UPDATE / DELETE → ``RAISE FAIL``). Volume is ~1-100 rows/day
on an SMB Frontdesk, so a Merkle hash chain (Mastio audit pattern in
``app/db/audit.py``) is overkill at this scale and is explicitly out of
scope for v1 — see ADR-025.

Design constraints (memory rule "audit log append-only" + ADR-025 threat
model):

- Audit row never carries plain admin secret — only SHA256 hash as
  ``actor_secret_hash`` so post-hoc analysis can correlate "same admin
  did these N actions" without exposing the secret value.
- Audit row never carries password / hash. ``log_password_change``
  records *that* a user rotated their password, never the value.
- Append-only enforced at the SQL trigger layer so a Connector
  compromise that gains DB-write access still cannot rewrite the
  trail without RAISE FAIL surfacing in the application logs.

The module is **self-standing**: it opens its own ``users.db`` engine
keyed on ``config_dir`` and does NOT import from a Phase 1 ``users_db``
module that may not exist yet on this branch base. When P1 lands the
two modules will live side by side, both writing to the same SQLite
file via SQLAlchemy's connection pool — SQLite handles the cross-engine
locking. A trivial post-merge rebase can later collapse the two
engine factories into one.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    Index,
    Integer,
    String,
    Text,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

_log = logging.getLogger("cullis_connector.identity.audit")

USERS_DB_FILENAME = "users.db"


class _Base(DeclarativeBase):
    pass


class LocalAuditLog(_Base):
    """Append-only row recording one local-auth security event."""

    __tablename__ = "local_audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(String(32), nullable=False)  # ISO-8601 UTC
    ip = Column(String(64), nullable=True)
    user_name = Column(String(128), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    status = Column(String(16), nullable=False)  # 'ok' | 'fail' | 'locked'
    detail = Column(Text, nullable=True)  # canonical JSON for structured details

    __table_args__ = (
        Index("idx_audit_user_ts", "user_name", "ts"),
        Index("idx_audit_action_ts", "action", "ts"),
    )


# ── Engine cache ──────────────────────────────────────────────────────────
# One engine per ``(config_dir, current event loop)``. Pytest-asyncio
# uses a fresh loop per worker / test; reusing an engine bound to a
# closed loop produces ``no such table`` failures because the connection
# pool's loop reference is stale. Mirrors the fix Phase 1 shipped for
# ``users_db.py`` (commit 600713ff in #548).
_engine_cache: dict[tuple[Path, int], AsyncEngine] = {}
_engine_lock = asyncio.Lock()


def _current_loop_key() -> int:
    """Return ``id`` of the running asyncio loop, or 0 when none is active."""
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return 0


def _users_db_path(config_dir: Path) -> Path:
    return Path(config_dir) / USERS_DB_FILENAME


def _engine_for(config_dir: Path) -> AsyncEngine | None:
    return _engine_cache.get((Path(config_dir).resolve(), _current_loop_key()))


async def init_audit_log(config_dir: Path) -> AsyncEngine:
    """Initialise the audit table + append-only triggers (idempotent).

    Creates the SQLite database file under ``<config_dir>/users.db`` if
    it does not exist, runs ``Base.metadata.create_all`` for the
    ``local_audit_log`` table, then installs the
    ``audit_no_update`` / ``audit_no_delete`` triggers. Safe to call
    multiple times; subsequent calls return the cached engine.
    """
    config_dir = Path(config_dir).resolve()
    config_dir.mkdir(parents=True, exist_ok=True)
    cache_key = (config_dir, _current_loop_key())

    async with _engine_lock:
        cached = _engine_cache.get(cache_key)
        if cached is not None:
            return cached

        db_path = _users_db_path(config_dir)
        url = f"sqlite+aiosqlite:///{db_path}"
        engine = create_async_engine(url, future=True)

        async with engine.begin() as conn:
            # Create the table if it does not exist. The SQLAlchemy
            # ``create_all`` is a no-op when the schema already matches.
            await conn.run_sync(_Base.metadata.create_all)
            # Triggers: BEFORE UPDATE / BEFORE DELETE → RAISE(FAIL).
            # ``CREATE TRIGGER IF NOT EXISTS`` keeps the call idempotent
            # across restarts.
            await conn.exec_driver_sql(
                "CREATE TRIGGER IF NOT EXISTS audit_no_update "
                "BEFORE UPDATE ON local_audit_log "
                "BEGIN SELECT RAISE(FAIL, 'audit log is append-only'); END;"
            )
            await conn.exec_driver_sql(
                "CREATE TRIGGER IF NOT EXISTS audit_no_delete "
                "BEFORE DELETE ON local_audit_log "
                "BEGIN SELECT RAISE(FAIL, 'audit log is append-only'); END;"
            )

        # Tighten the file permissions to 0600 on POSIX — the audit log
        # may carry IPs and usernames that should not be world-readable.
        if os.name == "posix":
            try:
                os.chmod(db_path, 0o600)
            except OSError:  # pragma: no cover — best effort
                _log.warning("could not chmod 0600 on %s", db_path)

        _engine_cache[cache_key] = engine
        return engine


def _session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def _append(
    config_dir: Path,
    *,
    action: str,
    status: str,
    ip: str | None = None,
    user_name: str | None = None,
    detail: dict[str, Any] | None = None,
) -> LocalAuditLog:
    engine = await init_audit_log(config_dir)
    detail_json = (
        json.dumps(detail, sort_keys=True, separators=(",", ":"))
        if detail
        else None
    )
    row = LocalAuditLog(
        ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ip=ip,
        user_name=user_name,
        action=action,
        status=status,
        detail=detail_json,
    )
    async with _session_factory(engine)() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row


async def log_login_attempt(
    config_dir: Path,
    *,
    ip: str,
    user_name: str | None,
    status: str,
    reason: str = "",
) -> LocalAuditLog:
    """Record one local-auth login attempt.

    ``status`` is ``'ok'`` for a successful login, ``'fail'`` for a
    bad password / unknown user, ``'locked'`` when the IP is rejected
    pre-bcrypt because of an active lockout.
    """
    detail = {"reason": reason} if reason else None
    return await _append(
        config_dir,
        action="login.attempt",
        status=status,
        ip=ip,
        user_name=user_name,
        detail=detail,
    )


async def log_password_change(
    config_dir: Path, *, user_name: str
) -> LocalAuditLog:
    """Record a successful password rotation. Never carries the value."""
    return await _append(
        config_dir,
        action="pw.change",
        status="ok",
        user_name=user_name,
    )


async def log_admin_action(
    config_dir: Path,
    *,
    action: str,
    target: str,
    actor_secret_hash: str,
) -> LocalAuditLog:
    """Record an admin action (user create / disable / reset, etc.).

    ``actor_secret_hash`` MUST be the SHA256 hex digest of the admin
    secret presented for the request — never the secret itself. The
    caller is responsible for hashing; this helper trusts the input
    and only validates that it looks like a 64-char hex string.
    """
    if (
        not isinstance(actor_secret_hash, str)
        or len(actor_secret_hash) != 64
        or any(c not in "0123456789abcdef" for c in actor_secret_hash.lower())
    ):
        raise ValueError(
            "actor_secret_hash must be a 64-char SHA256 hex digest"
        )
    return await _append(
        config_dir,
        action=action,
        status="ok",
        user_name=target,
        detail={"actor_secret_hash": actor_secret_hash},
    )


async def log_lockout_trigger(
    config_dir: Path,
    *,
    ip: str,
    locked_until: float,
    user_name: str | None = None,
) -> LocalAuditLog:
    """Record that a per-IP lockout fired (5 fails / 15 min)."""
    detail = {
        "locked_until": datetime.fromtimestamp(
            locked_until, tz=timezone.utc
        ).isoformat(timespec="seconds"),
    }
    return await _append(
        config_dir,
        action="login.locked",
        status="locked",
        ip=ip,
        user_name=user_name,
        detail=detail,
    )


def hash_admin_secret(secret: str) -> str:
    """Convenience: SHA256 hex digest of an admin secret string.

    Stored in the audit row as ``actor_secret_hash`` so post-hoc
    analysis can correlate "same admin did these N actions" without
    exposing the secret value itself.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


async def query_audit(
    config_dir: Path,
    *,
    since: datetime | None = None,
    user_name: str | None = None,
    action: str | None = None,
    limit: int = 200,
) -> list[LocalAuditLog]:
    """Query audit rows with optional filters, newest first.

    ``limit`` is clamped to ``[1, 1000]`` to bound memory use.
    """
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    engine = await init_audit_log(config_dir)
    stmt = select(LocalAuditLog)
    if since is not None:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        stmt = stmt.where(
            LocalAuditLog.ts >= since.isoformat(timespec="seconds")
        )
    if user_name is not None:
        stmt = stmt.where(LocalAuditLog.user_name == user_name)
    if action is not None:
        stmt = stmt.where(LocalAuditLog.action == action)
    stmt = stmt.order_by(LocalAuditLog.id.desc()).limit(limit)

    async with _session_factory(engine)() as session:
        result = await session.execute(stmt)
        return list(result.scalars().all())


def reset_engine_cache_for_tests() -> None:
    """Test-only helper: clear the engine cache so tests with fresh
    ``tmp_path`` directories do not share an open engine handle."""
    _engine_cache.clear()


# Suppress unused-import warning for ``stat`` — kept on the imports
# for future hooks (file-perm strict check on read).
_ = stat


__all__ = [
    "LocalAuditLog",
    "USERS_DB_FILENAME",
    "hash_admin_secret",
    "init_audit_log",
    "log_admin_action",
    "log_lockout_trigger",
    "log_login_attempt",
    "log_password_change",
    "query_audit",
    "reset_engine_cache_for_tests",
]
