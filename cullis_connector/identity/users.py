"""Local user accounts for Cullis Connector / Frontdesk shared mode.

ADR-025 Phase 1 — backing store for the Frontdesk dual-mode auth
flow. When the Frontdesk container is deployed without a corporate
IdP, end users sign in against a local users.db on the Connector.
This module owns the SQLAlchemy ORM model + the small set of async
helpers the admin API and the (later-phase) login endpoint use.

Design notes:

- bcrypt cost 12 — same as ``mcp_proxy/dashboard/session.py`` admin
  password hashing. ``bcrypt.checkpw`` is CPU-bound C code, so we
  always wrap it in ``asyncio.to_thread`` to keep the event loop
  responsive while a verification runs (~150 ms / call on commodity
  hardware).
- Username regex matches the Mastio convention
  (``mcp_proxy/admin/users.py``): ``^[a-zA-Z0-9._-]{1,64}$``. That
  guarantees the user_name is safe to splice into a SPIFFE id and
  closes any SQL-injection / log-poisoning vector on the bare string.
- Password rule v1 follows NIST 800-63B: min 8 chars, no upper bound,
  no complexity requirement, but reject all-whitespace strings to
  avoid accidental empty hashes from typo'd inputs.
- The plaintext password is NEVER persisted, NEVER returned, and
  NEVER logged. Only the bcrypt hash (60-char ``$2b$...``) leaves
  this module.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import Index, Integer, String, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_log = logging.getLogger("cullis_connector.identity.users")


# ── SQLAlchemy ORM ────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    """Declarative base scoped to the Connector users.db schema.

    Kept separate from any other ORM ``Base`` in the codebase so
    ``Base.metadata.create_all`` only creates this module's tables.
    """


class LocalUser(Base):
    __tablename__ = "local_users"

    user_name: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    must_change_password: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1,
    )
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    password_changed_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    disabled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


Index("idx_local_users_must_change", LocalUser.must_change_password)


# ── Public dataclass ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class User:
    """Read-only view of a local user row.

    Never carries the password hash — callers should not be able to
    accidentally serialise it into a response or a log line. The
    verification path lives entirely inside this module via
    :func:`verify_password`.
    """

    user_name: str
    display_name: str
    must_change_password: bool
    created_at: str
    password_changed_at: Optional[str]
    disabled: bool


def _row_to_user(row: LocalUser) -> User:
    return User(
        user_name=row.user_name,
        display_name=row.display_name or "",
        must_change_password=bool(row.must_change_password),
        created_at=row.created_at,
        password_changed_at=row.password_changed_at,
        disabled=bool(row.disabled),
    )


# ── Validation ────────────────────────────────────────────────────────────


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
MIN_PASSWORD_LENGTH = 8


def _validate_username(name: str) -> None:
    if not isinstance(name, str) or not _USERNAME_RE.match(name):
        raise ValueError(
            "user_name must match ^[a-zA-Z0-9._-]{1,64}$",
        )


def _validate_password(plain: str) -> None:
    if not isinstance(plain, str):
        raise ValueError("password must be a string")
    if len(plain) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters",
        )
    if not plain.strip():
        raise ValueError("password must not be only whitespace")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── bcrypt helpers ────────────────────────────────────────────────────────


def _hash_password_sync(plain: str) -> str:
    """Blocking bcrypt hash. Caller wraps in asyncio.to_thread."""
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


def _check_password_sync(plain: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ── CRUD helpers ──────────────────────────────────────────────────────────


async def create_user(
    session: AsyncSession,
    *,
    name: str,
    password: str,
    must_change: bool = True,
    display_name: str = "",
) -> User:
    """Insert a new local user.

    Raises ``ValueError`` on bad regex / weak password.
    Raises ``sqlalchemy.exc.IntegrityError`` on duplicate user_name —
    the admin router catches that and returns HTTP 409.
    """
    _validate_username(name)
    _validate_password(password)
    pwd_hash = await asyncio.to_thread(_hash_password_sync, password)
    row = LocalUser(
        user_name=name,
        password_hash=pwd_hash,
        display_name=display_name or None,
        must_change_password=1 if must_change else 0,
        created_at=_now_iso(),
        password_changed_at=None,
        disabled=0,
    )
    session.add(row)
    await session.flush()
    # NEVER log the password or the hash. The bcrypt cost embeds the
    # salt, so a leaked log line would still be brute-forceable for
    # weak passwords.
    _log.info("local_users: created user_name=%s", name)
    return _row_to_user(row)


async def get_user_by_name(
    session: AsyncSession, name: str,
) -> Optional[User]:
    """Return the user row, or ``None`` if it does not exist."""
    if not isinstance(name, str) or not name:
        return None
    stmt = select(LocalUser).where(LocalUser.user_name == name)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return _row_to_user(row)


async def list_users(
    session: AsyncSession,
    *,
    q: str = "",
    disabled: Optional[bool] = None,
    limit: int = 200,
) -> list[User]:
    """Return up to ``limit`` users, newest-first.

    ``q`` does a case-insensitive substring match on ``user_name``
    and ``display_name``. ``disabled`` filters by status when set;
    ``None`` returns both enabled and disabled rows.
    """
    stmt = select(LocalUser)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            (LocalUser.user_name.ilike(like))
            | (LocalUser.display_name.ilike(like))
        )
    if disabled is not None:
        stmt = stmt.where(LocalUser.disabled == (1 if disabled else 0))
    stmt = stmt.order_by(LocalUser.created_at.desc()).limit(int(limit))
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [_row_to_user(r) for r in rows]


async def delete_user(session: AsyncSession, name: str) -> bool:
    """Delete the user. Returns ``True`` if a row was removed."""
    stmt = select(LocalUser).where(LocalUser.user_name == name)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.flush()
    _log.info("local_users: deleted user_name=%s", name)
    return True


async def verify_password(
    session: AsyncSession, name: str, plain: str,
) -> bool:
    """Constant-time bcrypt verify. Returns ``False`` if user is missing."""
    if not isinstance(plain, str) or not plain:
        return False
    if not isinstance(name, str) or not name:
        return False
    stmt = select(LocalUser.password_hash).where(LocalUser.user_name == name)
    result = await session.execute(stmt)
    stored = result.scalar_one_or_none()
    if not stored:
        return False
    return await asyncio.to_thread(_check_password_sync, plain, stored)


async def set_password_hash(
    session: AsyncSession,
    name: str,
    plain: str,
    *,
    must_change: bool = False,
) -> bool:
    """Re-hash and persist a new password for an existing user.

    Returns ``False`` if the user does not exist. Validates the new
    password against the same length / whitespace rules used at
    ``create_user`` time.
    """
    _validate_password(plain)
    stmt = select(LocalUser).where(LocalUser.user_name == name)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return False
    new_hash = await asyncio.to_thread(_hash_password_sync, plain)
    row.password_hash = new_hash
    row.must_change_password = 1 if must_change else 0
    row.password_changed_at = _now_iso()
    await session.flush()
    _log.info(
        "local_users: password updated user_name=%s must_change=%s",
        name, bool(must_change),
    )
    return True


async def mark_password_changed(session: AsyncSession, name: str) -> bool:
    """Clear the must_change_password flag without touching the hash."""
    stmt = select(LocalUser).where(LocalUser.user_name == name)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return False
    row.must_change_password = 0
    row.password_changed_at = _now_iso()
    await session.flush()
    return True


async def reset_password(
    session: AsyncSession, name: str, new_password: str,
) -> bool:
    """Admin reset path — sets a new password and forces a change on next login."""
    return await set_password_hash(
        session, name, new_password, must_change=True,
    )


async def count_users(session: AsyncSession) -> int:
    """Return the total number of rows in ``local_users``.

    Used by the ADR-025 Phase 5 first-run wizard (F4 R3): a fresh
    Connector desktop install has an empty ``users.db`` and the SPA
    needs a zero-cost probe to decide between rendering the login
    form and the owner-setup form. Counts both enabled and disabled
    rows so a disabled-out-of-band first user does not accidentally
    re-trigger the wizard.
    """
    stmt = select(func.count()).select_from(LocalUser)
    result = await session.execute(stmt)
    return int(result.scalar_one() or 0)
