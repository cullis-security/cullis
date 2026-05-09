"""Persistent session-cookie ↔ user-principal cert binding — ADR-025 Phase 3.

When a local user authenticates the Connector mints a UserPrincipal
cert from Mastio (see ``csr_flow.py``) and caches it in process memory.
Across a Connector restart that in-memory cache is lost, but the
HMAC-signed session cookie the browser still holds remains valid.
This module persists the small bridge that lets us, given a still-valid
cookie after a restart, identify the principal_id the cookie was bound
to and re-fetch the cert (cache miss → ``UserProvisioner`` re-mints
under the user's name).

Schema (added to the existing ``users.db`` so admin-side user creation
and per-session state share one engine + WAL journal):

    CREATE TABLE local_session_certs (
      session_id        TEXT PRIMARY KEY,
      user_name         TEXT NOT NULL REFERENCES local_users(user_name)
                          ON DELETE CASCADE,
      principal_id      TEXT NOT NULL,
      cert_thumbprint   TEXT NOT NULL,
      cert_not_after    TEXT NOT NULL,
      created_at        TEXT NOT NULL
    );
    CREATE INDEX idx_session_certs_user ON local_session_certs(user_name);

The ``session_id`` is a stable hash of ``(cookie.iat, user_name)`` so
the same cookie maps to the same row across restarts even though we
never store the raw cookie value (defence in depth: a database leak
must not let an attacker forge cookies).

Rows are pruned when:

  - the user is deleted (``ON DELETE CASCADE`` from local_users)
  - explicit logout (router clears the row + the cookie together)
  - the cert is past its ``not_after`` (lazy cleanup on read; a stale
    row triggers a re-provision on the next request)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Index,
    String,
    delete,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from cullis_connector.identity.users import Base
from cullis_connector.identity.users_db import get_users_session

_log = logging.getLogger("cullis_connector.identity.cert_session_map")


# ── ORM ──────────────────────────────────────────────────────────────────


class LocalSessionCert(Base):
    """One row per (cookie ↔ minted UserPrincipal cert) binding.

    Lives in the same metadata as :class:`LocalUser` so
    ``Base.metadata.create_all`` (called by ``init_users_db``) creates
    both tables in a single migration step. The FK to ``local_users``
    keeps the row in sync with admin-side deletes.
    """

    __tablename__ = "local_session_certs"

    session_id: Mapped[str] = mapped_column(
        String, primary_key=True, nullable=False,
    )
    user_name: Mapped[str] = mapped_column(
        String, nullable=False,
    )
    principal_id: Mapped[str] = mapped_column(String, nullable=False)
    cert_thumbprint: Mapped[str] = mapped_column(String, nullable=False)
    cert_not_after: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


Index("idx_session_certs_user", LocalSessionCert.user_name)


# ── Public dataclass ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionCertBinding:
    """Read-only view of a row — never carries cert key material."""

    session_id: str
    user_name: str
    principal_id: str
    cert_thumbprint: str
    cert_not_after: str
    created_at: str


def _row_to_binding(row: LocalSessionCert) -> SessionCertBinding:
    return SessionCertBinding(
        session_id=row.session_id,
        user_name=row.user_name,
        principal_id=row.principal_id,
        cert_thumbprint=row.cert_thumbprint,
        cert_not_after=row.cert_not_after,
        created_at=row.created_at,
    )


# ── Helpers ──────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_session_id(*, iat: int, user_name: str) -> str:
    """Stable session_id from ``(iat, user_name)`` via HMAC-SHA256.

    We use HMAC with a constant key (the table is local; the goal is
    not authentication but a uniform fixed-length key that never
    leaks the raw iat). Hex-encoded to keep the column human-friendly
    for ad-hoc SQL inspection. Truncated to 32 hex chars (128 bits) —
    plenty against collisions for a per-user table.
    """
    if not isinstance(user_name, str) or not user_name:
        raise ValueError("user_name must be a non-empty string")
    if not isinstance(iat, int) or iat <= 0:
        raise ValueError("iat must be a positive int")
    msg = f"{iat}|{user_name}".encode("utf-8")
    digest = hmac.new(
        b"cullis-local-session-cert-v1", msg, hashlib.sha256,
    ).hexdigest()
    return digest[:32]


# ── CRUD (async) ─────────────────────────────────────────────────────────


async def upsert_binding(
    session: AsyncSession,
    *,
    session_id: str,
    user_name: str,
    principal_id: str,
    cert_thumbprint: str,
    cert_not_after: str,
) -> SessionCertBinding:
    """Insert or replace the row for ``session_id``.

    On re-login with the same ``(iat, user_name)`` the row is
    overwritten so the bound principal_id + thumbprint reflect the
    freshest cert. Rows for older cookies (different ``iat``) keep
    coexisting until they expire or the user is deleted.
    """
    if not session_id or not user_name or not principal_id:
        raise ValueError("session_id, user_name, principal_id all required")
    stmt = select(LocalSessionCert).where(
        LocalSessionCert.session_id == session_id
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        row = LocalSessionCert(
            session_id=session_id,
            user_name=user_name,
            principal_id=principal_id,
            cert_thumbprint=cert_thumbprint,
            cert_not_after=cert_not_after,
            created_at=_now_iso(),
        )
        session.add(row)
    else:
        row.user_name = user_name
        row.principal_id = principal_id
        row.cert_thumbprint = cert_thumbprint
        row.cert_not_after = cert_not_after
    await session.flush()
    return _row_to_binding(row)


async def get_binding(
    session: AsyncSession, session_id: str,
) -> Optional[SessionCertBinding]:
    if not session_id:
        return None
    stmt = select(LocalSessionCert).where(
        LocalSessionCert.session_id == session_id
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return _row_to_binding(row)


async def delete_binding(
    session: AsyncSession, session_id: str,
) -> bool:
    if not session_id:
        return False
    stmt = delete(LocalSessionCert).where(
        LocalSessionCert.session_id == session_id
    )
    result = await session.execute(stmt)
    await session.flush()
    return (result.rowcount or 0) > 0


async def delete_bindings_for_user(
    session: AsyncSession, user_name: str,
) -> int:
    """Drop every binding for ``user_name``.

    Called on admin-side user deletion (the FK cascades automatically
    too, but having the helper lets the router pre-emptively clean up
    so the response can include a count) and on hard logout.
    """
    if not user_name:
        return 0
    stmt = delete(LocalSessionCert).where(
        LocalSessionCert.user_name == user_name
    )
    result = await session.execute(stmt)
    await session.flush()
    return int(result.rowcount or 0)


# ── Convenience top-level wrappers ───────────────────────────────────────
#
# These shorthand wrappers open a session against the connector
# config_dir's users.db. The router code path uses these so it does
# not have to know about ``get_users_session`` explicitly.


async def record_binding(
    config_dir: Path,
    *,
    session_id: str,
    user_name: str,
    principal_id: str,
    cert_thumbprint: str,
    cert_not_after: str,
) -> SessionCertBinding:
    async with get_users_session(config_dir) as session:
        return await upsert_binding(
            session,
            session_id=session_id,
            user_name=user_name,
            principal_id=principal_id,
            cert_thumbprint=cert_thumbprint,
            cert_not_after=cert_not_after,
        )


async def lookup_binding(
    config_dir: Path, session_id: str,
) -> Optional[SessionCertBinding]:
    async with get_users_session(config_dir) as session:
        return await get_binding(session, session_id)


async def forget_binding(
    config_dir: Path, session_id: str,
) -> bool:
    async with get_users_session(config_dir) as session:
        return await delete_binding(session, session_id)


__all__ = [
    "LocalSessionCert",
    "SessionCertBinding",
    "delete_binding",
    "delete_bindings_for_user",
    "derive_session_id",
    "forget_binding",
    "get_binding",
    "lookup_binding",
    "record_binding",
    "upsert_binding",
]
