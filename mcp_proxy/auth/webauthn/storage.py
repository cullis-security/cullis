"""Persistence helpers for WebAuthn credentials and challenges.

The credential table is owned by the Mastio database (migration
``0038_webauthn_credentials``). Reads and writes go through this
module so the SQL stays in one place and the API router does not
import ``mcp_proxy.db`` directly for WebAuthn business logic.

Challenge storage is split:

* Production / multi-worker → Redis (keyed by ``principal_id`` +
  ceremony type), reusing the ``mcp_proxy.auth.dpop_jti_store`` Redis
  client.
* Single-process / tests → in-memory ``ChallengeStore``.

Both backends honour the ``webauthn_challenge_ttl_seconds`` config.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import text

from mcp_proxy.auth.webauthn.authentication import CredentialRecord
from mcp_proxy.db import get_db

_log = logging.getLogger("mcp_proxy.auth.webauthn.storage")


# ─────────────────────────────────────────────────────────────────────────────
# Credential persistence
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StoredCredential:
    """Full credential row as returned by the dashboard "list" endpoint."""

    credential_id: bytes
    principal_id: str
    sign_count: int
    aaguid: bytes | None
    transports: list[str] | None
    name: str | None
    created_at: str
    last_used_at: str | None


async def save_credential(
    *,
    principal_id: str,
    credential_id: bytes,
    credential_public_key: bytes,
    sign_count: int,
    aaguid: bytes | None,
    transports: list[str] | None,
    name: str | None,
) -> None:
    """Insert a freshly-registered credential row."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO user_webauthn_credentials (
                       credential_id, principal_id, credential_public_key,
                       sign_count, aaguid, transports, name,
                       created_at, last_used_at
                   ) VALUES (
                       :credential_id, :principal_id, :credential_public_key,
                       :sign_count, :aaguid, :transports, :name,
                       :created_at, NULL
                   )"""
            ),
            {
                "credential_id": credential_id,
                "principal_id": principal_id,
                "credential_public_key": credential_public_key,
                "sign_count": sign_count,
                "aaguid": aaguid,
                "transports": json.dumps(transports) if transports else None,
                "name": name,
                "created_at": ts,
            },
        )


async def load_credentials_for_principal(principal_id: str) -> list[StoredCredential]:
    """Return every credential row for a principal, newest first."""
    async with get_db() as conn:
        rows = (
            await conn.execute(
                text(
                    """SELECT credential_id, principal_id, sign_count,
                              aaguid, transports, name,
                              created_at, last_used_at
                         FROM user_webauthn_credentials
                        WHERE principal_id = :pid
                     ORDER BY created_at DESC"""
                ),
                {"pid": principal_id},
            )
        ).mappings().all()

    out: list[StoredCredential] = []
    for row in rows:
        transports_raw = row.get("transports")
        try:
            transports = json.loads(transports_raw) if transports_raw else None
        except (TypeError, ValueError):
            transports = None
        out.append(
            StoredCredential(
                credential_id=row["credential_id"],
                principal_id=row["principal_id"],
                sign_count=int(row["sign_count"] or 0),
                aaguid=row.get("aaguid"),
                transports=transports,
                name=row.get("name"),
                created_at=str(row["created_at"]),
                last_used_at=str(row["last_used_at"]) if row.get("last_used_at") else None,
            )
        )
    return out


async def load_credential_records_for_verification(
    principal_id: str,
) -> list[CredentialRecord]:
    """Slim projection used by :mod:`authentication.verify_response`.

    Pulled out separately because verification needs the public key
    bytes but does not need ``name`` / ``transports`` / timestamps —
    keeping the read narrow avoids carrying public keys through the
    dashboard render path where they would only add log-noise risk.
    """
    async with get_db() as conn:
        rows = (
            await conn.execute(
                text(
                    """SELECT credential_id, credential_public_key, sign_count
                         FROM user_webauthn_credentials
                        WHERE principal_id = :pid"""
                ),
                {"pid": principal_id},
            )
        ).mappings().all()
    return [
        CredentialRecord(
            credential_id=row["credential_id"],
            credential_public_key=row["credential_public_key"],
            sign_count=int(row["sign_count"] or 0),
        )
        for row in rows
    ]


async def update_sign_count(
    *,
    credential_id: bytes,
    new_sign_count: int,
) -> None:
    """Persist the new ``sign_count`` after a successful assertion.

    Also stamps ``last_used_at`` so the dashboard can show "last seen"
    next to each credential.
    """
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """UPDATE user_webauthn_credentials
                      SET sign_count = :sign_count,
                          last_used_at = :ts
                    WHERE credential_id = :credential_id"""
            ),
            {
                "credential_id": credential_id,
                "sign_count": int(new_sign_count),
                "ts": ts,
            },
        )


async def delete_credential(
    *,
    principal_id: str,
    credential_id: bytes,
) -> bool:
    """Remove a credential. Returns ``True`` iff a row was deleted.

    The dashboard renders ``credential_id`` base64url-encoded; callers
    must decode before passing it here. The ``principal_id`` filter
    means a leaked credential id cannot be used to revoke another
    user's authenticator from the dashboard.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """DELETE FROM user_webauthn_credentials
                    WHERE principal_id = :pid
                      AND credential_id = :credential_id"""
            ),
            {"pid": principal_id, "credential_id": credential_id},
        )
    return (result.rowcount or 0) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Challenge storage (TTL bucket keyed by principal + ceremony)
# ─────────────────────────────────────────────────────────────────────────────


class ChallengeStore(Protocol):
    """Backend interface for short-lived registration / authentication nonces."""

    async def put(self, *, principal_id: str, ceremony: str, value: str, ttl: int) -> None: ...
    async def take(self, *, principal_id: str, ceremony: str) -> str | None: ...


class InMemoryChallengeStore:
    """Process-local TTL bucket. Adequate for single-worker Mastio + tests."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def put(
        self, *, principal_id: str, ceremony: str, value: str, ttl: int,
    ) -> None:
        deadline = time.monotonic() + ttl
        async with self._lock:
            self._items[(principal_id, ceremony)] = (value, deadline)

    async def take(self, *, principal_id: str, ceremony: str) -> str | None:
        key = (principal_id, ceremony)
        async with self._lock:
            entry = self._items.pop(key, None)
        if entry is None:
            return None
        value, deadline = entry
        if deadline < time.monotonic():
            return None
        return value


class RedisChallengeStore:
    """Multi-worker safe store. Keys are ``webauthn:{ceremony}:{principal_id}``."""

    def __init__(self, redis_client: object) -> None:
        self._redis = redis_client

    async def put(
        self, *, principal_id: str, ceremony: str, value: str, ttl: int,
    ) -> None:
        await self._redis.set(  # type: ignore[attr-defined]
            self._key(principal_id, ceremony), value, ex=ttl,
        )

    async def take(self, *, principal_id: str, ceremony: str) -> str | None:
        key = self._key(principal_id, ceremony)
        raw = await self._redis.get(key)  # type: ignore[attr-defined]
        if raw is None:
            return None
        await self._redis.delete(key)  # type: ignore[attr-defined]
        if isinstance(raw, bytes):
            return raw.decode("ascii")
        return str(raw)

    @staticmethod
    def _key(principal_id: str, ceremony: str) -> str:
        return f"webauthn:{ceremony}:{principal_id}"


_DEFAULT_STORE: ChallengeStore | None = None


def get_challenge_store() -> ChallengeStore:
    """Return a process-level challenge store, building one on first use.

    Falls back to :class:`InMemoryChallengeStore`. The API router can
    swap in a Redis-backed store via :func:`set_challenge_store` once a
    Redis client is wired (production deploys).
    """
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = InMemoryChallengeStore()
    return _DEFAULT_STORE


def set_challenge_store(store: ChallengeStore) -> None:
    """Inject a custom store (Redis in production, fakes in tests)."""
    global _DEFAULT_STORE
    _DEFAULT_STORE = store
