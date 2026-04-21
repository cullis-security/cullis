"""
MCP Proxy database — async SQLAlchemy 2.x Core over aiosqlite / asyncpg.

Tables:
  - internal_agents: locally registered agents (for egress API key auth)
  - audit_log: append-only immutable audit trail
  - proxy_config: key-value store for broker uplink config from setup wizard
  - local_*: ADR-001 Phase 4 surface, schema-only until then

Design choices:
  - SQLAlchemy Core with AsyncEngine — single async driver, portable SQLite/Postgres
  - audit_log is append-only: no UPDATE or DELETE operations exposed
  - WAL mode enabled on SQLite for concurrent readers (no-op on Postgres)
  - get_db() yields an AsyncConnection already inside engine.begin(): callers no
    longer call db.commit(), transactions commit on context exit.
  - Schema bootstrap runs Alembic programmatically. Legacy SQLite proxies that
    pre-date Alembic are stamped at 0001_initial_snapshot before upgrade so
    their existing tables aren't recreated.
"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from mcp_proxy.db_models import metadata

_PROXY_PKG_DIR = Path(__file__).resolve().parent
_ALEMBIC_INI = _PROXY_PKG_DIR / "alembic.ini"
_ALEMBIC_INITIAL_REVISION = "0001_initial_snapshot"

_log = logging.getLogger("mcp_proxy")

# Module-level engine — set by init_db()
_engine: AsyncEngine | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_url(db_url: str) -> str:
    """Accept a SQLAlchemy URL or a raw SQLite path; return a SQLAlchemy URL."""
    if "://" in db_url:
        return db_url
    # Raw filesystem path — wrap as sqlite+aiosqlite
    return f"sqlite+aiosqlite:///{db_url}"


def _sqlite_path(db_url: str) -> str | None:
    """Extract the filesystem path from a sqlite URL, or None if not SQLite."""
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if db_url.startswith(prefix):
            return db_url[len(prefix):]
    return None


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


_LEGACY_TABLES = frozenset({"internal_agents", "audit_log", "proxy_config"})


def _detect_legacy_unstamped(sync_conn) -> bool:
    """True when any pre-Phase-1 table exists but alembic_version is missing.

    Two scenarios produce legacy-unstamped state:
      1. Pre-Phase-1 deployments that created the full _SCHEMA_SQL via raw
         CREATE TABLE IF NOT EXISTS.
      2. The demo_network proxy-init seed container, which writes only
         proxy_config (broker uplink config) before the proxy boots.

    Either way, alembic must be stamped at 0001_initial_snapshot so the
    upgrade chain doesn't try to recreate tables that already exist.
    """
    inspector = inspect(sync_conn)
    table_names = set(inspector.get_table_names())
    if "alembic_version" in table_names:
        return False
    return bool(_LEGACY_TABLES & table_names)


def _run_migrations_sync(url: str) -> None:
    """Run alembic stamp (if needed) + upgrade head. Synchronous on purpose:
    invoked from a thread via asyncio.to_thread to avoid blocking the loop.

    Stamp-existing detection runs only on SQLite — no proxy was ever deployed
    on Postgres pre-Phase-1, so legacy unstamped Postgres DBs cannot exist.

    Two legacy-unstamped scenarios are handled:
      - Full legacy schema (pre-Phase-1 deploy): all three legacy tables
        present → just stamp 0001 and upgrade.
      - Partial legacy (e.g. demo_network proxy-init has seeded only
        proxy_config): create the missing legacy tables idempotently via
        metadata.create_all so the stamped revision matches reality, then
        stamp + upgrade. Without this, alembic would skip CREATE TABLE for
        internal_agents / audit_log because 0001 is assumed already applied.
    """
    cfg = _alembic_config(url)

    needs_stamp = False
    sqlite_path = _sqlite_path(url)
    if sqlite_path and sqlite_path != ":memory:" and Path(sqlite_path).exists():
        from sqlalchemy import create_engine as create_sync_engine
        sync_url = url.replace("sqlite+aiosqlite://", "sqlite://", 1)
        try:
            sync_engine = create_sync_engine(sync_url, future=True)
            with sync_engine.connect() as conn:
                needs_stamp = _detect_legacy_unstamped(conn)
            if needs_stamp:
                # Fill in any legacy tables missing from a partial seed so
                # the 0001 stamp accurately describes the on-disk schema.
                from mcp_proxy.db_models import (
                    AuditLogEntry,
                    InternalAgent,
                    ProxyConfig,
                )
                with sync_engine.begin() as conn:
                    metadata.create_all(
                        bind=conn,
                        tables=[
                            InternalAgent.__table__,
                            AuditLogEntry.__table__,
                            ProxyConfig.__table__,
                        ],
                    )
            sync_engine.dispose()
        except Exception as exc:
            _log.debug("Pre-migration inspection skipped: %s", exc)

    if needs_stamp:
        _log.info("Legacy schema detected — stamping %s before upgrade",
                  _ALEMBIC_INITIAL_REVISION)
        command.stamp(cfg, _ALEMBIC_INITIAL_REVISION)

    command.upgrade(cfg, "head")


async def init_db(db_url: str) -> None:
    """Initialize the module-level AsyncEngine and run Alembic migrations.

    Accepts either a SQLAlchemy URL (``sqlite+aiosqlite:///path``) or a raw
    filesystem path for backward compatibility.

    Schema bootstrap runs ``alembic upgrade head``. Pre-Phase-1 SQLite
    deployments (which created tables outside Alembic) are detected and
    stamped at 0001_initial_snapshot first, so existing rows survive.

    Set ``PROXY_SKIP_MIGRATIONS=1`` to skip the alembic step — used by tests
    that build their own engine inside the same process.
    """
    global _engine
    import os

    url = _normalize_url(db_url)

    # Ensure parent directory exists for SQLite file DBs
    sqlite_path = _sqlite_path(url)
    if sqlite_path and sqlite_path != ":memory:":
        parent = Path(sqlite_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)

    if os.environ.get("PROXY_SKIP_MIGRATIONS") == "1":
        _log.warning("PROXY_SKIP_MIGRATIONS=1 — using metadata.create_all "
                     "instead of alembic upgrade head")
        _engine = create_async_engine(url, echo=False, future=True)
        async with _engine.begin() as conn:
            if _engine.dialect.name == "sqlite":
                await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.run_sync(metadata.create_all)
        _log.info("Database initialized (no-migrations mode): %s", url)
        return

    # Run alembic in a worker thread — alembic.command is synchronous and
    # would block the event loop otherwise.
    await asyncio.to_thread(_run_migrations_sync, url)

    _engine = create_async_engine(url, echo=False, future=True)
    if _engine.dialect.name == "sqlite":
        async with _engine.begin() as conn:
            await conn.execute(text("PRAGMA journal_mode=WAL"))

    _log.info("Database initialized (alembic upgrade head): %s", url)


async def dispose_db() -> None:
    """Dispose the module-level engine (shutdown hook)."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


def _require_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _engine


@asynccontextmanager
async def get_db() -> AsyncIterator[AsyncConnection]:
    """Yield an AsyncConnection inside an active transaction.

    The transaction auto-commits when the context exits cleanly and rolls
    back on exception. Callers MUST NOT call ``await conn.commit()``.

    Usage::

        async with get_db() as conn:
            result = await conn.execute(text("SELECT ..."), {"param": value})
            row = result.mappings().first()
    """
    engine = _require_engine()
    async with engine.begin() as conn:
        yield conn


# ─────────────────────────────────────────────────────────────────────────────
# Audit log — APPEND-ONLY (no update, no delete)
# ─────────────────────────────────────────────────────────────────────────────

async def log_audit(
    agent_id: str,
    action: str,
    status: str,
    *,
    tool_name: str | None = None,
    detail: str | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None,
) -> None:
    """Insert an immutable audit log entry."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO audit_log (timestamp, agent_id, action, tool_name, status, detail, request_id, duration_ms)
                   VALUES (:timestamp, :agent_id, :action, :tool_name, :status, :detail, :request_id, :duration_ms)"""
            ),
            {
                "timestamp": ts,
                "agent_id": agent_id,
                "action": action,
                "tool_name": tool_name,
                "status": status,
                "detail": detail,
                "request_id": request_id,
                "duration_ms": duration_ms,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Internal agents
# ─────────────────────────────────────────────────────────────────────────────

async def create_agent(
    agent_id: str,
    display_name: str,
    capabilities: list[str],
    api_key_hash: str,
    cert_pem: str | None = None,
    enrollment_method: str = "admin",
    spiffe_id: str | None = None,
) -> None:
    """Register a new internal agent.

    ADR-011 Phase 1 — ``enrollment_method`` defaults to ``admin`` so
    legacy callers (tests, dashboard) get the right metadata without
    code changes. The Connector approve flow and the BYOCA/SPIFFE
    enrollment endpoints pass the matching method value explicitly.
    """
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO internal_agents (
                       agent_id, display_name, capabilities, api_key_hash,
                       cert_pem, created_at, enrollment_method, spiffe_id,
                       enrolled_at
                   ) VALUES (
                       :agent_id, :display_name, :capabilities, :api_key_hash,
                       :cert_pem, :created_at, :enrollment_method, :spiffe_id,
                       :enrolled_at
                   )"""
            ),
            {
                "agent_id": agent_id,
                "display_name": display_name,
                "capabilities": json.dumps(capabilities),
                "api_key_hash": api_key_hash,
                "cert_pem": cert_pem,
                "created_at": ts,
                "enrollment_method": enrollment_method,
                "spiffe_id": spiffe_id,
                "enrolled_at": ts,
            },
        )


async def get_agent(agent_id: str) -> dict | None:
    """Fetch a single agent by ID."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return _agent_row_to_dict(row)


async def get_agent_by_key_hash(raw_api_key: str) -> dict | None:
    """Look up an active agent by verifying a raw API key against stored bcrypt hashes.

    Since bcrypt hashes are non-deterministic (salted), we cannot do a direct
    SQL lookup. Instead we fetch all active agents and verify against each hash.
    For efficiency with many agents, consider a prefix index approach.
    This is acceptable for the expected scale (tens to low hundreds of agents).
    """
    import bcrypt

    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents WHERE is_active = 1")
        )
        rows = result.mappings().all()
        for row in rows:
            stored_hash = row["api_key_hash"]
            if bcrypt.checkpw(raw_api_key.encode(), stored_hash.encode()):
                return _agent_row_to_dict(row)
    return None


async def list_agents() -> list[dict]:
    """List all internal agents."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents ORDER BY created_at DESC")
        )
        return [_agent_row_to_dict(row) for row in result.mappings().all()]


async def deactivate_agent(agent_id: str) -> bool:
    """Soft-delete an agent by setting ``is_active=0``.

    Bumps ``federation_revision`` too so the publisher (ADR-010 Phase 3)
    carries the deactivation to the Court on its next tick — a federated
    agent must be marked revoked there as well, not just on the Mastio.

    Returns True if the row existed (and was active).
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE internal_agents
                   SET is_active = 0,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :agent_id AND is_active = 1
                """
            ),
            {"agent_id": agent_id},
        )
        return result.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Proxy config (key-value)
# ─────────────────────────────────────────────────────────────────────────────

async def get_config(key: str) -> str | None:
    """Get a config value by key."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT value FROM proxy_config WHERE key = :key"),
            {"key": key},
        )
        row = result.mappings().first()
        return row["value"] if row else None


async def set_config(key: str, value: str) -> None:
    """Set a config value (upsert).

    SQLite and PostgreSQL both support ON CONFLICT ... DO UPDATE with the
    same syntax, so a raw text() upsert stays portable.
    """
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO proxy_config (key, value) VALUES (:key, :value)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value"""
            ),
            {"key": key, "value": value},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Mastio keys (ADR-012 Phase 2.0 multi-key store, issue #261)
# ─────────────────────────────────────────────────────────────────────────────

async def insert_mastio_key(
    *,
    kid: str,
    pubkey_pem: str,
    privkey_pem: str,
    cert_pem: str | None = None,
    created_at: str,
    activated_at: str | None = None,
    deprecated_at: str | None = None,
    expires_at: str | None = None,
) -> None:
    """Insert a new row into ``mastio_keys``.

    Raises the underlying DBAPI error on duplicate ``kid`` (primary key).
    Timestamps are stored as ISO-8601 UTC strings to match the rest of
    the proxy schema.
    """
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO mastio_keys
                    (kid, pubkey_pem, privkey_pem, cert_pem, created_at,
                     activated_at, deprecated_at, expires_at)
                VALUES
                    (:kid, :pub, :priv, :cert, :created,
                     :activated, :deprecated, :expires)
                """
            ),
            {
                "kid": kid,
                "pub": pubkey_pem,
                "priv": privkey_pem,
                "cert": cert_pem,
                "created": created_at,
                "activated": activated_at,
                "deprecated": deprecated_at,
                "expires": expires_at,
            },
        )


async def get_mastio_key_by_kid(kid: str) -> dict | None:
    """Fetch a single mastio key row by kid."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM mastio_keys WHERE kid = :kid"),
            {"kid": kid},
        )
        row = result.mappings().first()
        return dict(row) if row else None


async def get_mastio_keys_active() -> list[dict]:
    """All rows that are the current signer (activated, not deprecated).

    The invariant is exactly one; callers raise on 0 or >1. The query
    returns a list so the caller can surface a clear error rather than
    a silent ``.first()`` miss.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT * FROM mastio_keys
                 WHERE activated_at IS NOT NULL
                   AND deprecated_at IS NULL
                 ORDER BY activated_at ASC
                """
            )
        )
        return [dict(row) for row in result.mappings().all()]


async def get_mastio_keys_valid() -> list[dict]:
    """All rows still accepted for token verification.

    An activated key stays valid until its ``expires_at`` (if set) has
    passed. Deprecated-but-not-yet-expired keys remain in the set —
    that is the grace-period mechanic used by the verifier during
    rotation (Phase 2.2). Never-activated rows are excluded.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT * FROM mastio_keys
                 WHERE activated_at IS NOT NULL
                   AND (expires_at IS NULL OR expires_at > :now)
                 ORDER BY activated_at ASC
                """
            ),
            {"now": datetime.now(timezone.utc).isoformat()},
        )
        return [dict(row) for row in result.mappings().all()]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def cert_thumbprint_from_pem(pem: str | None) -> str | None:
    """SHA-256 hex of a cert's DER encoding.

    ADR-010 Phase 6b — ``internal_agents`` does not persist a thumbprint
    column, so callers that need one (``/public-key``, discovery search)
    derive it on-the-fly from ``cert_pem``.
    """
    if not pem:
        return None
    import base64
    import hashlib
    import re as _re

    try:
        der = base64.b64decode(_re.sub(r"-----.*?-----|\s", "", pem))
    except (ValueError, TypeError):
        return None
    return hashlib.sha256(der).hexdigest()


def _agent_row_to_dict(row: RowMapping) -> dict:
    """Convert a RowMapping to a plain dict with parsed capabilities."""
    out = {
        "agent_id": row["agent_id"],
        "display_name": row["display_name"],
        "capabilities": json.loads(row["capabilities"]),
        "api_key_hash": row["api_key_hash"],
        "cert_pem": row["cert_pem"],
        "created_at": row["created_at"],
        "is_active": bool(row["is_active"]),
    }
    # ADR-010 Phase 2/5 — federation flags are optional at read time
    # because legacy rows predating migration 0010 won't have them
    # (tests sometimes insert raw rows too).
    for key in ("federated", "federated_at", "federation_revision",
                "last_pushed_revision"):
        if key in row.keys():
            out[key] = (
                bool(row[key]) if key == "federated" else row[key]
            )
    # Migration 0017 — reach ('intra' | 'cross' | 'both'). Optional at
    # read time for the same reason as the federation flags above.
    if "reach" in row.keys() and row["reach"]:
        out["reach"] = row["reach"]
    else:
        # Legacy row before 0017: infer from ``federated`` so UI stays
        # coherent even if the migration hasn't applied yet.
        out["reach"] = "both" if out.get("federated") else "intra"
    # Migration 0013 — optional at read time so fixtures that build a row
    # by hand (without the column) don't blow up.
    if "device_info" in row.keys():
        out["device_info"] = row["device_info"]
    # Migration 0014 (F-B-11 Phase 2) — same permissiveness.
    if "dpop_jkt" in row.keys():
        out["dpop_jkt"] = row["dpop_jkt"]
    return out
