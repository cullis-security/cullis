"""
MCP Proxy database — async SQLAlchemy 2.x Core over aiosqlite / asyncpg.

Tables:
  - internal_agents: locally registered agents (mTLS client-cert auth, ADR-014)
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
from typing import Any, AsyncIterator, Mapping

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from mcp_proxy.db_models import metadata

_PROXY_PKG_DIR = Path(__file__).resolve().parent
_ALEMBIC_INI = _PROXY_PKG_DIR / "alembic.ini"
_ALEMBIC_INITIAL_REVISION = "0001_initial_snapshot"

# M-db-2 audit fix — Postgres advisory lock key for serialising the
# alembic upgrade across concurrent workers. Mirrors the constant in
# ``app/db/database.py``; the two locks are independent (different
# DBs / different alembic chains) so the keys can be the same value.
# ``0xC0115A1E_EB1C0DE`` reads "Cullis alembic code" — a memorable
# hex constant operators can grep in pg_locks during incident triage.
_ALEMBIC_ADVISORY_LOCK_KEY = 0xC0115A1E_EB1C0DE

_log = logging.getLogger("mcp_proxy")


def _engine_kwargs(url: str) -> dict:
    """Build the ``create_async_engine`` kwargs for the given DB URL.

    ADR-013 layer 4 — bound the DB connection pool explicitly so that
    under load the Mastio queues request handlers in the app tier
    (observable + bounded) instead of piling connections onto the DB
    until it saturates. This only matters for Postgres; SQLite (via
    aiosqlite) is single-writer and WAL mode covers concurrent readers,
    so the pool-sizing knobs are no-ops there.
    """
    kwargs = {"echo": False, "future": True}
    if not url.startswith("sqlite"):
        kwargs.update(
            pool_size=20,
            max_overflow=10,
            pool_timeout=5.0,
        )
    return kwargs

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
        _engine = create_async_engine(url, **_engine_kwargs(url))
        async with _engine.begin() as conn:
            if _engine.dialect.name == "sqlite":
                await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.run_sync(metadata.create_all)
        _log.info("Database initialized (no-migrations mode): %s", url)
        return

    # M-db-2 audit fix — under N concurrent workers booting against
    # the same Postgres cluster, two workers reading
    # ``alembic_version`` before either wrote the next revision could
    # race the same migration and fail mid-upgrade. Wrap the upgrade
    # in a Postgres session-level advisory lock keyed by a fixed
    # integer so only one worker runs the chain; others wait then
    # no-op once head is reached. SQLite is single-writer by file,
    # so the lock is skipped there.
    is_postgres = url.startswith("postgresql") or "+asyncpg" in url
    if is_postgres:
        lock_engine = create_async_engine(url, **_engine_kwargs(url))
        try:
            async with lock_engine.connect() as lock_conn:
                await lock_conn.execute(
                    text("SELECT pg_advisory_lock(:k)"),
                    {"k": _ALEMBIC_ADVISORY_LOCK_KEY},
                )
                try:
                    await asyncio.to_thread(_run_migrations_sync, url)
                finally:
                    await lock_conn.execute(
                        text("SELECT pg_advisory_unlock(:k)"),
                        {"k": _ALEMBIC_ADVISORY_LOCK_KEY},
                    )
        finally:
            await lock_engine.dispose()
    else:
        # Run alembic in a worker thread — alembic.command is synchronous
        # and would block the event loop otherwise.
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
# Audit log — APPEND-ONLY (no update, no delete) + H4 hash chain
# ─────────────────────────────────────────────────────────────────────────────

import asyncio as _asyncio
import hashlib as _hashlib

# Per-process lock so two concurrent log_audit() calls don't race for
# the same chain_seq. Multi-worker deployments rely on the
# UNIQUE(chain_seq) constraint to reject the loser; the application
# retries with the next seq.
_audit_chain_lock = _asyncio.Lock()
_AUDIT_CHAIN_GENESIS = "genesis"
_AUDIT_CHAIN_MAX_RETRIES = 5


def compute_audit_row_hash(
    *,
    chain_seq: int,
    timestamp: str,
    agent_id: str,
    action: str,
    tool_name: str | None,
    status: str,
    detail: str | None,
    request_id: str | None,
    prev_hash: str,
) -> str:
    """SHA-256 over a canonical encoding of every authoritative field.

    Any tamper to the row — including changing tool_name from ``None``
    to ``""`` — invalidates the hash. The encoding mirrors the Court
    pattern in ``app/db/audit.py``: pipe-delimited with empty-string
    sentinels for NULLs and a ``genesis`` literal for the head of the
    chain.
    """
    canonical = (
        f"{chain_seq}|{timestamp}|{agent_id}|{action}|"
        f"{tool_name or ''}|{status}|{detail or ''}|"
        f"{request_id or ''}|{prev_hash}"
    )
    return _hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _audit_chain_head(conn) -> tuple[int, str]:
    """Return ``(last_chain_seq, last_row_hash)``.

    Pre-migration rows have ``chain_seq IS NULL`` and are ignored by
    the chain — the first chained row gets ``chain_seq=1`` with
    ``prev_hash=genesis``.
    """
    row = (await conn.execute(
        text(
            "SELECT chain_seq, row_hash FROM audit_log "
            "WHERE chain_seq IS NOT NULL "
            "ORDER BY chain_seq DESC LIMIT 1",
        ),
    )).first()
    if row is None:
        return 0, _AUDIT_CHAIN_GENESIS
    return int(row[0]), str(row[1])


async def log_audit(
    agent_id: str,
    action: str,
    status: str,
    *,
    tool_name: str | None = None,
    detail: str | None = None,
    details: Mapping[str, Any] | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None,
) -> None:
    """Insert an immutable, hash-chained audit log entry.

    Forward integrity: each row carries ``prev_hash`` (the previous
    row's ``row_hash``) and a fresh ``row_hash`` over a canonical
    encoding of all authoritative fields. ``verify_audit_chain``
    walks the chain and surfaces breaks; an attacker rewriting a
    row, dropping one, or splicing in a forgery has to recompute
    every subsequent hash without operator detection.

    ``details`` lets callers attach a structured dict (e.g. LLM
    cost/tokens). When passed it is serialised to canonical JSON and
    stored in the same ``detail`` SQL column the legacy string uses,
    so the chain hash semantics stay identical. Pass ``detail`` for
    free-form human-readable strings, ``details`` for structured
    data; if both arrive ``details`` wins.
    """
    from sqlalchemy.exc import IntegrityError

    if details is not None:
        detail = json.dumps(
            dict(details), separators=(",", ":"), sort_keys=True, default=str,
        )

    ts = datetime.now(timezone.utc).isoformat()
    async with _audit_chain_lock:
        for _attempt in range(_AUDIT_CHAIN_MAX_RETRIES):
            async with get_db() as conn:
                last_seq, prev_hash = await _audit_chain_head(conn)
                chain_seq = last_seq + 1
                row_hash = compute_audit_row_hash(
                    chain_seq=chain_seq,
                    timestamp=ts,
                    agent_id=agent_id,
                    action=action,
                    tool_name=tool_name,
                    status=status,
                    detail=detail,
                    request_id=request_id,
                    prev_hash=prev_hash,
                )
                try:
                    await conn.execute(
                        text(
                            """INSERT INTO audit_log (
                                   timestamp, agent_id, action, tool_name,
                                   status, detail, request_id, duration_ms,
                                   chain_seq, prev_hash, row_hash
                               ) VALUES (
                                   :timestamp, :agent_id, :action, :tool_name,
                                   :status, :detail, :request_id, :duration_ms,
                                   :chain_seq, :prev_hash, :row_hash
                               )"""
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
                            "chain_seq": chain_seq,
                            "prev_hash": prev_hash,
                            "row_hash": row_hash,
                        },
                    )
                    return
                except IntegrityError:
                    # UNIQUE(chain_seq) collision — another worker
                    # claimed this seq. Reread the head and retry.
                    continue
        raise RuntimeError(
            f"log_audit: could not append after {_AUDIT_CHAIN_MAX_RETRIES} "
            "retries (chain_seq UNIQUE conflict). Confirm the audit_log "
            "schema or look for a stuck worker.",
        )


async def verify_audit_chain(
    *, start_seq: int = 1, limit: int | None = None,
) -> tuple[bool, int | None, str | None]:
    """Walk the hash chain forward and report the first break.

    Returns ``(ok, broken_seq, reason)``:
      * ``(True, None, None)`` — every chained row verifies.
      * ``(False, seq, reason)`` — the row at ``seq`` is the first
        with a recomputed ``row_hash`` that disagrees with the stored
        value, or whose ``prev_hash`` doesn't match the previous
        row's ``row_hash``, or whose ``chain_seq`` skipped a slot.

    Pre-migration rows (``chain_seq IS NULL``) are skipped.
    """
    async with get_db() as conn:
        stmt = (
            "SELECT chain_seq, prev_hash, row_hash, timestamp, agent_id, "
            "action, tool_name, status, detail, request_id FROM audit_log "
            "WHERE chain_seq IS NOT NULL AND chain_seq >= :start "
            "ORDER BY chain_seq ASC"
        )
        params: dict[str, int] = {"start": start_seq}
        if limit is not None:
            stmt += " LIMIT :lim"
            params["lim"] = limit
        rows = (await conn.execute(text(stmt), params)).all()

    expected_prev: str | None = None
    expected_seq: int | None = None
    for row in rows:
        chain_seq = int(row[0])
        prev_hash = str(row[1])
        stored_hash = str(row[2])
        if expected_seq is None:
            # First row in the iteration — pin the expected seq to
            # whatever the first chained row claims so we can detect
            # gaps from this point forward without false-flagging
            # legitimate truncation before ``start_seq``.
            expected_seq = chain_seq
            if start_seq == 1 and chain_seq == 1 and prev_hash != _AUDIT_CHAIN_GENESIS:
                return False, chain_seq, "first row prev_hash != genesis"
        else:
            if chain_seq != expected_seq:
                return False, chain_seq, f"chain_seq gap: expected {expected_seq}"
            if expected_prev is not None and prev_hash != expected_prev:
                return False, chain_seq, "prev_hash mismatch with previous row"
        recomputed = compute_audit_row_hash(
            chain_seq=chain_seq,
            timestamp=str(row[3]),
            agent_id=str(row[4]),
            action=str(row[5]),
            tool_name=row[6],
            status=str(row[7]),
            detail=row[8],
            request_id=row[9],
            prev_hash=prev_hash,
        )
        if recomputed != stored_hash:
            return False, chain_seq, "row_hash mismatch — row tampered"
        expected_prev = stored_hash
        expected_seq = chain_seq + 1
    return True, None, None


# ─────────────────────────────────────────────────────────────────────────────
# Internal agents
# ─────────────────────────────────────────────────────────────────────────────

async def create_agent(
    agent_id: str,
    display_name: str,
    capabilities: list[str],
    cert_pem: str | None = None,
    enrollment_method: str = "admin",
    spiffe_id: str | None = None,
) -> None:
    """Register a new internal agent.

    ADR-011 Phase 1 — ``enrollment_method`` defaults to ``admin`` so
    legacy callers (tests, dashboard) get the right metadata without
    code changes. The Connector approve flow and the BYOCA/SPIFFE
    enrollment endpoints pass the matching method value explicitly.

    ADR-014 PR-C — the agent's TLS client cert is the credential; no
    api_key_hash column exists.
    """
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO internal_agents (
                       agent_id, display_name, capabilities,
                       cert_pem, created_at, enrollment_method, spiffe_id,
                       enrolled_at
                   ) VALUES (
                       :agent_id, :display_name, :capabilities,
                       :cert_pem, :created_at, :enrollment_method, :spiffe_id,
                       :enrolled_at
                   )"""
            ),
            {
                "agent_id": agent_id,
                "display_name": display_name,
                "capabilities": json.dumps(capabilities),
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

    Ordering: ``kid`` lexicographic. With the single-row invariant the
    order is observationally identical to any other — but keeping the
    same ordering policy as ``get_mastio_keys_valid`` (below) means any
    future schema change that relaxes the invariant won't silently
    expose a timing oracle through this query's result list. See #282.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT * FROM mastio_keys
                 WHERE activated_at IS NOT NULL
                   AND deprecated_at IS NULL
                 ORDER BY kid ASC
                """
            )
        )
        return [dict(row) for row in result.mappings().all()]


async def swap_active_mastio_key(
    *,
    new_kid: str,
    new_pubkey_pem: str,
    new_privkey_pem: str,
    new_cert_pem: str | None,
    new_activated_at: str,
    new_created_at: str,
    old_kid: str,
    old_deprecated_at: str,
    old_expires_at: str,
) -> None:
    """Atomically insert a new active mastio key and deprecate the old one.

    Phase 2.1 rotation primitive. Runs the two writes in a single DB
    transaction so the ``exactly-one-active`` invariant is never
    observed broken from a parallel reader (e.g. the verifier doing
    ``find_by_kid`` during the swap).

    Both rows are required: the keystore rejects zero or multiple active
    rows, and the verifier needs the old row to remain resolvable
    through its grace window.

    Raises the underlying DBAPI error if either statement fails — the
    transaction is then rolled back by the ``get_db()`` context exit
    so the caller observes all-or-nothing semantics.
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
                     :activated, NULL, NULL)
                """
            ),
            {
                "kid": new_kid,
                "pub": new_pubkey_pem,
                "priv": new_privkey_pem,
                "cert": new_cert_pem,
                "created": new_created_at,
                "activated": new_activated_at,
            },
        )
        result = await conn.execute(
            text(
                """
                UPDATE mastio_keys
                   SET deprecated_at = :deprecated,
                       expires_at    = :expires
                 WHERE kid = :kid
                   AND activated_at IS NOT NULL
                   AND deprecated_at IS NULL
                """
            ),
            {
                "kid": old_kid,
                "deprecated": old_deprecated_at,
                "expires": old_expires_at,
            },
        )
        if result.rowcount != 1:
            raise RuntimeError(
                f"failed to deprecate old mastio key {old_kid!r}: "
                f"UPDATE touched {result.rowcount} rows"
            )


async def get_mastio_keys_valid() -> list[dict]:
    """All rows still accepted for token verification.

    An activated key stays valid until its ``expires_at`` (if set) has
    passed. Deprecated-but-not-yet-expired keys remain in the set —
    that is the grace-period mechanic used by the verifier during
    rotation (Phase 2.2). Never-activated rows are excluded.

    Ordering: ``kid`` lexicographic (not ``activated_at``). The JWKS
    endpoint surfaces this list verbatim, and sorting by activation
    time leaked a rotation-timing oracle (``keys[-1]`` was always the
    freshest signer). Lexicographic order is stable across rotations
    so a client that snapshots the key list cannot infer "a rotation
    just happened" from reordering alone. See #282.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT * FROM mastio_keys
                 WHERE activated_at IS NOT NULL
                   AND (expires_at IS NULL OR expires_at > :now)
                 ORDER BY kid ASC
                """
            ),
            {"now": datetime.now(timezone.utc).isoformat()},
        )
        return [dict(row) for row in result.mappings().all()]


async def get_mastio_keys_staged() -> list[dict]:
    """Staged rotation rows — inserted by ``rotate_mastio_key`` before
    the Court ACK and carrying ``activated_at IS NULL``.

    Empty list is the common case. Exactly one row is expected when a
    rotation is in flight or crashed mid-rotation (ADR-012 Phase 2.1
    race-safe flow, issue #281). The caller enforces the invariant.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT * FROM mastio_keys
                 WHERE activated_at IS NULL
                 ORDER BY created_at ASC
                """
            )
        )
        return [dict(row) for row in result.mappings().all()]


async def delete_staged_mastio_key(kid: str) -> int:
    """Delete a staged row (``activated_at IS NULL``) by kid.

    Used by ``rotate_mastio_key`` to clean up after a propagator
    failure, and by ``complete_staged_rotation(decision='drop')`` to
    roll back an orphaned staged row the operator has inspected.

    The ``activated_at IS NULL`` predicate guarantees we cannot
    accidentally delete an activated key even if the caller passes
    the wrong kid. Returns the number of rows deleted (0 or 1).
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                DELETE FROM mastio_keys
                 WHERE kid = :kid
                   AND activated_at IS NULL
                """
            ),
            {"kid": kid},
        )
        return result.rowcount


async def activate_staged_and_deprecate_old(
    *,
    new_kid: str,
    new_activated_at: str,
    old_kid: str,
    old_deprecated_at: str,
    old_expires_at: str,
) -> None:
    """Atomically activate a staged row and deprecate the current active.

    Phase 2.1 rotation commit step (issue #281). The staged row was
    inserted (``activated_at IS NULL``) before the Court was told, so
    the pubkey is durable on disk; this call is what flips the live
    signer *after* Court has ACK-ed the rotation.

    On Postgres we take a transaction-scoped advisory lock keyed off
    ``'mastio-rotate'`` so two proxy processes that raced past the
    in-process ``asyncio.Lock`` still serialize here. SQLite has a
    global writer lock so no extra primitive is needed.

    Both UPDATEs must touch exactly one row:

    - staged row transitions ``activated_at NULL → now()``
    - previous active row transitions ``deprecated_at NULL → now()``
      with ``expires_at`` set for the grace window

    Any rowcount mismatch raises RuntimeError *and* rolls the
    transaction back (the surrounding ``get_db`` context handles it),
    leaving the caller to decide recovery. A rowcount-0 on the
    deprecate UPDATE typically means a racing rotation got here first
    — the caller should not retry.
    """
    async with get_db() as conn:
        # Postgres: advisory lock in this transaction so a second rotate
        # that made it past ``AgentManager._rotation_lock`` (different
        # process) serializes behind us instead of interleaving. SQLite
        # already holds a global writer lock for the duration of the tx.
        if conn.dialect.name == "postgresql":
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('mastio-rotate'))")
            )

        activate = await conn.execute(
            text(
                """
                UPDATE mastio_keys
                   SET activated_at = :activated
                 WHERE kid = :kid
                   AND activated_at IS NULL
                """
            ),
            {"kid": new_kid, "activated": new_activated_at},
        )
        if activate.rowcount != 1:
            raise RuntimeError(
                f"failed to activate staged mastio key {new_kid!r}: "
                f"UPDATE touched {activate.rowcount} rows (expected 1 — "
                f"staged row missing or already activated)"
            )

        deprecate = await conn.execute(
            text(
                """
                UPDATE mastio_keys
                   SET deprecated_at = :deprecated,
                       expires_at    = :expires
                 WHERE kid = :kid
                   AND activated_at IS NOT NULL
                   AND deprecated_at IS NULL
                """
            ),
            {
                "kid": old_kid,
                "deprecated": old_deprecated_at,
                "expires": old_expires_at,
            },
        )
        if deprecate.rowcount != 1:
            raise RuntimeError(
                f"failed to deprecate old mastio key {old_kid!r}: "
                f"UPDATE touched {deprecate.rowcount} rows (expected 1 — "
                f"racing rotation may have already deprecated it)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# pending_updates — federation update framework (imp/federation_hardening_plan.md
# Parte 1). Boot detector writes, dashboard admin endpoint reads + mutates.
# ─────────────────────────────────────────────────────────────────────────────

_ALLOWED_PENDING_STATUS: frozenset[str] = frozenset({
    "pending", "applied", "failed", "rolled_back",
})


async def insert_pending_update(
    *,
    migration_id: str,
    detected_at: str,
    status: str = "pending",
) -> int:
    """Insert a row flagging a migration as pending against current state.

    Used by the boot detector (PR 2) after each call to
    :meth:`Migration.check` that returns True. Idempotent: if a row for
    ``migration_id`` already exists (the detector re-ran on a boot with
    no admin intervention in between), the insert is a no-op and returns
    ``0``. Fresh inserts return ``1``.

    The ``status`` default is ``"pending"``; callers normally omit it.
    """
    if status not in _ALLOWED_PENDING_STATUS:
        raise ValueError(
            f"status {status!r} not in {sorted(_ALLOWED_PENDING_STATUS)}"
        )
    async with get_db() as conn:
        dialect = conn.dialect.name
        if dialect == "postgresql":
            stmt = text(
                """
                INSERT INTO pending_updates
                    (migration_id, detected_at, status)
                VALUES
                    (:mid, :detected, :status)
                ON CONFLICT (migration_id) DO NOTHING
                """
            )
        else:
            # SQLite equivalent; Postgres rejects this syntax.
            stmt = text(
                """
                INSERT OR IGNORE INTO pending_updates
                    (migration_id, detected_at, status)
                VALUES
                    (:mid, :detected, :status)
                """
            )
        result = await conn.execute(
            stmt,
            {"mid": migration_id, "detected": detected_at, "status": status},
        )
        return result.rowcount or 0


async def update_pending_update_status(
    *,
    migration_id: str,
    status: str,
    applied_at: str | None = None,
    error: str | None = None,
) -> int:
    """Update ``status`` (and optionally ``applied_at`` / ``error``) of a row.

    Returns the rowcount. Zero means the ``migration_id`` is not in the
    table — the caller (admin endpoint) decides whether to surface 404
    or treat it as a no-op.

    The caller is responsible for the status-field coherence invariants
    documented in the Alembic migration docstring; this helper does not
    enforce them so a single UPDATE can atomically set e.g.
    ``status='applied', applied_at='...', error=NULL``.
    """
    if status not in _ALLOWED_PENDING_STATUS:
        raise ValueError(
            f"status {status!r} not in {sorted(_ALLOWED_PENDING_STATUS)}"
        )
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE pending_updates
                   SET status = :status,
                       applied_at = :applied_at,
                       error = :error
                 WHERE migration_id = :mid
                """
            ),
            {
                "mid": migration_id,
                "status": status,
                "applied_at": applied_at,
                "error": error,
            },
        )
        return result.rowcount or 0


async def get_pending_updates(status: str | None = None) -> list[dict]:
    """Return ``pending_updates`` rows, optionally filtered by status.

    Ordered by ``migration_id`` (lexical — chronological with the
    ``YYYY-MM-DD-slug`` convention). An unknown ``status`` filter
    raises :class:`ValueError`; pass ``None`` (the default) to list all.
    """
    if status is not None and status not in _ALLOWED_PENDING_STATUS:
        raise ValueError(
            f"status {status!r} not in {sorted(_ALLOWED_PENDING_STATUS)}"
        )
    async with get_db() as conn:
        if status is None:
            result = await conn.execute(
                text(
                    "SELECT * FROM pending_updates "
                    "ORDER BY migration_id ASC"
                )
            )
        else:
            result = await conn.execute(
                text(
                    "SELECT * FROM pending_updates "
                    "WHERE status = :status "
                    "ORDER BY migration_id ASC"
                ),
                {"status": status},
            )
        return [dict(row) for row in result.mappings().all()]


# ─────────────────────────────────────────────────────────────────────────────
# migration_state_backups — per-migration snapshot blob for rollback
# (PR 3 federation update framework).
# ─────────────────────────────────────────────────────────────────────────────


async def insert_migration_backup(
    *,
    migration_id: str,
    created_at: str,
    snapshot_json: str,
) -> None:
    """Write (or overwrite) the backup row for a migration.

    ``INSERT OR REPLACE`` (SQLite) / ``ON CONFLICT ... DO UPDATE``
    (Postgres) — a second apply on the same ``migration_id`` overwrites
    the prior snapshot. Rollback always uses the most recent backup; the
    previous state is deliberately not recoverable because the admin
    drove a fresh apply and implicitly acknowledged that reset.
    """
    async with get_db() as conn:
        dialect = conn.dialect.name
        if dialect == "postgresql":
            stmt = text(
                """
                INSERT INTO migration_state_backups
                    (migration_id, created_at, snapshot_json)
                VALUES
                    (:mid, :created, :snapshot)
                ON CONFLICT (migration_id) DO UPDATE
                    SET created_at = EXCLUDED.created_at,
                        snapshot_json = EXCLUDED.snapshot_json
                """
            )
        else:
            stmt = text(
                """
                INSERT OR REPLACE INTO migration_state_backups
                    (migration_id, created_at, snapshot_json)
                VALUES
                    (:mid, :created, :snapshot)
                """
            )
        await conn.execute(
            stmt,
            {
                "mid": migration_id,
                "created": created_at,
                "snapshot": snapshot_json,
            },
        )


async def get_migration_backup(migration_id: str) -> dict | None:
    """Return the backup row for a migration, or None."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT migration_id, created_at, snapshot_json "
                "FROM migration_state_backups WHERE migration_id = :mid"
            ),
            {"mid": migration_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None


async def delete_migration_backup(migration_id: str) -> int:
    """Delete the backup row for a migration.

    Returns the rowcount. Zero means there was no backup to begin with;
    the caller decides whether that matters (``rollback`` treats "no
    backup" as an error, ``up`` ignores).
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "DELETE FROM migration_state_backups "
                "WHERE migration_id = :mid"
            ),
            {"mid": migration_id},
        )
        return result.rowcount or 0


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
