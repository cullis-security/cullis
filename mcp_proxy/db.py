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
import base64
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import bcrypt
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
    dpop_jkt: str | None = None,
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

    # P1.2 — fall back to the per-request contextvar stamped by the
    # DPoP auth deps so DPoP-bound paths populate the column without
    # threading the value through every caller. The kwarg still wins
    # when an explicit value is passed (audit replays / system tasks
    # that want to assert a non-default jkt).
    if dpop_jkt is None:
        from mcp_proxy.auth.dpop_context import current_dpop_jkt
        dpop_jkt = current_dpop_jkt()

    ts = datetime.now(timezone.utc).isoformat()

    # F0.4 / ADR-033 — route through the batched audit chain when the
    # singleton is registered AND the operator hasn't opted out. The
    # legacy per-row path stays the default until the lifespan has
    # finished startup, so this is also safe to call from migration
    # code, tests that bypass the lifespan, and the alembic env.
    try:
        from mcp_proxy.audit_chain import get_batched_chain
        from mcp_proxy.config import get_settings as _get_settings_for_audit
        _chain = get_batched_chain()
        _chain_disabled = _get_settings_for_audit().audit_chain_disabled
    except Exception:  # pragma: no cover — defensive: never break audit on config errors
        _chain = None
        _chain_disabled = True
    if _chain is not None and not _chain_disabled:
        from mcp_proxy.audit_chain import AuditChainExhausted
        try:
            await _chain.append({
                "timestamp": ts,
                "agent_id": agent_id,
                "action": action,
                "tool_name": tool_name,
                "status": status,
                "detail": detail,
                "request_id": request_id,
                "duration_ms": duration_ms,
                "dpop_jkt": dpop_jkt,
            })
            return
        except AuditChainExhausted as exc:
            try:
                fail_deny = _get_settings_for_audit().audit_fail_deny
            except Exception:  # pragma: no cover — defensive
                fail_deny = True
            if fail_deny:
                # Preserve legacy semantics: surface as RuntimeError
                # so the calling request becomes a 5xx and never
                # returns success without a matching audit row.
                raise RuntimeError(
                    "log_audit: could not append after "
                    f"{_AUDIT_CHAIN_MAX_RETRIES} retries (chain_seq "
                    "UNIQUE conflict). Confirm the audit_log schema "
                    "or look for a stuck worker."
                ) from exc
            _log.critical(
                "log_audit: %s. MCP_PROXY_AUDIT_FAIL_DENY=false: "
                "returning to caller without persisting the audit "
                "row. agent_id=%s action=%s tool_name=%s status=%s "
                "request_id=%s",
                exc, agent_id, action, tool_name, status, request_id,
            )
            return

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
                                   chain_seq, prev_hash, row_hash, dpop_jkt
                               ) VALUES (
                                   :timestamp, :agent_id, :action, :tool_name,
                                   :status, :detail, :request_id, :duration_ms,
                                   :chain_seq, :prev_hash, :row_hash, :dpop_jkt
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
                            "dpop_jkt": dpop_jkt,
                        },
                    )
                    return
                except IntegrityError:
                    # UNIQUE(chain_seq) collision — another worker
                    # claimed this seq. Reread the head and retry.
                    continue
        # H3 P0.3 — audit-fail-deny gate. The default-true stance (raise
        # so the request surfaces 500 and the caller never returns a
        # success without a matching audit row) is the production-
        # correct behaviour and matches the threat-model claim. The
        # opt-out (audit_fail_deny=false) is for operators who run an
        # external audit sink (S3 / Datadog plugin) and prefer to keep
        # serving on local-audit unavailability.
        from mcp_proxy.config import get_settings
        try:
            fail_deny = get_settings().audit_fail_deny
        except Exception:  # pragma: no cover — settings.get() never raises today
            fail_deny = True
        msg = (
            f"log_audit: could not append after {_AUDIT_CHAIN_MAX_RETRIES} "
            "retries (chain_seq UNIQUE conflict). Confirm the audit_log "
            "schema or look for a stuck worker."
        )
        if fail_deny:
            raise RuntimeError(msg)
        _log.critical(
            "%s. MCP_PROXY_AUDIT_FAIL_DENY=false: returning to caller "
            "without persisting the audit row. agent_id=%s action=%s "
            "tool_name=%s status=%s request_id=%s",
            msg, agent_id, action, tool_name, status, request_id,
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


async def list_user_principals() -> list[dict]:
    """List user principals registered on this Mastio.

    Pairs with the dashboard ``/proxy/users`` page. Reads the same
    ``local_user_principals`` table the admin API at
    ``/v1/admin/users`` exposes — one row per Frontdesk SSO user that
    has either touched the CSR endpoint at least once
    (``upsert_from_csr`` populator) or been pre-created via
    ``POST /v1/admin/users``. Ordered most-recently-created first so
    the dashboard top row is the latest signup.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT principal_id, user_name, display_name, reach, "
                "       surface, cert_thumbprint, pubkey_thumbprint, "
                "       created_at, last_active_at "
                "  FROM local_user_principals "
                " ORDER BY created_at DESC"
            )
        )
        return [dict(row) for row in result.mappings().all()]


async def count_user_principals() -> int:
    """Cheap count for the sidebar badge on /proxy/users."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT COUNT(*) AS n FROM local_user_principals")
        )
        row = result.mappings().first()
        return int(row["n"]) if row else 0


async def get_user_principal_pubkey_thumbprint(
    principal_id: str,
) -> tuple[bool, str | None]:
    """TOFU pubkey lookup for a user principal.

    Returns ``(exists, pubkey_thumbprint)``:
      - ``(False, None)`` — no row in ``local_user_principals`` for this
        principal_id. Caller (``sign_user_csr``) treats this as "first
        touch" and the row will be created with the CSR's pubkey on the
        downstream upsert. Caller (``client_cert.py``) treats this as
        "principal unknown" and rejects.
      - ``(True, None)`` — row exists, no pubkey pinned yet (legacy row
        from before migration 0030, or admin-pre-created via
        ``POST /v1/admin/users``). Sign signer treats this as TOFU
        first-cert opportunity. Cert-auth dep rejects.
      - ``(True, "<sha256_hex>")`` — pinned. Caller compares to the
        presented pubkey and refuses on mismatch.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT pubkey_thumbprint "
                "  FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": principal_id},
        )
        row = result.mappings().first()
        if row is None:
            return (False, None)
        return (True, row["pubkey_thumbprint"])


async def get_workload_principal_pubkey_thumbprint(
    principal_id: str,
) -> tuple[bool, str | None]:
    """TOFU pubkey lookup for a workload principal.

    Same semantics as :func:`get_user_principal_pubkey_thumbprint` but
    backed by ``local_workload_principals``. Workloads do not currently
    have a CSR mint flow on ``/v1/principals/csr`` (only users do), so
    today this returns ``(False, None)`` for any workload that hasn't
    been pre-created via ``POST /v1/admin/workloads``. The cert-auth
    dep uses this to reject any cert that claims a workload identity
    the registry does not know.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT pubkey_thumbprint "
                "  FROM local_workload_principals "
                " WHERE principal_id = :pid"
            ),
            {"pid": principal_id},
        )
        row = result.mappings().first()
        if row is None:
            return (False, None)
        return (True, row["pubkey_thumbprint"])


async def set_user_principal_pubkey_thumbprint_if_unset(
    principal_id: str,
    pubkey_thumbprint: str,
) -> bool:
    """Set ``pubkey_thumbprint`` on a user principal IFF currently NULL.

    Used by the CSR signer for the TOFU first-cert step. Returns True
    when the row was actually updated (NULL → value), False when the
    row already had a pubkey pinned (caller must verify match
    elsewhere — this helper does NOT overwrite).

    Atomic single-statement UPDATE so concurrent first-mints either
    cooperate (same pubkey, second is a no-op) or one wins (different
    pubkeys race, the first sets the row, the second is rejected on
    the next request via the lookup helper).
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE local_user_principals "
                "   SET pubkey_thumbprint = :thumb "
                " WHERE principal_id = :pid "
                "   AND pubkey_thumbprint IS NULL"
            ),
            {"pid": principal_id, "thumb": pubkey_thumbprint},
        )
        return result.rowcount > 0


async def clear_user_principal_pubkey_thumbprint(principal_id: str) -> bool:
    """Null out the TOFU-pinned pubkey for a user principal.

    Used by the admin "reset TOFU pin" path when the on-disk pubkey
    pinned at first-touch has become stale (Connector wiped its
    keystore, customer rebuilt the laptop, ADR-021 v0.1 in-memory keys
    didn't survive a Mastio restart). After this call the next CSR
    from this principal will be accepted regardless of pubkey and the
    fresh thumb gets pinned on that signature via ``upsert_from_csr``.

    Returns True iff a row was actually updated. False when the
    principal_id doesn't exist OR ``pubkey_thumbprint`` was already
    NULL (caller can decide whether that's a 404 or a no-op).

    Cert thumbprint is left alone — it rotates every CSR refresh
    anyway and is not the load-bearing TOFU identifier. Only the
    SPKI hash matters.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE local_user_principals "
                "   SET pubkey_thumbprint = NULL "
                " WHERE principal_id = :pid "
                "   AND pubkey_thumbprint IS NOT NULL"
            ),
            {"pid": principal_id},
        )
        return result.rowcount > 0


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


# ─────────────────────────────────────────────────────────────────────────────
# AI provider credentials (migration 0027)
# ─────────────────────────────────────────────────────────────────────────────


async def get_ai_provider_creds(provider: str) -> dict | None:
    """Fetch a single AI provider credential row.

    Returns ``{"provider", "creds", "enabled", "updated_at", "updated_by"}``
    with ``creds`` already JSON-decoded into a dict, or ``None`` when no
    row exists. Disabled rows are returned as-is so the admin UI can
    surface ``enabled: false`` without a separate query.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT provider, creds_json, enabled, updated_at, updated_by "
                "FROM ai_provider_credentials WHERE provider = :p"
            ),
            {"p": provider.lower()},
        )
        row = result.mappings().first()
    if row is None:
        return None
    # Wave B B1 (audit 2026-05-11) — decrypt envelope before JSON-parse.
    # Pre-fix the column was plaintext JSON; legacy rows still are
    # (decrypt_at_rest passes them through). 0032 migration upgrades
    # them to the v1 envelope.
    from mcp_proxy.tools.secret_encrypt import decrypt_at_rest
    raw = await decrypt_at_rest(row["creds_json"])
    try:
        creds = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        creds = {}
    return {
        "provider": row["provider"],
        "creds": creds,
        "enabled": bool(row["enabled"]),
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    }


async def list_ai_provider_creds() -> list[dict]:
    """Return every configured provider row.

    Order is stable (alphabetical by provider) so the dashboard render
    never flickers between page loads.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT provider, creds_json, enabled, updated_at, updated_by "
                "FROM ai_provider_credentials ORDER BY provider ASC"
            ),
        )
        rows = result.mappings().all()
    # Wave B B1 — decrypt every row's envelope before JSON-parse.
    from mcp_proxy.tools.secret_encrypt import decrypt_at_rest
    out: list[dict] = []
    for row in rows:
        raw = await decrypt_at_rest(row["creds_json"])
        try:
            creds = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            creds = {}
        out.append({
            "provider": row["provider"],
            "creds": creds,
            "enabled": bool(row["enabled"]),
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
        })
    return out


async def upsert_ai_provider_creds(
    provider: str,
    creds: Mapping[str, Any],
    *,
    enabled: bool = True,
    updated_by: str | None = None,
) -> None:
    """Insert or replace a provider's credentials.

    The dict is serialised to canonical JSON (sorted keys) so audit
    diffs stay deterministic.
    """
    payload = json.dumps(dict(creds), separators=(",", ":"), sort_keys=True)
    # Wave B B1 (audit 2026-05-11) — wrap in the v1 Fernet envelope
    # before persisting. Legacy plaintext rows are upgraded by the
    # 0032 migration.
    from mcp_proxy.tools.secret_encrypt import encrypt_at_rest
    encrypted_payload = await encrypt_at_rest(payload)
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO ai_provider_credentials
                       (provider, creds_json, enabled, updated_at, updated_by)
                   VALUES (:p, :c, :en, :ts, :ub)
                   ON CONFLICT(provider) DO UPDATE SET
                       creds_json = excluded.creds_json,
                       enabled    = excluded.enabled,
                       updated_at = excluded.updated_at,
                       updated_by = excluded.updated_by"""
            ),
            {
                "p": provider.lower(),
                "c": encrypted_payload,
                "en": bool(enabled),
                "ts": ts,
                "ub": updated_by,
            },
        )


async def delete_ai_provider_creds(provider: str) -> bool:
    """Remove a provider row. Returns True when a row was deleted."""
    async with get_db() as conn:
        result = await conn.execute(
            text("DELETE FROM ai_provider_credentials WHERE provider = :p"),
            {"p": provider.lower()},
        )
    return (result.rowcount or 0) > 0


async def set_ai_provider_enabled(provider: str, enabled: bool) -> bool:
    """Toggle the ``enabled`` flag without rotating credentials."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE ai_provider_credentials "
                "SET enabled = :en, updated_at = :ts "
                "WHERE provider = :p"
            ),
            {"p": provider.lower(), "en": bool(enabled), "ts": ts},
        )
    return (result.rowcount or 0) > 0


# ── User API tokens (ADR-027) ──────────────────────────────────────────────

# Plaintext token wire format: ``culk_`` + 52 chars (256-bit body, base32 lower,
# strip padding). Total length 57 chars. Stable prefix lets downstream tooling
# (audit greps, log scrubbers, secret scanners) recognise the token class.
_API_TOKEN_PREFIX = "culk_"
_API_TOKEN_BODY_BYTES = 32
_API_TOKEN_BODY_LEN = 52  # base32(32B) without padding
_API_TOKEN_FULL_LEN = len(_API_TOKEN_PREFIX) + _API_TOKEN_BODY_LEN

# bcrypt cost. 12 ≈ 200ms on commodity hardware; balances offline-crack
# resistance and per-request auth latency. Matches dashboard password hash.
_API_TOKEN_BCRYPT_COST = 12


def _new_api_token_plaintext() -> str:
    """Return a fresh ``culk_<52 base32 chars>`` token string."""
    raw = secrets.token_bytes(_API_TOKEN_BODY_BYTES)
    body = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    # base32(32 bytes) = 52 chars without padding — never 51 or 53. Assert
    # tightens any silent change in the stdlib.
    assert len(body) == _API_TOKEN_BODY_LEN, f"unexpected body length: {len(body)}"
    return f"{_API_TOKEN_PREFIX}{body}"


def _hash_api_token(plaintext: str) -> str:
    """Return the bcrypt hash of ``plaintext`` as an ASCII string."""
    return bcrypt.hashpw(
        plaintext.encode("utf-8"),
        bcrypt.gensalt(rounds=_API_TOKEN_BCRYPT_COST),
    ).decode("ascii")


def _check_api_token(plaintext: str, hashed: str) -> bool:
    """Constant-time bcrypt compare."""
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        # Malformed hash row in DB — refuse, do not raise to caller.
        return False


def _new_token_id() -> str:
    """Return a 22-char URL-safe unique id for a token row."""
    return secrets.token_urlsafe(16)


async def mint_user_api_token(
    *,
    principal_id: str,
    label: str,
    created_by: str,
    scope_providers: list[str] | None = None,
    scope_paths: list[str] | None = None,
    expires_at: str | None = None,
) -> dict:
    """Mint a new API token for a user principal.

    Returns a dict with the cleartext token in the ``token`` field — this
    is the ONLY time the cleartext is visible to the caller. Subsequent
    reads (``get_user_api_token``, ``list_user_api_tokens``) return only
    metadata + ``token_last4``.

    Arguments:
        principal_id: ``local_user_principals.principal_id`` (user::name)
        label: operator-visible name, e.g. ``"Cursor laptop daniele"``
        created_by: principal_id of the admin or self-mint user
        scope_providers: empty list = no restriction; ``["anthropic"]`` =
            only that provider. Stored verbatim, not enforced here.
        scope_paths: defaults to ``["/v1/*"]``. Stored verbatim.
        expires_at: ISO-8601 UTC, or ``None`` for no expiry.
    """
    if not principal_id:
        raise ValueError("principal_id is required")
    if not label or not label.strip():
        raise ValueError("label is required")
    if not created_by:
        raise ValueError("created_by is required")

    # Audit Wave A C3 (2026-05-11) — pre-fix the mint accepted ANY
    # ``principal_id``, including foreign-org or non-existent values.
    # Combined with CRIT-1 that let an attacker mint synthetic
    # identities and drive both the cert + culk_ surfaces as the same
    # phantom user. Validate now: principal_id must exist in
    # ``local_user_principals`` AND its inferred ``::user::`` shape
    # must point at this Mastio's own org. We deliberately accept
    # rows regardless of ``surface`` / ``reach`` — those are display
    # metadata, not authority.
    from mcp_proxy.config import get_settings
    settings = get_settings()
    own_org = (settings.org_id or "").strip()
    if "::user::" not in principal_id:
        # culk_ tokens are user-only by ADR-027 Phase 1; refuse
        # workload / agent / unknown shapes here so the audit trail
        # cannot point at a phantom typed identity.
        raise ValueError(
            f"principal_id must be a user principal "
            f"(``<org>::user::<name>``); got {principal_id!r}",
        )
    if own_org and not principal_id.startswith(f"{own_org}::"):
        raise ValueError(
            f"principal_id {principal_id!r} is not in this Mastio's "
            f"org ({own_org!r}); cannot mint cross-org culk_ tokens",
        )
    async with get_db() as _check_conn:
        existing = (await _check_conn.execute(
            text(
                "SELECT 1 FROM local_user_principals "
                " WHERE principal_id = :pid LIMIT 1"
            ),
            {"pid": principal_id},
        )).first()
    if existing is None:
        raise ValueError(
            f"principal_id {principal_id!r} is not registered in "
            "local_user_principals; pre-create the user via "
            "POST /v1/admin/users or via Frontdesk SSO before minting "
            "tokens for it",
        )

    plaintext = _new_api_token_plaintext()
    token_hash = _hash_api_token(plaintext)
    last4 = plaintext[-4:]
    token_id = _new_token_id()
    ts = datetime.now(timezone.utc).isoformat()
    providers_json = json.dumps(
        sorted(scope_providers or []), separators=(",", ":"),
    )
    paths_json = json.dumps(
        scope_paths if scope_paths is not None else ["/v1/*"],
        separators=(",", ":"),
    )
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO user_api_tokens (
                       id, principal_id, label,
                       token_hash, token_last4,
                       scope_providers_json, scope_paths_json,
                       created_at, created_by, expires_at
                   ) VALUES (
                       :id, :pid, :label,
                       :hash, :last4,
                       :prov, :paths,
                       :ts, :cb, :exp
                   )"""
            ),
            {
                "id": token_id,
                "pid": principal_id,
                "label": label.strip(),
                "hash": token_hash,
                "last4": last4,
                "prov": providers_json,
                "paths": paths_json,
                "ts": ts,
                "cb": created_by,
                "exp": expires_at,
            },
        )
    return {
        "id": token_id,
        "principal_id": principal_id,
        "label": label.strip(),
        "token": plaintext,           # only here, never returned again
        "token_last4": last4,
        "scope_providers": sorted(scope_providers or []),
        "scope_paths": scope_paths if scope_paths is not None else ["/v1/*"],
        "created_at": ts,
        "created_by": created_by,
        "expires_at": expires_at,
        "last_used_at": None,
        "last_used_ip": None,
        "revoked_at": None,
        "revoked_by": None,
    }


def _row_to_token_dict(row: Mapping[str, Any], include_hash: bool = False) -> dict:
    """Project a DB row into the public dict shape used by the API."""
    try:
        providers = json.loads(row["scope_providers_json"] or "[]")
    except (TypeError, ValueError):
        providers = []
    try:
        paths = json.loads(row["scope_paths_json"] or '["/v1/*"]')
    except (TypeError, ValueError):
        paths = ["/v1/*"]
    out = {
        "id":               row["id"],
        "principal_id":     row["principal_id"],
        "label":            row["label"],
        "token_last4":      row["token_last4"],
        "scope_providers":  providers,
        "scope_paths":      paths,
        "created_at":       row["created_at"],
        "created_by":       row["created_by"],
        "last_used_at":     row["last_used_at"],
        "last_used_ip":     row["last_used_ip"],
        "expires_at":       row["expires_at"],
        "revoked_at":       row["revoked_at"],
        "revoked_by":       row["revoked_by"],
    }
    if include_hash:
        out["token_hash"] = row["token_hash"]
    return out


async def get_user_api_token(token_id: str) -> dict | None:
    """Fetch a token row by id, including revoked/expired rows."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT id, principal_id, label, token_hash, token_last4, "
                "scope_providers_json, scope_paths_json, created_at, created_by, "
                "last_used_at, last_used_ip, expires_at, revoked_at, revoked_by "
                "FROM user_api_tokens WHERE id = :id"
            ),
            {"id": token_id},
        )
        row = result.mappings().first()
    if row is None:
        return None
    return _row_to_token_dict(row)


async def list_user_api_tokens(
    principal_id: str | None = None,
    *,
    include_revoked: bool = False,
) -> list[dict]:
    """List token rows ordered by created_at desc.

    With ``principal_id=None`` returns all tokens across all users — used
    by the admin Cross-org view. With a specific ``principal_id`` returns
    only that user's tokens.

    By default skips revoked rows; pass ``include_revoked=True`` for audit
    use cases (dashboard "show history").
    """
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if principal_id is not None:
        clauses.append("principal_id = :pid")
        params["pid"] = principal_id
    if not include_revoked:
        clauses.append("revoked_at IS NULL")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        "SELECT id, principal_id, label, token_hash, token_last4, "
        "scope_providers_json, scope_paths_json, created_at, created_by, "
        "last_used_at, last_used_ip, expires_at, revoked_at, revoked_by "
        "FROM user_api_tokens" + where + " ORDER BY created_at DESC"
    )
    async with get_db() as conn:
        result = await conn.execute(text(sql), params)
        rows = result.mappings().all()
    return [_row_to_token_dict(r) for r in rows]


async def _find_active_token_candidates_by_last4(last4: str) -> list[dict]:
    """Return active (not revoked, not expired) tokens whose ``token_last4``
    matches. Includes ``token_hash`` for bcrypt verification in the resolver.

    The list is typically 0-2 entries on a healthy deployment because
    last4 has ~65k buckets. The resolver bcrypt-checks each candidate.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT id, principal_id, label, token_hash, token_last4, "
                "scope_providers_json, scope_paths_json, created_at, created_by, "
                "last_used_at, last_used_ip, expires_at, revoked_at, revoked_by "
                "FROM user_api_tokens "
                "WHERE token_last4 = :last4 "
                "  AND revoked_at IS NULL "
                "  AND (expires_at IS NULL OR expires_at > :now)"
            ),
            {"last4": last4, "now": now_iso},
        )
        rows = result.mappings().all()
    return [_row_to_token_dict(r, include_hash=True) for r in rows]


async def verify_user_api_token(plaintext: str) -> dict | None:
    """Resolve a plaintext API token to its row.

    Returns the public token dict (no hash) on success, or ``None`` if no
    active row matches. Constant-ish time even for unknown tokens:
    bcrypt is run on every candidate; if zero candidates match the last4
    prefix the function returns quickly, but that timing leak is bounded
    by the size of the keyspace (~65k buckets) and is acceptable for the
    threat model (ADR-027 §threat model).
    """
    if not plaintext or not plaintext.startswith(_API_TOKEN_PREFIX):
        return None
    if len(plaintext) != _API_TOKEN_FULL_LEN:
        return None
    last4 = plaintext[-4:]
    candidates = await _find_active_token_candidates_by_last4(last4)
    for cand in candidates:
        if _check_api_token(plaintext, cand["token_hash"]):
            # Drop the hash before handing back to caller — never let it
            # leave this function. Defence-in-depth against accidental
            # logging of the row.
            cand.pop("token_hash", None)
            return cand
    return None


async def touch_user_api_token(token_id: str, *, client_ip: str | None) -> None:
    """Update ``last_used_at`` (and optionally ``last_used_ip``) on auth hit.

    Best-effort: failures are logged but not raised. The auth path must
    not break because of a stat-tracking UPDATE.
    """
    ts = datetime.now(timezone.utc).isoformat()
    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    "UPDATE user_api_tokens "
                    "SET last_used_at = :ts, last_used_ip = :ip "
                    "WHERE id = :id"
                ),
                {"id": token_id, "ts": ts, "ip": client_ip},
            )
    except Exception:  # noqa: BLE001
        _log = logging.getLogger("mcp_proxy.db.api_tokens")
        _log.warning("failed to touch user_api_token %s", token_id, exc_info=True)


async def revoke_user_api_token(token_id: str, *, revoked_by: str) -> bool:
    """Mark a token as revoked.

    Returns True if the row was updated (was active), False if no-op
    (already revoked or unknown id). Revocation is final — to "unrevoke"
    the admin must mint a new token.
    """
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE user_api_tokens "
                "SET revoked_at = :ts, revoked_by = :by "
                "WHERE id = :id AND revoked_at IS NULL"
            ),
            {"id": token_id, "ts": ts, "by": revoked_by},
        )
    return (result.rowcount or 0) > 0
