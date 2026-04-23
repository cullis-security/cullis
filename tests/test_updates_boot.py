"""Boot detector tests (PR 2 federation update framework).

Exercises the full detect→insert→halt→gauge flow against a throwaway
SQLite DB. Migrations are registered via the same ``fake_pkg`` trick
used in PR 1 (module-name filter in registry isolates test classes).
``AgentManager`` is replaced by a minimal stub with the two attributes
the detector touches (``mark_sign_halted`` + ``is_sign_halted``) — the
real class's ``__init__`` pulls in PKI setup that is not necessary
here.
"""
from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, get_pending_updates, init_db
from mcp_proxy.updates import registry as registry_mod
from mcp_proxy.updates.base import Migration


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()


@pytest.fixture
def fake_pkg(monkeypatch):
    """Per-test throwaway migrations package.

    Unique name embedded in ``__name__`` so the registry's module-name
    filter only picks up *this* test's classes, not those registered
    by earlier tests (they still exist in ``Migration.__subclasses__``
    but match a stale package prefix).
    """
    pkg_name = (
        f"mcp_proxy.updates.migrations._boot_testfixtures_{id(monkeypatch)}"
    )
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, pkg_name, pkg)
    monkeypatch.setattr(registry_mod, "_migrations_pkg", pkg)
    return pkg


@dataclass
class StubAgentManager:
    """Minimal AgentManager surface the detector touches."""

    is_sign_halted: bool = False
    sign_halt_reason: str | None = None
    halt_calls: list[str] = field(default_factory=list)

    def mark_sign_halted(self, reason: str) -> None:
        self.is_sign_halted = True
        self.sign_halt_reason = reason
        self.halt_calls.append(reason)


def _make_migration(
    fake_pkg_mod: types.ModuleType,
    name: str,
    migration_id: str,
    *,
    criticality: str = "info",
    affects: tuple[str, ...] = (),
    check_returns: bool | None = True,
    check_raises: type[Exception] | None = None,
) -> type[Migration]:
    """Build a fake Migration class with controllable ``check`` behaviour."""
    async def _check(self) -> bool:
        if check_raises is not None:
            raise check_raises("synthetic failure for test")
        return bool(check_returns)

    async def _up(self) -> None:
        return None

    async def _rollback(self) -> None:
        return None

    cls = type(
        name,
        (Migration,),
        {
            "migration_id": migration_id,
            "migration_type": "cert-schema",
            "criticality": criticality,
            "description": f"test fixture {name}",
            "preserves_enrollments": True,
            "affects_enrollments": affects,
            "check": _check,
            "up": _up,
            "rollback": _rollback,
        },
    )
    cls.__module__ = fake_pkg_mod.__name__
    # Pin on the fake package so ``Migration.__subclasses__`` (weakrefs)
    # doesn't drop the class before ``discover()`` walks the tree. Test
    # callers that ignore the return value would otherwise rely on GC
    # timing — works locally, flakes in CI (see the sibling comment in
    # tests/test_updates_registry.py::_fixture_cls).
    setattr(fake_pkg_mod, name, cls)
    return cls


async def _insert_active_agent_with_method(method: str) -> None:
    """Insert one ``is_active=1`` row so ``_current_enrollment_types`` sees it."""
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, api_key_hash, "
                " cert_pem, created_at, is_active, enrollment_method) "
                "VALUES "
                "(:aid, :name, '[]', :hash, NULL, '2026-04-23T00:00:00+00:00', "
                " 1, :method)"
            ),
            {
                "aid": f"agent-{method}",
                "name": f"agent {method}",
                "hash": "x" * 64,
                "method": method,
            },
        )


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_boot_with_no_migrations_noop(fresh_db, fake_pkg):
    from mcp_proxy.updates.boot import detect_pending_migrations

    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    assert result == {"detected_ids": [], "halt_reasons": []}
    assert mgr.is_sign_halted is False
    assert await get_pending_updates() == []


@pytest.mark.asyncio
async def test_boot_inserts_pending_non_critical_no_halt(fresh_db, fake_pkg):
    _make_migration(
        fake_pkg, "Info1", "2099-01-01-info",
        criticality="info", affects=("connector",), check_returns=True,
    )

    from mcp_proxy.updates.boot import detect_pending_migrations
    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    assert result["detected_ids"] == ["2099-01-01-info"]
    assert result["halt_reasons"] == []
    assert mgr.is_sign_halted is False

    rows = await get_pending_updates()
    assert len(rows) == 1
    assert rows[0]["migration_id"] == "2099-01-01-info"
    assert rows[0]["status"] == "pending"


@pytest.mark.asyncio
async def test_boot_critical_affecting_my_enrollment_halts(fresh_db, fake_pkg):
    await _insert_active_agent_with_method("connector")
    _make_migration(
        fake_pkg, "CritConnector", "2099-02-01-crit",
        criticality="critical", affects=("connector",), check_returns=True,
    )

    from mcp_proxy.updates.boot import detect_pending_migrations
    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    assert result["halt_reasons"] == ["2099-02-01-crit"]
    assert mgr.is_sign_halted is True
    assert mgr.sign_halt_reason is not None
    assert "2099-02-01-crit" in mgr.sign_halt_reason


@pytest.mark.asyncio
async def test_boot_critical_not_affecting_my_enrollment_no_halt(
    fresh_db, fake_pkg,
):
    # Proxy hosts a byoca agent; migration affects only spire.
    await _insert_active_agent_with_method("byoca")
    _make_migration(
        fake_pkg, "CritSpire", "2099-02-02-crit-spire",
        criticality="critical", affects=("spire",), check_returns=True,
    )

    from mcp_proxy.updates.boot import detect_pending_migrations
    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    # Row still inserted (operator should know), but no halt because
    # this proxy has no spire agents.
    assert result["detected_ids"] == ["2099-02-02-crit-spire"]
    assert result["halt_reasons"] == []
    assert mgr.is_sign_halted is False


@pytest.mark.asyncio
async def test_boot_empty_enrollment_defaults_to_connector(fresh_db, fake_pkg):
    # No agents enrolled yet → defaults to {"connector"}; a critical
    # connector-affecting migration must still halt, because that is
    # the only enrollment path an un-provisioned proxy can take.
    _make_migration(
        fake_pkg, "EmptyCrit", "2099-02-03-empty-crit",
        criticality="critical", affects=("connector",), check_returns=True,
    )
    from mcp_proxy.updates.boot import detect_pending_migrations
    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    assert result["halt_reasons"] == ["2099-02-03-empty-crit"]
    assert mgr.is_sign_halted is True


@pytest.mark.asyncio
async def test_boot_check_exception_logged_skipped(
    fresh_db, fake_pkg, monkeypatch,
):
    _make_migration(
        fake_pkg, "Crash", "2099-03-01-crash",
        criticality="critical", affects=("connector",),
        check_raises=RuntimeError,
    )
    # Also register a healthy one to confirm the loop continues past the crash.
    _make_migration(
        fake_pkg, "Healthy", "2099-03-02-healthy",
        criticality="info", affects=("connector",), check_returns=True,
    )

    # The ``mcp_proxy`` root logger has ``propagate=False`` so caplog
    # does not receive warnings from its descendants. Monkeypatch the
    # module logger directly (memory ``feedback_mcp_proxy_logger_caplog``).
    import mcp_proxy.updates.boot as boot_mod
    captured: list[str] = []

    def _capture(msg, *args, **_kwargs):
        try:
            captured.append(msg % args if args else str(msg))
        except TypeError:
            captured.append(str(msg))

    monkeypatch.setattr(boot_mod.logger, "warning", _capture)

    mgr = StubAgentManager()
    result = await boot_mod.detect_pending_migrations(mgr)

    assert result["detected_ids"] == ["2099-03-02-healthy"]
    assert "2099-03-01-crash" not in result["detected_ids"]
    assert mgr.is_sign_halted is False
    assert any("2099-03-01-crash" in line for line in captured), (
        f"expected crash id in warnings; got {captured!r}"
    )


@pytest.mark.asyncio
async def test_boot_idempotent_double_call(fresh_db, fake_pkg):
    _make_migration(
        fake_pkg, "Dup", "2099-04-01-dup",
        criticality="info", affects=(), check_returns=True,
    )
    from mcp_proxy.updates.boot import detect_pending_migrations
    mgr = StubAgentManager()

    first = await detect_pending_migrations(mgr)
    second = await detect_pending_migrations(mgr)

    # Same detected list both calls — row was inserted once, re-inserts
    # were no-ops via ON CONFLICT / INSERT OR IGNORE.
    assert first == second == {
        "detected_ids": ["2099-04-01-dup"],
        "halt_reasons": [],
    }
    rows = await get_pending_updates()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_boot_skips_already_applied_rows(fresh_db, fake_pkg):
    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    from mcp_proxy.updates.boot import detect_pending_migrations

    # Admin applied this one prior to the restart; boot must not
    # regress the row to "pending".
    await insert_pending_update(
        migration_id="2099-05-01-applied",
        detected_at="2099-05-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-05-01-applied",
        status="applied",
        applied_at="2099-05-01T01:00:00+00:00",
    )

    # Its check() still returns True because the migration
    # implementation checks for un-applied state only lazily — simulate
    # a migration that can't tell it already ran.
    _make_migration(
        fake_pkg, "Applied", "2099-05-01-applied",
        criticality="critical", affects=("connector",), check_returns=True,
    )

    mgr = StubAgentManager()
    result = await detect_pending_migrations(mgr)

    assert result["detected_ids"] == []
    assert result["halt_reasons"] == []
    assert mgr.is_sign_halted is False

    rows = await get_pending_updates()
    assert len(rows) == 1
    assert rows[0]["status"] == "applied"
