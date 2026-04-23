"""End-to-end tests for the federation-update admin endpoints.

Covers the three handlers in ``mcp_proxy/dashboard/updates_router.py``:

- ``GET /proxy/updates`` — merged list of migrations × pending_updates rows.
- ``POST /proxy/updates/{id}/apply`` — confirm_text gate, up() wrapping,
  status transitions (pending→applied / pending→failed), sign-halt clear.
- ``POST /proxy/updates/{id}/rollback`` — confirm_text gate, rollback()
  wrapping, status transitions (applied/failed→rolled_back / →failed),
  sign-halt clear.

Migrations are registered via the ``fake_pkg`` pattern from PR 1/2/3 —
each test points :mod:`mcp_proxy.updates.registry` at a throwaway
package so test-only fixture classes never leak into production
discovery.

The dashboard session is bootstrapped by the ``proxy_logged_in``
fixture (mirrors the one in ``test_proxy_dashboard_mastio_key``).
CSRF tokens are scraped from the rendered ``/proxy`` page because the
new endpoint returns JSON and does not embed a token of its own.
"""
from __future__ import annotations

import re
import sys
import types

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp_proxy.updates import registry as registry_mod
from mcp_proxy.updates.base import Migration


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_logged_in(tmp_path, monkeypatch):
    """Standalone proxy with an admin session cookie in place."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.setenv("CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS", "0")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            resp = await client.post(
                "/proxy/login",
                data={"password": "test-password-1234"},
                follow_redirects=False,
            )
            assert resp.status_code in (302, 303), resp.text
            yield app, client
    get_settings.cache_clear()


@pytest.fixture
def fake_pkg(monkeypatch):
    """Per-test throwaway migrations package (pattern from PR 2/3 tests)."""
    pkg_name = (
        "mcp_proxy.updates.migrations"
        f"._admin_endpoint_testfixtures_{id(monkeypatch)}"
    )
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, pkg_name, pkg)
    monkeypatch.setattr(registry_mod, "_migrations_pkg", pkg)
    return pkg


def _make_migration(
    fake_pkg_mod: types.ModuleType,
    name: str,
    migration_id: str,
    *,
    criticality: str = "info",
    affects: tuple[str, ...] = (),
    check_returns: bool = True,
    up_raises: type[Exception] | None = None,
    rollback_raises: type[Exception] | None = None,
) -> type[Migration]:
    async def _check(self) -> bool:
        return check_returns

    async def _up(self) -> None:
        if up_raises is not None:
            raise up_raises("synthetic up() failure")
        return None

    async def _rollback(self) -> None:
        if rollback_raises is not None:
            raise rollback_raises("synthetic rollback() failure")
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
    setattr(fake_pkg_mod, name, cls)  # keep weakref alive
    return cls


async def _csrf_token(client: AsyncClient) -> str:
    """Scrape a CSRF token from a rendered dashboard page.

    ``/proxy/updates`` returns JSON, so we pull the token from
    ``/proxy/mastio-key`` which always renders after login on a
    standalone proxy.
    """
    page = await client.get("/proxy/mastio-key")
    assert page.status_code == 200, page.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token missing from /proxy/mastio-key"
    return m.group(1)


# ── GET /proxy/updates ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_empty_when_no_migrations_registered(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/updates/api")
    assert resp.status_code == 200
    assert resp.json() == {"updates": []}


@pytest.mark.asyncio
async def test_list_returns_migration_metadata_and_db_state(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "Alpha", "2099-01-01-alpha",
        criticality="critical", affects=("connector",),
    )

    # Seed a pending_updates row as the boot detector would.
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-01-01-alpha",
        detected_at="2099-01-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/updates/api")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["updates"]) == 1

    entry = body["updates"][0]
    assert entry["migration_id"] == "2099-01-01-alpha"
    assert entry["migration_type"] == "cert-schema"
    assert entry["criticality"] == "critical"
    assert entry["affects_enrollments"] == ["connector"]
    assert entry["preserves_enrollments"] is True
    assert entry["db_status"] == "pending"
    assert entry["detected_at"] == "2099-01-01T00:00:00+00:00"
    assert entry["applied_at"] is None
    assert entry["error"] is None


@pytest.mark.asyncio
async def test_list_shows_migration_without_db_row(
    proxy_logged_in, fake_pkg,
):
    """Discovered migrations without a pending_updates row surface with
    ``db_status=None`` — the boot detector may not have run or ``check()``
    may have been False at boot."""
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "Beta", "2099-02-01-beta")

    resp = await client.get("/proxy/updates/api")
    body = resp.json()
    assert body["updates"][0]["db_status"] is None
    assert body["updates"][0]["applied_at"] is None


# ── POST /proxy/updates/{id}/apply ───────────────────────────────────


@pytest.mark.asyncio
async def test_apply_happy_path(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "HappyApply", "2099-03-01-apply")

    from mcp_proxy.db import insert_pending_update, get_pending_updates
    await insert_pending_update(
        migration_id="2099-03-01-apply",
        detected_at="2099-03-01T00:00:00+00:00",
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-03-01-apply/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "status": "applied", "migration_id": "2099-03-01-apply",
    }

    rows = [
        r for r in await get_pending_updates()
        if r["migration_id"] == "2099-03-01-apply"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "applied"
    assert rows[0]["applied_at"] is not None


@pytest.mark.asyncio
async def test_apply_migration_not_found_404(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/does-not-exist/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_apply_already_applied_returns_409(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "AlreadyApplied", "2099-04-01-done")

    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    await insert_pending_update(
        migration_id="2099-04-01-done",
        detected_at="2099-04-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-04-01-done",
        status="applied",
        applied_at="2099-04-01T01:00:00+00:00",
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-04-01-done/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 409
    assert "applied" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_apply_exception_sets_failed_and_logs_audit(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "BoomApply", "2099-05-01-boom",
        up_raises=RuntimeError,
    )

    from mcp_proxy.db import insert_pending_update, get_pending_updates
    await insert_pending_update(
        migration_id="2099-05-01-boom",
        detected_at="2099-05-01T00:00:00+00:00",
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-05-01-boom/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 500

    rows = [
        r for r in await get_pending_updates()
        if r["migration_id"] == "2099-05-01-boom"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert "synthetic up()" in (rows[0]["error"] or "")


@pytest.mark.asyncio
async def test_apply_without_csrf_returns_403(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "NoCsrf", "2099-06-01-nocsrf")

    resp = await client.post(
        "/proxy/updates/2099-06-01-nocsrf/apply",
        data={"confirm_text": "APPLY"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_apply_wrong_confirm_text_returns_400(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "BadConfirm", "2099-07-01-bad")

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-07-01-bad/apply",
        data={"csrf_token": csrf, "confirm_text": "GO"},
    )
    assert resp.status_code == 400
    assert "APPLY" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_apply_missing_confirm_text_returns_400(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "MissingConfirm", "2099-08-01-mis")

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-08-01-mis/apply",
        data={"csrf_token": csrf},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_apply_retry_from_failed_status(proxy_logged_in, fake_pkg):
    """PR 5: apply() accepts status='failed' and clears the stale error.

    Retry semantics: the admin fixed whatever made up() fail and re-runs.
    up() is documented idempotent (PR 1 ABC contract), so the second call
    is safe. Post-success the error field must be NULL — a stale error
    next to a successful apply would confuse the UI badge and the audit
    trail.
    """
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "RetryOK", "2099-retry-01")

    from mcp_proxy.db import (
        insert_pending_update,
        update_pending_update_status,
        get_pending_updates,
    )

    # Seed the prior-failed state — row exists, status='failed',
    # error populated.
    await insert_pending_update(
        migration_id="2099-retry-01",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-retry-01",
        status="failed",
        error="transient: flaky filesystem, now fixed",
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-retry-01/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "status": "applied", "migration_id": "2099-retry-01",
    }

    rows = [
        r for r in await get_pending_updates()
        if r["migration_id"] == "2099-retry-01"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "applied"
    assert rows[0]["applied_at"] is not None
    # The stale ``error`` must be cleared — otherwise the UI shows a
    # red "Last error" panel next to an applied badge.
    assert rows[0]["error"] is None


@pytest.mark.asyncio
async def test_apply_clears_sign_halt(proxy_logged_in, fake_pkg):
    """After a successful apply, the sign-halt flag is cleared.

    The boot detector re-runs but the now-applied migration is skipped
    (status='applied'), so halt stays cleared.
    """
    app_, client = proxy_logged_in
    _make_migration(
        fake_pkg, "HaltingApply", "2099-09-01-halt",
        criticality="critical", affects=("connector",),
    )

    agent_mgr = app_.state.agent_manager
    agent_mgr.mark_sign_halted(
        "pending critical federation updates: 2099-09-01-halt",
    )
    assert agent_mgr.is_sign_halted is True

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-09-01-halt/apply",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},
    )
    assert resp.status_code == 200, resp.text
    assert agent_mgr.is_sign_halted is False
    assert agent_mgr.sign_halt_reason is None


# ── POST /proxy/updates/{id}/rollback ────────────────────────────────


async def _seed_applied_migration(fake_pkg, migration_id: str, **kwargs):
    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    _make_migration(fake_pkg, "ToRollback", migration_id, **kwargs)
    await insert_pending_update(
        migration_id=migration_id,
        detected_at="2099-10-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id=migration_id,
        status="applied",
        applied_at="2099-10-01T01:00:00+00:00",
    )


@pytest.mark.asyncio
async def test_rollback_happy_path(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    await _seed_applied_migration(fake_pkg, "2099-10-01-rbk")

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-10-01-rbk/rollback",
        data={"csrf_token": csrf, "confirm_text": "ROLLBACK"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "status": "rolled_back", "migration_id": "2099-10-01-rbk",
    }

    from mcp_proxy.db import get_pending_updates
    rows = [
        r for r in await get_pending_updates()
        if r["migration_id"] == "2099-10-01-rbk"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "rolled_back"


@pytest.mark.asyncio
async def test_rollback_pending_status_returns_409(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "PendingNoRb", "2099-11-01-pend")

    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-11-01-pend",
        detected_at="2099-11-01T00:00:00+00:00",
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-11-01-pend/rollback",
        data={"csrf_token": csrf, "confirm_text": "ROLLBACK"},
    )
    assert resp.status_code == 409
    assert "pending" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_rollback_exception_sets_failed(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    await _seed_applied_migration(
        fake_pkg, "2099-12-01-rb-boom", rollback_raises=RuntimeError,
    )

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-12-01-rb-boom/rollback",
        data={"csrf_token": csrf, "confirm_text": "ROLLBACK"},
    )
    assert resp.status_code == 500

    from mcp_proxy.db import get_pending_updates
    rows = [
        r for r in await get_pending_updates()
        if r["migration_id"] == "2099-12-01-rb-boom"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert "synthetic rollback()" in (rows[0]["error"] or "")


@pytest.mark.asyncio
async def test_rollback_clears_sign_halt(proxy_logged_in, fake_pkg):
    app_, client = proxy_logged_in
    await _seed_applied_migration(fake_pkg, "2099-13-01-rb-halt")

    agent_mgr = app_.state.agent_manager
    agent_mgr.mark_sign_halted("manual halt for test")
    assert agent_mgr.is_sign_halted is True

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-13-01-rb-halt/rollback",
        data={"csrf_token": csrf, "confirm_text": "ROLLBACK"},
    )
    assert resp.status_code == 200
    assert agent_mgr.is_sign_halted is False


@pytest.mark.asyncio
async def test_rollback_wrong_confirm_text_returns_400(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    await _seed_applied_migration(fake_pkg, "2099-14-01-rb-bad")

    csrf = await _csrf_token(client)
    resp = await client.post(
        "/proxy/updates/2099-14-01-rb-bad/rollback",
        data={"csrf_token": csrf, "confirm_text": "APPLY"},  # wrong
    )
    assert resp.status_code == 400
    assert "ROLLBACK" in resp.json()["detail"]
