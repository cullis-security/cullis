"""Mastio update-check service tests.

Covers the helper module (``mcp_proxy/dashboard/update_check.py``) +
the two dashboard endpoints (``GET /proxy/api/update-status`` +
``POST /proxy/api/update-status/dismiss``).

The test never hits ``api.github.com`` for real — every test monkeypatches
``_fetch_latest_from_github`` so the suite stays hermetic and runs
offline.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient


# ── helper unit tests (semver compare) ─────────────────────────────────


def test_is_newer_basic_patch_bump():
    from mcp_proxy.dashboard.update_check import _is_newer
    assert _is_newer("mastio-v0.3.8", "0.3.7") is True
    assert _is_newer("mastio-v0.3.7", "0.3.8") is False
    assert _is_newer("mastio-v0.3.8", "0.3.8") is False


def test_is_newer_minor_and_major():
    from mcp_proxy.dashboard.update_check import _is_newer
    assert _is_newer("mastio-v0.4.0", "0.3.99") is True
    assert _is_newer("mastio-v1.0.0", "0.99.99") is True


def test_is_newer_rc_loses_to_final_with_same_xyz():
    """A pre-release with the same x.y.z must NOT trigger the banner
    when the operator is already on the final release. Matches semver
    spec: 0.3.8-rc1 < 0.3.8."""
    from mcp_proxy.dashboard.update_check import _is_newer
    assert _is_newer("mastio-v0.3.8-rc1", "0.3.8") is False
    assert _is_newer("mastio-v0.3.8", "0.3.8-rc1") is True


def test_is_newer_dev_always_outdated():
    """A Mastio running from source (``dev`` version) should always
    see any release as newer, so the operator gets the banner."""
    from mcp_proxy.dashboard.update_check import _is_newer
    assert _is_newer("mastio-v0.0.1", "dev") is True
    assert _is_newer("mastio-v999.999.999", "dev") is True


def test_is_newer_malformed_tag_refuses():
    """Garbled GitHub data → don't fire the banner. Defensive: the
    banner exists for operator UX, not for surfacing API noise."""
    from mcp_proxy.dashboard.update_check import _is_newer
    assert _is_newer("connector-v0.4.4", "0.3.7") is False  # wrong prefix
    assert _is_newer("mastio-v0.3", "0.3.7") is False       # short semver
    assert _is_newer("mastio-vX.Y.Z", "0.3.7") is False     # not numeric


# ── status + dismiss flow ──────────────────────────────────────────────


@pytest.fixture
def _isolated_db(tmp_path, monkeypatch):
    """Per-test SQLite + cleared settings cache."""
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL",
        f"sqlite+aiosqlite:///{tmp_path}/proxy_update.sqlite",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("CULLIS_MASTIO_VERSION", "0.3.7")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_get_update_status_fetches_when_cache_empty(
    _isolated_db, monkeypatch,
):
    from mcp_proxy.db import init_db
    from mcp_proxy.dashboard import update_check
    settings_url = (await _get_settings()).database_url
    await init_db(settings_url)

    fetch_calls: list[int] = []

    async def fake_fetch():
        fetch_calls.append(1)
        return update_check.ReleaseInfo(
            tag="mastio-v0.3.8",
            html_url="https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8",
        )

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    status = await update_check.get_update_status()
    assert status.current == "0.3.7"
    assert status.latest == "mastio-v0.3.8"
    assert status.available is True
    assert len(fetch_calls) == 1, "first call should hit GitHub"


@pytest.mark.asyncio
async def test_get_update_status_uses_cache_inside_window(
    _isolated_db, monkeypatch,
):
    from mcp_proxy.db import init_db, set_config
    from mcp_proxy.dashboard import update_check
    s = await _get_settings()
    await init_db(s.database_url)

    # Pre-seed a fresh cache.
    now = datetime.now(timezone.utc)
    await set_config("update_check_last_poll_at", now.isoformat())
    await set_config("update_check_latest_tag", "mastio-v0.3.8")
    await set_config(
        "update_check_latest_url",
        "https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8",
    )

    fetch_calls: list[int] = []

    async def fake_fetch():
        fetch_calls.append(1)
        return None

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    status = await update_check.get_update_status()
    assert status.latest == "mastio-v0.3.8"
    assert status.available is True
    assert len(fetch_calls) == 0, "cache should short-circuit the fetch"


@pytest.mark.asyncio
async def test_get_update_status_refetches_after_window(
    _isolated_db, monkeypatch,
):
    from mcp_proxy.db import init_db, set_config
    from mcp_proxy.dashboard import update_check
    s = await _get_settings()
    await init_db(s.database_url)

    # Pre-seed a STALE cache (older than the 24h window).
    stale = datetime.now(timezone.utc) - timedelta(days=2)
    await set_config("update_check_last_poll_at", stale.isoformat())
    await set_config("update_check_latest_tag", "mastio-v0.3.7")

    async def fake_fetch():
        return update_check.ReleaseInfo(
            tag="mastio-v0.4.0",
            html_url="https://github.com/cullis-security/cullis/releases/tag/mastio-v0.4.0",
        )

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    status = await update_check.get_update_status()
    assert status.latest == "mastio-v0.4.0"


@pytest.mark.asyncio
async def test_get_update_status_swallows_fetch_failure(
    _isolated_db, monkeypatch,
):
    """When GitHub is unreachable, the cache TIMESTAMP still advances
    (so we don't hammer the API) but the cached tag stays as-is."""
    from mcp_proxy.db import init_db, get_config, set_config
    from mcp_proxy.dashboard import update_check
    s = await _get_settings()
    await init_db(s.database_url)

    # Stale cache → fetch will be attempted but fails.
    stale = datetime.now(timezone.utc) - timedelta(days=2)
    await set_config("update_check_last_poll_at", stale.isoformat())
    await set_config("update_check_latest_tag", "mastio-v0.3.8")

    async def fake_fetch():
        return None  # transport error / non-200 / JSON decode

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    status = await update_check.get_update_status()
    # Tag survives.
    assert status.latest == "mastio-v0.3.8"
    # Timestamp advances so the next call doesn't refetch immediately.
    new_ts = await get_config("update_check_last_poll_at")
    assert new_ts != stale.isoformat()


@pytest.mark.asyncio
async def test_dismiss_hides_banner_for_current_latest(
    _isolated_db, monkeypatch,
):
    from mcp_proxy.db import init_db
    from mcp_proxy.dashboard import update_check
    s = await _get_settings()
    await init_db(s.database_url)

    async def fake_fetch():
        return update_check.ReleaseInfo(
            tag="mastio-v0.3.8",
            html_url="https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8",
        )

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    status = await update_check.get_update_status()
    assert status.available is True

    dismissed = await update_check.dismiss_current_latest()
    assert dismissed == "mastio-v0.3.8"

    # Available should now be False even though current < latest.
    status2 = await update_check.get_update_status()
    assert status2.latest == "mastio-v0.3.8"
    assert status2.available is False


@pytest.mark.asyncio
async def test_dismiss_does_not_block_newer_release(
    _isolated_db, monkeypatch,
):
    """Dismissing v0.3.8 must NOT suppress the banner when v0.3.9 arrives
    later. The dismiss is per-tag, not permanent."""
    from mcp_proxy.db import init_db
    from mcp_proxy.dashboard import update_check
    s = await _get_settings()
    await init_db(s.database_url)

    next_tag = "mastio-v0.3.8"

    async def fake_fetch():
        return update_check.ReleaseInfo(
            tag=next_tag,
            html_url=f"https://github.com/cullis-security/cullis/releases/tag/{next_tag}",
        )

    monkeypatch.setattr(update_check, "_fetch_latest_from_github", fake_fetch)
    await update_check.get_update_status()
    await update_check.dismiss_current_latest()

    # New release arrives.
    next_tag = "mastio-v0.3.9"
    # Bypass the 24h cache by setting last_poll_at to a stale time.
    from mcp_proxy.db import set_config
    stale = datetime.now(timezone.utc) - timedelta(days=2)
    await set_config("update_check_last_poll_at", stale.isoformat())

    status = await update_check.get_update_status()
    assert status.latest == "mastio-v0.3.9"
    assert status.available is True, (
        "dismiss on v0.3.8 must not silence v0.3.9"
    )


# ── _fetch_latest_from_github (HTTP layer, mocked transport) ───────────


@pytest.mark.asyncio
async def test_fetch_picks_highest_mastio_semver_ignoring_other_prefixes(
    monkeypatch,
):
    """Releases page lists connector + chat + frontdesk-bundle + mastio
    tags. Only ``mastio-v*`` count; among those, the highest x.y.z wins
    (final > rc)."""
    import httpx
    from mcp_proxy.dashboard import update_check

    payload = [
        # Most recent on top — GitHub's natural order is by published_at desc.
        {"tag_name": "connector-v0.4.5",
         "html_url": "https://github.com/cullis-security/cullis/releases/tag/connector-v0.4.5"},
        {"tag_name": "mastio-v0.3.8-rc2",
         "html_url": "https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8-rc2"},
        {"tag_name": "frontdesk-bundle-v0.3.0",
         "html_url": "https://github.com/cullis-security/cullis/releases/tag/frontdesk-bundle-v0.3.0"},
        {"tag_name": "mastio-v0.3.7",
         "html_url": "https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.7"},
        {"tag_name": "mastio-v0.3.8",
         "html_url": "https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8"},
    ]

    def handler(request):
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)
    info = await update_check._fetch_latest_from_github()
    assert info is not None
    assert info.tag == "mastio-v0.3.8", (
        f"expected the final release to beat the rc; got {info.tag}"
    )


@pytest.mark.asyncio
async def test_fetch_refuses_non_github_html_url(monkeypatch):
    """Defensive: a poisoned response that points html_url at evil.com
    must be skipped so the modal can't redirect the operator off-site."""
    import httpx
    from mcp_proxy.dashboard import update_check

    payload = [{
        "tag_name": "mastio-v0.9.9",
        "html_url": "https://evil.example.com/phish",
    }]

    def handler(request):
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)
    info = await update_check._fetch_latest_from_github()
    assert info is None, (
        "non-github.com html_url must be refused to prevent operator "
        "phishing via a poisoned release entry"
    )


@pytest.mark.asyncio
async def test_fetch_returns_none_on_http_error(monkeypatch):
    import httpx
    from mcp_proxy.dashboard import update_check

    def handler(request):
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)
    info = await update_check._fetch_latest_from_github()
    assert info is None


# ── /proxy/api/update-status dashboard endpoint ────────────────────────


async def _spin_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL",
        f"sqlite+aiosqlite:///{tmp_path}/p.sqlite",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("CULLIS_MASTIO_VERSION", "0.3.7")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _admin_login(client: AsyncClient) -> str:
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")
    r = await client.post(
        "/proxy/login",
        data={"password": "test-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Pull a CSRF token from any logged-in page that includes one.
    page = await client.get("/proxy/overview")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    return m.group(1) if m else ""


@pytest.mark.asyncio
async def test_endpoint_returns_empty_when_no_session(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            r = await cli.get("/proxy/api/update-status")
            assert r.status_code == 200
            assert r.text == "", (
                "anonymous visitor must not learn whether an update is "
                "available — empty fragment matches the badge pattern"
            )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_endpoint_renders_banner_when_available(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _admin_login(cli)

            from mcp_proxy.dashboard import update_check

            async def fake_fetch():
                return update_check.ReleaseInfo(
                    tag="mastio-v0.3.8",
                    html_url="https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8",
                )

            monkeypatch.setattr(
                update_check, "_fetch_latest_from_github", fake_fetch,
            )
            r = await cli.get("/proxy/api/update-status")
            assert r.status_code == 200
            assert "Mastio update available" in r.text
            assert "mastio-v0.3.8" in r.text
            # The stripped version makes it into the tarball URL.
            assert "cullis-mastio-bundle-0.3.8.tar.gz" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_dismiss_endpoint_persists_and_hides_banner(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            csrf = await _admin_login(cli)

            from mcp_proxy.dashboard import update_check

            async def fake_fetch():
                return update_check.ReleaseInfo(
                    tag="mastio-v0.3.8",
                    html_url="https://github.com/cullis-security/cullis/releases/tag/mastio-v0.3.8",
                )

            monkeypatch.setattr(
                update_check, "_fetch_latest_from_github", fake_fetch,
            )
            # First call → banner renders.
            r1 = await cli.get("/proxy/api/update-status")
            assert "Mastio update available" in r1.text

            # Dismiss.
            r2 = await cli.post(
                "/proxy/api/update-status/dismiss",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r2.status_code == 303

            # Subsequent banner GET returns empty.
            r3 = await cli.get("/proxy/api/update-status")
            assert r3.text == ""
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_dismiss_requires_csrf(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _admin_login(cli)
            r = await cli.post(
                "/proxy/api/update-status/dismiss",
                data={"csrf_token": "wrong"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "error=csrf" in r.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── shared setting fetch ──────────────────────────────────────────────


async def _get_settings():
    from mcp_proxy.config import get_settings
    return get_settings()
