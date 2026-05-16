"""Polling loop — single-iteration coverage and backoff path.

The full loop with timers is exercised by spawning the task with a
stop_event that is set immediately after a single iteration window;
the iteration itself is tested via :func:`intune_poll_once` so
timing-based flakiness stays out of the suite.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.mdm.intune import IntuneClient, IntuneGraphError
from mcp_proxy.mdm.poller import (
    intune_poll_loop,
    intune_poll_once,
)


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "poller.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


def _mock_client(pages: list[dict]) -> IntuneClient:
    """Build an IntuneClient with httpx.MockTransport baked in."""
    iter_pages = iter(pages)

    def handler(request: httpx.Request) -> httpx.Response:
        if "/oauth2/v2.0/token" in str(request.url):
            return httpx.Response(200, json={
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 3600,
            })
        if "managedDevices" in str(request.url):
            try:
                return httpx.Response(200, json=next(iter_pages))
            except StopIteration:
                return httpx.Response(200, json={"value": [],
                                                  "@odata.deltaLink": "x"})
        return httpx.Response(404)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return IntuneClient(tenant_id="t", client_id="c",
                        client_secret="s", http_client=http)


@pytest.mark.asyncio
async def test_poll_once_persists_devices_and_delta_link(db_engine):
    pages = [{
        "value": [
            {"id": "d1", "complianceState": "compliant",
             "azureADDeviceId": "aad-1"},
            {"id": "d2", "complianceState": "noncompliant"},
        ],
        "@odata.deltaLink": "https://graph.test/delta?token=PERSIST_ME",
    }]
    client = _mock_client(pages)
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)

    touched, next_delta = await intune_poll_once(client, now=now)
    assert touched == 2
    assert next_delta == "https://graph.test/delta?token=PERSIST_ME"

    async with get_db() as conn:
        compliance = (await conn.execute(
            text("SELECT compliance FROM mdm_device_state WHERE device_id = 'd1'"),
        )).scalar()
        delta_link_persisted = (await conn.execute(
            text("SELECT value FROM proxy_config WHERE key = 'mdm.intune.delta_link'"),
        )).scalar()
    assert compliance == "compliant"
    assert delta_link_persisted == "https://graph.test/delta?token=PERSIST_ME"

    await client.aclose()


@pytest.mark.asyncio
async def test_poll_once_second_call_uses_persisted_delta_link(db_engine):
    # First round persists the delta link.
    first_pages = [{"value": [], "@odata.deltaLink": "https://graph.test/d2"}]
    client1 = _mock_client(first_pages)
    await intune_poll_once(client1)
    await client1.aclose()

    # Second client should send the persisted delta link on its
    # next call. We assert by capturing the URL the client requests.
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "/oauth2/v2.0/token" in str(request.url):
            return httpx.Response(200, json={
                "access_token": "tok", "token_type": "Bearer",
                "expires_in": 3600,
            })
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={
            "value": [], "@odata.deltaLink": "https://graph.test/d3",
        })

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client2 = IntuneClient(tenant_id="t", client_id="c", client_secret="s",
                           http_client=http)
    await intune_poll_once(client2)
    await client2.aclose()

    assert any("https://graph.test/d2" in u for u in seen_urls), seen_urls


@pytest.mark.asyncio
async def test_loop_exits_when_stop_event_set(db_engine, monkeypatch):
    """The lifespan teardown signals stop_event; the loop must exit
    within the timeout (we use a tiny interval so the test is fast)."""

    # Stub IntuneClient so the loop hits a no-op iteration immediately.
    handler_calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        handler_calls["n"] += 1
        if "/oauth2/v2.0/token" in str(request.url):
            return httpx.Response(200, json={
                "access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
            })
        return httpx.Response(200, json={"value": [],
                                          "@odata.deltaLink": "x"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "mcp_proxy.mdm.poller.IntuneClient",
        lambda tenant_id, client_id, client_secret: IntuneClient(
            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret,
            http_client=httpx.AsyncClient(transport=transport),
        ),
    )

    stop = asyncio.Event()
    task = asyncio.create_task(
        intune_poll_loop(
            tenant_id="t", client_id="c", client_secret="s",
            interval_seconds=60, stop_event=stop,
        ),
    )
    # Give the loop one tick to register the first poll, then stop.
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert task.done()


@pytest.mark.asyncio
async def test_loop_backs_off_on_graph_error_and_continues(db_engine, monkeypatch):
    """A Graph error must not crash the loop; the next iteration runs
    after the backoff window."""

    call_count = {"n": 0}

    async def fake_intune_poll_once(client, *, now=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise IntuneGraphError(429, "throttled")
        return (0, None)

    monkeypatch.setattr(
        "mcp_proxy.mdm.poller.intune_poll_once", fake_intune_poll_once,
    )
    # Compress backoff so the test runs fast.
    monkeypatch.setattr(
        "mcp_proxy.mdm.poller._BACKOFF_SECONDS", (0.05, 0.1),
    )
    # Stub IntuneClient construction so no HTTP setup is needed.

    class _FakeClient:
        async def aclose(self):
            return None

    monkeypatch.setattr(
        "mcp_proxy.mdm.poller.IntuneClient",
        lambda **kwargs: _FakeClient(),
    )

    stop = asyncio.Event()
    task = asyncio.create_task(
        intune_poll_loop(
            tenant_id="t", client_id="c", client_secret="s",
            interval_seconds=60, stop_event=stop,
        ),
    )
    await asyncio.sleep(0.3)
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert call_count["n"] >= 2  # error + at least one retry
