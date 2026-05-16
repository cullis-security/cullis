"""IntuneClient — auth + delta paging against a mocked Graph API.

Uses ``respx`` if available, falls back to a hand-rolled httpx
``MockTransport`` so the test does not gain a new dependency. The
test is hermetic; no real network calls.
"""
from __future__ import annotations

import json

import httpx
import pytest

from mcp_proxy.mdm.intune import (
    IntuneClient,
    IntuneGraphError,
    map_compliance_state,
    project_device_row,
)


def _make_handler(*, token_body: dict | None = None,
                  token_status: int = 200,
                  pages: list[dict] | None = None):
    """Build an httpx MockTransport handler with deterministic responses."""
    token_body = token_body or {
        "access_token": "fake-bearer-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    pages = pages or [{"value": [], "@odata.deltaLink": "https://graph.test/delta?token=abc"}]
    page_iter = iter(pages)
    state = {"token_calls": 0, "delta_calls": 0, "saw_token_header": []}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/oauth2/v2.0/token" in url:
            state["token_calls"] += 1
            return httpx.Response(token_status, json=token_body)
        if "managedDevices" in url or "graph.test" in url:
            state["delta_calls"] += 1
            state["saw_token_header"].append(request.headers.get("Authorization", ""))
            try:
                page = next(page_iter)
            except StopIteration:
                page = {"value": [], "@odata.deltaLink": "https://graph.test/delta?final"}
            return httpx.Response(200, json=page)
        return httpx.Response(404, json={"error": "unexpected url"})

    return handler, state


@pytest.mark.asyncio
async def test_fetch_managed_devices_acquires_token_once_per_run():
    handler, state = _make_handler()
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)

    client = IntuneClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="secret",
        http_client=http,
    )
    devices, delta = await client.fetch_managed_devices_delta()
    assert devices == []
    assert delta == "https://graph.test/delta?token=abc"
    assert state["token_calls"] == 1
    assert state["saw_token_header"][0].startswith("Bearer ")
    await client.aclose()


@pytest.mark.asyncio
async def test_token_cached_across_consecutive_calls():
    handler, state = _make_handler()
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)

    client = IntuneClient(
        tenant_id="t", client_id="c", client_secret="s",
        http_client=http,
    )
    await client.fetch_managed_devices_delta()
    await client.fetch_managed_devices_delta()
    # Token endpoint hit once, not twice.
    assert state["token_calls"] == 1
    assert state["delta_calls"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_paging_walks_next_link_and_terminates_on_delta_link():
    pages = [
        {
            "value": [{"id": "dev-1", "complianceState": "compliant"}],
            "@odata.nextLink": "https://graph.test/next-1",
        },
        {
            "value": [{"id": "dev-2", "complianceState": "noncompliant"}],
            "@odata.nextLink": "https://graph.test/next-2",
        },
        {
            "value": [{"id": "dev-3", "complianceState": "unknown"}],
            "@odata.deltaLink": "https://graph.test/final-delta",
        },
    ]
    handler, state = _make_handler(pages=pages)
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)

    client = IntuneClient(
        tenant_id="t", client_id="c", client_secret="s",
        http_client=http,
    )
    devices, delta = await client.fetch_managed_devices_delta()
    assert [d["id"] for d in devices] == ["dev-1", "dev-2", "dev-3"]
    assert delta == "https://graph.test/final-delta"
    assert state["delta_calls"] == 3
    await client.aclose()


@pytest.mark.asyncio
async def test_token_endpoint_401_raises_graph_error_without_leaking_body():
    handler, _ = _make_handler(
        token_body={"error": "invalid_client", "error_description": "secret xyz"},
        token_status=401,
    )
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)

    client = IntuneClient(
        tenant_id="t", client_id="c", client_secret="THE_SECRET_VALUE",
        http_client=http,
    )
    with pytest.raises(IntuneGraphError) as exc:
        await client.fetch_managed_devices_delta()
    assert exc.value.status == 401
    # The secret MUST NOT appear in the exception message.
    assert "THE_SECRET_VALUE" not in str(exc.value)
    assert "xyz" not in str(exc.value)
    await client.aclose()


@pytest.mark.asyncio
async def test_constructor_rejects_empty_credentials():
    with pytest.raises(ValueError):
        IntuneClient(tenant_id="", client_id="x", client_secret="y")
    with pytest.raises(ValueError):
        IntuneClient(tenant_id="x", client_id="", client_secret="y")
    with pytest.raises(ValueError):
        IntuneClient(tenant_id="x", client_id="y", client_secret="")


@pytest.mark.asyncio
async def test_401_on_devices_triggers_token_refresh_and_retry():
    """A token that expires between issuance and the next call should
    not raise — the client refreshes once and retries."""
    page = {"value": [{"id": "dev-1", "complianceState": "compliant"}],
            "@odata.deltaLink": "https://graph.test/d"}
    token_body = {"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}

    state = {"token_calls": 0, "device_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "/oauth2/v2.0/token" in str(request.url):
            state["token_calls"] += 1
            tok = "tok-1" if state["token_calls"] == 1 else "tok-2"
            return httpx.Response(200, json={**token_body, "access_token": tok})
        if "managedDevices" in str(request.url):
            state["device_calls"] += 1
            if state["device_calls"] == 1:
                return httpx.Response(401, json={"error": "expired"})
            return httpx.Response(200, json=page)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    client = IntuneClient(
        tenant_id="t", client_id="c", client_secret="s", http_client=http,
    )
    devices, _ = await client.fetch_managed_devices_delta()
    assert [d["id"] for d in devices] == ["dev-1"]
    assert state["token_calls"] == 2
    assert state["device_calls"] == 2
    await client.aclose()


# ── pure helpers ──────────────────────────────────────────────────


def test_map_compliance_state_conservative_unknown_default():
    assert map_compliance_state("compliant") == "compliant"
    assert map_compliance_state("noncompliant") == "non_compliant"
    # Every other Graph value falls into 'unknown' so a stale or
    # conflicted device cannot accidentally be granted managed tier.
    for s in ("inGracePeriod", "conflict", "error", "configManager",
              "unknown", None, "", "totally-unexpected"):
        assert map_compliance_state(s) == "unknown", s


def test_project_device_row_picks_known_fields_only():
    graph = {
        "id": "abc",
        "complianceState": "compliant",
        "azureADDeviceId": "aad-1",
        "userPrincipalName": "alice@example.com",
        "deviceName": "alice-laptop",
        "manufacturer": "Infineon",
        "serialNumber": "SN-001",
        "extraFutureField": "should not crash",
    }
    row = project_device_row(graph)
    assert row == {
        "device_id": "abc",
        "compliance": "compliant",
        "azure_ad_device_id": "aad-1",
        "user_principal_name": "alice@example.com",
        "device_name": "alice-laptop",
        "manufacturer": "Infineon",
        "serial_number": "SN-001",
    }
