"""ADR-029 Phase G, peer-Mastio URL discovery via Court.

Pins :class:`mcp_proxy.policy.federation_catalog.FederationCatalog`:

- Env override wins over Court.
- Court 200 + valid URL caches a positive entry.
- Court 404 caches a negative entry.
- Transport errors do NOT cache (next call retries).
- Malformed Court responses are treated as miss + non-definitive.
- ``invalidate`` drops cached entries.
- Empty target_org / missing Court base URL short-circuit to None.
"""
from __future__ import annotations

import httpx
import pytest

from mcp_proxy.policy.federation_catalog import FederationCatalog


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def _client_factory(transport):
    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)
    return _Client


# ── env override ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_env_override_wins_over_court(monkeypatch):
    """When env map has an entry for the target org, the catalog uses
    it directly and never opens an HTTP client at all."""
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        return httpx.Response(200, json={"org_id": "x", "mastio_url": "https://from-court"})

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(
        court_base_url="https://court.local",
        env_map={"acme": "https://env-override.local/v1/policy/tool-call"},
    )
    url = await cat.resolve("acme")
    assert url == "https://env-override.local/v1/policy/tool-call"
    assert hits["n"] == 0


@pytest.mark.asyncio
async def test_no_court_no_env_returns_none():
    """No env entry and no Court uplink configured -> None."""
    cat = FederationCatalog(court_base_url=None, env_map={})
    assert await cat.resolve("acme") is None


@pytest.mark.asyncio
async def test_empty_target_org_returns_none():
    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("") is None


# ── positive Court lookup + caching ──────────────────────────────────


@pytest.mark.asyncio
async def test_court_200_caches_positive(monkeypatch):
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        assert req.url.path == "/v1/federation/orgs/acme/mastio-url"
        return httpx.Response(
            200, json={"org_id": "acme", "mastio_url": "https://acme.example/"},
        )

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local/", env_map={})
    assert await cat.resolve("acme") == "https://acme.example"  # trailing / stripped
    assert hits["n"] == 1
    # Second call hits cache, no HTTP.
    assert await cat.resolve("acme") == "https://acme.example"
    assert hits["n"] == 1


# ── negative Court lookup + caching ──────────────────────────────────


@pytest.mark.asyncio
async def test_court_404_caches_negative(monkeypatch):
    """A 404 from Court means the org has not published a URL. The
    catalog caches the miss so we do not flood Court for the whole TTL."""
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        return httpx.Response(404, json={"detail": "no mastio_url"})

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("ghost") is None
    assert hits["n"] == 1
    assert await cat.resolve("ghost") is None
    assert hits["n"] == 1


# ── transport errors do NOT cache ────────────────────────────────────


@pytest.mark.asyncio
async def test_transport_error_does_not_cache(monkeypatch):
    """Flaky Court must not lock out cross-org calls for the TTL.
    Each call retries until Court is back."""
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        raise httpx.ConnectError("simulated", request=req)

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") is None
    assert hits["n"] == 1
    assert await cat.resolve("acme") is None
    assert hits["n"] == 2


@pytest.mark.asyncio
async def test_court_500_does_not_cache(monkeypatch):
    """Non-200/404 (e.g. 500, 502) is treated as transient and retried."""
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        return httpx.Response(500, json={"detail": "internal"})

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") is None
    assert hits["n"] == 1
    assert await cat.resolve("acme") is None
    assert hits["n"] == 2


# ── malformed responses ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_non_json_body_returns_none(monkeypatch):
    def _handler(req):
        return httpx.Response(200, content=b"not-json")

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") is None


@pytest.mark.asyncio
async def test_non_http_url_rejected(monkeypatch):
    """If Court somehow returns ``javascript:...`` or another bogus
    protocol, the catalog refuses to surface it — defense in depth on
    top of the admin PATCH validator."""
    def _handler(req):
        return httpx.Response(
            200, json={"org_id": "acme", "mastio_url": "javascript:alert(1)"},
        )

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") is None


@pytest.mark.asyncio
async def test_missing_mastio_url_field_returns_none(monkeypatch):
    def _handler(req):
        return httpx.Response(200, json={"org_id": "acme"})

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") is None


# ── invalidate ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invalidate_specific_entry(monkeypatch):
    hits = {"n": 0}
    payloads = [
        {"org_id": "acme", "mastio_url": "https://first.example"},
        {"org_id": "acme", "mastio_url": "https://second.example"},
    ]

    def _handler(req):
        n = hits["n"]
        hits["n"] += 1
        return httpx.Response(200, json=payloads[min(n, len(payloads) - 1)])

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    assert await cat.resolve("acme") == "https://first.example"
    assert hits["n"] == 1
    cat.invalidate("acme")
    assert await cat.resolve("acme") == "https://second.example"
    assert hits["n"] == 2


@pytest.mark.asyncio
async def test_invalidate_all(monkeypatch):
    hits = {"n": 0}

    def _handler(req):
        hits["n"] += 1
        return httpx.Response(
            200, json={"org_id": "x", "mastio_url": "https://x.example"},
        )

    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient",
        _client_factory(_mock_transport(_handler)),
    )

    cat = FederationCatalog(court_base_url="https://court.local", env_map={})
    await cat.resolve("a")
    await cat.resolve("b")
    assert hits["n"] == 2
    cat.invalidate()
    await cat.resolve("a")
    await cat.resolve("b")
    assert hits["n"] == 4
