"""P1.3 — X-Cullis-* incoming request header strip.

Mastio's auth deps derive trust state from the DPoP token + the
verified principal cert chain; no handler reads ``X-Cullis-*`` off
an inbound request. The middleware enforces that contract at the
request boundary so a future refactor cannot be tricked into
trusting a forged value.

These tests register a one-route FastAPI app behind the middleware
and assert that:

* Any incoming ``X-Cullis-*`` header is missing by the time the
  handler reads the request — covers the canonical attacker
  injection paths ("X-Cullis-Trust", "X-Cullis-Admin",
  "X-Cullis-Agent-Id", "X-Cullis-Org-Id", "X-Cullis-Mastio-Signature").
* Case is irrelevant: ``X-CULLIS-Foo`` and ``x-cullis-foo`` both
  drop.
* Non-cullis headers pass through untouched.
* The middleware is opt-out via configuration only — there is no
  client-supplied header that can keep an X-Cullis-* on the wire.
* The opt-in logging gate fires when env is set and is silent when
  unset, so a busy dashboard doesn't flood the log.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient


def _build_app():
    """Single-route FastAPI app behind the strip middleware.

    The handler echoes the headers the ASGI scope hands it (i.e. the
    post-strip view) as JSON so each test can assert ``X-Cullis-*``
    absence directly.
    """
    from mcp_proxy.middleware.strip_x_cullis_headers import (
        StripXCullisHeadersMiddleware,
    )

    app = FastAPI()
    app.add_middleware(StripXCullisHeadersMiddleware)

    @app.get("/echo")
    async def echo(request: Request):
        return {
            "headers": [
                [k, v] for k, v in request.headers.items()
                if k.lower() != "host"
            ],
        }

    return app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=_build_app())
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── strip on canonical attacker injection vectors ──────────────────


@pytest.mark.asyncio
async def test_strip_drops_x_cullis_trust_spoof(client):
    """The flagship attack: client sets X-Cullis-Trust to spoof a
    trust state. Handler must not see it."""
    resp = await client.get(
        "/echo",
        headers={"X-Cullis-Trust": "spoofed-admin"},
    )
    assert resp.status_code == 200
    seen = {k.lower() for k, _ in resp.json()["headers"]}
    assert "x-cullis-trust" not in seen


@pytest.mark.asyncio
async def test_strip_drops_every_x_cullis_variant(client):
    """Cover the names a real attacker would reach for first."""
    resp = await client.get(
        "/echo",
        headers={
            "X-Cullis-Admin": "true",
            "X-Cullis-Agent-Id": "spoofed::agent::root",
            "X-Cullis-Org-Id": "victim-org",
            "X-Cullis-Mastio-Signature": "deadbeef",
            "X-Cullis-Trace": "phantom-trace",
        },
    )
    seen = {k.lower() for k, _ in resp.json()["headers"]}
    assert not any(name.startswith("x-cullis-") for name in seen), seen


@pytest.mark.asyncio
async def test_strip_is_case_insensitive(client):
    """RFC 9110 §5.1: header names are case-insensitive. The strip
    must follow."""
    resp = await client.get(
        "/echo",
        headers={
            "x-cullis-lowered": "1",
            "X-CULLIS-UPPERED": "2",
            "X-Cullis-Mixed": "3",
        },
    )
    seen = {k.lower() for k, _ in resp.json()["headers"]}
    assert not any(name.startswith("x-cullis-") for name in seen), seen


@pytest.mark.asyncio
async def test_non_cullis_headers_pass_through(client):
    """Headers outside the X-Cullis-* family must reach the handler
    unchanged — strip is targeted, not a denylist sweep."""
    resp = await client.get(
        "/echo",
        headers={
            "Authorization": "Bearer abc",
            "DPoP": "proof.proof.proof",
            "X-Request-Id": "req-1",
            "User-Agent": "cullis-sdk-test/0.1",
        },
    )
    headers = {k.lower(): v for k, v in resp.json()["headers"]}
    assert headers["authorization"] == "Bearer abc"
    assert headers["dpop"] == "proof.proof.proof"
    assert headers["x-request-id"] == "req-1"


# ── opt-in audit log ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_log_silent_by_default(monkeypatch):
    """Default config: silent. A noisy client must not flood the log
    with one entry per request.

    Verified by monkey-patching the module-level ``_log`` so we
    capture the calls directly. ``caplog`` is unreliable here because
    the production logger setup runs with ``propagate=False`` and
    uvicorn rewires its handlers, dropping caplog hooks mid-run on CI
    (see memory ``mastio_logger_silently_muted_in_lifespan``).
    """
    monkeypatch.delenv("CULLIS_LOG_STRIPPED_HEADERS", raising=False)
    from mcp_proxy.middleware import strip_x_cullis_headers as mod

    captured: list[tuple[str, tuple]] = []

    class _FakeLog:
        def info(self, msg, *args):
            captured.append((msg, args))

    monkeypatch.setattr(mod, "_log", _FakeLog())

    app = _build_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        await ac.get("/echo", headers={"X-Cullis-Trust": "x"})

    rendered = [(msg % args) if args else msg for msg, args in captured]
    assert not any(
        "stripped" in line and "x-cullis" in line.lower()
        for line in rendered
    )


@pytest.mark.asyncio
async def test_log_fires_under_opt_in(monkeypatch):
    """``CULLIS_LOG_STRIPPED_HEADERS=1`` → INFO record per stripped
    request, with the stripped names visible for forensic correlation.

    Same module-level monkey-patch pattern as the silent test —
    pytest's ``caplog`` fixture misses records when ``propagate=False``
    + uvicorn's logging reinit drop them mid-test on CI runners.
    """
    monkeypatch.setenv("CULLIS_LOG_STRIPPED_HEADERS", "1")
    from mcp_proxy.middleware import strip_x_cullis_headers as mod

    captured: list[tuple[str, tuple]] = []

    class _FakeLog:
        def info(self, msg, *args):
            captured.append((msg, args))

    monkeypatch.setattr(mod, "_log", _FakeLog())

    # Snapshot env at construction (see middleware docstring); rebuild
    # the app after setenv.
    app = _build_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        await ac.get("/echo", headers={"X-Cullis-Trust": "x"})

    rendered = [(msg % args) if args else msg for msg, args in captured]
    # ASGI normalises header names to lower-case on the wire, so the
    # log message records the lower form regardless of how the client
    # spelled it. The forensic correlation point is the header family
    # ("x-cullis-trust"), not the exact casing.
    assert any(
        "stripped" in line and "x-cullis-trust" in line.lower()
        for line in rendered
    ), rendered


# ── pass-through when no X-Cullis-* present ────────────────────────


@pytest.mark.asyncio
async def test_no_x_cullis_no_changes(client):
    """A request with zero X-Cullis-* headers must traverse the
    middleware without scope copy or log event."""
    resp = await client.get(
        "/echo",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    headers = {k.lower() for k, _ in resp.json()["headers"]}
    assert "accept" in headers
