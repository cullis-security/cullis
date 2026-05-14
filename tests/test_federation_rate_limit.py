"""Rate-limit regression for the Court federation surfaces.

security-review-app-2026-05-14.md F-002 — federation endpoints
(``publish-agent``, ``publish-stats``, ``audit/replicate``, ``agents``,
``agents/search``, ``orgs/{id}/mastio-url``) are reachable from any
internet peer. Without rate limiting, an attacker who guesses an
``org_id`` can stage countersig-failing calls in a tight loop to burn
ECDSA-verify CPU and flood the per-org audit chain with
``federation.*_rejected`` rows; the unauthenticated ``mastio-url``
discovery can be polled with zero auth at all.

The fix wires the same per-IP bucket pattern that
``onboarding.rotate_mastio_pubkey`` uses (issue #282) onto every
federation surface. This file exercises the buckets to prove they
trip before the heavyweight verify / audit-write paths.

The tests monkeypatch ``get_client_ip`` (the per-module symbol that
each handler imports) because httpx + ASGI does not flow X-Forwarded-
For through uvicorn's ProxyHeadersMiddleware — same pattern as
``test_broker_mastio_pubkey_rotate_rate_limit.py``.
"""
from __future__ import annotations

import json

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def _reset_rate_limit_between_tests():
    """Clear the in-memory rate limiter window before each test so
    shared state from prior tests does not poison the budget under
    test (same shape as the rotate-pubkey rate-limit suite).
    """
    from app.rate_limit.limiter import rate_limiter
    try:
        rate_limiter._windows.clear()
    except AttributeError:
        pass
    yield
    try:
        rate_limiter._windows.clear()
    except AttributeError:
        pass


# ── federation.publish bucket (publish-agent) ────────────────────────


async def test_publish_agent_rate_limit_blocks_burst(
    client: AsyncClient, monkeypatch,
):
    """Burst past the per-IP ``federation.publish`` budget must trip
    the limiter before any ECDSA verify / audit-write runs.

    The body is intentionally minimal and the org is unknown, so the
    handler would otherwise reach ``log_event("publish_rejected",
    ...)`` on every call. With the rate-limit gate, the budget-th+1
    request is rejected with 429 before it can pollute the chain.
    """
    from app.federation import publish as publish_mod
    monkeypatch.setattr(
        publish_mod, "get_client_ip", lambda req: "203.0.113.10",
    )

    # Bucket is registered at 30/min/IP. Drive the budget to the
    # ceiling with malformed-but-shape-valid requests, then assert
    # the next request is 429.
    body = {
        "agent_id": "unknown-org::ghost",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        "capabilities": [],
        "display_name": "ghost",
    }
    raw = json.dumps(body).encode()
    saw_429 = False
    for i in range(40):
        r = await client.post(
            "/v1/federation/publish-agent",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Cullis-Mastio-Signature": "AA",
            },
        )
        if r.status_code == 429:
            saw_429 = True
            assert i >= 30, (
                f"limiter tripped too early at call #{i+1} — expected "
                f"after 30 calls/min, bucket may be misconfigured"
            )
            break
    assert saw_429, (
        "burst of 40 publish-agent calls from one IP never tripped "
        "the federation.publish bucket — F-002 regression"
    )


async def test_publish_agent_rate_limit_is_per_ip(
    client: AsyncClient, monkeypatch,
):
    """A second IP must NOT be penalised when the first IP has
    consumed its budget. Proves the bucket is keyed on client IP, not
    a global counter.
    """
    from app.federation import publish as publish_mod
    body = {
        "agent_id": "unknown-org::ghost",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        "capabilities": [],
        "display_name": "ghost",
    }
    raw = json.dumps(body).encode()

    # IP A — drain bucket past the ceiling.
    monkeypatch.setattr(
        publish_mod, "get_client_ip", lambda req: "203.0.113.20",
    )
    for _ in range(35):
        await client.post(
            "/v1/federation/publish-agent",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Cullis-Mastio-Signature": "AA",
            },
        )

    # IP B — fresh bucket, must NOT see 429.
    monkeypatch.setattr(
        publish_mod, "get_client_ip", lambda req: "203.0.113.21",
    )
    r = await client.post(
        "/v1/federation/publish-agent",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": "AA",
        },
    )
    assert r.status_code != 429, (
        f"second IP saw a 429 — federation.publish bucket appears to "
        f"be a global counter, not per-IP. Body: {r.text}"
    )


# ── federation.audit_replicate bucket ────────────────────────────────


async def test_audit_replicate_rate_limit_blocks_burst(
    client: AsyncClient, monkeypatch,
):
    """``audit/replicate`` accepts up to 1000 entries per batch, with
    each rejected batch appending a ``federation.audit_replicate_rejected``
    row to the per-org chain. The bucket caps unauthenticated bursts
    well before the chain-write contention shows up.
    """
    from app.federation import audit_replicate as audit_mod
    monkeypatch.setattr(
        audit_mod, "get_client_ip", lambda req: "203.0.113.30",
    )

    body = {
        "mastio_org_id": "unknown-org",
        "entries": [
            {
                "chain_seq": 1,
                "entry_hash": "a" * 64,
                "previous_hash": None,
                "timestamp": "2026-05-14T00:00:00Z",
                "event_type": "test.event",
                "result": "ok",
            },
        ],
    }
    raw = json.dumps(body).encode()
    saw_429 = False
    for i in range(40):
        r = await client.post(
            "/v1/federation/audit/replicate",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Cullis-Mastio-Signature": "AA",
            },
        )
        if r.status_code == 429:
            saw_429 = True
            assert i >= 30, (
                f"limiter tripped too early at call #{i+1} — expected "
                f"after 30 calls/min for federation.audit_replicate"
            )
            break
    assert saw_429, (
        "burst of 40 audit/replicate calls from one IP never tripped "
        "the federation.audit_replicate bucket — F-002 regression"
    )


# ── federation.mastio_url_lookup bucket (UNAUTH discovery) ───────────


async def test_mastio_url_lookup_rate_limit_blocks_burst(
    client: AsyncClient, monkeypatch,
):
    """``GET /v1/federation/orgs/{id}/mastio-url`` is fully
    unauthenticated. Without rate-limiting an attacker can poll
    discovery in a tight loop with zero auth at all. Bucket is
    60/min/IP — burst of 80 must trip before the 80th.
    """
    from app.federation import read as read_mod
    monkeypatch.setattr(
        read_mod, "get_client_ip", lambda req: "203.0.113.40",
    )

    saw_429 = False
    for i in range(80):
        r = await client.get("/v1/federation/orgs/unknown-org/mastio-url")
        if r.status_code == 429:
            saw_429 = True
            assert i >= 60, (
                f"limiter tripped too early at call #{i+1} — expected "
                f"after 60 calls/min for federation.mastio_url_lookup"
            )
            break
    assert saw_429, (
        "burst of 80 mastio-url-lookup calls from one IP never "
        "tripped the federation.mastio_url_lookup bucket — F-002 "
        "regression"
    )
