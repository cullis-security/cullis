"""Tests for ``/v1/auth/login-challenge`` + ``/v1/auth/sign-challenged-assertion``.

Device-code Connectors hold the agent private key locally; the Mastio
gives them a short-lived nonce, the client signs an assertion that
embeds it, and the Mastio verifies + counter-signs.
"""
from __future__ import annotations

import base64

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from httpx import ASGITransport, AsyncClient

from cullis_sdk.auth import build_client_assertion
from tests.cert_factory import (
    get_agent_key_pem,
    get_org_ca_pem,
    make_agent_cert,
)


ORG_ID = "challenge-test"


def _cert_pem(agent_id: str) -> str:
    _, cert = make_agent_cert(agent_id, ORG_ID)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(agent_id: str) -> str:
    return get_agent_key_pem(agent_id, ORG_ID)


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", ORG_ID)
    monkeypatch.delenv("MCP_PROXY_STANDALONE", raising=False)

    from mcp_proxy.auth.challenge_store import reset_challenge_store
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    reset_challenge_store()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            # Seed the Org CA the challenge verifier loads.
            from mcp_proxy.db import set_config
            await set_config("org_ca_cert", get_org_ca_pem(ORG_ID))
            yield app, client
    get_settings.cache_clear()
    reset_challenge_store()


async def _provision_agent(agent_id: str, *, cert_pem: str | None = None) -> str:
    """Insert an internal_agents row with the real cert + an API-key.
    Returns the raw API-key to use in X-API-Key."""
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import get_db

    raw_key = generate_api_key(agent_id)
    pem = cert_pem if cert_pem is not None else _cert_pem(agent_id)

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, cert_pem, api_key_hash, "
                " created_at, is_active) "
                "VALUES (:agent_id, :display_name, :capabilities, :cert_pem, "
                " :api_key_hash, :created_at, :is_active)"
            ),
            {
                "agent_id": agent_id,
                "display_name": agent_id,
                "capabilities": "[]",
                "cert_pem": pem,
                "api_key_hash": hash_api_key(raw_key),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": 1,
            },
        )
    return raw_key


async def _issue_challenge(client: AsyncClient, api_key: str) -> str:
    resp = await client.post(
        "/v1/auth/login-challenge",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["nonce"]


# ── login-challenge ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_challenge_issued_for_authenticated_agent(proxy_app):
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    resp = await client.post(
        "/v1/auth/login-challenge",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "alice"
    assert body["expires_in"] == 120
    # 32 random bytes → 43 base64url chars (no padding).
    assert len(body["nonce"]) == 43


@pytest.mark.asyncio
async def test_challenge_rejects_unauthenticated(proxy_app):
    _, client = proxy_app
    resp = await client.post("/v1/auth/login-challenge")
    assert resp.status_code == 401


# ── sign-challenged-assertion ────────────────────────────────────────


@pytest.mark.asyncio
async def test_happy_path_sign_challenged_assertion(proxy_app):
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    nonce = await _issue_challenge(client, api_key)
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"), nonce=nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "alice"
    assert body["client_assertion"] == assertion
    # mastio_signature may be None when the mastio identity isn't
    # loaded in the test harness — both shapes are valid responses.
    assert "mastio_signature" in body


@pytest.mark.asyncio
async def test_nonce_replay_rejected(proxy_app):
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    nonce = await _issue_challenge(client, api_key)
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"), nonce=nonce,
    )

    first = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert first.status_code == 200
    # Same nonce, same assertion → 401 on replay (nonce was consumed).
    second = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert second.status_code == 401
    assert "nonce" in second.json()["detail"].lower()


@pytest.mark.asyncio
async def test_nonce_bound_to_issuing_agent(proxy_app):
    """Nonce issued for agent A can't be redeemed by agent B's API-key.
    Defence-in-depth beyond the sub==agent check."""
    _, client = proxy_app
    api_key_a = await _provision_agent("alice")
    api_key_b = await _provision_agent("bob")

    # A issues and gets a nonce.
    nonce = await _issue_challenge(client, api_key_a)
    # B tries to redeem it (with a B-signed assertion).
    assertion, _ = build_client_assertion(
        "bob", _cert_pem("bob"), _key_pem("bob"), nonce=nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key_b},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    # B's consume() for (bob, nonce) misses because the nonce was
    # stored under (alice, nonce).
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_assertion_sub_mismatch_rejected(proxy_app):
    """A tries to redeem B's assertion using A's API-key (via A's nonce).
    Caught by the ``sub != agent_id`` check."""
    _, client = proxy_app
    api_key_a = await _provision_agent("alice")
    await _provision_agent("bob")
    nonce = await _issue_challenge(client, api_key_a)
    # Assertion signed by bob — wrong sub for the X-API-Key caller.
    assertion, _ = build_client_assertion(
        "bob", _cert_pem("bob"), _key_pem("bob"), nonce=nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key_a},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert resp.status_code == 401
    assert "sub" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_nonce_claim_tampered_rejected(proxy_app):
    """Assertion signs nonce X, request body carries nonce Y. Caught by
    the ``decoded.nonce == body.nonce`` check — enforces that the
    client signature covers the nonce actually being consumed."""
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    nonce_a = await _issue_challenge(client, api_key)
    nonce_b = await _issue_challenge(client, api_key)
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"), nonce=nonce_a,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce_b},
    )
    # nonce_b is consumed (we issued it above and the handler consumes
    # first thing); the assertion's ``nonce`` claim is nonce_a → mismatch.
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_cert_pin_mismatch_rejected(proxy_app):
    """An agent enrolled with cert X presents a valid chain-of-trust
    cert Y (same CA). Caught by the ``leaf_der != pinned_der`` check."""
    _, client = proxy_app
    # Provision alice with bob's cert pinned — simulates rotation drift
    # or an attempt to swap the cert out.
    api_key = await _provision_agent("alice", cert_pem=_cert_pem("bob"))
    nonce = await _issue_challenge(client, api_key)
    # Alice signs an assertion with her own cert (matches chain but not pin).
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"), nonce=nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert resp.status_code == 401
    assert "pinned" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_missing_nonce_in_assertion_rejected(proxy_app):
    """Assertion has no ``nonce`` claim at all → mismatch vs request body."""
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    nonce = await _issue_challenge(client, api_key)
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"),  # no nonce
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sign_rejects_unauthenticated(proxy_app):
    _, client = proxy_app
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        json={"client_assertion": "x.y.z", "nonce": "whatever"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sign_rejects_nonexistent_nonce(proxy_app):
    """No challenge was ever issued with this nonce → 401 even before
    any crypto runs."""
    _, client = proxy_app
    api_key = await _provision_agent("alice")
    # Fake nonce the store never saw.
    fake_nonce = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
    assertion, _ = build_client_assertion(
        "alice", _cert_pem("alice"), _key_pem("alice"), nonce=fake_nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": fake_nonce},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sign_rejects_chain_not_signed_by_org_ca(proxy_app):
    """Assertion signed with a valid-looking cert from a different
    Org CA. The x5c chain fails ``_verify_chain`` against this Mastio's
    pinned Org CA."""
    _, client = proxy_app
    # Provision alice with a cert from ORG_ID's CA (correct).
    api_key = await _provision_agent("alice")
    nonce = await _issue_challenge(client, api_key)
    # Build assertion with a cert from a DIFFERENT org — its CA won't
    # match the one set_config('org_ca_cert', ...) pinned in the fixture.
    other_cert = _cert_pem_from_other_org("alice")
    other_key = _key_pem_from_other_org("alice")
    assertion, _ = build_client_assertion(
        "alice", other_cert, other_key, nonce=nonce,
    )
    resp = await client.post(
        "/v1/auth/sign-challenged-assertion",
        headers={"X-API-Key": api_key},
        json={"client_assertion": assertion, "nonce": nonce},
    )
    assert resp.status_code == 401
    assert "chain" in resp.json()["detail"].lower()


def _cert_pem_from_other_org(agent_id: str) -> str:
    _, cert = make_agent_cert(agent_id, "other-org-unrelated")
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem_from_other_org(agent_id: str) -> str:
    return get_agent_key_pem(agent_id, "other-org-unrelated")


# ── store unit tests (InMemoryChallengeStore) ────────────────────────


@pytest.mark.asyncio
async def test_in_memory_store_issue_and_consume():
    from mcp_proxy.auth.challenge_store import InMemoryChallengeStore
    store = InMemoryChallengeStore()
    assert await store.issue("alice", "nonce1") is True
    assert await store.consume("alice", "nonce1") is True
    # Second consume is a miss.
    assert await store.consume("alice", "nonce1") is False


@pytest.mark.asyncio
async def test_in_memory_store_collision_refused():
    from mcp_proxy.auth.challenge_store import InMemoryChallengeStore
    store = InMemoryChallengeStore()
    assert await store.issue("alice", "nonce1") is True
    # Same (agent_id, nonce) pair — issue refuses so caller regenerates.
    assert await store.issue("alice", "nonce1") is False


@pytest.mark.asyncio
async def test_in_memory_store_cross_agent_isolation():
    from mcp_proxy.auth.challenge_store import InMemoryChallengeStore
    store = InMemoryChallengeStore()
    await store.issue("alice", "n")
    # Bob tries to consume a nonce issued for alice — different key, miss.
    assert await store.consume("bob", "n") is False
    # Alice can still consume.
    assert await store.consume("alice", "n") is True
