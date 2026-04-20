"""ADR-012 Phase 4 — local-first ingress auth adapter.

Covers the happy path the sandbox demo needs: when the feature flag is
on and an agent presents a Bearer LOCAL_TOKEN, the MCP ingress handler
serves the request without DPoP and without contacting the Court.

Also pins the two invariants the dual dep must hold:
  * flag off → legacy DPoP path unchanged (Bearer ignored, DPoP required),
  * flag on + bad Bearer → 401 with a local-auth-specific message
    (we don't silently fall through to DPoP because that leaks a
    misleading error back to the client that opted into local auth).
"""
from __future__ import annotations

import importlib

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.local_issuer import LocalIssuer
from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.models import TokenPayload


@pytest_asyncio.fixture
async def app_with_flag_on(tmp_path, monkeypatch):
    """Minimal FastAPI app with the local-first dep wired + a live DB
    containing one active agent. We don't boot the full proxy app here
    — the dep is what we're testing, and isolating it keeps the test
    fast and deterministic.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    # Reload db module so its engine picks up the new URL.
    import mcp_proxy.db as db_mod
    importlib.reload(db_mod)
    await db_mod.init_db(f"sqlite+aiosqlite:///{db_file}")

    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    raw = generate_api_key("orga::alice")
    await db_mod.create_agent(
        agent_id="orga::alice",
        display_name="alice",
        capabilities=["order.read", "order.write"],
        api_key_hash=hash_api_key(raw),
    )

    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    issuer = LocalIssuer(org_id="orga", leaf_key=key, leaf_pubkey_pem=pub_pem)

    app = FastAPI()
    app.state.local_issuer = issuer

    @app.get("/probe")
    async def probe(agent: TokenPayload = pytest.importorskip("fastapi").Depends(get_authenticated_agent)):  # type: ignore[valid-type]
        return {"agent_id": agent.agent_id, "org": agent.org, "caps": agent.scope}

    yield {"app": app, "issuer": issuer}

    get_settings.cache_clear()
    await db_mod.dispose_db()


@pytest.mark.asyncio
async def test_local_token_happy_path_returns_agent_with_capabilities(app_with_flag_on):
    """Bearer LOCAL_TOKEN → 200 with agent_id + org + capabilities from DB."""
    issuer = app_with_flag_on["issuer"]
    token = issuer.issue("orga::alice", ttl_seconds=60).token

    with TestClient(app_with_flag_on["app"]) as client:
        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == "orga::alice"
    assert body["org"] == "orga"
    assert sorted(body["caps"]) == ["order.read", "order.write"]


@pytest.mark.asyncio
async def test_unknown_agent_is_rejected(app_with_flag_on):
    """LOCAL_TOKEN for an agent not registered in the DB → 401."""
    issuer = app_with_flag_on["issuer"]
    token = issuer.issue("orga::ghost", ttl_seconds=60).token

    with TestClient(app_with_flag_on["app"]) as client:
        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "not registered" in resp.json()["detail"].lower() or "deactivated" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_non_local_kid_falls_through_to_dpop(app_with_flag_on):
    """Flag on + token whose kid does NOT match the LocalIssuer → the
    local branch must step aside so the DPoP path can decide. This is
    how broker-issued JWTs keep working alongside local tokens and how
    a malformed bearer never short-circuits the canonical auth flow.
    """
    with TestClient(app_with_flag_on["app"]) as client:
        resp = client.get("/probe", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401
    # Fall-through to DPoP → challenge mentions DPoP realm.
    assert "dpop" in resp.headers.get("WWW-Authenticate", "").lower()


@pytest.mark.asyncio
async def test_tampered_local_token_is_rejected(app_with_flag_on):
    """Kid matches but signature / claims invalid → 401 "local token: …".
    This catches tamper attempts that stripped and resigned a genuine
    header without the matching key.
    """
    import jwt as jose_jwt
    issuer = app_with_flag_on["issuer"]
    # Forge a header that mimics the LocalIssuer's kid so we go past the
    # pre-filter, but sign with an HMAC key so the signature check fails.
    tampered = jose_jwt.encode(
        {"sub": "orga::alice"},
        "not-the-mastio-key",
        algorithm="HS256",
        headers={"kid": issuer.kid},
    )
    with TestClient(app_with_flag_on["app"]) as client:
        resp = client.get("/probe", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401
    assert "local token" in resp.json()["detail"].lower()


@pytest_asyncio.fixture
async def app_with_flag_off(tmp_path, monkeypatch):
    """Flag-off variant: no local_issuer on state, MCP_PROXY_LOCAL_AUTH_ENABLED unset.
    A Bearer token should be ignored and the dep should fall through to
    the DPoP path (which, with no DPoP header, returns 401 DPoP-realm).
    """
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("MCP_PROXY_LOCAL_AUTH_ENABLED", raising=False)
    monkeypatch.delenv("PROXY_LOCAL_AUTH", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.db as db_mod
    importlib.reload(db_mod)
    await db_mod.init_db(f"sqlite+aiosqlite:///{db_file}")

    app = FastAPI()
    app.state.local_issuer = None

    @app.get("/probe")
    async def probe(agent: TokenPayload = pytest.importorskip("fastapi").Depends(get_authenticated_agent)):  # type: ignore[valid-type]
        return {"agent_id": agent.agent_id}

    yield app

    get_settings.cache_clear()
    await db_mod.dispose_db()


@pytest.mark.asyncio
async def test_flag_off_falls_through_to_dpop(app_with_flag_off):
    """Bearer presented, flag off → dep falls through to DPoP which
    requires an ``Authorization: DPoP …`` scheme, surfacing a DPoP 401.
    """
    with TestClient(app_with_flag_off) as client:
        resp = client.get("/probe", headers={"Authorization": "Bearer whatever"})
    assert resp.status_code == 401
    # WWW-Authenticate should be DPoP (realm), not Bearer — proves fall-through.
    assert "dpop" in resp.headers.get("WWW-Authenticate", "").lower()
