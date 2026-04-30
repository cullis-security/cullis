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
from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey, compute_kid
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

    await db_mod.create_agent(
        agent_id="orga::alice",
        display_name="alice",
        capabilities=["order.read", "order.write"],
    )

    from datetime import datetime, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    kid = compute_kid(pub_pem)
    now = datetime.now(timezone.utc)
    await db_mod.insert_mastio_key(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem,
        created_at=now.isoformat(), activated_at=now.isoformat(),
    )
    active = MastioKey(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem, cert_pem=None,
        created_at=now, activated_at=now, deprecated_at=None, expires_at=None,
    )
    issuer = LocalIssuer(org_id="orga", active_key=active)

    app = FastAPI()
    app.state.local_issuer = issuer
    app.state.local_keystore = LocalKeyStore()

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
    app.state.local_keystore = None

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


@pytest.mark.asyncio
async def test_grace_window_deprecated_kid_is_accepted(app_with_flag_on):
    """Regression test for #279 (Phase 2.2 grace-window).

    A token minted under kid K_old must keep verifying after a rotation
    that deprecated K_old (within its grace window) and activated K_new.
    Before the fix, the dep pre-filter compared against ``issuer.kid``
    only (K_new) and dropped the K_old token into the DPoP fall-through,
    producing a 401 even though JWKS/keystore/validator all accepted it.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    import mcp_proxy.db as db_mod
    from mcp_proxy.auth.local_issuer import LocalIssuer
    from mcp_proxy.auth.local_keystore import MastioKey, compute_kid

    app = app_with_flag_on["app"]
    old_issuer = app_with_flag_on["issuer"]

    # Mint a token under the original (soon-to-be-deprecated) kid.
    old_token = old_issuer.issue("orga::alice", ttl_seconds=60).token
    old_kid = old_issuer.kid

    # Simulate a Phase 2.1 rotation: generate a new keypair, insert as
    # the new active row, and deprecate the old row with a grace window.
    new_key = ec.generate_private_key(ec.SECP256R1())
    new_priv = new_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    new_pub = new_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    new_kid = compute_kid(new_pub)
    now = datetime.now(timezone.utc)
    grace_expires = now + timedelta(days=7)

    await db_mod.swap_active_mastio_key(
        new_kid=new_kid,
        new_pubkey_pem=new_pub,
        new_privkey_pem=new_priv,
        new_cert_pem=None,
        new_activated_at=now.isoformat(),
        new_created_at=now.isoformat(),
        old_kid=old_kid,
        old_deprecated_at=now.isoformat(),
        old_expires_at=grace_expires.isoformat(),
    )

    # Point the app's LocalIssuer at the new active key, mirroring what
    # the dashboard rotation handler does post-swap.
    new_active = MastioKey(
        kid=new_kid,
        pubkey_pem=new_pub,
        privkey_pem=new_priv,
        cert_pem=None,
        created_at=now,
        activated_at=now,
        deprecated_at=None,
        expires_at=None,
    )
    app.state.local_issuer = LocalIssuer(org_id="orga", active_key=new_active)

    # The old-kid token should still authenticate — that's the whole
    # point of the Phase 2.2 grace window.
    with TestClient(app) as client:
        resp = client.get(
            "/probe", headers={"Authorization": f"Bearer {old_token}"},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "orga::alice"
    assert body["org"] == "orga"


@pytest.mark.asyncio
async def test_expired_grace_kid_is_rejected(app_with_flag_on):
    """Negative regression: once the grace window elapses, the deprecated
    kid must no longer authenticate. Proves the fix doesn't over-accept.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    import mcp_proxy.db as db_mod
    from mcp_proxy.auth.local_issuer import LocalIssuer
    from mcp_proxy.auth.local_keystore import MastioKey, compute_kid

    app = app_with_flag_on["app"]
    old_issuer = app_with_flag_on["issuer"]

    old_token = old_issuer.issue("orga::alice", ttl_seconds=3600).token
    old_kid = old_issuer.kid

    new_key = ec.generate_private_key(ec.SECP256R1())
    new_priv = new_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    new_pub = new_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    new_kid = compute_kid(new_pub)
    now = datetime.now(timezone.utc)
    # grace window already elapsed
    expired = now - timedelta(minutes=1)

    await db_mod.swap_active_mastio_key(
        new_kid=new_kid,
        new_pubkey_pem=new_pub,
        new_privkey_pem=new_priv,
        new_cert_pem=None,
        new_activated_at=now.isoformat(),
        new_created_at=now.isoformat(),
        old_kid=old_kid,
        old_deprecated_at=(now - timedelta(days=8)).isoformat(),
        old_expires_at=expired.isoformat(),
    )

    new_active = MastioKey(
        kid=new_kid,
        pubkey_pem=new_pub,
        privkey_pem=new_priv,
        cert_pem=None,
        created_at=now,
        activated_at=now,
        deprecated_at=None,
        expires_at=None,
    )
    app.state.local_issuer = LocalIssuer(org_id="orga", active_key=new_active)

    with TestClient(app) as client:
        resp = client.get(
            "/probe", headers={"Authorization": f"Bearer {old_token}"},
        )
    # Expired-grace kid is unknown-to-the-dep, so it falls through to
    # DPoP (no DPoP header present) → 401 DPoP realm.
    assert resp.status_code == 401
    assert "dpop" in resp.headers.get("WWW-Authenticate", "").lower()


# ── Audit 2026-04-30 lane 1 H2 — preserve reach on LOCAL_TOKEN egress ─


@pytest.mark.asyncio
async def test_local_token_egress_preserves_intra_reach(tmp_path, monkeypatch):
    """Audit 2026-04-30 lane 1 H2 — LOCAL_TOKEN egress dep must NOT
    drop the DB-stored ``reach`` field. Before the fix,
    ``_maybe_local_internal_agent`` built ``InternalAgent(...)`` with
    no ``reach=`` kwarg, so the model default ``"both"`` shadowed an
    intra-only agent and reach_guard.py:119 silently relaxed reach.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from datetime import datetime, timezone

    from mcp_proxy.auth.local_agent_dep import _maybe_local_internal_agent

    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.db as db_mod
    importlib.reload(db_mod)
    await db_mod.init_db(f"sqlite+aiosqlite:///{db_file}")

    # Create the agent with reach="intra" — the value that must
    # survive the LOCAL_TOKEN dep round-trip. ``create_agent`` doesn't
    # take a ``reach`` kwarg (set via dashboard later), so we patch it
    # in directly.
    await db_mod.create_agent(
        agent_id="orga::intra-only",
        display_name="intra-only",
        capabilities=[],
    )
    from sqlalchemy import text as _sql_text
    async with db_mod.get_db() as conn:
        await conn.execute(
            _sql_text("UPDATE internal_agents SET reach='intra' WHERE agent_id=:aid"),
            {"aid": "orga::intra-only"},
        )

    # Mint key + LocalIssuer.
    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    kid = compute_kid(pub_pem)
    now = datetime.now(timezone.utc)
    await db_mod.insert_mastio_key(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem,
        created_at=now.isoformat(), activated_at=now.isoformat(),
    )
    active = MastioKey(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem, cert_pem=None,
        created_at=now, activated_at=now, deprecated_at=None, expires_at=None,
    )
    issuer = LocalIssuer(org_id="orga", active_key=active)
    keystore = LocalKeyStore()

    token = issuer.issue("orga::intra-only", ttl_seconds=60).token

    # Mock minimal Request so the dep can run.
    class _State:
        pass

    class _AppState:
        local_issuer = issuer
        local_keystore = keystore

    class _App:
        state = _AppState()

    class _Headers(dict):
        def get(self, key, default=None):  # type: ignore[override]
            return super().get(key.lower(), default)

    class _Request:
        app = _App()
        headers = _Headers({"authorization": f"Bearer {token}"})
        client = None
        method = "POST"
        url = type("U", (), {"path": "/v1/egress/test"})()

    agent = await _maybe_local_internal_agent(_Request())

    assert agent is not None
    assert agent.agent_id == "orga::intra-only"
    assert agent.reach == "intra", (
        f"reach must be preserved from DB; got {agent.reach!r} "
        "(audit H2 — silent reach relaxation regressed)"
    )

    get_settings.cache_clear()
    await db_mod.dispose_db()
