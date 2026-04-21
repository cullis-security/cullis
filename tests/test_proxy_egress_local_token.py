"""ADR-012 Phase 5 — egress auth accepts LOCAL_TOKEN.

The egress dep ``get_agent_from_dpop_api_key`` historically required
``X-API-Key`` + DPoP. With the flag on, it must short-circuit on a
Bearer LOCAL_TOKEN and return an ``InternalAgent`` synthesized from
the DB record keyed by the token's ``sub`` claim. Handlers downstream
(``egress/router``, ``egress/oneshot``) are unchanged — they still
receive an ``InternalAgent``.

The opposite path (flag off or missing Bearer) must stay bit-identical
to the legacy DPoP/API-key flow so today's egress callers don't break
on this change.
"""
from __future__ import annotations

import importlib

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.dpop_api_key import get_agent_from_dpop_api_key
from mcp_proxy.auth.local_issuer import LocalIssuer
from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey, compute_kid
from mcp_proxy.models import InternalAgent


@pytest_asyncio.fixture
async def egress_app_flag_on(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.db as db_mod
    importlib.reload(db_mod)
    await db_mod.init_db(f"sqlite+aiosqlite:///{db_file}")

    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    raw = generate_api_key("orga::sender")
    await db_mod.create_agent(
        agent_id="orga::sender",
        display_name="sender",
        capabilities=["oneshot.message"],
        api_key_hash=hash_api_key(raw),
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

    @app.get("/egress/probe")
    async def probe(agent: InternalAgent = Depends(get_agent_from_dpop_api_key)):
        return {"agent_id": agent.agent_id, "caps": agent.capabilities}

    yield {"app": app, "issuer": issuer, "api_key": raw}

    get_settings.cache_clear()
    await db_mod.dispose_db()


@pytest.mark.asyncio
async def test_egress_accepts_local_token_when_flag_on(egress_app_flag_on):
    issuer = egress_app_flag_on["issuer"]
    token = issuer.issue("orga::sender", ttl_seconds=60).token

    with TestClient(egress_app_flag_on["app"]) as client:
        resp = client.get(
            "/egress/probe",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "orga::sender"
    assert resp.json()["caps"] == ["oneshot.message"]


@pytest.mark.asyncio
async def test_egress_api_key_path_still_works_alongside(egress_app_flag_on):
    """X-API-Key must keep working even with the flag on — operators can
    mix the two during the migration window."""
    with TestClient(egress_app_flag_on["app"]) as client:
        resp = client.get(
            "/egress/probe",
            headers={"X-API-Key": egress_app_flag_on["api_key"]},
        )
    # API-key path returns the same shape.
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "orga::sender"


@pytest.mark.asyncio
async def test_egress_rejects_bearer_when_flag_off(tmp_path, monkeypatch):
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

    @app.get("/egress/probe")
    async def probe(agent: InternalAgent = Depends(get_agent_from_dpop_api_key)):
        return {"agent_id": agent.agent_id}

    try:
        with TestClient(app) as client:
            resp = client.get(
                "/egress/probe",
                headers={"Authorization": "Bearer whatever"},
            )
        # Flag off → falls through to the legacy X-API-Key path, which
        # rejects because no X-API-Key header was provided.
        assert resp.status_code == 401
    finally:
        get_settings.cache_clear()
        await db_mod.dispose_db()
