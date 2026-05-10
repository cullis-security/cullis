"""Password-login + change-password endpoints — happy path + rejections.

The login endpoint mints a DPoP-bound JWT via the in-process
``LocalIssuer``. We decode the resulting JWT (re-using the keystore
the issuer signed it with) so each test pins both the HTTP contract
AND the cnf.jkt binding the SPA needs to spend the token on /csr.

Change-password is exercised with a ``dependency_overrides`` swap to
sidestep DPoP-proof construction in unit tests — the e2e DPoP path is
already covered by ``test_principals_csr.py`` and the smoke suite.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


def _b64url_uint(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(
        n.to_bytes(length, "big"),
    ).decode().rstrip("=")


def _make_dpop_jwk() -> dict:
    """Generate a P-256 keypair and serialise its public part as a JWK.

    Mirrors what the SPA will do client-side via Web Crypto. We only
    need the public JWK for ``cnf.jkt`` derivation server-side.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = priv.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_uint(pub_numbers.x, 32),
        "y": _b64url_uint(pub_numbers.y, 32),
    }


async def _spin_proxy(tmp_path, monkeypatch, org_id: str):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _create_user(cli, *, user_name: str, password: str | None):
    from mcp_proxy.config import get_settings
    h = {"X-Admin-Secret": get_settings().admin_secret}
    payload = {"user_name": user_name}
    if password is not None:
        payload["password"] = password
    r = await cli.post("/v1/admin/users", headers=h, json=payload)
    assert r.status_code == 201, r.text
    return r.json()


# ── login: 401 paths ───────────────────────────────────────────────────


async def test_login_401_when_user_missing(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-miss")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "nobody",
                    "password": "GoodEnoughPwd!",
                    "dpop_jwk": _make_dpop_jwk(),
                },
            )
            assert r.status_code == 401
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_login_401_when_sso_only(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-sso")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="ivy", password=None)
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "ivy",
                    "password": "WhateverPwd!",
                    "dpop_jwk": _make_dpop_jwk(),
                },
            )
            assert r.status_code == 401
            assert "SSO" in r.json()["detail"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_login_401_on_wrong_password(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-wrong")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="jane", password="RealPwd!2026")
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "jane",
                    "password": "WrongPwd!2026",
                    "dpop_jwk": _make_dpop_jwk(),
                },
            )
            assert r.status_code == 401
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_login_401_when_disabled(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-disabled")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.config import get_settings
            h = {"X-Admin-Secret": get_settings().admin_secret}
            await _create_user(cli, user_name="ken", password="RealPwd!2026")
            await cli.post(
                "/v1/admin/users/lg-disabled::user::ken/deactivate",
                headers=h,
            )
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "ken",
                    "password": "RealPwd!2026",
                    "dpop_jwk": _make_dpop_jwk(),
                },
            )
            assert r.status_code == 401
            assert "disabled" in r.json()["detail"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_login_400_on_bad_jwk(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-badjwk")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="leo", password="RealPwd!2026")
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "leo",
                    "password": "RealPwd!2026",
                    "dpop_jwk": {"kty": "RSA"},  # missing required members
                },
            )
            assert r.status_code == 400
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── login: happy path ─────────────────────────────────────────────────


async def test_login_ok_returns_dpop_bound_jwt(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-ok")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="mia", password="RealPwd!2026")
            jwk = _make_dpop_jwk()
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "mia",
                    "password": "RealPwd!2026",
                    "dpop_jwk": jwk,
                },
            )
            assert r.status_code == 200, r.text
            data = r.json()
            assert data["token_type"] == "DPoP"
            assert data["principal_id"] == "lg-ok::user::mia"
            assert data["must_change_password"] is True
            assert data["expires_in"] > 0

            # Decode the JWT payload (no signature check — the keystore
            # rotation API isn't needed for this assertion).
            payload_b64 = data["access_token"].split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            from mcp_proxy.auth.dpop import compute_jkt
            expected_jkt = compute_jkt(jwk)
            assert claims["cnf"]["jkt"] == expected_jkt
            assert claims["principal_type"] == "user"
            assert claims["sub"] == "lg-ok::user::mia"
            assert claims["must_change_password"] is True
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_login_must_change_false_after_admin_clears_flag(
    tmp_path, monkeypatch,
):
    """Admin-cleared flag (or post change-password) flows through to
    the login response so the SPA stops showing the change screen."""
    app = await _spin_proxy(tmp_path, monkeypatch, "lg-flag")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="nina", password="RealPwd!2026")
            from mcp_proxy.db import get_db
            from sqlalchemy import text
            async with get_db() as conn:
                await conn.execute(
                    text(
                        "UPDATE local_user_principals "
                        "   SET must_change_password = :mcp "
                        " WHERE user_name = 'nina'"
                    ),
                    {"mcp": False},
                )
            r = await cli.post(
                "/v1/principals/password-login",
                json={
                    "user_name": "nina",
                    "password": "RealPwd!2026",
                    "dpop_jwk": _make_dpop_jwk(),
                },
            )
            assert r.status_code == 200
            assert r.json()["must_change_password"] is False
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── change-password: dependency-override path ─────────────────────────


def _override_user_token(app, principal_id: str, org: str):
    from mcp_proxy.auth.dependencies import get_authenticated_agent
    from mcp_proxy.models import TokenPayload

    async def _stub() -> TokenPayload:
        return TokenPayload(
            sub=f"spiffe://cullis.test/{org}/user/{principal_id.split('::')[-1]}",
            agent_id=principal_id,
            org=org,
            exp=2_000_000_000,
            iat=1_000_000_000,
            jti="test-jti",
            scope=["local"],
            cnf={"jkt": "test-jkt"},
            principal_type="user",
        )

    app.dependency_overrides[get_authenticated_agent] = _stub


async def test_change_password_happy_path(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "cp-ok")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="omar", password="OldPwd!2026")
            pid = "cp-ok::user::omar"
            _override_user_token(app, pid, "cp-ok")
            try:
                r = await cli.post(
                    "/v1/principals/change-password",
                    json={
                        "old_password": "OldPwd!2026",
                        "new_password": "NewPwd!2026",
                    },
                )
                assert r.status_code == 200, r.text
                assert r.json()["must_change_password"] is False

                # And the new password actually works on a re-login.
                r2 = await cli.post(
                    "/v1/principals/password-login",
                    json={
                        "user_name": "omar",
                        "password": "NewPwd!2026",
                        "dpop_jwk": _make_dpop_jwk(),
                    },
                )
                assert r2.status_code == 200
                assert r2.json()["must_change_password"] is False
            finally:
                app.dependency_overrides.clear()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_change_password_rejects_wrong_old(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "cp-wrong")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="paul", password="OldPwd!2026")
            pid = "cp-wrong::user::paul"
            _override_user_token(app, pid, "cp-wrong")
            try:
                r = await cli.post(
                    "/v1/principals/change-password",
                    json={
                        "old_password": "WrongPwd!2026",
                        "new_password": "NewPwd!2026",
                    },
                )
                assert r.status_code == 401
            finally:
                app.dependency_overrides.clear()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_change_password_rejects_same_password(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "cp-same")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _create_user(cli, user_name="quinn", password="SamePwd!2026")
            pid = "cp-same::user::quinn"
            _override_user_token(app, pid, "cp-same")
            try:
                r = await cli.post(
                    "/v1/principals/change-password",
                    json={
                        "old_password": "SamePwd!2026",
                        "new_password": "SamePwd!2026",
                    },
                )
                assert r.status_code == 400
            finally:
                app.dependency_overrides.clear()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_change_password_403_for_non_user_principal(
    tmp_path, monkeypatch,
):
    """An agent / workload JWT must NOT be accepted here even if its
    cnf and DPoP all check out — the password leg is user-only."""
    app = await _spin_proxy(tmp_path, monkeypatch, "cp-agent")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.auth.dependencies import get_authenticated_agent
            from mcp_proxy.models import TokenPayload

            async def _agent_stub():
                return TokenPayload(
                    sub="spiffe://cullis.test/cp-agent/agent/bot",
                    agent_id="cp-agent::bot",
                    org="cp-agent",
                    exp=2_000_000_000, iat=1_000_000_000,
                    jti="t", scope=["local"], cnf={"jkt": "x"},
                    principal_type="agent",
                )
            app.dependency_overrides[get_authenticated_agent] = _agent_stub
            try:
                r = await cli.post(
                    "/v1/principals/change-password",
                    json={
                        "old_password": "AnyPwd!2026",
                        "new_password": "NextPwd!2026",
                    },
                )
                assert r.status_code == 403
            finally:
                app.dependency_overrides.clear()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
