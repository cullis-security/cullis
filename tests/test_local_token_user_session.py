"""ADR-032 Layer 2 R2 — LOCAL_TOKEN auth dep stamps on_behalf_of_user.

R1 wired ``maybe_stamp_user_session`` into the Bearer-DPoP dep
(``dependencies.py``) and the cert+DPoP dep (``dpop_client_cert.py``).
The third auth-producing path — LOCAL_TOKEN with cnf.jkt + DPoP proof,
landed in ``mcp_proxy/auth/local_agent_dep.py`` — was the symmetric
gap. Without this wire-up, a Connector that bound an OIDC user
session but talked to its Mastio via LOCAL_TOKEN (the SDK's default
intra-org egress) silently dropped the user attribution on every
audit row.

These tests exercise the dep end-to-end via Starlette ``Request`` stubs
so a future refactor can't drop the call without going red.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import importlib
import time
import uuid

import jwt as jose_jwt
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request as StarletteRequest


def _gen_ca() -> tuple[rsa.RSAPrivateKey, str, str]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    return ca_key, key_pem, cert_pem


def _issue_leaf(ca_key, ca_cert_pem: str, agent_id: str):
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject).issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=30)
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    x5c = [base64.b64encode(
        leaf.public_bytes(serialization.Encoding.DER)
    ).decode()]
    return key_pem, x5c


def _build_assertion(agent_id: str, leaf_key_pem: str, x5c: list[str]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jose_jwt.encode(
        payload, leaf_key_pem, algorithm="RS256", headers={"x5c": x5c},
    )


def _make_dpop_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x = base64.urlsafe_b64encode(
        nums.x.to_bytes(32, "big"),
    ).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(
        nums.y.to_bytes(32, "big"),
    ).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return priv, jwk


def _build_dpop_proof(
    priv, jwk, method: str, url: str, *,
    access_token: str | None = None,
) -> str:
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    claims: dict = {
        "jti": uuid.uuid4().hex,
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    if access_token:
        claims["ath"] = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).rstrip(b"=").decode()
    return jose_jwt.encode(
        claims, priv_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.invalid")
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")
    monkeypatch.setenv("MCP_PROXY_DPOP_IAT_WINDOW", "120")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    async with app.router.lifespan_context(app):
        from mcp_proxy.db import set_config
        ca_key, ca_key_pem, ca_cert_pem = _gen_ca()
        await set_config("org_ca_key", ca_key_pem)
        await set_config("org_ca_cert", ca_cert_pem)

        mgr = app.state.agent_manager
        await mgr.load_org_ca(ca_key_pem, ca_cert_pem)
        await mgr.ensure_mastio_identity()
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        app.state.local_keystore = LocalKeyStore()
        app.state.local_issuer = await build_from_keystore(
            "acme", app.state.local_keystore,
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as client:
            yield {
                "app": app, "client": client,
                "ca_key": ca_key, "ca_cert_pem": ca_cert_pem,
            }

    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def clear_user_contextvar():
    from mcp_proxy.auth.user_context import (
        reset_on_behalf_of_user,
        set_on_behalf_of_user,
    )
    tok = set_on_behalf_of_user(None)
    yield
    reset_on_behalf_of_user(tok)


async def _mint_bound_token(ctx, agent_id: str):
    leaf_key_pem, x5c = _issue_leaf(
        ctx["ca_key"], ctx["ca_cert_pem"], agent_id,
    )
    assertion = _build_assertion(agent_id, leaf_key_pem, x5c)
    priv, jwk = _make_dpop_keypair()
    proof = _build_dpop_proof(
        priv, jwk, "POST", "http://test/v1/auth/token",
    )
    resp = await ctx["client"].post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"], priv, jwk


@pytest.mark.asyncio
async def test_local_token_with_session_headers_stamps_user_contextvar(
    proxy_app,
):
    """The headline R2 fix. A Connector that holds an OIDC user session
    plus a LOCAL_TOKEN sends both on the request; the dep verifies the
    LOCAL_TOKEN + DPoP, then stamps the user contextvar so downstream
    audit rows record the on_behalf_of_user_id."""
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token
    from mcp_proxy.auth.user_context import current_on_behalf_of_user
    from mcp_proxy.db import create_user_session

    ctx = proxy_app
    # Use a typed-principal agent_id so ``_maybe_local_token`` follows
    # the typed-principal branch (skips ``internal_agents`` lookup); the
    # session-stamping helper runs from the shared
    # ``_enforce_local_token_dpop_binding`` step, which both branches
    # reach. Regular ``acme::connector`` agents would otherwise need
    # an extra DB seed for the registry.
    agent_id = "acme::user::alice-deadbeef"
    token, priv, jwk = await _mint_bound_token(ctx, agent_id)

    principal_id = "acme::user::alice-deadbeef"
    session_token = "sess-r2-local-token-happy"
    await create_user_session(
        session_id=session_token,
        principal_id=principal_id,
        agent_cert_thumbprint="a" * 64,
        sso_subject="alice@acme.com",
        idp_issuer="https://idp.example.com",
        display_name="Alice",
        expires_at=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=1),
    )

    proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/proxy/agents/list",
        access_token=token,
    )
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", proof.encode()),
            (b"x-cullis-session-token", session_token.encode()),
            (b"x-cullis-on-behalf-of-user", principal_id.encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)

    payload = await _maybe_local_token(req)
    assert payload is not None
    assert payload.agent_id == agent_id
    assert current_on_behalf_of_user() == principal_id


@pytest.mark.asyncio
async def test_local_token_without_session_headers_leaves_contextvar_unset(
    proxy_app,
):
    """No session headers → request is anonymous-agent (the LOCAL_TOKEN
    still authenticates the agent, contextvar stays None). Mirrors the
    behaviour for cert+DPoP / Bearer-DPoP requests without the headers
    so audit rows continue to record agent-only attribution."""
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token
    from mcp_proxy.auth.user_context import current_on_behalf_of_user

    ctx = proxy_app
    agent_id = "acme::user::alice-deadbeef"
    token, priv, jwk = await _mint_bound_token(ctx, agent_id)

    proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/proxy/agents/list",
        access_token=token,
    )
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", proof.encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    payload = await _maybe_local_token(req)

    assert payload is not None
    assert payload.agent_id == agent_id
    assert current_on_behalf_of_user() is None


@pytest.mark.asyncio
async def test_local_token_with_unknown_session_token_leaves_contextvar_unset(
    proxy_app,
):
    """Session header refers to an unknown / revoked / expired row.
    The dep does NOT 401 the request (graceful by design — agent identity
    is the primary credential). The contextvar is left at None so audit
    rows fall back to agent-only attribution and a WARN is emitted."""
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token
    from mcp_proxy.auth.user_context import current_on_behalf_of_user

    ctx = proxy_app
    agent_id = "acme::user::alice-deadbeef"
    token, priv, jwk = await _mint_bound_token(ctx, agent_id)

    proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/proxy/agents/list",
        access_token=token,
    )
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", proof.encode()),
            (b"x-cullis-session-token", b"sess-does-not-exist"),
            (b"x-cullis-on-behalf-of-user", b"acme::user::nobody"),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    payload = await _maybe_local_token(req)

    assert payload is not None
    assert payload.agent_id == agent_id
    assert current_on_behalf_of_user() is None
