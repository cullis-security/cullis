"""ADR-012 Phase 2 — proxy-native ``POST /v1/auth/token`` integration tests.

When the feature flag is on the Mastio must:
  * issue Bearer tokens signed by its own leaf key,
  * reject assertions that don't chain to the pinned Org CA,
  * never forward the login to the Court (the core ADR-012 promise).

The last property is verified by pointing the proxy at an unreachable
broker URL and asserting a successful 200 — a response at all proves
the reverse-proxy catch-all never ran, because that forwarder's httpx
client would have faulted on the dead address.
"""
from __future__ import annotations

import base64
import datetime
import importlib
import uuid

import jwt as jose_jwt
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient


def _gen_ca() -> tuple[bytes, str, str]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    return ca_key, key_pem, cert_pem


def _issue_leaf(ca_key, ca_cert_pem: str, agent_id: str) -> tuple[str, str, list[str]]:
    """Mint a leaf cert for ``agent_id`` signed by ``ca_key``. Returns
    ``(leaf_key_pem, leaf_cert_pem, x5c_der_b64)``.
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject).issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    x5c = [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]
    return key_pem, cert_pem, x5c


def _build_assertion(
    agent_id: str,
    leaf_key_pem: str,
    x5c: list[str],
    *,
    exp_seconds: int = 300,
    audience: str = "agent-trust-broker",
) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=exp_seconds)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jose_jwt.encode(
        payload, leaf_key_pem, algorithm="RS256", headers={"x5c": x5c}
    )


@pytest_asyncio.fixture
async def flag_on_proxy(tmp_path, monkeypatch):
    """Proxy app booted with ``MCP_PROXY_LOCAL_AUTH_ENABLED=1``.

    The fixture also installs the Org CA and forces the Mastio identity
    to bootstrap so ``app.state.local_issuer`` is live by the time the
    test runs.
    """
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    # Dead-address broker: if the reverse-proxy fallback runs for any
    # reason, the httpx call here will raise — the test will see that.
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.invalid")
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    async with app.router.lifespan_context(app):
        # Seed Org CA so ensure_mastio_identity() has what it needs, then
        # rebuild the LocalIssuer (lifespan ran before the CA was present).
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
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield {"app": app, "client": client, "ca_key": ca_key, "ca_cert_pem": ca_cert_pem}

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_local_token_issued_from_valid_assertion(flag_on_proxy):
    """Happy path — valid x5c chains to Org CA, Mastio signs a Bearer."""
    ctx = flag_on_proxy
    client = ctx["client"]
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)

    resp = await client.post("/v1/auth/token", json={"client_assertion": assertion})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "local"
    assert body["expires_in"] > 0
    assert body["issued_by"] == "cullis-mastio:acme"

    issuer = ctx["app"].state.local_issuer
    pub_pem = issuer.active_key.pubkey_pem
    claims = jose_jwt.decode(
        body["access_token"],
        pub_pem,
        algorithms=["ES256"],
        audience="cullis-local",
        issuer="cullis-mastio:acme",
    )
    assert claims["sub"] == "acme::alice"
    assert claims["scope"] == "local"


@pytest.mark.asyncio
async def test_local_token_rejects_foreign_ca(flag_on_proxy):
    """An assertion signed by a CA *not* pinned on this Mastio is 401."""
    ctx = flag_on_proxy
    other_ca_key, _, other_ca_cert_pem = _gen_ca()
    leaf_key_pem, _, x5c = _issue_leaf(other_ca_key, other_ca_cert_pem, "acme::mallory")
    assertion = _build_assertion("acme::mallory", leaf_key_pem, x5c)

    resp = await ctx["client"].post(
        "/v1/auth/token", json={"client_assertion": assertion}
    )
    assert resp.status_code == 401
    assert "chain" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_local_token_rejects_wrong_signature(flag_on_proxy):
    """Assertion signed with a key that doesn't match the cert in x5c → 401."""
    ctx = flag_on_proxy
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    stray_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    stray_pem = stray_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    now = datetime.datetime.now(datetime.timezone.utc)
    bogus = jose_jwt.encode(
        {
            "sub": "acme::alice",
            "iss": "acme::alice",
            "aud": "agent-trust-broker",
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
            "jti": uuid.uuid4().hex,
        },
        stray_pem,
        algorithm="RS256",
        headers={"x5c": x5c},
    )
    resp = await ctx["client"].post("/v1/auth/token", json={"client_assertion": bogus})
    assert resp.status_code == 401
    assert "assertion" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_local_token_rejects_expired_assertion(flag_on_proxy):
    """Expired assertion (beyond the 30s leeway) → 401."""
    ctx = flag_on_proxy
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion(
        "acme::alice", leaf_key_pem, x5c, exp_seconds=-3600,
    )
    resp = await ctx["client"].post(
        "/v1/auth/token", json={"client_assertion": assertion}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_local_token_never_hits_the_court(flag_on_proxy):
    """MCP_PROXY_BROKER_URL points to an unresolvable host; a successful
    200 here is itself proof that no forward to the Court happened.
    """
    ctx = flag_on_proxy
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)
    resp = await ctx["client"].post("/v1/auth/token", json={"client_assertion": assertion})
    assert resp.status_code == 200


@pytest_asyncio.fixture
async def flag_off_proxy(tmp_path, monkeypatch):
    """Proxy app with the flag *off*. /v1/auth/token must fall through to
    the reverse-proxy forwarder and surface an upstream error because
    broker.invalid is not resolvable.
    """
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.invalid")
    # ``standalone`` defaults to True (PR-D), and that auto-enables
    # local_auth via config.py. Pin it off explicitly so the forwarder
    # contract this test asserts still holds.
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "false")
    monkeypatch.delenv("PROXY_LOCAL_AUTH", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield {"app": app, "client": client}

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_flag_off_path_falls_through_to_reverse_proxy(flag_off_proxy):
    """When the flag is off, /v1/auth/token must hit the reverse-proxy and
    fail at DNS on the dead broker address — proves the local handler
    isn't registered.
    """
    client = flag_off_proxy["client"]
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": "irrelevant"},
    )
    # The forwarder reports upstream unavailability as 502/503/504.
    assert resp.status_code >= 500
