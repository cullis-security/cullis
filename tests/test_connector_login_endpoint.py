"""ADR-032 Layer 2 — Mastio ``POST/DELETE /v1/principals/connector-login``.

Covers the happy path of binding a user identity to an enrolled
Connector and the parallel logout / revoke path. Schema invariants
(``user_sessions`` row shape, ``local_user_principals`` SSO columns)
are checked directly against the test sqlite so a future migration
that drops a column trips a test, not a customer report.
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.models import TokenPayload


pytestmark = pytest.mark.asyncio


def _fake_agent(*, org: str = "acme", agent_id: str = "acme::connector") -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}",
        scope=[],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "connector_login.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


@pytest.fixture
def app_client(proxy_db):
    from mcp_proxy.main import app

    app.dependency_overrides[get_authenticated_agent] = lambda: _fake_agent()
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_authenticated_agent, None)


def _body(**overrides):
    base = {
        "user_subject_sso": "alice@acme.com",
        "display_name": "Alice Smith",
        "idp_issuer": "https://idp.example.com",
        "device_cert_thumbprint": "a" * 64,
    }
    base.update(overrides)
    return base


async def test_connector_login_creates_session_and_user_row(app_client):
    resp = app_client.post("/v1/principals/connector-login", json=_body())
    assert resp.status_code == 201, resp.text
    data = resp.json()

    user_id = data["user_id"]
    # Slug is ``<base>-<8 hex hash>`` (HIGH C3 cross-IdP collision fix).
    assert user_id.startswith("acme::user::alice-")
    assert len(user_id.rsplit("-", 1)[1]) == 8
    assert isinstance(data["session_token"], str) and len(data["session_token"]) > 16
    assert data["expires_at"]

    async with get_db() as conn:
        sess = (await conn.execute(
            text("SELECT * FROM user_sessions WHERE session_id = :sid"),
            {"sid": data["session_token"]},
        )).mappings().first()
        assert sess is not None
        assert sess["principal_id"] == user_id
        assert sess["sso_subject"] == "alice@acme.com"
        assert sess["idp_issuer"] == "https://idp.example.com"
        assert sess["agent_cert_thumbprint"] == "a" * 64
        assert sess["revoked_at"] is None

        user = (await conn.execute(
            text(
                "SELECT principal_id, user_name, sso_subject, idp_issuer "
                "FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": user_id},
        )).mappings().first()
        assert user is not None
        assert user["user_name"].startswith("alice-")
        assert user["sso_subject"] == "alice@acme.com"
        assert user["idp_issuer"] == "https://idp.example.com"


async def test_connector_login_idempotent_on_same_user(app_client):
    r1 = app_client.post("/v1/principals/connector-login", json=_body())
    r2 = app_client.post("/v1/principals/connector-login", json=_body())
    assert r1.status_code == 201
    assert r2.status_code == 201
    # Each call mints a fresh session — semantically a re-login.
    assert r1.json()["session_token"] != r2.json()["session_token"]
    # Same (issuer, sub) → same principal_id (deterministic hash suffix).
    assert r1.json()["user_id"] == r2.json()["user_id"]
    # The user row stays single.
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT principal_id FROM local_user_principals "
                "WHERE principal_id = :pid"
            ),
            {"pid": r1.json()["user_id"]},
        )).all()
        assert len(rows) == 1


async def test_connector_login_slug_strips_email_domain(app_client):
    resp = app_client.post(
        "/v1/principals/connector-login",
        json=_body(user_subject_sso="Bob.Tanaka@acme.com"),
    )
    assert resp.status_code == 201
    user_id = resp.json()["user_id"]
    assert user_id.startswith("acme::user::bob.tanaka-")
    assert len(user_id.rsplit("-", 1)[1]) == 8


async def test_connector_login_cross_idp_no_collision(app_client):
    """HIGH C3 fix — same local-part, different IdPs ≠ same principal_id.

    Pre-fix the slug was just the local-part of the email, so
    ``alice@acme.com`` from the corporate IdP and ``alice@external.com``
    from a B2B partner federated into the same Mastio would collapse to
    ``acme::user::alice`` and the upsert would silently rebind. With
    the deterministic ``(issuer, subject)`` hash suffix the two land
    on distinct principal_ids and the partner cannot take over the
    corporate identity by logging in second.
    """
    r1 = app_client.post(
        "/v1/principals/connector-login",
        json=_body(
            user_subject_sso="alice@acme.com",
            idp_issuer="https://idp.corporate.example",
        ),
    )
    r2 = app_client.post(
        "/v1/principals/connector-login",
        json=_body(
            user_subject_sso="alice@external.com",
            idp_issuer="https://idp.partner.example",
        ),
    )
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["user_id"] != r2.json()["user_id"]
    # Same readable prefix, distinct suffix.
    assert r1.json()["user_id"].startswith("acme::user::alice-")
    assert r2.json()["user_id"].startswith("acme::user::alice-")


async def test_connector_login_same_idp_same_sub_is_stable(app_client):
    """Same (issuer, subject) → identical principal_id across re-logins.

    Closes the failure mode where a hash that includes timing / a
    nonce would silently shard a single user across many rows on
    every token refresh.
    """
    r1 = app_client.post("/v1/principals/connector-login", json=_body())
    r2 = app_client.post("/v1/principals/connector-login", json=_body())
    assert r1.json()["user_id"] == r2.json()["user_id"]


async def test_connector_logout_revokes_session(app_client):
    login = app_client.post("/v1/principals/connector-login", json=_body())
    token = login.json()["session_token"]

    out = app_client.delete(
        "/v1/principals/connector-login",
        headers={"X-Cullis-Session-Token": token},
    )
    assert out.status_code == 204, out.text

    async with get_db() as conn:
        sess = (await conn.execute(
            text("SELECT revoked_at FROM user_sessions WHERE session_id = :sid"),
            {"sid": token},
        )).mappings().first()
        assert sess is not None
        assert sess["revoked_at"] is not None


async def test_connector_logout_without_token_is_204_noop(app_client):
    out = app_client.delete("/v1/principals/connector-login")
    assert out.status_code == 204


# ── MEDIUM C2 — server-side device_cert_thumbprint derivation ─────────────


def _self_signed_cert_pem(*, cn: str = "test-agent") -> tuple[str, str]:
    """Mint a throwaway self-signed leaf for the X-SSL-Client-Cert path.

    Returns ``(escaped_pem, thumbprint_hex)``. ``escaped_pem`` matches
    the nginx ``$ssl_client_escaped_cert`` shape that
    ``_decode_escaped_pem`` parses back to plain PEM.
    """
    import hashlib as _hashlib
    from urllib.parse import quote as _quote
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID as _NameOID

    key = _ec.generate_private_key(_ec.SECP256R1())
    name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, cn)])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_dt.now(_tz.utc) - _td(minutes=5))
        .not_valid_after(_dt.now(_tz.utc) + _td(hours=1))
        .sign(key, _hashes.SHA256())
    )
    pem = cert.public_bytes(_ser.Encoding.PEM).decode("ascii")
    der = cert.public_bytes(_ser.Encoding.DER)
    thumb = _hashlib.sha256(der).hexdigest()
    return _quote(pem, safe=""), thumb


async def test_connector_login_rejects_body_thumbprint_mismatch(app_client):
    """MEDIUM C2 — when nginx forwards a verified client cert, the body
    thumbprint MUST equal the SHA-256 of that cert's DER bytes.
    Otherwise the caller could bind a session to a thumbprint they do
    not actually hold, defeating ``maybe_stamp_user_session`` pinning.
    """
    escaped, real_thumb = _self_signed_cert_pem()
    headers = {
        "X-SSL-Client-Verify": "SUCCESS",
        "X-SSL-Client-Cert": escaped,
    }
    resp = app_client.post(
        "/v1/principals/connector-login",
        json=_body(device_cert_thumbprint="b" * 64),  # ≠ real_thumb
        headers=headers,
    )
    assert resp.status_code == 400, resp.text
    assert "thumbprint" in resp.text.lower()
    # Sanity: when the body matches, the call succeeds and binds the
    # *server-derived* thumbprint in the session row.
    ok = app_client.post(
        "/v1/principals/connector-login",
        json=_body(device_cert_thumbprint=real_thumb),
        headers=headers,
    )
    assert ok.status_code == 201
    async with get_db() as conn:
        sess = (await conn.execute(
            text(
                "SELECT agent_cert_thumbprint FROM user_sessions "
                "WHERE session_id = :sid"
            ),
            {"sid": ok.json()["session_token"]},
        )).mappings().first()
    assert sess is not None
    assert sess["agent_cert_thumbprint"] == real_thumb


async def test_connector_login_no_nginx_falls_back_to_body(app_client):
    """When nginx is not in the path (dev / test without mTLS the
    headers are absent) the body thumbprint is honoured as-is.
    The 400 reject is gated on ``X-SSL-Client-Verify=SUCCESS``;
    without that signal the proxy cannot derive a server-side value
    and refusing every request would block local development.
    """
    resp = app_client.post(
        "/v1/principals/connector-login",
        json=_body(device_cert_thumbprint="c" * 64),
        # No X-SSL-Client-* headers — bare HTTP path.
    )
    assert resp.status_code == 201
