"""ADR-012 Phase 3 / Phase 2.0 — LocalValidator unit tests.

Paired with ``tests/test_proxy_local_issuer.py``: that file pins what
the issuer emits, this one pins what the validator accepts. Round-trip
coverage is the main invariant — a token produced by ``LocalIssuer``
must always decode to a ``LocalTokenPayload`` whose fields match.

Everything that deviates from the expected wire format (wrong audience,
wrong kid, missing claims, expired, signed by a stranger, malformed
header) must raise ``LocalTokenError`` — so the FastAPI dependency can
turn it into a uniform 401 without leaking internals.

Phase 2.0: the validator is now keystore-driven, so tests use a real
proxy SQLite fixture with the ``mastio_keys`` migration applied and
insert rows via ``insert_mastio_key`` rather than handing a leaf key
to an in-memory issuer.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import jwt as jose_jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.local_issuer import LocalIssuer
from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey, compute_kid
from mcp_proxy.auth.local_validator import (
    LocalTokenError,
    LocalTokenPayload,
    require_local_token,
    validate_local_token,
)
from mcp_proxy.db import insert_mastio_key


def _fresh_pair() -> tuple[ec.EllipticCurvePrivateKey, str, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, priv_pem, pub_pem


async def _install_active_issuer(org_id: str = "orga") -> tuple[LocalIssuer, str]:
    """Insert a fresh active key into the DB and return an issuer for it.

    Returns ``(issuer, priv_pem)`` so tests that hand-craft tokens can
    sign with the right private key without re-deriving it.
    """
    _, priv_pem, pub_pem = _fresh_pair()
    kid = compute_kid(pub_pem)
    now = datetime.now(timezone.utc)
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem,
        created_at=now.isoformat(), activated_at=now.isoformat(),
    )
    active = MastioKey(
        kid=kid, pubkey_pem=pub_pem, privkey_pem=priv_pem, cert_pem=None,
        created_at=now, activated_at=now, deprecated_at=None, expires_at=None,
    )
    return LocalIssuer(org_id=org_id, active_key=active), priv_pem


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_validate_roundtrip_issuer_to_validator(proxy_db):
    issuer, _ = await _install_active_issuer("orga")
    token = issuer.issue(
        "orga::alice", ttl_seconds=60, extra_claims={"tenant": "t-1"},
    )

    keystore = LocalKeyStore()
    payload = await validate_local_token(
        token.token, keystore, expected_issuer=issuer.issuer,
    )
    assert isinstance(payload, LocalTokenPayload)
    assert payload.agent_id == "orga::alice"
    assert payload.issuer == "cullis-mastio:orga"
    assert payload.org_id == "orga"
    assert payload.scope == "local"
    assert payload.expires_at == token.expires_at
    assert payload.issued_at == token.issued_at
    assert payload.jti
    assert payload.extra == {"tenant": "t-1"}


@pytest.mark.asyncio
async def test_rejects_token_signed_by_foreign_key(proxy_db):
    issuer_a, _ = await _install_active_issuer("orga")
    # A second issuer whose kid is NOT registered in the keystore — the
    # forgery should be caught at the kid-lookup step, not the signature
    # check.
    _, priv_pem_b, pub_pem_b = _fresh_pair()
    now = datetime.now(timezone.utc)
    foreign = MastioKey(
        kid=compute_kid(pub_pem_b), pubkey_pem=pub_pem_b, privkey_pem=priv_pem_b,
        cert_pem=None, created_at=now, activated_at=now,
        deprecated_at=None, expires_at=None,
    )
    issuer_b = LocalIssuer(org_id="orga", active_key=foreign)
    foreign_token = issuer_b.issue("orga::alice").token

    keystore = LocalKeyStore()
    with pytest.raises(LocalTokenError) as err:
        await validate_local_token(
            foreign_token, keystore, expected_issuer=issuer_a.issuer,
        )
    assert "kid" in str(err.value).lower()


@pytest.mark.asyncio
async def test_rejects_expired_past_leeway(proxy_db):
    issuer, priv_pem = await _install_active_issuer("orga")
    now = int(time.time())
    expired_token = jose_jwt.encode(
        {
            "iss": issuer.issuer,
            "aud": "cullis-local",
            "sub": "orga::alice",
            "scope": "local",
            "iat": now - 3600,
            "exp": now - 3000,
            "jti": "x",
        },
        priv_pem,
        algorithm="ES256",
        headers={"kid": issuer.kid, "typ": "JWT"},
    )
    keystore = LocalKeyStore()
    with pytest.raises(LocalTokenError) as err:
        await validate_local_token(
            expired_token, keystore, expected_issuer=issuer.issuer,
        )
    assert "expired" in str(err.value).lower()


@pytest.mark.asyncio
async def test_rejects_wrong_audience(proxy_db):
    issuer, priv_pem = await _install_active_issuer("orga")
    now = int(time.time())
    wrong_aud = jose_jwt.encode(
        {
            "iss": issuer.issuer,
            "aud": "someone-else",
            "sub": "orga::alice",
            "scope": "local",
            "iat": now,
            "exp": now + 60,
            "jti": "x",
        },
        priv_pem,
        algorithm="ES256",
        headers={"kid": issuer.kid, "typ": "JWT"},
    )
    keystore = LocalKeyStore()
    with pytest.raises(LocalTokenError) as err:
        await validate_local_token(
            wrong_aud, keystore, expected_issuer=issuer.issuer,
        )
    assert "audience" in str(err.value).lower()


@pytest.mark.asyncio
async def test_rejects_missing_required_claim(proxy_db):
    issuer, priv_pem = await _install_active_issuer("orga")
    now = int(time.time())
    token = jose_jwt.encode(
        {
            "iss": issuer.issuer,
            "aud": "cullis-local",
            "sub": "orga::alice",
            "iat": now,
            "exp": now + 60,
            "jti": "x",
        },
        priv_pem,
        algorithm="ES256",
        headers={"kid": issuer.kid, "typ": "JWT"},
    )
    keystore = LocalKeyStore()
    with pytest.raises(LocalTokenError):
        await validate_local_token(
            token, keystore, expected_issuer=issuer.issuer,
        )


@pytest.mark.asyncio
async def test_rejects_unexpected_algorithm(proxy_db):
    issuer, _ = await _install_active_issuer("orga")
    token = jose_jwt.encode(
        {
            "iss": issuer.issuer,
            "aud": "cullis-local",
            "sub": "orga::alice",
            "scope": "local",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "jti": "x",
        },
        "symmetric-key",
        algorithm="HS256",
        headers={"kid": issuer.kid},
    )
    keystore = LocalKeyStore()
    with pytest.raises(LocalTokenError) as err:
        await validate_local_token(
            token, keystore, expected_issuer=issuer.issuer,
        )
    assert "alg" in str(err.value).lower()


def test_require_local_token_endpoint_happy_and_error_paths(tmp_path, monkeypatch):
    """Synchronous harness around the FastAPI dependency — mounts a fresh
    proxy DB in the test's own event loop."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import asyncio
    from mcp_proxy.db import dispose_db, init_db

    async def _bootstrap() -> tuple[LocalIssuer, str]:
        await init_db(url)
        return await _install_active_issuer("orga")

    try:
        loop = asyncio.new_event_loop()
        try:
            issuer, _ = loop.run_until_complete(_bootstrap())
        finally:
            loop.close()

        app = FastAPI()
        app.state.local_issuer = None
        app.state.local_keystore = None

        @app.get("/probe")
        async def probe(payload: LocalTokenPayload = Depends(require_local_token)):
            return {"agent": payload.agent_id, "scope": payload.scope}

        with TestClient(app) as client:
            resp = client.get("/probe", headers={"Authorization": "Bearer xxx"})
            assert resp.status_code == 503

            app.state.local_issuer = issuer
            app.state.local_keystore = LocalKeyStore()
            token = issuer.issue("orga::alice", ttl_seconds=60).token

            assert client.get("/probe").status_code == 401
            resp = client.get(
                "/probe", headers={"Authorization": "DPoP " + token},
            )
            assert resp.status_code == 401
            resp = client.get(
                "/probe", headers={"Authorization": "Bearer not-a-jwt"},
            )
            assert resp.status_code == 401

            resp = client.get(
                "/probe", headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            assert resp.json() == {"agent": "orga::alice", "scope": "local"}
    finally:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(dispose_db())
        finally:
            loop.close()
        get_settings.cache_clear()
