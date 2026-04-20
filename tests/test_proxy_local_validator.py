"""ADR-012 Phase 3 — LocalValidator unit tests.

Paired with ``tests/test_proxy_local_issuer.py``: that file pins what
the issuer emits, this one pins what the validator accepts. Round-trip
coverage is the main invariant — a token produced by ``LocalIssuer``
must always decode to a ``LocalTokenPayload`` whose fields match.

Everything that deviates from the expected wire format (wrong audience,
wrong kid, missing claims, expired, signed by a stranger, malformed
header) must raise ``LocalTokenError`` — so the FastAPI dependency can
turn it into a uniform 401 without leaking internals.
"""
from __future__ import annotations

import time

import jwt as jose_jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.local_issuer import LocalIssuer
from mcp_proxy.auth.local_validator import (
    LocalTokenError,
    LocalTokenPayload,
    require_local_token,
    validate_local_token,
)


def _fresh_issuer(org_id: str = "orga") -> LocalIssuer:
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return LocalIssuer(org_id=org_id, leaf_key=key, leaf_pubkey_pem=pub_pem)


def test_validate_roundtrip_issuer_to_validator():
    issuer = _fresh_issuer("orga")
    token = issuer.issue("orga::alice", ttl_seconds=60, extra_claims={"tenant": "t-1"})

    payload = validate_local_token(token.token, issuer)
    assert isinstance(payload, LocalTokenPayload)
    assert payload.agent_id == "orga::alice"
    assert payload.issuer == "cullis-mastio:orga"
    assert payload.org_id == "orga"
    assert payload.scope == "local"
    assert payload.expires_at == token.expires_at
    assert payload.issued_at == token.issued_at
    assert payload.jti  # non-empty
    assert payload.extra == {"tenant": "t-1"}


def test_rejects_token_signed_by_foreign_key():
    issuer_a = _fresh_issuer("orga")
    issuer_b = _fresh_issuer("orga")  # same org, different key → different kid
    foreign_token = issuer_b.issue("orga::alice").token

    with pytest.raises(LocalTokenError) as err:
        validate_local_token(foreign_token, issuer_a)
    assert "kid" in str(err.value).lower()


def test_rejects_expired_past_leeway():
    issuer = _fresh_issuer("orga")
    # Craft an expired token by issuing with a past ttl — since `issue`
    # validates ttl > 0, mint it manually using the same private key.
    now = int(time.time())
    priv_pem = issuer._leaf_key.private_bytes(  # noqa: SLF001
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
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
    with pytest.raises(LocalTokenError) as err:
        validate_local_token(expired_token, issuer)
    assert "expired" in str(err.value).lower()


def test_rejects_wrong_audience():
    issuer = _fresh_issuer("orga")
    now = int(time.time())
    priv_pem = issuer._leaf_key.private_bytes(  # noqa: SLF001
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
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
    with pytest.raises(LocalTokenError) as err:
        validate_local_token(wrong_aud, issuer)
    assert "audience" in str(err.value).lower()


def test_rejects_missing_required_claim():
    issuer = _fresh_issuer("orga")
    now = int(time.time())
    priv_pem = issuer._leaf_key.private_bytes(  # noqa: SLF001
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Missing ``scope`` — one of the required claims.
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
    with pytest.raises(LocalTokenError):
        validate_local_token(token, issuer)


def test_rejects_unexpected_algorithm():
    # Hand-craft an HS256 JWT with the right claims but wrong alg.
    issuer = _fresh_issuer("orga")
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
    with pytest.raises(LocalTokenError) as err:
        validate_local_token(token, issuer)
    assert "alg" in str(err.value).lower()


def test_require_local_token_endpoint_happy_and_error_paths():
    app = FastAPI()
    app.state.local_issuer = None

    @app.get("/probe")
    async def probe(payload=pytest.importorskip("fastapi").Depends(require_local_token)):  # type: ignore[valid-type]
        return {"agent": payload.agent_id, "scope": payload.scope}

    with TestClient(app) as client:
        # No issuer loaded → 503.
        resp = client.get("/probe", headers={"Authorization": "Bearer xxx"})
        assert resp.status_code == 503

        # Wire an issuer.
        issuer = _fresh_issuer("orga")
        app.state.local_issuer = issuer
        token = issuer.issue("orga::alice", ttl_seconds=60).token

        # No header → 401.
        assert client.get("/probe").status_code == 401

        # Wrong scheme → 401.
        resp = client.get("/probe", headers={"Authorization": "DPoP " + token})
        assert resp.status_code == 401

        # Malformed → 401.
        resp = client.get("/probe", headers={"Authorization": "Bearer not-a-jwt"})
        assert resp.status_code == 401

        # Happy path.
        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json() == {"agent": "orga::alice", "scope": "local"}
