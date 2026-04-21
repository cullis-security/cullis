"""ADR-012 Phase 1 / Phase 2.0 — unit tests for ``LocalIssuer`` and the
``/.well-known/jwks-local.json`` endpoint.

The issuer is the primitive behind every intra-org session token. These
tests pin the wire format (ES256 claims, kid derivation, JWKS shape) so
future refactors can't silently break the contract the validator depends
on. Phase 2.0 shifts the issuer from holding its own leaf key+pubkey
pair to wrapping a ``MastioKey`` pulled from the keystore; the tests
reflect that change but keep the same wire-level assertions.
"""
from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timezone

import jwt as jose_jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.local_issuer import (
    LOCAL_AUDIENCE,
    LOCAL_ISSUER_PREFIX,
    LOCAL_SCOPE,
    LocalIssuer,
)
from mcp_proxy.auth.local_keystore import MastioKey, compute_kid


def _fresh_key() -> tuple[ec.EllipticCurvePrivateKey, str, str]:
    """Return ``(priv_key_obj, priv_pem, pub_pem)`` for a fresh EC P-256 key."""
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


def _active_key(priv_pem: str, pub_pem: str) -> MastioKey:
    """Build an in-memory active ``MastioKey`` without touching the DB."""
    now = datetime.now(timezone.utc)
    return MastioKey(
        kid=compute_kid(pub_pem),
        pubkey_pem=pub_pem,
        privkey_pem=priv_pem,
        cert_pem=None,
        created_at=now,
        activated_at=now,
        deprecated_at=None,
        expires_at=None,
    )


def _decode_with_issuer(token: str, issuer: LocalIssuer) -> dict:
    return jose_jwt.decode(
        token,
        issuer.active_key.pubkey_pem,
        algorithms=["ES256"],
        audience=LOCAL_AUDIENCE,
        issuer=issuer.issuer,
    )


def test_issue_produces_decodable_es256_token_with_expected_claims():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    before = int(time.time())
    result = issuer.issue("orga::alice", ttl_seconds=60)
    after = int(time.time())

    header = jose_jwt.get_unverified_header(result.token)
    assert header["alg"] == "ES256"
    assert header["typ"] == "JWT"
    assert header["kid"] == issuer.kid
    assert header["kid"] == result.kid

    claims = _decode_with_issuer(result.token, issuer)
    assert claims["iss"] == f"{LOCAL_ISSUER_PREFIX}:orga"
    assert claims["aud"] == LOCAL_AUDIENCE
    assert claims["sub"] == "orga::alice"
    assert claims["scope"] == LOCAL_SCOPE
    assert before <= claims["iat"] <= after
    assert claims["exp"] == claims["iat"] + 60
    assert isinstance(claims["jti"], str) and len(claims["jti"]) >= 32
    assert result.issued_at == claims["iat"]
    assert result.expires_at == claims["exp"]


def test_kid_is_stable_for_same_pubkey_and_unique_across_keys():
    _, priv1, pub1 = _fresh_key()
    _, priv2, pub2 = _fresh_key()

    issuer1a = LocalIssuer(org_id="orga", active_key=_active_key(priv1, pub1))
    issuer1b = LocalIssuer(org_id="orga", active_key=_active_key(priv1, pub1))
    issuer2 = LocalIssuer(org_id="orga", active_key=_active_key(priv2, pub2))

    assert issuer1a.kid == issuer1b.kid
    assert issuer1a.kid != issuer2.kid

    expected = f"mastio-{hashlib.sha256(pub1.encode()).hexdigest()[:16]}"
    assert issuer1a.kid == expected


def test_extra_claims_cannot_overwrite_reserved_fields():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    extra = {
        "iss": "attacker",
        "sub": "attacker",
        "aud": "attacker",
        "scope": "root",
        "exp": 0,
        "iat": 0,
        "jti": "pinned",
        "capabilities": ["order.read"],
        "tenant_id": "t-42",
    }
    result = issuer.issue("orga::alice", ttl_seconds=60, extra_claims=extra)
    claims = _decode_with_issuer(result.token, issuer)

    assert claims["iss"] == issuer.issuer
    assert claims["sub"] == "orga::alice"
    assert claims["aud"] == LOCAL_AUDIENCE
    assert claims["scope"] == LOCAL_SCOPE
    assert claims["jti"] != "pinned"
    assert claims["capabilities"] == ["order.read"]
    assert claims["tenant_id"] == "t-42"


def test_issue_rejects_invalid_inputs():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    with pytest.raises(ValueError):
        issuer.issue("", ttl_seconds=60)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=0)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=-1)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=3601)


def test_constructor_rejects_bad_inputs():
    _, priv_pem, pub_pem = _fresh_key()
    with pytest.raises(ValueError):
        LocalIssuer(org_id="", active_key=_active_key(priv_pem, pub_pem))
    with pytest.raises(TypeError):
        LocalIssuer(org_id="orga", active_key="not-a-key")  # type: ignore[arg-type]

    # An inactive (never-activated or deprecated) key cannot anchor an issuer.
    now = datetime.now(timezone.utc)
    never_active = MastioKey(
        kid=compute_kid(pub_pem), pubkey_pem=pub_pem, privkey_pem=priv_pem,
        cert_pem=None, created_at=now,
        activated_at=None, deprecated_at=None, expires_at=None,
    )
    with pytest.raises(ValueError, match="not currently active"):
        LocalIssuer(org_id="orga", active_key=never_active)


def test_jwks_roundtrip_matches_leaf_pubkey():
    priv, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    jwks = issuer.jwks()
    assert "keys" in jwks and len(jwks["keys"]) == 1
    jwk = jwks["keys"][0]
    assert jwk == {
        "kty": "EC",
        "crv": "P-256",
        "x": jwk["x"],
        "y": jwk["y"],
        "use": "sig",
        "alg": "ES256",
        "kid": issuer.kid,
    }

    def _unb64u(s: str) -> int:
        pad = "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")

    numbers = priv.public_key().public_numbers()
    assert _unb64u(jwk["x"]) == numbers.x
    assert _unb64u(jwk["y"]) == numbers.y


def test_jwks_endpoint_returns_key_when_issuer_loaded():
    from mcp_proxy.auth.jwks_local import router as jwks_router

    app = FastAPI()
    app.include_router(jwks_router)

    with TestClient(app) as client:
        # No issuer attached → 503.
        app.state.local_issuer = None
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 503

        _, priv_pem, pub_pem = _fresh_key()
        app.state.local_issuer = LocalIssuer(
            org_id="orga", active_key=_active_key(priv_pem, pub_pem),
        )
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 200
        body = resp.json()
        assert body["keys"][0]["kid"] == app.state.local_issuer.kid
        assert body["keys"][0]["alg"] == "ES256"
