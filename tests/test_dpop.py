"""
Unit tests for app/auth/dpop.py — DPoP RFC 9449 implementation.

Tests are pure unit tests: no HTTP client, no DB, no broker startup.
They test the dpop module functions directly.

Coverage:
  compute_jkt:
    1.  EC P-256 thumbprint matches known RFC 7638 test vector
    2.  RSA thumbprint is computed from e, kty, n members only
    3.  Unknown kty raises ValueError

  verify_dpop_proof:
    4.  Valid proof → returns jkt
    5.  Wrong typ → 401
    6.  Symmetric alg (HS256) → 401
    7.  Private key 'd' in jwk → 401
    8.  Invalid signature → 401
    9.  Missing jti → 401
    10. Replayed jti → 401
    11. Expired iat (> 60s) → 401
    12. Future iat (> 5s clock skew) → 401
    13. htm mismatch → 401
    14. htu mismatch (path different) → 401
    15. htu match after ws:// normalization
    16. htu match ignoring query string
    17. ath mismatch → 401
    18. ath match → returns jkt
    19. Missing iat → 401
    20. Malformed JWT → 401
"""
import base64
import hashlib
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from jose import jwt as jose_jwt

from app.auth.dpop import compute_jkt, verify_dpop_proof, _normalize_htu, generate_dpop_nonce, get_current_dpop_nonce, _is_valid_nonce
from app.auth.dpop_jti_store import get_dpop_jti_store, reset_dpop_jti_store

pytestmark = pytest.mark.asyncio
from tests.cert_factory import make_dpop_key_pair, make_dpop_proof


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fresh_proof(privkey, jwk, method="POST", url="http://test/auth/token",
                 access_token=None, jti=None, iat_offset=0, nonce=None):
    return make_dpop_proof(privkey, jwk, method, url,
                           access_token=access_token,
                           jti=jti, iat_offset=iat_offset, nonce=nonce)


# Shared key pair for nonce tests
_nonce_privkey, _nonce_jwk = make_dpop_key_pair()

def _make_proof(method="POST", url="http://test/auth/token",
                access_token=None, nonce=None):
    return _fresh_proof(_nonce_privkey, _nonce_jwk, method, url,
                        access_token=access_token, nonce=nonce)


# ─────────────────────────────────────────────────────────────────────────────
# compute_jkt
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_jkt_ec_known_vector():
    """
    RFC 7638 Section 3.1 test vector for EC P-256.
    https://www.rfc-editor.org/rfc/rfc7638#section-3.1
    """
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    }
    # Expected: SHA-256 of '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}'
    canonical = json.dumps(
        {"crv": "P-256", "kty": "EC",
         "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    assert compute_jkt(jwk) == expected


def test_compute_jkt_rsa_uses_only_required_members():
    """RSA jkt is computed from e, kty, n — ignores any extra members."""
    jwk = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "d": "should-be-ignored",  # private — must not affect thumbprint
        "alg": "RS256",             # optional — must not affect thumbprint
    }
    canonical = json.dumps(
        {"e": "AQAB", "kty": "RSA", "n": jwk["n"]},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    assert compute_jkt(jwk) == expected


def test_compute_jkt_unknown_kty_raises():
    with pytest.raises(ValueError, match="Unsupported kty"):
        compute_jkt({"kty": "OKP", "crv": "Ed25519"})


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — valid case
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_valid_proof_returns_jkt():
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk)
    jkt = await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert jkt == compute_jkt(jwk)


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — header checks
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_wrong_typ():
    privkey, jwk = make_dpop_key_pair()
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    proof = jose_jwt.encode(
        {"jti": str(uuid.uuid4()), "htm": "POST",
         "htu": "http://test/auth/token", "iat": __import__("time").time()},
        priv_pem, algorithm="ES256",
        headers={"typ": "JWT", "jwk": jwk},  # wrong typ
    )
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "typ" in exc.value.detail.lower()


async def test_verify_symmetric_alg_rejected():
    """HS256 must be rejected — symmetric algorithms are forbidden for DPoP."""
    privkey, jwk = make_dpop_key_pair()
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    # Build a structurally valid proof but with alg=HS256 in the header
    import struct, hmac as _hmac
    header_dict = {"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header_dict).encode()
    ).rstrip(b"=").decode()
    payload_dict = {"jti": str(uuid.uuid4()), "htm": "POST",
                    "htu": "http://test/auth/token", "iat": __import__("time").time()}
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).rstrip(b"=").decode()
    fake_sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    proof = f"{header_b64}.{payload_b64}.{fake_sig}"
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "algorithm" in exc.value.detail.lower()


async def test_verify_private_key_in_jwk_rejected():
    """jwk containing 'd' (private key component) must be rejected."""
    privkey, jwk = make_dpop_key_pair()
    evil_jwk = dict(jwk)
    evil_jwk["d"] = "private-key-material"
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    proof = jose_jwt.encode(
        {"jti": str(uuid.uuid4()), "htm": "POST",
         "htu": "http://test/auth/token", "iat": __import__("time").time()},
        priv_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": evil_jwk},
    )
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "private key" in exc.value.detail.lower()


async def test_verify_invalid_signature():
    """Proof signed with a different key → signature verification fails."""
    privkey1, jwk1 = make_dpop_key_pair()
    privkey2, _    = make_dpop_key_pair()
    # Build proof: header says jwk1 but signed with privkey2
    priv2_pem = privkey2.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    proof = jose_jwt.encode(
        {"jti": str(uuid.uuid4()), "htm": "POST",
         "htu": "http://test/auth/token", "iat": __import__("time").time()},
        priv2_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk1},  # wrong key in header
    )
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "signature" in exc.value.detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — JTI checks
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_missing_jti():
    privkey, jwk = make_dpop_key_pair()
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    proof = jose_jwt.encode(
        {"htm": "POST", "htu": "http://test/auth/token", "iat": __import__("time").time()},
        # no jti
        priv_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "jti" in exc.value.detail.lower()


async def test_verify_replayed_jti():
    """Same JTI used twice → second call raises 401 replay detected."""
    privkey, jwk = make_dpop_key_pair()
    fixed_jti = str(uuid.uuid4())
    proof1 = _fresh_proof(privkey, jwk, jti=fixed_jti)
    proof2 = _fresh_proof(privkey, jwk, jti=fixed_jti)

    # First use succeeds
    await verify_dpop_proof(proof1, htm="POST", htu="http://test/auth/token", require_nonce=False)

    # Second use fails
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof2, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "replay" in exc.value.detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — iat checks
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_expired_iat():
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, iat_offset=-120)  # 2 minutes ago
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "iat" in exc.value.detail.lower()


async def test_verify_future_iat_beyond_skew():
    """iat > +5s in the future (beyond clock skew tolerance) → 401."""
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, iat_offset=30)  # 30s in the future
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "iat" in exc.value.detail.lower()


async def test_verify_missing_iat():
    privkey, jwk = make_dpop_key_pair()
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    proof = jose_jwt.encode(
        {"jti": str(uuid.uuid4()), "htm": "POST",
         "htu": "http://test/auth/token"},  # no iat
        priv_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "iat" in exc.value.detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — htm / htu checks
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_htm_mismatch():
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, method="GET")  # proof says GET
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "htm" in exc.value.detail.lower()


async def test_verify_htu_mismatch():
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, url="http://test/other/endpoint")
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False)
    assert exc.value.status_code == 401
    assert "htu" in exc.value.detail.lower()


async def test_verify_htu_ws_normalization():
    """ws:// in the proof htu is normalized to http:// for comparison."""
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, method="GET", url="ws://test/broker/ws")
    # Broker compares against the HTTP equivalent — must match after normalization
    jkt = await verify_dpop_proof(proof, htm="GET", htu="http://test/broker/ws", require_nonce=False)
    assert jkt == compute_jkt(jwk)


async def test_verify_htu_query_string_stripped():
    """Query string in htu is stripped for comparison — proof without it must match."""
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, url="http://test/auth/token")
    # Broker URL has a query string (should be stripped)
    jkt = await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token?foo=bar", require_nonce=False)
    assert jkt == compute_jkt(jwk)


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — ath checks
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_ath_mismatch():
    """ath computed on a different token → 401."""
    privkey, jwk = make_dpop_key_pair()
    proof = _fresh_proof(privkey, jwk, access_token="real-token")
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False,
                          access_token="different-token")
    assert exc.value.status_code == 401
    assert "ath" in exc.value.detail.lower()


async def test_verify_ath_match():
    """ath computed on the correct token → succeeds."""
    privkey, jwk = make_dpop_key_pair()
    token = "correct-access-token"
    proof = _fresh_proof(privkey, jwk, access_token=token)
    jkt = await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token", require_nonce=False,
                             access_token=token)
    assert jkt == compute_jkt(jwk)


# ─────────────────────────────────────────────────────────────────────────────
# verify_dpop_proof — malformed input
# ─────────────────────────────────────────────────────────────────────────────

async def test_verify_malformed_jwt():
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof("not.a.valid.jwt.at.all", htm="POST", require_nonce=False,
                          htu="http://test/auth/token")
    assert exc.value.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Server Nonce (RFC 9449 §8)
# ─────────────────────────────────────────────────────────────────────────────

async def test_nonce_required_when_enabled():
    """Proof without nonce is rejected when require_nonce=True."""
    reset_dpop_jti_store()
    generate_dpop_nonce()  # ensure a nonce exists
    proof = _make_proof("POST", "http://test/auth/token")
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token",
                                require_nonce=True)
    assert exc.value.status_code == 401
    assert "use_dpop_nonce" in exc.value.detail


async def test_nonce_valid_accepted():
    """Proof with valid nonce is accepted."""
    reset_dpop_jti_store()
    nonce = generate_dpop_nonce()
    proof = _make_proof("POST", "http://test/auth/token", nonce=nonce)
    jkt = await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token",
                                  require_nonce=True)
    assert jkt


async def test_nonce_wrong_rejected():
    """Proof with wrong nonce is rejected."""
    reset_dpop_jti_store()
    generate_dpop_nonce()
    proof = _make_proof("POST", "http://test/auth/token", nonce="wrong-nonce")
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token",
                                require_nonce=True)
    assert exc.value.status_code == 401
    assert "use_dpop_nonce" in exc.value.detail


async def test_previous_nonce_still_valid():
    """After rotation, the previous nonce is still accepted."""
    reset_dpop_jti_store()
    nonce1 = generate_dpop_nonce()
    nonce2 = generate_dpop_nonce()  # rotates — nonce1 becomes previous
    assert nonce1 != nonce2
    assert _is_valid_nonce(nonce1)
    assert _is_valid_nonce(nonce2)

    proof = _make_proof("POST", "http://test/auth/token", nonce=nonce1)
    jkt = await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token",
                                  require_nonce=True)
    assert jkt


async def test_nonce_response_header():
    """The 401 response includes DPoP-Nonce header."""
    reset_dpop_jti_store()
    generate_dpop_nonce()
    proof = _make_proof("POST", "http://test/auth/token")
    with pytest.raises(HTTPException) as exc:
        await verify_dpop_proof(proof, htm="POST", htu="http://test/auth/token",
                                require_nonce=True)
    assert "DPoP-Nonce" in exc.value.headers
