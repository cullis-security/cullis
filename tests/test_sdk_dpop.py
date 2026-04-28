"""F-B-11 Phase 3c — DpopKey + CullisClient egress proof emission.

Covers two levels:

* Unit tests on ``cullis_sdk.dpop.DpopKey`` — generate, persist (0600,
  atomic), load-or-generate roundtrip, thumbprint stability, sign_proof
  produces a JWT accepted by the server verifier (``compute_jkt`` on the
  proof's ``jwk`` header matches ``DpopKey.thumbprint()``; ``ath`` matches
  ``sha256(api_key)``).

* Integration tests on ``CullisClient`` — ``from_enrollment`` with
  ``enable_dpop=True`` generates + persists a key under a test base
  dir; ``_egress_http`` includes a signed ``DPoP`` header on every
  request; a 401 with ``use_dpop_nonce`` triggers exactly one retry
  with the new nonce claim; ``enable_dpop=False`` keeps the legacy
  behaviour.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat

import httpx
import jwt as pyjwt
import pytest

from cullis_sdk import DpopKey


# ── DpopKey unit tests ──────────────────────────────────────────────


def test_generate_creates_valid_ec_key(tmp_path):
    key = DpopKey.generate(path=tmp_path / "agent.jwk")
    assert key.public_jwk["kty"] == "EC"
    assert key.public_jwk["crv"] == "P-256"
    # Both coords are base64url-encoded 32-byte big-endian ints.
    for field in ("x", "y"):
        raw = base64.urlsafe_b64decode(key.public_jwk[field] + "==")
        assert len(raw) == 32
    assert key.path == tmp_path / "agent.jwk"


def test_save_uses_0600_and_atomic(tmp_path):
    path = tmp_path / "agent.jwk"
    DpopKey.generate(path=path)
    # chmod 0600 (owner read/write only).
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"
    # No lingering tempfile from the atomic write.
    temps = list(tmp_path.glob("agent.jwk.tmp-*"))
    assert temps == [], f"stray tempfile(s) after atomic save: {temps}"


def test_load_or_generate_is_idempotent(tmp_path):
    """A second call with the same agent_id returns the same key — the
    server-side pinned thumbprint must keep matching after a restart."""
    first = DpopKey.load_or_generate("acme::alice", base_dir=tmp_path)
    second = DpopKey.load_or_generate("acme::alice", base_dir=tmp_path)
    assert first.thumbprint() == second.thumbprint()
    assert first.public_jwk == second.public_jwk


def test_load_or_generate_sanitises_agent_id(tmp_path):
    """``agent_id`` contains ``:`` which is illegal on Windows and a
    footgun on some filesystems. The on-disk filename must not carry
    it verbatim."""
    DpopKey.load_or_generate("acme::alice", base_dir=tmp_path)
    files = list(tmp_path.glob("*.jwk"))
    assert len(files) == 1
    name = files[0].name
    assert ":" not in name
    assert "alice" in name  # still recognisable


def test_thumbprint_matches_rfc7638_compute_jkt(tmp_path):
    """The SDK-side ``thumbprint()`` must match the server's
    ``mcp_proxy.auth.dpop.compute_jkt`` byte-for-byte — they are the
    only two parties that have to agree on the value."""
    from mcp_proxy.auth.dpop import compute_jkt

    key = DpopKey.load_or_generate("acme::alice", base_dir=tmp_path)
    assert key.thumbprint() == compute_jkt(key.public_jwk)


def test_sign_proof_yields_valid_dpop_jwt(tmp_path):
    """The JWT carries ``typ=dpop+jwt`` + ``jwk`` header + claims
    verifier requires: htm, htu, iat, jti; ``ath`` when access_token
    given; ``nonce`` when given."""
    key = DpopKey.load_or_generate("acme::alice", base_dir=tmp_path)
    api_key = "sk_local_test_" + "x" * 32
    proof = key.sign_proof(
        "POST",
        "http://proxy.test/v1/egress/message/send",
        access_token=api_key,
        nonce="server-nonce-abc",
    )
    header = pyjwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "jwk" in header and "d" not in header["jwk"]
    # Roundtrip: verify signature against the embedded jwk.
    from cryptography.hazmat.primitives import serialization
    pub = key.private_key.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    claims = pyjwt.decode(proof, pub_pem, algorithms=["ES256"], options={"verify_aud": False})
    assert claims["htm"] == "POST"
    assert claims["htu"] == "http://proxy.test/v1/egress/message/send"
    assert claims["nonce"] == "server-nonce-abc"
    assert "jti" in claims and "iat" in claims
    expected_ath = base64.urlsafe_b64encode(
        hashlib.sha256(api_key.encode()).digest()
    ).rstrip(b"=").decode()
    assert claims["ath"] == expected_ath


def test_load_rejects_public_only_jwk(tmp_path):
    """If the on-disk file somehow loses the ``d`` field (copy of the
    public jwk), loading must fail loudly — we cannot sign without
    the private half."""
    path = tmp_path / "agent.jwk"
    bad = {
        "private_jwk": {
            "kty": "EC", "crv": "P-256", "x": "A" * 43, "y": "B" * 43,
        },  # no 'd'
    }
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="private"):
        DpopKey.load(path)


def test_reject_non_ec_p256_construction():
    with pytest.raises(ValueError):
        DpopKey.__init__(
            DpopKey.__new__(DpopKey),
            private_key=None,  # type: ignore[arg-type]
            public_jwk={"kty": "RSA", "n": "x", "e": "y"},
        )


# ── CullisClient integration ────────────────────────────────────────


@pytest.fixture
def stub_enroll_server(tmp_path, monkeypatch):
    """Patch the ``from_enrollment`` GET to return a synthetic config
    without touching the network."""
    def _mock_enroll_get(self, url, **kwargs):
        class _Resp:
            status_code = 200
            def json(self):
                return {
                    "api_key": "sk_local_test_" + "z" * 32,
                    "agent_id": "acme::alice",
                    "proxy_url": "http://proxy.test",
                    "org_id": "acme",
                }
            def raise_for_status(self):
                pass
        return _Resp()

    monkeypatch.setattr(httpx.Client, "get", _mock_enroll_get)


def test_from_enrollment_generates_and_persists_dpop_key(
    stub_enroll_server, tmp_path,
):
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
    )
    assert client._egress_dpop_key is not None
    # The key was persisted to the supplied base_dir.
    files = list(tmp_path.glob("*.jwk"))
    assert len(files) == 1


def test_from_enrollment_disable_dpop_keeps_legacy(
    stub_enroll_server, tmp_path,
):
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
        enable_dpop=False,
    )
    assert client._egress_dpop_key is None
    assert list(tmp_path.glob("*.jwk")) == []


def test_proxy_headers_injects_dpop_when_key_present(
    stub_enroll_server, tmp_path,
):
    """ADR-014 PR-C: ``proxy_headers`` no longer ships ``X-API-Key`` —
    the cert at TLS handshake is the agent identity. DPoP proof still
    rides per-request."""
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
    )
    headers = client.proxy_headers("POST", "http://proxy.test/v1/egress/ping")
    assert "DPoP" in headers
    assert "X-API-Key" not in headers

    # The proof's jwk thumbprint matches the registered key.
    from mcp_proxy.auth.dpop import compute_jkt
    proof_header = pyjwt.get_unverified_header(headers["DPoP"])
    assert compute_jkt(proof_header["jwk"]) == client._egress_dpop_key.thumbprint()


def test_proxy_headers_skips_dpop_without_url(
    stub_enroll_server, tmp_path,
):
    """Defensive: ``proxy_headers()`` without method/url (legacy
    integration code) skips the DPoP proof to avoid shipping an
    empty-htu signature. Post-PR-C the result is just the JSON
    content-type — no api_key bearer fallback exists anymore."""
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
    )
    headers = client.proxy_headers()  # no method/url
    assert "DPoP" not in headers
    assert "X-API-Key" not in headers


def test_egress_http_retries_on_use_dpop_nonce(
    stub_enroll_server, tmp_path, monkeypatch,
):
    """Server returns 401 ``use_dpop_nonce`` + fresh nonce header on
    the first attempt; the SDK picks up the nonce and retries exactly
    once, including the nonce in the new proof."""
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
    )

    attempts: list[dict] = []

    def _mock_post(self, url, **kwargs):
        headers = kwargs.get("headers") or {}
        attempts.append({"headers": dict(headers)})
        if len(attempts) == 1:
            return _Resp401UseNonce()
        return _Resp200()

    class _Resp401UseNonce:
        status_code = 401
        text = '{"detail":"use_dpop_nonce"}'
        headers = {"dpop-nonce": "fresh-server-nonce"}
        def json(self):
            return {"detail": "use_dpop_nonce"}
        def raise_for_status(self):
            raise httpx.HTTPStatusError("401", request=None, response=self)  # pragma: no cover

    class _Resp200:
        status_code = 200
        text = "{}"
        headers = {"dpop-nonce": "next-nonce"}
        def json(self):
            return {"ok": True}
        def raise_for_status(self):
            pass

    monkeypatch.setattr(httpx.Client, "post", _mock_post)

    resp = client._egress_http("post", "/v1/egress/message/send", json={})
    assert resp.status_code == 200
    assert len(attempts) == 2  # one initial + one retry, no loop

    # Retry proof carries the fresh nonce; initial did not.
    first_proof = attempts[0]["headers"]["DPoP"]
    second_proof = attempts[1]["headers"]["DPoP"]
    first_claims = pyjwt.decode(first_proof, options={"verify_signature": False})
    second_claims = pyjwt.decode(second_proof, options={"verify_signature": False})
    assert first_claims.get("nonce") in (None, "")
    assert second_claims["nonce"] == "fresh-server-nonce"
    # Client cached the nonce the server rotated on the 200.
    assert client._egress_dpop_nonce == "next-nonce"


def test_egress_http_gives_up_after_one_retry(
    stub_enroll_server, tmp_path, monkeypatch,
):
    """Persistent ``use_dpop_nonce`` responses must NOT loop — the SDK
    retries once, then surfaces the 401 so the caller can decide."""
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "http://proxy.test/v1/enroll/fake",
        dpop_base_dir=tmp_path,
        verify_tls=False,
    )

    calls: list[int] = []

    class _Resp401:
        status_code = 401
        text = '{"detail":"use_dpop_nonce"}'
        headers = {"dpop-nonce": "still-rotating"}
        def json(self):
            return {"detail": "use_dpop_nonce"}
        def raise_for_status(self):
            raise httpx.HTTPStatusError("401", request=None, response=self)  # pragma: no cover

    def _mock_post(self, url, **kwargs):
        calls.append(1)
        return _Resp401()

    monkeypatch.setattr(httpx.Client, "post", _mock_post)

    resp = client._egress_http("post", "/v1/egress/x", json={})
    assert resp.status_code == 401
    assert len(calls) == 2  # initial + 1 retry, not more
