"""Tests for :meth:`CullisClient.login_via_proxy_with_local_key`.

Exercises the three-hop flow (challenge → sign-challenged-assertion →
/v1/auth/token) through monkeypatched ``_http`` responses, without
actually standing up a Mastio or Court. Integration with a real Mastio
is covered by ``tests/test_proxy_challenge_response.py``.
"""
from __future__ import annotations

import base64

import httpx
import pytest

from cullis_sdk.client import CullisClient
from tests.cert_factory import (
    get_agent_key_pem,
    make_agent_cert,
)


AGENT_ID = "alice"
ORG_ID = "login-sdk-test"


def _cert_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    _, cert = make_agent_cert(AGENT_ID, ORG_ID)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem() -> str:
    return get_agent_key_pem(AGENT_ID, ORG_ID)


def _build_client() -> CullisClient:
    client = CullisClient("http://mastio.test", verify_tls=False)
    client._proxy_api_key = "test-api-key"
    client._proxy_agent_id = AGENT_ID
    client._signing_key_pem = _key_pem()
    client._cert_pem = _cert_pem()
    return client


class _Resp:
    """Tiny httpx.Response stand-in the monkeypatched _http returns."""
    def __init__(self, status_code: int, body: dict | None = None,
                 text_body: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
        self._text = text_body or ""
        self.headers = headers or {}
        self.request = None

    def json(self):
        return self._body

    @property
    def text(self):
        return self._text or str(self._body)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=None,
                response=self,
            )


def _script_http(monkeypatch, client: CullisClient, responses: list[tuple[str, _Resp]]):
    """Replace client._http.post with a scripted queue. Each entry is
    (path_substring_to_match, response)."""
    pending = list(responses)
    posted: list[tuple[str, dict, dict]] = []

    def _post(url, json=None, headers=None, **kw):
        posted.append((url, json or {}, headers or {}))
        if not pending:
            raise AssertionError(f"unexpected POST {url}")
        expected_fragment, resp = pending.pop(0)
        assert expected_fragment in url, (
            f"expected URL containing {expected_fragment!r}, got {url!r}"
        )
        return resp

    monkeypatch.setattr(client._http, "post", _post)
    return posted


def test_happy_path(monkeypatch):
    client = _build_client()
    try:
        nonce = base64.urlsafe_b64encode(b"\x11" * 32).rstrip(b"=").decode()
        assertion_echo = "signed.assertion.jwt"
        posted = _script_http(monkeypatch, client, [
            ("/v1/auth/login-challenge",
             _Resp(200, {"nonce": nonce, "expires_in": 120, "agent_id": AGENT_ID})),
            ("/v1/auth/sign-challenged-assertion",
             _Resp(200, {"client_assertion": assertion_echo,
                         "agent_id": AGENT_ID,
                         "mastio_signature": "sig-bytes-b64"})),
            ("/v1/auth/token",
             _Resp(200, {"access_token": "broker-token-xyz"})),
        ])
        client.login_via_proxy_with_local_key()
        assert client.token == "broker-token-xyz"
        # Token call carried the mastio counter-sig.
        token_headers = posted[2][2]
        assert token_headers.get("X-Cullis-Mastio-Signature") == "sig-bytes-b64"
        # sign-challenged-assertion was given the nonce we fetched in step 1.
        sign_body = posted[1][1]
        assert sign_body["nonce"] == nonce
    finally:
        client.close()


def test_missing_signing_key_raises(monkeypatch):
    client = _build_client()
    client._signing_key_pem = None
    try:
        with pytest.raises(RuntimeError, match="local signing key"):
            client.login_via_proxy_with_local_key()
    finally:
        client.close()


def test_missing_cert_raises(monkeypatch):
    client = _build_client()
    client._cert_pem = None
    try:
        with pytest.raises(RuntimeError, match="certificate PEM"):
            client.login_via_proxy_with_local_key()
    finally:
        client.close()


def test_missing_proxy_enrollment_raises(monkeypatch):
    client = CullisClient("http://mastio.test", verify_tls=False)
    client._signing_key_pem = _key_pem()
    client._cert_pem = _cert_pem()
    # _proxy_api_key / _proxy_agent_id missing.
    try:
        with pytest.raises(RuntimeError, match="proxy enrollment"):
            client.login_via_proxy_with_local_key()
    finally:
        client.close()


def test_challenge_404_no_silent_fallback(monkeypatch):
    """If the Mastio doesn't expose /v1/auth/login-challenge (legacy
    deploy) the client must surface a clear PermissionError. No silent
    fallback to the legacy ``login_via_proxy`` — that would mask a
    misconfigured proxy."""
    client = _build_client()
    try:
        _script_http(monkeypatch, client, [
            ("/v1/auth/login-challenge",
             _Resp(404, text_body="not found")),
        ])
        with pytest.raises(PermissionError, match="HTTP 404"):
            client.login_via_proxy_with_local_key()
        assert client.token is None  # no broker token issued
    finally:
        client.close()


def test_sign_401_surfaces(monkeypatch):
    """Auth broken at step 3 → PermissionError with status surfaced."""
    client = _build_client()
    try:
        nonce = base64.urlsafe_b64encode(b"\x22" * 32).rstrip(b"=").decode()
        _script_http(monkeypatch, client, [
            ("/v1/auth/login-challenge",
             _Resp(200, {"nonce": nonce, "expires_in": 120, "agent_id": AGENT_ID})),
            ("/v1/auth/sign-challenged-assertion",
             _Resp(401, text_body="challenge nonce invalid")),
        ])
        with pytest.raises(PermissionError, match="HTTP 401"):
            client.login_via_proxy_with_local_key()
        assert client.token is None
    finally:
        client.close()


def test_connect_error_wrapped_as_connection_error(monkeypatch):
    client = _build_client()
    try:
        def _boom(*a, **kw):
            raise httpx.ConnectError("refused")
        monkeypatch.setattr(client._http, "post", _boom)
        with pytest.raises(ConnectionError, match="Proxy unreachable"):
            client.login_via_proxy_with_local_key()
    finally:
        client.close()


def test_mastio_signature_absent_omits_header(monkeypatch):
    """Legacy proxy without ADR-009 Phase 2 mastio identity → the
    response has ``mastio_signature: None``; the SDK must not forward
    an empty X-Cullis-Mastio-Signature header."""
    client = _build_client()
    try:
        nonce = base64.urlsafe_b64encode(b"\x33" * 32).rstrip(b"=").decode()
        posted = _script_http(monkeypatch, client, [
            ("/v1/auth/login-challenge",
             _Resp(200, {"nonce": nonce, "expires_in": 120, "agent_id": AGENT_ID})),
            ("/v1/auth/sign-challenged-assertion",
             _Resp(200, {"client_assertion": "x.y.z",
                         "agent_id": AGENT_ID,
                         "mastio_signature": None})),
            ("/v1/auth/token",
             _Resp(200, {"access_token": "tok"})),
        ])
        client.login_via_proxy_with_local_key()
        token_headers = posted[2][2]
        assert "X-Cullis-Mastio-Signature" not in token_headers
    finally:
        client.close()


def test_from_connector_loads_both_key_and_cert(tmp_path):
    """Regression: ``from_connector`` must populate BOTH
    ``_signing_key_pem`` and ``_cert_pem`` so the new login path works
    without the caller re-reading the files."""
    import json
    identity_dir = tmp_path / "identity"
    identity_dir.mkdir()
    (identity_dir / "agent.key").write_text(_key_pem())
    (identity_dir / "agent.crt").write_text(_cert_pem())
    (identity_dir / "api_key").write_text("api-key-blob")
    (identity_dir / "metadata.json").write_text(json.dumps({
        "agent_id": f"{ORG_ID}::{AGENT_ID}",
        "site_url": "http://mastio.test",
    }))

    client = CullisClient.from_connector(tmp_path, enable_dpop=False)
    try:
        assert client._signing_key_pem is not None
        assert "BEGIN" in client._signing_key_pem
        assert client._cert_pem is not None
        assert "BEGIN CERTIFICATE" in client._cert_pem
    finally:
        client.close()
