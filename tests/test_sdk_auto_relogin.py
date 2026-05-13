"""Tests for the CullisClient auto-relogin path on token-expiry 401.

The Mastio's LOCAL_TOKEN has a finite TTL (typically 1h for
autonomous agents). Before this PR, ``_authed_request`` returned the
401 verbatim and the caller had to re-login + retry by hand. The
insurance-demo agents on cullis-vm crash-looped on the same claim
forever once the token expired — observed live on 2026-05-13.

The new behavior: a 401 that is NOT a DPoP nonce challenge triggers
``self._relogin_callable`` once (set by the login method that last
minted the token), then retries the request. A second 401 propagates.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from cullis_sdk.client import CullisClient


class _Resp:
    def __init__(self, status_code: int, body: dict | None = None,
                 text_body: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
        self._text = text_body or ""
        self.headers = headers or {}

    def json(self):
        return self._body

    @property
    def text(self):
        return self._text or str(self._body)


def _client_with_token(token: str = "TOKEN-1") -> CullisClient:
    c = CullisClient("http://mastio.test", verify_tls=False)
    c.token = token
    # Stub DPoP so _headers() doesn't blow up at request time.
    c._dpop_proof = lambda *_a, **_k: "fake-dpop-proof"  # type: ignore[method-assign]
    return c


def test_authed_request_success_does_not_relogin():
    """200 on first try → relogin never invoked."""
    c = _client_with_token()
    relogin_calls = []
    c._relogin_callable = lambda: relogin_calls.append("called")

    sent = []
    def _request(method, url, headers=None, **kw):
        sent.append((method, url))
        return _Resp(200, body={"ok": True})
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("GET", "/v1/mcp")
    assert resp.status_code == 200
    assert len(sent) == 1
    assert relogin_calls == []


def test_authed_request_401_token_expired_triggers_relogin_and_retries():
    """First call 401 (no DPoP-nonce marker) → relogin fires → retry succeeds."""
    c = _client_with_token()

    relogin_calls = []
    def _relogin():
        relogin_calls.append("called")
        c.token = "TOKEN-2"  # simulate fresh mint
    c._relogin_callable = _relogin

    responses = iter([
        _Resp(401, body={"detail": "token expired"}, text_body="token expired"),
        _Resp(200, body={"ok": True}),
    ])
    sent = []
    def _request(method, url, headers=None, **kw):
        sent.append((method, url, headers.get("Authorization") if headers else None))
        return next(responses)
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("POST", "/v1/mcp")
    assert resp.status_code == 200
    assert relogin_calls == ["called"]
    assert len(sent) == 2
    # Second request used the freshly-minted token.
    assert "TOKEN-2" in sent[1][2]


def test_authed_request_401_after_relogin_propagates():
    """If the retry ALSO 401s, the second 401 is returned (no infinite loop)."""
    c = _client_with_token()
    relogin_calls = []
    def _relogin():
        relogin_calls.append("called")
        c.token = "TOKEN-2"
    c._relogin_callable = _relogin

    responses = iter([
        _Resp(401, body={"detail": "expired"}, text_body="expired"),
        _Resp(401, body={"detail": "still bad"}, text_body="still bad"),
    ])
    def _request(method, url, headers=None, **kw):
        return next(responses)
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("POST", "/v1/mcp")
    assert resp.status_code == 401
    # Relogin was attempted exactly once, not twice.
    assert relogin_calls == ["called"]


def test_authed_request_dpop_nonce_path_does_not_relogin():
    """The existing DPoP nonce challenge path must still work — the
    response carries the marker and is replayed with the SAME token,
    not relogged-in."""
    c = _client_with_token()
    relogin_calls = []
    c._relogin_callable = lambda: relogin_calls.append("called")

    responses = iter([
        _Resp(401, body={"error": "use_dpop_nonce"},
              text_body='{"error":"use_dpop_nonce"}'),
        _Resp(200, body={"ok": True}),
    ])
    def _request(method, url, headers=None, **kw):
        return next(responses)
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("POST", "/v1/mcp")
    assert resp.status_code == 200
    # Relogin must NOT have fired — DPoP nonce challenge replays
    # with the same token, not a fresh one.
    assert relogin_calls == []


def test_authed_request_no_relogin_callable_propagates_401():
    """Clients without a relogin callable (e.g. direct cert-only bootstraps)
    see the 401 verbatim — backwards-compatible with the pre-fix path."""
    c = _client_with_token()
    assert c._relogin_callable is None

    def _request(method, url, headers=None, **kw):
        return _Resp(401, body={"detail": "expired"}, text_body="expired")
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("POST", "/v1/mcp")
    assert resp.status_code == 401


def test_authed_request_relogin_exception_propagates_original_401():
    """If the relogin callable itself blows up (proxy unreachable, cert
    revoked), the caller sees the ORIGINAL 401, not the secondary
    exception — same observable behavior as before the auto-retry."""
    c = _client_with_token()
    def _relogin():
        raise ConnectionError("proxy down")
    c._relogin_callable = _relogin

    def _request(method, url, headers=None, **kw):
        return _Resp(401, body={"detail": "expired"}, text_body="expired")
    c._http.request = _request  # type: ignore[method-assign]

    resp = c._authed_request("POST", "/v1/mcp")
    assert resp.status_code == 401
