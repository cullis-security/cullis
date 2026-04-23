"""Tests for the ``pubkey_fetcher`` injection into
:meth:`CullisClient.decrypt_oneshot`, the new
:meth:`CullisClient.get_agent_public_key_via_egress` egress-only helper,
and the default proxy-then-broker chain
:meth:`CullisClient._fetch_pubkey_proxy_then_broker`.

Covers:
  - default chain: proxy path hit first, broker fallback ONLY on
    404 / 501 / cert_pem=null. 401 / transport errors propagate
    without fallback (preserves diagnostic signal);
  - explicit ``pubkey_fetcher`` still overrides the default;
  - egress-only helper fail-fast contract for device-code callers.
"""
from __future__ import annotations

import time
import uuid

import pytest

from cullis_sdk.client import CullisClient, PubkeyFetchError

from tests.test_audit_oneshot_envelope_integrity import (
    _alice_cert_pem,
    _inbox_row,
    _mtls_envelope,
)


def _client() -> CullisClient:
    """Fresh client with no pubkey cache — forces the fetcher path."""
    c = CullisClient("http://test", verify_tls=False)
    return c


def test_decrypt_oneshot_uses_injected_fetcher_mtls_mode():
    sender = "fetch1::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch1",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"note": "hello"},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    calls: list[str] = []

    def fetcher(agent_id: str) -> str:
        calls.append(agent_id)
        return _alice_cert_pem(sender, "fetch1")

    client = _client()
    try:
        result = client.decrypt_oneshot(row, pubkey_fetcher=fetcher)
    finally:
        client.close()

    assert calls == [sender]
    assert result["mode"] == "mtls-only"
    assert result["sender_verified"] is True
    assert result["payload"] == {"note": "hello"}


def test_decrypt_oneshot_propagates_fetcher_error():
    sender = "fetch2::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch2",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"x": 1},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    def failing_fetcher(agent_id: str) -> str:
        raise PubkeyFetchError("proxy returned no cert_pem for " + agent_id)

    client = _client()
    try:
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.decrypt_oneshot(row, pubkey_fetcher=failing_fetcher)
    finally:
        client.close()
    assert sender in str(excinfo.value)


def test_decrypt_oneshot_default_fetcher_uses_cache_shortcut():
    """The default fetcher checks ``_pubkey_cache`` first before any HTTP —
    a pre-populated cache means no proxy/broker call is made. Covers
    the common case where a previous receive already cached the sender."""
    sender = "fetch3::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch3",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"x": 2},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    client = _client()
    try:
        client._pubkey_cache[sender] = (
            _alice_cert_pem(sender, "fetch3"), time.time(),
        )
        result = client.decrypt_oneshot(row)
    finally:
        client.close()

    assert result["sender_verified"] is True


class _StubResponse:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=None, response=None,
            )


def test_get_agent_public_key_via_egress_happy_path(monkeypatch):
    client = _client()
    try:
        cert = "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----"

        def fake_egress_http(method, path, **kwargs):
            assert method == "get"
            assert path == "/v1/egress/agents/acme::alice/public-key"
            return _StubResponse(200, {"agent_id": "acme::alice", "cert_pem": cert})

        monkeypatch.setattr(client, "_egress_http", fake_egress_http)
        pem = client.get_agent_public_key_via_egress("acme::alice")
        assert pem == cert
        # Cache hit on the second call, no HTTP.
        calls = {"n": 0}

        def count_and_fail(*_a, **_kw):
            calls["n"] += 1
            return _StubResponse(500)
        monkeypatch.setattr(client, "_egress_http", count_and_fail)
        pem2 = client.get_agent_public_key_via_egress("acme::alice")
        assert pem2 == cert
        assert calls["n"] == 0
    finally:
        client.close()


def test_get_agent_public_key_via_egress_raises_on_empty_cert(monkeypatch):
    client = _client()
    try:
        def fake_egress_http(method, path, **kwargs):
            return _StubResponse(200, {"agent_id": "acme::ghost", "cert_pem": None})
        monkeypatch.setattr(client, "_egress_http", fake_egress_http)
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.get_agent_public_key_via_egress("acme::ghost")
        assert "acme::ghost" in str(excinfo.value)
    finally:
        client.close()


def test_get_agent_public_key_via_egress_wraps_transport_errors(monkeypatch):
    client = _client()
    try:
        def boom(*_a, **_kw):
            raise RuntimeError("network went away")
        monkeypatch.setattr(client, "_egress_http", boom)
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.get_agent_public_key_via_egress("acme::alice")
        assert "network went away" in str(excinfo.value)
    finally:
        client.close()


# ── Default fetcher: proxy-first, broker fallback on 404/501/cert=null ──


def _make_raise_for_status(status_code):
    """Build a raise_for_status method that mirrors httpx behaviour."""
    def raise_for_status(self):
        if status_code >= 400:
            import httpx
            # httpx.HTTPStatusError needs a response object with a
            # ``status_code`` attribute; build a minimal stub.
            class _Resp:
                pass
            resp = _Resp()
            resp.status_code = status_code
            raise httpx.HTTPStatusError(
                f"HTTP {status_code}", request=None, response=resp,
            )
    return raise_for_status


class _ProxyResp:
    def __init__(self, status_code: int, cert_pem=None):
        self.status_code = status_code
        self._body = {"agent_id": "x", "cert_pem": cert_pem}

    def json(self):
        return self._body

    def raise_for_status(self):
        _make_raise_for_status(self.status_code)(self)


def test_default_fetcher_proxy_happy_path(monkeypatch):
    """Default chain: proxy returns 200 + cert_pem → no broker call."""
    sender = "chain1::alice"
    cert_pem = _alice_cert_pem(sender, "chain1")
    corr, nonce, ts = str(uuid.uuid4()), str(uuid.uuid4()), int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="chain1",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"ok": True},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    client = _client()
    try:
        proxy_calls = []

        def fake_egress(method, path, **_):
            proxy_calls.append((method, path))
            return _ProxyResp(200, cert_pem=cert_pem)

        broker_hits = {"n": 0}

        def fake_broker(agent_id, force_refresh=False):
            broker_hits["n"] += 1
            return "should-not-be-used"

        monkeypatch.setattr(client, "_egress_http", fake_egress)
        monkeypatch.setattr(client, "get_agent_public_key", fake_broker)

        result = client.decrypt_oneshot(row)
        assert result["sender_verified"] is True
        assert proxy_calls == [("get", f"/v1/egress/agents/{sender}/public-key")]
        assert broker_hits["n"] == 0
    finally:
        client.close()


def _decrypt_with_default_chain(
    monkeypatch, client, sender, org, *, proxy_resp, broker_return=None,
    broker_exc=None,
):
    """Helper — wire the default chain onto the client and run a
    decrypt_oneshot. Returns the result (or raises on failure)."""
    corr, nonce, ts = str(uuid.uuid4()), str(uuid.uuid4()), int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id=org,
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"n": 1},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    def fake_egress(method, path, **_):
        if callable(proxy_resp):
            return proxy_resp()
        return proxy_resp

    def fake_broker(agent_id, force_refresh=False):
        if broker_exc is not None:
            raise broker_exc
        return broker_return

    monkeypatch.setattr(client, "_egress_http", fake_egress)
    monkeypatch.setattr(client, "get_agent_public_key", fake_broker)
    return client.decrypt_oneshot(row)


def test_default_fetcher_falls_back_to_broker_on_proxy_404(monkeypatch):
    """Proxy 404 (endpoint missing on old proxy OR agent unknown to proxy)
    → fallback to broker. Broker has the cert → decrypt succeeds."""
    sender = "chain2::alice"
    client = _client()
    try:
        result = _decrypt_with_default_chain(
            monkeypatch, client, sender, "chain2",
            proxy_resp=_ProxyResp(404),
            broker_return=_alice_cert_pem(sender, "chain2"),
        )
        assert result["sender_verified"] is True
    finally:
        client.close()


def test_default_fetcher_falls_back_to_broker_on_proxy_501(monkeypatch):
    """501 Not Implemented → same fallback story as 404."""
    sender = "chain3::alice"
    client = _client()
    try:
        result = _decrypt_with_default_chain(
            monkeypatch, client, sender, "chain3",
            proxy_resp=_ProxyResp(501),
            broker_return=_alice_cert_pem(sender, "chain3"),
        )
        assert result["sender_verified"] is True
    finally:
        client.close()


def test_default_fetcher_falls_back_on_proxy_cert_pem_null(monkeypatch):
    """200 with cert_pem=null means 'proxy got the request but doesn't
    know this agent' (e.g. cross-org with no broker bridge wired on the
    proxy). Still a fallback condition — broker might have it."""
    sender = "chain4::alice"
    client = _client()
    try:
        result = _decrypt_with_default_chain(
            monkeypatch, client, sender, "chain4",
            proxy_resp=_ProxyResp(200, cert_pem=None),
            broker_return=_alice_cert_pem(sender, "chain4"),
        )
        assert result["sender_verified"] is True
    finally:
        client.close()


def test_default_fetcher_no_fallback_on_proxy_401(monkeypatch):
    """401 = auth broken. Falling back to the broker would just surface
    the same auth failure (or worse, mask it) — propagate immediately
    as PubkeyFetchError so the operator sees the real problem."""
    sender = "chain5::alice"
    client = _client()
    try:
        broker_calls = {"n": 0}

        def broker(agent_id, force_refresh=False):
            broker_calls["n"] += 1
            return "UNUSED"

        monkeypatch.setattr(client, "get_agent_public_key", broker)

        with pytest.raises(PubkeyFetchError, match="HTTP 401"):
            _decrypt_with_default_chain(
                monkeypatch, client, sender, "chain5",
                proxy_resp=_ProxyResp(401),
                broker_return="UNUSED",
            )
        # Critical: broker was never called. 401 = no fallback.
        assert broker_calls["n"] == 0
    finally:
        client.close()


def test_default_fetcher_no_fallback_on_transport_error(monkeypatch):
    """Network / connection errors = environment broken, not endpoint
    missing. Propagate without touching broker (same auth likely fails)."""
    sender = "chain6::alice"
    client = _client()
    try:
        broker_calls = {"n": 0}

        def broker(agent_id, force_refresh=False):
            broker_calls["n"] += 1
            return "UNUSED"

        monkeypatch.setattr(client, "get_agent_public_key", broker)

        def exploding_proxy():
            raise RuntimeError("connection refused")

        with pytest.raises(PubkeyFetchError, match="transport failure"):
            _decrypt_with_default_chain(
                monkeypatch, client, sender, "chain6",
                proxy_resp=exploding_proxy,
                broker_return="UNUSED",
            )
        assert broker_calls["n"] == 0
    finally:
        client.close()


def test_default_fetcher_both_fail_surfaces_both_diagnostics(monkeypatch):
    """Proxy 404 → fallback broker → broker also errors. The raised
    PubkeyFetchError message should mention BOTH so an operator can see
    why both lookups failed without having to re-run with DEBUG logs."""
    sender = "chain7::alice"
    client = _client()
    try:
        with pytest.raises(PubkeyFetchError) as excinfo:
            _decrypt_with_default_chain(
                monkeypatch, client, sender, "chain7",
                proxy_resp=_ProxyResp(404),
                broker_exc=RuntimeError("broker unreachable"),
            )
        msg = str(excinfo.value)
        assert "404" in msg
        assert "broker unreachable" in msg
    finally:
        client.close()


def test_explicit_pubkey_fetcher_still_overrides_default(monkeypatch):
    """When the caller passes pubkey_fetcher explicitly, NEITHER the
    proxy nor the broker path runs — backward compat for tests and for
    Connector device-code callers that pin the egress-only helper."""
    sender = "chain8::alice"
    client = _client()
    try:
        proxy_calls = {"n": 0}
        broker_calls = {"n": 0}

        monkeypatch.setattr(
            client, "_egress_http",
            lambda *a, **kw: (proxy_calls.__setitem__("n", proxy_calls["n"] + 1) or _ProxyResp(500)),
        )
        monkeypatch.setattr(
            client, "get_agent_public_key",
            lambda *a, **kw: (broker_calls.__setitem__("n", broker_calls["n"] + 1) or "UNUSED"),
        )

        fetcher_calls = []

        def custom(agent_id):
            fetcher_calls.append(agent_id)
            return _alice_cert_pem(sender, "chain8")

        corr, nonce, ts = str(uuid.uuid4()), str(uuid.uuid4()), int(time.time())
        env = _mtls_envelope(
            sender_agent_id=sender, sender_org_id="chain8",
            correlation_id=corr, nonce=nonce, timestamp=ts,
            payload={"x": 1},
        )
        row = _inbox_row(env, sender_agent_id=sender)
        client.decrypt_oneshot(row, pubkey_fetcher=custom)

        assert fetcher_calls == [sender]
        assert proxy_calls["n"] == 0
        assert broker_calls["n"] == 0
    finally:
        client.close()


def test_get_agent_public_key_via_egress_force_refresh(monkeypatch):
    client = _client()
    try:
        cert1 = "CERT-V1"
        cert2 = "CERT-V2"
        state = {"cert": cert1}

        def fake_egress_http(method, path, **kwargs):
            return _StubResponse(200, {"agent_id": "acme::alice", "cert_pem": state["cert"]})
        monkeypatch.setattr(client, "_egress_http", fake_egress_http)

        assert client.get_agent_public_key_via_egress("acme::alice") == cert1
        state["cert"] = cert2
        # Without force_refresh, TTL cache still returns V1.
        assert client.get_agent_public_key_via_egress("acme::alice") == cert1
        # With force_refresh=True, HTTP is re-hit.
        assert client.get_agent_public_key_via_egress(
            "acme::alice", force_refresh=True,
        ) == cert2
    finally:
        client.close()
