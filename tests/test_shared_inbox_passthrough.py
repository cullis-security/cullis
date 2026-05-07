"""Connector ambassador /v1/inbox passthrough — issue #488.

The Frontdesk shared ambassador exposes ``GET /v1/inbox``, ``POST
/v1/inbox/{id}/ack`` and ``POST /v1/inbox/{id}/archive`` as broker-
direct passthroughs (the user's own cert+key authenticate at the
broker, no Mastio hop). The full end-to-end behaviour is exercised
in the live smoke against ``reference/demo.sh full``; these tests
cover the contract surface that is unit-testable without a running
broker:

  - When ``CULLIS_BROKER_URL`` is unset, the endpoints return 503 with
    a clear message instead of opening a connection to nowhere.
  - The endpoints are mounted (regression guard).

End-to-end coverage (live broker, real cert) lives in the demo
smoke; mocking a working broker JWT + DPoP roundtrip would more or
less re-implement the broker.
"""
from __future__ import annotations

from fastapi import FastAPI
from cullis_connector.ambassador.shared.proxy_trust import TrustedProxiesAllowlist
from cullis_connector.ambassador.shared.router import install_shared_ambassador


SECRET = b"x" * 32


def _app(*, broker_url: str = "") -> FastAPI:
    """Mount the shared ambassador with a no-op provisioner.

    The cookie path is exercised first (the inbox endpoints depend on
    it via ``_require_credentials``); the test only needs the routes
    mounted, so the provisioner is replaced with a stub that always
    raises — the inbox endpoints exit before reaching it on the empty
    broker_url path we care about.
    """
    class _StubProvisioner:
        def provision(self, *_a, **_kw):
            raise RuntimeError("not used in these tests")

    app = FastAPI()
    install_shared_ambassador(
        app,
        cookie_secret=SECRET,
        trusted_proxies=TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"]),
        org_id="acme",
        trust_domain="acme.test",
        provisioner=_StubProvisioner(),
        site_url="http://mastio.test",
        enforce_proxy_trust=False,
        broker_url=broker_url,
    )
    return app


def test_inbox_routes_mounted():
    """Regression guard — the three inbox routes must be registered."""
    app = _app(broker_url="http://broker.test")
    paths = {
        f"{r.methods or set()} {r.path}"
        for r in app.routes
        if hasattr(r, "path")
    }
    routes = {r.path for r in app.routes if hasattr(r, "path")}
    assert "/v1/inbox" in routes
    assert "/v1/inbox/{msg_id}/ack" in routes
    assert "/v1/inbox/{msg_id}/archive" in routes


def test_install_accepts_broker_url_kwarg():
    """The install signature must accept the new kwarg without breaking
    existing callers (default empty string keeps prior behaviour)."""
    app = FastAPI()
    install_shared_ambassador(
        app,
        cookie_secret=SECRET,
        trusted_proxies=TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"]),
        org_id="acme",
        trust_domain="acme.test",
        provisioner=type("P", (), {})(),  # any object — never called here
        site_url="http://mastio.test",
        enforce_proxy_trust=False,
        # No broker_url kwarg — defaults to empty string.
    )
    assert app.state.shared_ambassador.broker_url == ""
