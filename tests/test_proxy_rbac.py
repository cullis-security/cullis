"""Tests for ``mcp_proxy.rbac`` and the multi-role extension to
``ProxyDashboardSession``.

Covers the back-compat surface (single-role cookies / single-role callers
keep working unchanged) and the new ``roles`` tuple consumed by
``require_role``. The enterprise plugin ``rbac_multi_admin`` lives in the
private cullis-enterprise repo and tests the full DB-backed login flow;
the unit tests here only exercise the core hook surface.
"""
from __future__ import annotations

import json as _json
import time as _time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── ProxyDashboardSession back-compat ────────────────────────────────


def test_session_default_roles_mirrors_role():
    from mcp_proxy.dashboard.session import ProxyDashboardSession
    s = ProxyDashboardSession(role="admin")
    assert s.roles == ("admin",)


def test_session_explicit_roles_kept():
    from mcp_proxy.dashboard.session import ProxyDashboardSession
    s = ProxyDashboardSession(role="operator", roles=("operator", "viewer"))
    assert s.role == "operator"
    assert s.roles == ("operator", "viewer")


def test_session_empty_role_yields_empty_roles():
    from mcp_proxy.dashboard.session import ProxyDashboardSession
    s = ProxyDashboardSession(role="", logged_in=False)
    assert s.roles == ()


# ── Cookie round-trip back-compat ────────────────────────────────────


def _signed_cookie(payload: dict) -> str:
    from mcp_proxy.dashboard.session import _sign
    return _sign(_json.dumps(payload))


def test_legacy_cookie_without_roles_field_still_loads():
    """Cookies issued before this change have no ``roles`` key. Reading them
    must yield ``roles == (role,)`` so existing logged-in users don't lose
    their session on rollout."""
    from mcp_proxy.dashboard.session import _COOKIE_NAME, get_session
    from starlette.requests import Request

    legacy_payload = {
        "role": "admin",
        "csrf_token": "abc",
        "exp": int(_time.time()) + 3600,
    }
    cookie_value = _signed_cookie(legacy_payload)
    scope = {
        "type": "http",
        "headers": [(b"cookie", f"{_COOKIE_NAME}={cookie_value}".encode())],
    }
    req = Request(scope)
    s = get_session(req)
    assert s.logged_in is True
    assert s.role == "admin"
    assert s.roles == ("admin",)


def test_new_cookie_with_roles_round_trips():
    from mcp_proxy.dashboard.session import _COOKIE_NAME, get_session
    from starlette.requests import Request

    payload = {
        "role": "operator",
        "roles": ["operator", "viewer"],
        "csrf_token": "abc",
        "exp": int(_time.time()) + 3600,
    }
    cookie_value = _signed_cookie(payload)
    scope = {
        "type": "http",
        "headers": [(b"cookie", f"{_COOKIE_NAME}={cookie_value}".encode())],
    }
    s = get_session(Request(scope))
    assert s.logged_in is True
    assert s.role == "operator"
    assert s.roles == ("operator", "viewer")


def test_set_session_default_back_compat(monkeypatch):
    """``set_session(response, role='admin')`` (no ``roles``) must produce
    a cookie that round-trips into ``roles=('admin',)`` — guarantees the
    one production callsite in dashboard/router.py keeps working."""
    from fastapi import Response
    from mcp_proxy.dashboard.session import (
        _COOKIE_NAME, get_session, set_session,
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)

    response = Response()
    set_session(response, role="admin")
    cookie_header = response.headers["set-cookie"]
    cookie_value = cookie_header.split(";", 1)[0].split("=", 1)[1]

    from starlette.requests import Request
    scope = {
        "type": "http",
        "headers": [(b"cookie", f"{_COOKIE_NAME}={cookie_value}".encode())],
    }
    s = get_session(Request(scope))
    assert s.role == "admin"
    assert s.roles == ("admin",)
    get_settings.cache_clear()


def test_set_session_explicit_roles(monkeypatch):
    from fastapi import Response
    from mcp_proxy.dashboard.session import (
        _COOKIE_NAME, get_session, set_session,
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)

    response = Response()
    set_session(response, role="viewer", roles=("viewer",))
    cookie_value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]

    from starlette.requests import Request
    scope = {
        "type": "http",
        "headers": [(b"cookie", f"{_COOKIE_NAME}={cookie_value}".encode())],
    }
    s = get_session(Request(scope))
    assert s.role == "viewer"
    assert s.roles == ("viewer",)
    get_settings.cache_clear()


# ── require_role gate behaviour ──────────────────────────────────────


def _app_with_role_gate(*roles: str) -> TestClient:
    from mcp_proxy.rbac import require_role

    app = FastAPI()

    @app.get("/protected")
    def protected(session=__import__(
        "fastapi", fromlist=["Depends"],
    ).Depends(require_role(*roles))):
        return {"role": session.role, "roles": list(session.roles)}

    return TestClient(app)


def _login_client(client: TestClient, role: str, roles: tuple[str, ...] | None = None):
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign
    payload = {
        "role": role,
        "csrf_token": "csrf",
        "exp": int(_time.time()) + 3600,
    }
    if roles is not None:
        payload["roles"] = list(roles)
    client.cookies.set(_COOKIE_NAME, _sign(_json.dumps(payload)))


def test_require_role_admin_implicit(monkeypatch):
    """Admin role passes every gate even without being declared."""
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    client = _app_with_role_gate("operator")
    _login_client(client, role="admin")
    r = client.get("/protected")
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"


def test_require_role_unauth_returns_401(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    client = _app_with_role_gate("operator")
    r = client.get("/protected")
    assert r.status_code == 401


def test_require_role_mismatch_returns_403(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    client = _app_with_role_gate("operator")
    _login_client(client, role="viewer", roles=("viewer",))
    r = client.get("/protected")
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "role_required"
    assert r.json()["detail"]["allowed"] == ["operator"]


def test_require_role_match_returns_200(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 32)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    client = _app_with_role_gate("operator", "viewer")
    _login_client(client, role="operator", roles=("operator",))
    r = client.get("/protected")
    assert r.status_code == 200
    assert r.json()["roles"] == ["operator"]


def test_require_role_empty_args_raises():
    from mcp_proxy.rbac import require_role
    with pytest.raises(ValueError):
        require_role()


# ── helpers ──────────────────────────────────────────────────────────


def test_has_role_true_false():
    from mcp_proxy.dashboard.session import ProxyDashboardSession
    from mcp_proxy.rbac import has_role
    s = ProxyDashboardSession(role="operator", roles=("operator", "viewer"))
    assert has_role(s, "operator") is True
    assert has_role(s, "viewer") is True
    assert has_role(s, "admin") is False


def test_has_role_logged_out_session():
    from mcp_proxy.dashboard.session import ProxyDashboardSession
    from mcp_proxy.rbac import has_role
    s = ProxyDashboardSession(role="none", logged_in=False)
    assert has_role(s, "admin") is False


def test_filter_roles_dedup_preserves_order():
    from mcp_proxy.rbac import filter_roles
    assert filter_roles(["admin", "viewer", "admin", "", "operator", "viewer"]) == (
        "admin", "viewer", "operator",
    )
