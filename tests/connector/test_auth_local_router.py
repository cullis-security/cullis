"""Integration tests for /api/auth/* — ADR-025 Phase 2.

Drives ``cullis_connector.web.build_app`` via fastapi.testclient and
asserts the login + change-password + whoami contracts: cookie
issuance, must_change_password gating, generic 401 on every credential
failure, logout cookie clearing, runtime-info no-auth path.

Each test gets a fresh ``tmp_path`` so the per-test users.db + cookie
secret are isolated from siblings.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    parse_local_cookie,
)
from cullis_connector.identity.users_db import dispose_users_engines
from cullis_connector.web import build_app


ADMIN_SECRET = "test-admin-secret-not-default"


@pytest.fixture(autouse=True)
async def _cleanup_engines():
    yield
    await dispose_users_engines()


@pytest.fixture
def connector_config(tmp_path):
    cfg = ConnectorConfig(
        config_dir=tmp_path / "connector",
        site_url="http://mastio.test",
        verify_tls=False,
    )
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    return cfg


@pytest.fixture
def client(connector_config, monkeypatch):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    # Allow non-Secure cookie under TestClient (http://testserver)
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    app = build_app(connector_config)
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"
    return tc


def _admin_headers() -> dict[str, str]:
    return {"X-Admin-Secret": ADMIN_SECRET}


def _create_user(
    client: TestClient,
    *,
    user_name: str,
    password: str,
    must_change: bool = True,
) -> None:
    r = client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": user_name,
            "password": password,
            "must_change_password": must_change,
        },
    )
    assert r.status_code == 201, r.text


def _cookie_secret(client: TestClient) -> bytes:
    """Read the on-disk cookie secret bootstrapped by the router.

    Used to manually parse the issued cookie in assertions without
    going through the router again.
    """
    config_dir = client.app.state.connector_config.config_dir
    return (config_dir / "cookie.secret").read_bytes()


# ── runtime-info (no auth) ───────────────────────────────────────────────


def test_runtime_info_returns_local_mode_no_auth(client):
    r = client.get("/api/auth/runtime-info")
    assert r.status_code == 200
    body = r.json()
    assert body["auth_mode"] == "local"
    assert body["login_url"] == "/login"
    assert body["require_change_password_url"] == "/change-password"


def test_runtime_info_does_not_set_cookie(client):
    r = client.get("/api/auth/runtime-info")
    assert r.status_code == 200
    assert LOCAL_SESSION_COOKIE_NAME not in r.cookies


# ── login: success path ─────────────────────────────────────────────────


def test_login_success_must_change_true_sets_cookie(client):
    _create_user(
        client, user_name="mario", password="temp123!secure", must_change=True,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "temp123!secure"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["must_change_password"] is True
    assert body["principal_name"] == "mario"
    assert body["exp"] > 0

    # Cookie issued
    raw = r.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    assert raw, "expected cookie to be set"
    payload = parse_local_cookie(raw, _cookie_secret(client))
    assert payload is not None
    assert payload.user_name == "mario"
    assert payload.must_change_password is True


def test_login_success_must_change_false(client):
    _create_user(
        client,
        user_name="alice",
        password="longpassword",
        must_change=False,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "alice", "password": "longpassword"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["must_change_password"] is False


# ── login: failure paths ─────────────────────────────────────────────────


def test_login_wrong_password_returns_401_generic(client):
    _create_user(client, user_name="mario", password="longpassword")
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "WRONG-pass"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"
    assert LOCAL_SESSION_COOKIE_NAME not in r.cookies


def test_login_unknown_user_returns_same_401_message(client):
    """Username enumeration defence — same code + message as wrong pw."""
    r = client.post(
        "/api/auth/login",
        json={"user_name": "ghost", "password": "anything-here"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_disabled_user_rejected(client, connector_config):
    """A disabled user cannot log in even with the right password."""
    from sqlalchemy import update

    from cullis_connector.identity.users import LocalUser
    from cullis_connector.identity.users_db import get_users_session

    _create_user(
        client, user_name="disabled-user", password="longpassword",
        must_change=False,
    )

    # Manually flip the disabled column — there is no admin endpoint
    # for it yet (Phase 1 didn't ship one).
    import asyncio

    async def _disable():
        async with get_users_session(connector_config.config_dir) as session:
            await session.execute(
                update(LocalUser)
                .where(LocalUser.user_name == "disabled-user")
                .values(disabled=1),
            )

    asyncio.get_event_loop().run_until_complete(_disable())

    r = client.post(
        "/api/auth/login",
        json={"user_name": "disabled-user", "password": "longpassword"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_validation_error_short_user_name(client):
    r = client.post(
        "/api/auth/login",
        json={"user_name": "", "password": "longpassword"},
    )
    # Pydantic min_length=1 → 422
    assert r.status_code == 422


# ── whoami-local ─────────────────────────────────────────────────────────


def test_whoami_local_requires_cookie(client):
    r = client.get("/api/auth/whoami-local")
    assert r.status_code == 401


def test_whoami_local_returns_payload_after_login(client):
    _create_user(
        client, user_name="mario", password="longpassword", must_change=True,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 200
    # TestClient session keeps cookies across requests.
    r2 = client.get("/api/auth/whoami-local")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["user_name"] == "mario"
    assert body["must_change_password"] is True
    assert body["principal_name"] == "mario"
    assert body["exp"] > 0


def test_whoami_local_rejects_tampered_cookie(client):
    _create_user(client, user_name="mario", password="longpassword")
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    # Replace the cookie with garbage and confirm the dep rejects it.
    client.cookies.set(LOCAL_SESSION_COOKIE_NAME, "tampered.value")
    r = client.get("/api/auth/whoami-local")
    assert r.status_code == 401


# ── change-password ──────────────────────────────────────────────────────


def test_change_password_happy_path_clears_must_change(client):
    _create_user(
        client, user_name="mario", password="oldpassword", must_change=True,
    )
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "oldpassword"},
    )
    r = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "oldpassword",
            "new_password": "fresh-and-long-enough",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["must_change_password"] is False

    # Cookie reissued with must_change=False
    raw = r.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    assert raw
    parsed = parse_local_cookie(raw, _cookie_secret(client))
    assert parsed is not None
    assert parsed.must_change_password is False
    assert parsed.user_name == "mario"

    # And subsequent login uses the new password.
    client.cookies.clear()
    r2 = client.post(
        "/api/auth/login",
        json={
            "user_name": "mario",
            "password": "fresh-and-long-enough",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["must_change_password"] is False


def test_change_password_wrong_old_returns_401(client):
    _create_user(client, user_name="mario", password="oldpassword")
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "oldpassword"},
    )
    r = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "WRONG-old-pw",
            "new_password": "fresh-and-long-enough",
        },
    )
    assert r.status_code == 401


def test_change_password_too_short_returns_400_or_422(client):
    _create_user(client, user_name="mario", password="oldpassword")
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "oldpassword"},
    )
    r = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "oldpassword",
            "new_password": "short",
        },
    )
    assert r.status_code in (400, 422)


def test_change_password_requires_cookie(client):
    _create_user(client, user_name="mario", password="oldpassword")
    r = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "oldpassword",
            "new_password": "fresh-and-long-enough",
        },
    )
    assert r.status_code == 401


# ── logout ───────────────────────────────────────────────────────────────


def test_logout_clears_cookie_via_max_age_zero(client):
    _create_user(client, user_name="mario", password="longpassword")
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert LOCAL_SESSION_COOKIE_NAME in set_cookie
    assert "Max-Age=0" in set_cookie or "max-age=0" in set_cookie.lower()


def test_logout_without_cookie_is_no_op(client):
    """Idempotent logout — no auth required, succeeds for stateless clients."""
    r = client.post("/api/auth/logout")
    assert r.status_code == 200


def test_post_logout_cookie_invalid_on_whoami(client):
    _create_user(client, user_name="mario", password="longpassword")
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    client.post("/api/auth/logout")
    # TestClient mirrors the Set-Cookie Max-Age=0 by removing the cookie.
    r = client.get("/api/auth/whoami-local")
    assert r.status_code == 401


# ── server-side fallback HTML ────────────────────────────────────────────


def test_login_page_renders(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in" in r.text


def test_change_password_page_renders(client):
    r = client.get("/change-password")
    assert r.status_code == 200
    assert "Set a" in r.text or "new password" in r.text


# ── AUTH_MODE gating ─────────────────────────────────────────────────────


def test_auth_local_router_not_mounted_when_oidc(connector_config, monkeypatch):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "oidc")
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    app = build_app(connector_config)
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"
    r = tc.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 404
    r2 = tc.get("/api/auth/runtime-info")
    assert r2.status_code == 404


# ── Issue #634 — deferred provisioning header sanitization ───────────────


def test_sanitize_header_value_strips_lf_cr_and_truncates():
    from cullis_connector.auth.local_router import _sanitize_header_value

    assert _sanitize_header_value("one line") == "one line"
    # LF / CR / tab / vertical-tab / null — every control byte goes
    assert _sanitize_header_value("a\nb\rc\td\ve") == "a b c d e"
    # Multi-line httpx-style error message (the real-world case from
    # issue #634)
    httpx_style = (
        "transport failure calling Mastio /v1/principals/csr: "
        "Client error '400 Bad Request' for url 'https://x/y'\n"
        "For more information check: https://developer.mozilla.org/..."
    )
    out = _sanitize_header_value(httpx_style)
    assert "\n" not in out and "\r" not in out
    # Truncation honoured
    long_value = "a" * 1000
    assert len(_sanitize_header_value(long_value, max_len=256)) == 256
    # Non-latin1 codepoints get replaced (uvicorn header writer is
    # strict latin-1)
    assert "?" in _sanitize_header_value("emoji 😀 here")


def test_login_deferred_provisioning_header_does_not_crash_uvicorn(
    client, monkeypatch,
):
    """Regression for issue #634.

    When ``_bind_login_cert`` returns a ``deferred`` status with a
    detail message that contains LF (real httpx errors look like
    ``"... 400 Bad Request ...\\nFor more information check: ..."``),
    the old code stuffed the raw multi-line string into
    ``X-Cullis-Provisioning-Detail`` and uvicorn's header writer
    aborted the response with
    ``RuntimeError: Invalid HTTP header value``.

    After the fix the detail flows through ``_sanitize_header_value``
    and the response is well-formed.
    """
    from cullis_connector.auth import local_router as _lr

    multiline_detail = (
        "transport failure calling Mastio /v1/principals/csr: "
        "Client error '400 Bad Request' for url 'https://x/y'\n"
        "For more information check: https://developer.mozilla.org/Web/HTTP/Status/400"
    )

    async def fake_bind(request, payload):  # noqa: ARG001
        return "deferred", multiline_detail

    monkeypatch.setattr(_lr, "_bind_login_cert", fake_bind)

    _create_user(
        client, user_name="bob", password="longpassword", must_change=False,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "bob", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["provisioning"] == "deferred"
    assert r.headers.get("X-Cullis-Provisioning-Failed") == "true"
    raw_detail = r.headers.get("X-Cullis-Provisioning-Detail", "")
    assert raw_detail, "detail header should be present when detail provided"
    # Critical invariant: NO control bytes in the wire-form header value
    assert "\n" not in raw_detail
    assert "\r" not in raw_detail
    # Truncation honoured to keep header well under 2 KB
    assert len(raw_detail) <= 256


# ── ADR-025 Phase 5 / F4 R3 — first-run wizard ──────────────────────────


def test_runtime_info_setup_required_true_when_users_empty(client):
    """A fresh Connector with no users.db rows surfaces setup_required."""
    r = client.get("/api/auth/runtime-info")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["setup_required"] is True
    assert body["setup_url"] == "/api/auth/first-run-setup"


def test_runtime_info_setup_required_false_after_first_user(client):
    """As soon as any user exists the wizard is no longer needed."""
    _create_user(
        client, user_name="alice", password="longpassword", must_change=False,
    )
    r = client.get("/api/auth/runtime-info")
    assert r.status_code == 200, r.text
    assert r.json()["setup_required"] is False


def test_first_run_setup_creates_owner_user_and_issues_cookie(client):
    r = client.post(
        "/api/auth/first-run-setup",
        json={
            "user_name": "owner",
            "password": "longpassword",
            "display_name": "Owner User",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["must_change_password"] is False
    assert body["provisioning"] == "skipped"
    # Cookie was issued so the operator lands on the dashboard right
    # after setup without a second password prompt.
    cookie_names = {c.name for c in client.cookies.jar}
    assert LOCAL_SESSION_COOKIE_NAME in cookie_names
    secret = _cookie_secret(client)
    raw_cookie = client.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    payload = parse_local_cookie(raw_cookie, secret)
    assert payload is not None
    assert payload.user_name == "owner"
    assert payload.must_change_password is False


def test_first_run_setup_refused_with_409_when_user_already_exists(client):
    _create_user(
        client, user_name="alice", password="longpassword", must_change=False,
    )
    r = client.post(
        "/api/auth/first-run-setup",
        json={"user_name": "second", "password": "longpassword"},
    )
    assert r.status_code == 409, r.text
    assert "setup already completed" in r.text


def test_first_run_setup_password_too_short_returns_400_or_422(client):
    r = client.post(
        "/api/auth/first-run-setup",
        json={"user_name": "owner", "password": "short"},
    )
    # Pydantic min_length=8 raises 422 before the handler runs.
    assert r.status_code in {400, 422}, r.text


def test_first_run_setup_invalid_username_rejected(client):
    """user_name regex rejects spaces / control bytes via create_user."""
    r = client.post(
        "/api/auth/first-run-setup",
        json={
            "user_name": "bad user!",
            "password": "longpassword",
        },
    )
    assert r.status_code in {400, 422}, r.text


def test_first_run_setup_then_login_succeeds(client):
    """End-to-end: setup → cookie → logout → login with same creds."""
    r = client.post(
        "/api/auth/first-run-setup",
        json={"user_name": "owner", "password": "longpassword"},
    )
    assert r.status_code == 201, r.text
    # Drop the cookie so we exercise the real login path next.
    client.post("/api/auth/logout")
    r = client.post(
        "/api/auth/login",
        json={"user_name": "owner", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["must_change_password"] is False


# ── ADR-025 Phase 5 / F4 R3 — login → Mastio attribution chain ─────────


def test_login_invokes_mastio_attribution_helper(client, monkeypatch):
    """Login success path calls ``_bind_mastio_user_session`` so the
    Connector posts a user_login_attribution to Mastio after bcrypt
    verify. Helper is monkey-patched to avoid spinning a real Mastio.
    """
    from cullis_connector.auth import local_router as _lr

    seen: dict[str, object] = {}

    async def fake_bind_login_cert(request, payload):  # noqa: ARG001
        return "skipped", None

    async def fake_bind_mastio(
        request, *, user_name, display_name, device_thumbprint,
    ):  # noqa: ARG001
        seen["user_name"] = user_name
        seen["display_name"] = display_name
        seen["device_thumbprint"] = device_thumbprint
        return "ok", None

    monkeypatch.setattr(_lr, "_bind_login_cert", fake_bind_login_cert)
    monkeypatch.setattr(_lr, "_bind_mastio_user_session", fake_bind_mastio)

    _create_user(
        client, user_name="alice", password="longpassword", must_change=False,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "alice", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    assert seen.get("user_name") == "alice"
    # No enrolled cert in this test fixture, so the helper gets the
    # empty thumbprint and (in the real helper) returns "skipped".
    assert "device_thumbprint" in seen


def test_login_skips_attribution_when_must_change(client, monkeypatch):
    """First-login (must_change=True) skips both CSR + attribution so
    the cert + user session are bound to the post-change state.
    """
    from cullis_connector.auth import local_router as _lr

    invoked: list[str] = []

    async def fake_bind_mastio(request, **kwargs):  # noqa: ARG001
        invoked.append("called")
        return "ok", None

    monkeypatch.setattr(_lr, "_bind_mastio_user_session", fake_bind_mastio)

    _create_user(
        client, user_name="bob", password="longpassword", must_change=True,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "bob", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    assert invoked == [], "attribution must not run while must_change=True"
    assert r.json()["must_change_password"] is True
