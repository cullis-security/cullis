"""
First-boot admin password flow (shake-out P0-06 redo).

A fresh broker deploy lands the operator on /dashboard/setup with no
authentication — they pick the admin password there.  After submit they
are sent to /dashboard/login and can sign in with the password they just
chose.  The .env ADMIN_SECRET is never a dashboard login credential:
it remains valid only for the `x-admin-secret` HTTP API header on the
admin routers (onboarding/policy/org).
"""
import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


@pytest.fixture
def fresh_admin_state():
    """Simulate a pristine broker: no stored hash, user_set flag false.

    The autouse conftest fixture seeds a hash + flips user_set to True
    so existing tests behave as post-setup deployments; these tests
    override that to exercise the first-boot path.
    """
    import app.kms.admin_secret as _admin_mod
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = False
    yield
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = None


async def test_fresh_login_redirects_to_setup_with_no_auth(
    client: AsyncClient, fresh_admin_state
):
    """GET /dashboard/login on a fresh deploy redirects to /setup without
    ever asking for credentials."""
    resp = await client.get("/dashboard/login", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/setup"


async def test_setup_page_renders_without_session(
    client: AsyncClient, fresh_admin_state
):
    """GET /dashboard/setup works with no session cookie on a fresh deploy."""
    resp = await client.get("/dashboard/setup", follow_redirects=False)
    assert resp.status_code == 200
    assert "Set the admin password" in resp.text
    # Sanity: form posts back to /dashboard/setup
    assert 'action="/dashboard/setup"' in resp.text


async def test_login_post_with_admin_secret_rejected_on_fresh_deploy(
    client: AsyncClient, fresh_admin_state
):
    """Even posting ADMIN_SECRET to /login on a fresh deploy must not
    authenticate — it bounces to /setup (no credential shortcut)."""
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/setup"
    assert "atn_session" not in dict(resp.cookies)


async def test_setup_submit_stores_hash_and_redirects_to_login(
    client: AsyncClient, fresh_admin_state
):
    """Valid POST → bcrypt hash persisted, user_set=true, redirect to /login."""
    new_password = "a-brand-new-admin-password"
    resp = await client.post(
        "/dashboard/setup",
        data={
            "password": new_password,
            "password_confirm": new_password,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
    # No session cookie issued by /setup — the operator must sign in
    # with the password they just chose.
    assert "atn_session" not in dict(resp.cookies)

    from app.kms.admin_secret import (
        is_admin_password_user_set, get_admin_secret_hash,
    )
    assert await is_admin_password_user_set() is True
    assert await get_admin_secret_hash() is not None


async def test_setup_rejects_short_password(
    client: AsyncClient, fresh_admin_state
):
    resp = await client.post(
        "/dashboard/setup",
        data={"password": "short", "password_confirm": "short"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "at least" in resp.text

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is False


async def test_setup_rejects_mismatched_confirmation(
    client: AsyncClient, fresh_admin_state
):
    resp = await client.post(
        "/dashboard/setup",
        data={
            "password": "one-really-long-passphrase",
            "password_confirm": "another-really-long-passphrase",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "do not match" in resp.text

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is False


async def test_end_to_end_setup_then_login(
    client: AsyncClient, fresh_admin_state
):
    """Full happy path: GET /login → /setup, POST /setup → /login,
    POST /login → /dashboard."""
    # 1. GET /login → /setup
    r1 = await client.get("/dashboard/login", follow_redirects=False)
    assert r1.status_code == 303 and r1.headers["location"] == "/dashboard/setup"

    # 2. GET /setup → 200
    r2 = await client.get("/dashboard/setup", follow_redirects=False)
    assert r2.status_code == 200

    # 3. POST /setup with a valid password → /login
    new_pw = "pick-something-sensible"
    r3 = await client.post(
        "/dashboard/setup",
        data={"password": new_pw, "password_confirm": new_pw},
        follow_redirects=False,
    )
    assert r3.status_code == 303 and r3.headers["location"] == "/dashboard/login"

    # 4. GET /login → 200 (form is now shown)
    r4 = await client.get("/dashboard/login", follow_redirects=False)
    assert r4.status_code == 200
    assert 'action="/dashboard/login"' in r4.text

    # 5. POST /login with the new password → /dashboard (with session)
    r5 = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": new_pw},
        follow_redirects=False,
    )
    assert r5.status_code == 303
    assert r5.headers["location"] == "/dashboard"
    assert "atn_session" in dict(r5.cookies)


async def test_admin_secret_rejected_after_user_set(client: AsyncClient):
    """After setup completes (autouse fixture state), the .env ADMIN_SECRET
    must not be accepted as a dashboard credential — only the stored hash
    is trusted."""
    import app.kms.admin_secret as _admin_mod
    import bcrypt

    real_pw = "the-real-admin-password-12345"
    _admin_mod._cached_hash = bcrypt.hashpw(
        real_pw.encode(), bcrypt.gensalt(rounds=4)
    ).decode()
    _admin_mod._cached_user_set = True

    # Wrong password (the old .env secret) must be rejected.
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "Invalid" in resp.text

    # The real password works.
    resp2 = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": real_pw},
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert resp2.headers["location"] == "/dashboard"


async def test_setup_page_redirects_to_login_after_user_set(
    client: AsyncClient,
):
    """Admin who already set a password should not see the first-boot
    wizard again — they are sent to /login (setup is one-shot)."""
    resp = await client.get(
        "/dashboard/setup", follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"


async def test_setup_post_after_user_set_redirects_to_login(
    client: AsyncClient,
):
    """POSTing to /setup once the password is set is a no-op: redirect to
    /login so an attacker can't overwrite the admin password by spamming
    the public endpoint."""
    resp = await client.post(
        "/dashboard/setup",
        data={
            "password": "attacker-would-love-this",
            "password_confirm": "attacker-would-love-this",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
