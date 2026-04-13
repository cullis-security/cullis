"""
First-boot admin password flow (shake-out P0-06).

A fresh broker deploy must not accept the .env ADMIN_SECRET as a regular
dashboard credential: it can be used once to reach the setup wizard, at
which point the operator picks a real password that is bcrypt-hashed and
persisted. After that, .env ADMIN_SECRET is refused and only the stored
hash is trusted.
"""
import json
import codecs
import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


def _extract_csrf(cookies: dict) -> str:
    """Mirror of tests.test_dashboard._extract_csrf — pull the CSRF token
    out of the signed session cookie."""
    cookie = cookies.get("atn_session", "")
    if not cookie:
        return ""
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        return json.loads(payload_str).get("csrf_token", "")
    except (json.JSONDecodeError, TypeError):
        return ""


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
    # Teardown is handled by the outer autouse fixture, but scrub the
    # module to leave no test-to-test bleed if the autouse order changes.
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = None


async def test_first_boot_login_redirects_to_setup(
    client: AsyncClient, fresh_admin_state
):
    """.env ADMIN_SECRET authenticates, but lands the admin on /setup,
    not on the overview."""
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/setup"
    assert "atn_session" in dict(resp.cookies)


async def test_setup_page_renders_for_fresh_admin(
    client: AsyncClient, fresh_admin_state
):
    login = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(login.cookies)
    resp = await client.get("/dashboard/setup", cookies=cookies)
    assert resp.status_code == 200
    assert "Set the admin password" in resp.text


async def test_overview_redirects_to_setup_before_password_set(
    client: AsyncClient, fresh_admin_state
):
    """If the admin bypasses /setup and hits the overview directly, the
    root handler must bounce them back to /setup."""
    login = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(login.cookies)
    resp = await client.get(
        "/dashboard", cookies=cookies, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/setup"


async def test_setup_submit_stores_hash_and_forces_relogin(
    client: AsyncClient, fresh_admin_state
):
    login = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(login.cookies)
    csrf = _extract_csrf(cookies)

    new_password = "a-brand-new-admin-password"
    resp = await client.post(
        "/dashboard/setup",
        data={
            "csrf_token": csrf,
            "password": new_password,
            "password_confirm": new_password,
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"

    # Flag was persisted.
    from app.kms.admin_secret import (
        is_admin_password_user_set, get_admin_secret_hash,
    )
    assert await is_admin_password_user_set() is True
    assert await get_admin_secret_hash() is not None

    # The new password lets us back in and lands on /dashboard.
    resp2 = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": new_password},
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert resp2.headers["location"] == "/dashboard"


async def test_setup_rejects_short_password(
    client: AsyncClient, fresh_admin_state
):
    login = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(login.cookies)
    csrf = _extract_csrf(cookies)

    resp = await client.post(
        "/dashboard/setup",
        data={"csrf_token": csrf, "password": "short", "password_confirm": "short"},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "at least" in resp.text

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is False


async def test_setup_rejects_mismatched_confirmation(
    client: AsyncClient, fresh_admin_state
):
    login = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(login.cookies)
    csrf = _extract_csrf(cookies)

    resp = await client.post(
        "/dashboard/setup",
        data={
            "csrf_token": csrf,
            "password": "one-really-long-passphrase",
            "password_confirm": "another-really-long-passphrase",
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "do not match" in resp.text


async def test_admin_secret_rejected_after_user_set(client: AsyncClient):
    """After setup completes (autouse fixture state), the .env ADMIN_SECRET
    must not be accepted as a dashboard credential — only the stored hash
    is trusted. This is the whole point of P0-06: no more grep .env."""
    import app.kms.admin_secret as _admin_mod
    import bcrypt

    # Fixed state: a specific hash for a specific password, user_set=True.
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


async def test_setup_page_redirects_to_settings_after_user_set(
    client: AsyncClient,
):
    """Admin who already set a password should not see the first-boot
    wizard again — they are sent to the regular change-password page."""
    # Login with the (autouse) seeded hash == .env admin_secret.
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    cookies = dict(resp.cookies)

    resp2 = await client.get(
        "/dashboard/setup", cookies=cookies, follow_redirects=False
    )
    assert resp2.status_code == 303
    assert resp2.headers["location"] == "/dashboard/admin/settings"
