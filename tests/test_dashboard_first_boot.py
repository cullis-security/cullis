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

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.xdist_group(name="serial_dashboard_first_boot"),
]


FRESH_BOOTSTRAP_TOKEN = "fresh-deploy-bootstrap-token-for-tests"


@pytest.fixture
def fresh_admin_state(tmp_path, monkeypatch):
    """Simulate a pristine broker: no stored hash, user_set flag false,
    bootstrap token seeded in a tmp-path location (audit F-B-4).

    The autouse conftest fixture seeds a hash + flips user_set to True
    so existing tests behave as post-setup deployments; these tests
    override that to exercise the first-boot path.
    """
    import app.kms.admin_secret as _admin_mod

    token_path = tmp_path / ".admin_bootstrap_token"
    consumed_path = tmp_path / ".admin_bootstrap_token.consumed"
    token_path.write_text(FRESH_BOOTSTRAP_TOKEN + "\n")

    monkeypatch.setattr(_admin_mod, "_LOCAL_BOOTSTRAP_TOKEN_PATH", token_path)
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = False
    yield
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = None
    for p in (token_path, consumed_path):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


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
    assert "cullis_session" not in dict(resp.cookies)


async def test_setup_submit_stores_hash_and_redirects_to_login(
    client: AsyncClient, fresh_admin_state
):
    """Valid POST → bcrypt hash persisted, user_set=true, redirect to /login."""
    new_password = "a-brand-new-admin-password"
    resp = await client.post(
        "/dashboard/setup",
        data={
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
            "password": new_password,
            "password_confirm": new_password,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
    # No session cookie issued by /setup — the operator must sign in
    # with the password they just chose.
    assert "cullis_session" not in dict(resp.cookies)

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
        data={
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
            "password": "short",
            "password_confirm": "short",
        },
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
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
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

    # 3. POST /setup with a valid password + bootstrap token → /login
    new_pw = "pick-something-sensible"
    r3 = await client.post(
        "/dashboard/setup",
        data={
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
            "password": new_pw,
            "password_confirm": new_pw,
        },
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
    assert "cullis_session" in dict(r5.cookies)


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
            "bootstrap_token": "irrelevant-after-user-set",
            "password": "attacker-would-love-this",
            "password_confirm": "attacker-would-love-this",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"


# ── Audit F-B-4 + F-D-3 regression tests ───────────────────────────
#
# F-B-4: /dashboard/setup must refuse a POST that does not carry a
#        valid bootstrap token. The token is printed on broker startup
#        and stored at ``certs/.admin_bootstrap_token`` (0600).
# F-D-3: token consumption is atomic — only one concurrent POST can
#        commit, losers see 403.

async def test_setup_requires_bootstrap_token(
    client: AsyncClient, fresh_admin_state
):
    """Audit F-B-4: POST without a bootstrap_token is rejected before
    any password work happens."""
    resp = await client.post(
        "/dashboard/setup",
        data={
            "password": "a-sufficiently-long-password",
            "password_confirm": "a-sufficiently-long-password",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "bootstrap token" in resp.text.lower()

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is False


async def test_setup_rejects_wrong_bootstrap_token(
    client: AsyncClient, fresh_admin_state
):
    """Audit F-B-4: POST with a wrong bootstrap_token is a 403."""
    resp = await client.post(
        "/dashboard/setup",
        data={
            "bootstrap_token": "not-the-real-token",
            "password": "a-sufficiently-long-password",
            "password_confirm": "a-sufficiently-long-password",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert "invalid or expired" in resp.text.lower()

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is False


async def test_setup_bootstrap_token_is_one_shot(
    client: AsyncClient, fresh_admin_state
):
    """Audit F-B-4 + F-D-3: a second POST reusing the same token is
    rejected. The first POST consumes the token; the consumed marker is
    never re-readable as a valid token."""
    new_pw = "correct-horse-battery-staple"

    first = await client.post(
        "/dashboard/setup",
        data={
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
            "password": new_pw,
            "password_confirm": new_pw,
        },
        follow_redirects=False,
    )
    assert first.status_code == 303

    # Reset the "user-set" cache so the early redirect does not mask the
    # token-consumed semantics — we want to assert the atomic consume is
    # what rejects the second POST, not the early is-user-set shortcut.
    import app.kms.admin_secret as _admin_mod
    _admin_mod._cached_user_set = False

    second = await client.post(
        "/dashboard/setup",
        data={
            "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
            "password": "another-long-enough-password",
            "password_confirm": "another-long-enough-password",
        },
        follow_redirects=False,
    )
    assert second.status_code == 403


async def test_setup_concurrent_posts_only_one_wins(
    client: AsyncClient, fresh_admin_state
):
    """Audit F-D-3: two parallel POSTs with the same valid token must
    serialize — only one commits, the other is rejected. Closes the
    TOCTOU window between is_admin_password_user_set and
    mark_admin_password_user_set."""
    import asyncio

    async def _post(pw: str):
        return await client.post(
            "/dashboard/setup",
            data={
                "bootstrap_token": FRESH_BOOTSTRAP_TOKEN,
                "password": pw,
                "password_confirm": pw,
            },
            follow_redirects=False,
        )

    r_a, r_b = await asyncio.gather(
        _post("password-from-operator-a"),
        _post("password-from-attacker-b"),
    )
    statuses = sorted([r_a.status_code, r_b.status_code])
    # Exactly one 303 (winner), one not-303 (loser: 303-to-login via early
    # user-set check OR 403 via lost rename/CAS).
    assert statuses.count(303) == 1
    assert 303 in statuses
    loser_code = [s for s in statuses if s != 303][0]
    assert loser_code in (303, 403)

    from app.kms.admin_secret import is_admin_password_user_set
    assert await is_admin_password_user_set() is True


# ── Audit F-B-4: unit tests on the kms helper ─────────────────────

def test_generate_bootstrap_token_is_idempotent(tmp_path, monkeypatch):
    """Second call does not regenerate an existing token — a broker
    restart must keep the value the operator may have already copied."""
    import asyncio
    import app.kms.admin_secret as _admin_mod

    monkeypatch.setattr(
        _admin_mod, "_LOCAL_BOOTSTRAP_TOKEN_PATH", tmp_path / ".token",
    )
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = False

    try:
        first = asyncio.get_event_loop().run_until_complete(
            _admin_mod.generate_bootstrap_token_if_needed()
        )
        second = asyncio.get_event_loop().run_until_complete(
            _admin_mod.generate_bootstrap_token_if_needed()
        )
    finally:
        _admin_mod._cached_user_set = None

    assert first is not None and len(first) > 30
    assert second is None  # no regeneration


def test_generate_bootstrap_token_skipped_when_already_user_set(
    tmp_path, monkeypatch,
):
    import asyncio
    import app.kms.admin_secret as _admin_mod

    monkeypatch.setattr(
        _admin_mod, "_LOCAL_BOOTSTRAP_TOKEN_PATH", tmp_path / ".token",
    )
    _admin_mod._cached_user_set = True

    try:
        result = asyncio.get_event_loop().run_until_complete(
            _admin_mod.generate_bootstrap_token_if_needed()
        )
    finally:
        _admin_mod._cached_user_set = None

    assert result is None
    assert not (tmp_path / ".token").exists()


def test_consume_bootstrap_token_local_atomic_rename(tmp_path, monkeypatch):
    """Local backend uses os.rename for the atomic consume. Calling the
    helper twice with the same token: first commits, second is rejected."""
    import asyncio
    import app.kms.admin_secret as _admin_mod

    token_path = tmp_path / ".token"
    token = "unit-test-bootstrap-token"
    token_path.write_text(token + "\n")
    monkeypatch.setattr(
        _admin_mod, "_LOCAL_BOOTSTRAP_TOKEN_PATH", token_path,
    )
    monkeypatch.setattr(
        _admin_mod, "_LOCAL_HASH_PATH", tmp_path / ".hash",
    )
    monkeypatch.setattr(
        _admin_mod, "_LOCAL_USER_SET_PATH", tmp_path / ".user_set",
    )
    _admin_mod._cached_hash = None
    _admin_mod._cached_user_set = False

    try:
        first = asyncio.get_event_loop().run_until_complete(
            _admin_mod.consume_bootstrap_token_and_set_password(
                token, "bcrypt$stub-hash",
            )
        )
        # Reset user_set cache to isolate the rename-based atomicity.
        _admin_mod._cached_user_set = False
        second = asyncio.get_event_loop().run_until_complete(
            _admin_mod.consume_bootstrap_token_and_set_password(
                token, "bcrypt$stub-hash-2",
            )
        )
    finally:
        _admin_mod._cached_user_set = None
        _admin_mod._cached_hash = None

    assert first is True
    assert second is False
    # Consumed marker file exists, original token file does not.
    assert (tmp_path / ".token.consumed").exists()
    assert not token_path.exists()
