"""First-boot scriptable admin-password seed (PR #566).

Covers ``mcp_proxy.dashboard.session.seed_initial_admin_password``: a
no-op when the env value is empty OR when a hash already exists in
``proxy_config.admin_password_hash``, otherwise hashes and persists so
the operator can sign in at /proxy/login without first opening
/proxy/register in a browser. The Mastio bundle reads
``MCP_PROXY_INITIAL_ADMIN_PASSWORD`` from proxy.env, this seed is what
turns it into a usable login.
"""
from __future__ import annotations

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def init_db_isolated(tmp_path, monkeypatch):
    """Tear up a clean SQLite db on a path the lifespan ignores; we
    drive ``init_db`` ourselves so the test owns the schema lifecycle
    (no FastAPI lifespan dance, no shared in-memory state across
    tests)."""
    db_file = tmp_path / "proxy_seed_test.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import init_db
    settings = get_settings()
    await init_db(settings.database_url)
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_seed_writes_hash_when_none_exists(init_db_isolated):
    """Happy path: pristine DB + non-empty plaintext → hash persisted,
    helper returns True so the lifespan can log the seed event."""
    from mcp_proxy.dashboard.session import (
        is_admin_password_set,
        seed_initial_admin_password,
        verify_admin_password,
    )

    assert await is_admin_password_set() is False
    seeded = await seed_initial_admin_password("dogfood-pass-12345")
    assert seeded is True
    assert await is_admin_password_set() is True
    # The hash actually verifies the original plaintext (bcrypt round-trip).
    assert await verify_admin_password("dogfood-pass-12345") is True
    assert await verify_admin_password("wrong-password-xx") is False


@pytest.mark.asyncio
async def test_seed_is_noop_when_password_already_set(init_db_isolated):
    """Subsequent boots must not surprise-rotate the password. The
    persisted hash always wins; rotation goes through the dashboard."""
    from mcp_proxy.dashboard.session import (
        seed_initial_admin_password,
        set_admin_password,
        verify_admin_password,
    )

    # Operator-rotated password from a previous boot.
    await set_admin_password("operator-rotated-pw-99")

    # Bundle re-runs deploy.sh, which still carries the original env
    # value (the seed is mint-once but the env line is sticky).
    seeded = await seed_initial_admin_password("dogfood-pass-12345")
    assert seeded is False

    # The rotated password is still the live one.
    assert await verify_admin_password("operator-rotated-pw-99") is True
    assert await verify_admin_password("dogfood-pass-12345") is False


@pytest.mark.asyncio
async def test_seed_is_noop_for_empty_value(init_db_isolated):
    """``MCP_PROXY_INITIAL_ADMIN_PASSWORD`` defaults to ``""`` so any
    deploy that doesn't set it preserves the historical browser-wizard
    UX. Empty string must short-circuit before bcrypt complains about
    minimum length."""
    from mcp_proxy.dashboard.session import (
        is_admin_password_set,
        seed_initial_admin_password,
    )

    seeded = await seed_initial_admin_password("")
    assert seeded is False
    assert await is_admin_password_set() is False
