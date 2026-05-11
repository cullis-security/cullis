"""Shared helpers for ``user_api_tokens`` test files.

The Wave A C3 fix (audit 2026-05-11 MASTER) makes
``mint_user_api_token`` refuse any ``principal_id`` that does not
already exist in ``local_user_principals`` AND is not in the same org
as the Mastio. The 4 token-related test files in this directory
rely on minting tokens for ad-hoc test users (alice, bob, ..., mia)
without going through the admin pre-create API.

This helper centralises the pre-seed: every test that mints can rely
on the standard principals being present. New tests that need a
non-standard name should call ``seed_test_principal()`` in their
fixture before minting.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import text


# Default principal names used by the existing tests in
# test_user_api_tokens_db.py / test_admin_api_tokens.py /
# test_api_token_resolver.py / test_dashboard_api_tokens.py. Add new
# names here when a new test references them. Org defaults to ``acme``
# so the seed matches the Mastio test fixture's ``MCP_PROXY_ORG_ID``.
DEFAULT_TEST_USER_NAMES: tuple[str, ...] = (
    "alice", "bob", "carol", "dave", "erin",
    "frank", "grace", "heidi", "ivan", "jane",
    "ken", "leo", "mia",
)
DEFAULT_TEST_ORG: str = "acme"


def _principal_id(org: str, user_name: str) -> str:
    return f"{org}::user::{user_name}"


async def seed_test_principal(
    user_name_or_pid: str,
    *,
    org: str = DEFAULT_TEST_ORG,
) -> str:
    """Insert a single user principal row, idempotent.

    Accepts either a bare user_name (``"alice"``) — then prefixed with
    ``{org}::user::`` — or a full canonical principal_id
    (``"orga::user::alice@orga.test"``). Returns the resulting
    principal_id."""
    from mcp_proxy.db import get_db
    if "::user::" in user_name_or_pid:
        pid = user_name_or_pid
        # Pull the trailing component as the display user_name.
        user_name = pid.split("::user::", 1)[1]
    else:
        pid = _principal_id(org, user_name_or_pid)
        user_name = user_name_or_pid
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        existing = (await conn.execute(
            text(
                "SELECT principal_id FROM local_user_principals "
                " WHERE principal_id = :pid"
            ),
            {"pid": pid},
        )).first()
        if existing is None:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, reach, surface, "
                    " created_at) "
                    "VALUES (:pid, :name, 'intra', NULL, :now)"
                ),
                {"pid": pid, "name": user_name, "now": now},
            )
    return pid


async def seed_default_test_principals(
    names: Iterable[str] = DEFAULT_TEST_USER_NAMES,
    *,
    org: str = DEFAULT_TEST_ORG,
) -> None:
    """Seed every name in ``names`` (default: the well-known set used
    by the four token test files). Idempotent on row collisions."""
    for name in names:
        await seed_test_principal(name, org=org)
