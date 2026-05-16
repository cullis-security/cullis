"""ADR-032 Layer 2 — audit_log.on_behalf_of_user_id populates from
the per-request contextvar.

Mirrors the structure of ``tests/test_audit_dpop_jkt.py`` (the same
pattern PR #715 / #731 used for ``dpop_jkt``). Two cases:

* Explicit kwarg wins — call-site can override the contextvar (system
  task replays).
* No kwarg + contextvar set → the column populates from the contextvar.
* No kwarg + no contextvar → column stays NULL (the historical default).
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.auth.user_context import (
    reset_on_behalf_of_user,
    set_on_behalf_of_user,
)
from mcp_proxy.db import dispose_db, get_db, init_db, log_audit


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "audit_obo.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


async def _last_audit_row() -> dict:
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT agent_id, action, on_behalf_of_user_id "
                "FROM audit_log ORDER BY id DESC LIMIT 1"
            ),
        )).mappings().first()
    assert row is not None, "expected at least one audit row"
    return dict(row)


async def test_log_audit_persists_explicit_on_behalf_of_user(proxy_db):
    await log_audit(
        "acme::connector", "tool.exec", "success",
        on_behalf_of_user_id="acme::user::alice",
    )
    row = await _last_audit_row()
    assert row["on_behalf_of_user_id"] == "acme::user::alice"


async def test_log_audit_reads_contextvar_when_kwarg_absent(proxy_db):
    tok = set_on_behalf_of_user("acme::user::bob")
    try:
        await log_audit("acme::connector", "tool.exec", "success")
    finally:
        reset_on_behalf_of_user(tok)
    row = await _last_audit_row()
    assert row["on_behalf_of_user_id"] == "acme::user::bob"


async def test_log_audit_default_is_null(proxy_db):
    # Defensive reset in case a sibling test leaked a contextvar.
    tok = set_on_behalf_of_user(None)
    try:
        await log_audit("acme::connector", "tool.exec", "success")
    finally:
        reset_on_behalf_of_user(tok)
    row = await _last_audit_row()
    assert row["on_behalf_of_user_id"] is None


async def test_explicit_kwarg_wins_over_contextvar(proxy_db):
    tok = set_on_behalf_of_user("acme::user::contextvar")
    try:
        await log_audit(
            "acme::connector", "tool.exec", "success",
            on_behalf_of_user_id="acme::user::kwarg",
        )
    finally:
        reset_on_behalf_of_user(tok)
    row = await _last_audit_row()
    assert row["on_behalf_of_user_id"] == "acme::user::kwarg"
