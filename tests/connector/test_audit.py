"""Tests for cullis_connector.identity.audit — append-only local audit log."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from cullis_connector.identity.audit import (
    USERS_DB_FILENAME,
    hash_admin_secret,
    init_audit_log,
    log_admin_action,
    log_lockout_trigger,
    log_login_attempt,
    log_password_change,
    query_audit,
    reset_engine_cache_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_engine_cache():
    reset_engine_cache_for_tests()
    yield
    reset_engine_cache_for_tests()


# ── Roundtrip ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_log_login_attempt_and_query_roundtrip(tmp_path: Path):
    await log_login_attempt(
        tmp_path,
        ip="10.0.0.5",
        user_name="mario",
        status="ok",
    )
    rows = await query_audit(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row.action == "login.attempt"
    assert row.status == "ok"
    assert row.ip == "10.0.0.5"
    assert row.user_name == "mario"
    # Detail should be NULL when no reason is provided.
    assert row.detail is None


@pytest.mark.asyncio
async def test_log_login_attempt_with_reason(tmp_path: Path):
    await log_login_attempt(
        tmp_path,
        ip="10.0.0.5",
        user_name="mario",
        status="fail",
        reason="bad_password",
    )
    rows = await query_audit(tmp_path)
    parsed = json.loads(rows[0].detail)
    assert parsed == {"reason": "bad_password"}


@pytest.mark.asyncio
async def test_log_password_change(tmp_path: Path):
    await log_password_change(tmp_path, user_name="mario")
    rows = await query_audit(tmp_path)
    assert len(rows) == 1
    assert rows[0].action == "pw.change"
    assert rows[0].status == "ok"
    assert rows[0].user_name == "mario"
    # Threat-model invariant: never log the password / hash.
    assert rows[0].detail is None


@pytest.mark.asyncio
async def test_log_admin_action_stores_sha256_only(tmp_path: Path):
    secret = "super-secret-admin-token"
    secret_hash = hash_admin_secret(secret)
    await log_admin_action(
        tmp_path,
        action="admin.user.create",
        target="lucia",
        actor_secret_hash=secret_hash,
    )
    rows = await query_audit(tmp_path)
    assert len(rows) == 1
    detail = json.loads(rows[0].detail)
    assert detail == {"actor_secret_hash": secret_hash}
    # The plain secret must never appear anywhere on the row.
    serialised = "|".join(
        str(v) for v in (rows[0].action, rows[0].user_name, rows[0].detail)
    )
    assert secret not in serialised
    # And the stored hash must match SHA256 of the secret.
    assert secret_hash == hashlib.sha256(secret.encode()).hexdigest()


@pytest.mark.asyncio
async def test_log_admin_action_rejects_non_hex(tmp_path: Path):
    with pytest.raises(ValueError):
        await log_admin_action(
            tmp_path,
            action="admin.user.create",
            target="lucia",
            actor_secret_hash="not-a-hash",
        )


@pytest.mark.asyncio
async def test_log_lockout_trigger(tmp_path: Path):
    unlock_at = time.time() + 900  # 15 min from now
    await log_lockout_trigger(
        tmp_path,
        ip="10.0.0.5",
        locked_until=unlock_at,
        user_name="mario",
    )
    rows = await query_audit(tmp_path)
    assert len(rows) == 1
    assert rows[0].action == "login.locked"
    assert rows[0].status == "locked"
    detail = json.loads(rows[0].detail)
    assert "locked_until" in detail


# ── Append-only triggers ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_blocked_by_trigger(tmp_path: Path):
    await log_login_attempt(
        tmp_path, ip="10.0.0.5", user_name="mario", status="ok"
    )
    engine = await init_audit_log(tmp_path)
    async with engine.begin() as conn:
        with pytest.raises((IntegrityError, OperationalError)) as exc:
            await conn.exec_driver_sql(
                "UPDATE local_audit_log SET status = 'fail' WHERE id = 1"
            )
        assert "append-only" in str(exc.value)


@pytest.mark.asyncio
async def test_delete_blocked_by_trigger(tmp_path: Path):
    await log_login_attempt(
        tmp_path, ip="10.0.0.5", user_name="mario", status="ok"
    )
    engine = await init_audit_log(tmp_path)
    async with engine.begin() as conn:
        with pytest.raises((IntegrityError, OperationalError)) as exc:
            await conn.exec_driver_sql("DELETE FROM local_audit_log WHERE id = 1")
        assert "append-only" in str(exc.value)


# ── Query filters ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_by_user_name(tmp_path: Path):
    await log_login_attempt(tmp_path, ip="1.1.1.1", user_name="mario", status="ok")
    await log_login_attempt(tmp_path, ip="1.1.1.2", user_name="lucia", status="ok")
    rows = await query_audit(tmp_path, user_name="mario")
    assert len(rows) == 1
    assert rows[0].user_name == "mario"


@pytest.mark.asyncio
async def test_filter_by_action(tmp_path: Path):
    await log_login_attempt(tmp_path, ip="1.1.1.1", user_name="mario", status="ok")
    await log_password_change(tmp_path, user_name="mario")
    rows = await query_audit(tmp_path, action="pw.change")
    assert len(rows) == 1
    assert rows[0].action == "pw.change"


@pytest.mark.asyncio
async def test_filter_by_since(tmp_path: Path):
    await log_login_attempt(tmp_path, ip="1.1.1.1", user_name="mario", status="ok")
    future = datetime.now(timezone.utc) + timedelta(days=1)
    rows = await query_audit(tmp_path, since=future)
    assert rows == []
    past = datetime.now(timezone.utc) - timedelta(days=1)
    rows = await query_audit(tmp_path, since=past)
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_query_limit_clamped(tmp_path: Path):
    for i in range(5):
        await log_login_attempt(
            tmp_path, ip=f"1.1.1.{i}", user_name=f"u{i}", status="ok"
        )
    rows = await query_audit(tmp_path, limit=2)
    assert len(rows) == 2
    # Newest first.
    assert rows[0].id > rows[1].id


# ── File permissions (POSIX) ───────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX-only file mode check")
async def test_users_db_is_chmod_0600(tmp_path: Path):
    await log_login_attempt(
        tmp_path, ip="10.0.0.5", user_name="mario", status="ok"
    )
    db_path = tmp_path / USERS_DB_FILENAME
    assert db_path.exists()
    mode = db_path.stat().st_mode
    # No group / other bits allowed.
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


# ── Init idempotence ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_init_audit_log_is_idempotent(tmp_path: Path):
    e1 = await init_audit_log(tmp_path)
    e2 = await init_audit_log(tmp_path)
    # Same engine returned on subsequent calls (cached).
    assert e1 is e2


# ── Hash helper ───────────────────────────────────────────────────────────


def test_hash_admin_secret_matches_sha256():
    secret = "abc123"
    expected = hashlib.sha256(secret.encode()).hexdigest()
    assert hash_admin_secret(secret) == expected
    assert len(hash_admin_secret(secret)) == 64
