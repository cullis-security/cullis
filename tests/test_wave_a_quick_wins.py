"""Wave A quick wins — D2 + B2 + C3.

Audit refs: imp/audits/2026-05-11-MASTER.md (Wave A PR4).

  D2 — POLICY_ENFORCEMENT=false must SystemExit in production
       (app/config.py validate_config).
  B2 — AI gateway upstream error body is scrubbed for provider key
       shapes before flowing into audit detail
       (mcp_proxy/egress/ai_gateway.scrub_secrets).
  C3 — admin mint refuses non-user / foreign-org / non-existent
       principal_id (mcp_proxy/db.mint_user_api_token).

E1 (delete dead app/e2e_crypto.verify_inner_signature) was deferred:
the function is referenced by tests/test_oneshot_cross_envelope.py and
removing it requires migrating that test to the SDK twin first. Will
land as a separate PR.
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


# ─── D2 — POLICY_ENFORCEMENT=false production gate ───


def _make_prod_settings(monkeypatch, **overrides):
    """Build a Settings instance with the minimum prod-shaped env to
    pass every other gate, so we can isolate the policy_enforcement
    check. Returns the constructed Settings + the validate_config
    callable to invoke."""
    from app import config as app_config

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "deny")
    monkeypatch.setenv("DATABASE_URL", "postgresql://prod:prod@prod/prod")
    monkeypatch.setenv("KMS_BACKEND", "vault")
    monkeypatch.setenv("VAULT_TOKEN", "prod-token")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.prod")
    monkeypatch.setenv("REDIS_URL", "redis://prod-redis:6379/0")
    monkeypatch.setenv("ADMIN_SECRET", "a-production-grade-secret-not-default")
    # broker_ca_key_path needs to exist on disk; point at /etc/hosts as
    # a stand-in (the prod gate just checks Path.exists).
    monkeypatch.setenv("BROKER_CA_KEY_PATH", "/etc/hosts")
    for k, v in overrides.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    # Force a fresh Settings — pydantic_settings caches defaults at
    # class scope, so we re-import the module to re-evaluate.
    settings = app_config.Settings()
    return settings, app_config.validate_config


def test_d2_policy_enforcement_false_blocks_production_boot(monkeypatch):
    """The headline D2 fix: ``POLICY_ENFORCEMENT=false`` in prod must
    SystemExit at startup, mirroring the POLICY_DEFAULT_DECISION gate."""
    settings, validate_config = _make_prod_settings(
        monkeypatch, POLICY_ENFORCEMENT="false",
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_d2_policy_enforcement_true_passes_production_boot(monkeypatch):
    """Negative control — default ``POLICY_ENFORCEMENT=true`` does not
    trip the new gate. The prod-shaped fixture passes every other gate
    so the call returns cleanly; the new gate must not be the one that
    breaks it."""
    settings, validate_config = _make_prod_settings(
        monkeypatch, POLICY_ENFORCEMENT="true",
    )
    # Should not raise. If the gate accidentally fired on True we'd
    # SystemExit here.
    validate_config(settings)


def test_d2_policy_enforcement_dev_default_no_gate(monkeypatch):
    """D2 only fires in production. In dev, POLICY_ENFORCEMENT=false
    is allowed (developers may need it for repro). Validate that the
    dev path does NOT exit on this env var."""
    from app import config as app_config

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("POLICY_ENFORCEMENT", "false")
    monkeypatch.setenv("ADMIN_SECRET", "dev-grade-secret-not-default")
    settings = app_config.Settings()
    # Dev path doesn't enforce the policy_enforcement gate; the only
    # exits in dev are ADMIN_SECRET-default and BROKER_PUBLIC_URL.
    # We don't strictly assert no-exit (other dev gates may fire) —
    # we assert that the prod-only critical message is NOT logged.
    import logging
    caplog_records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = caplog_records.append  # type: ignore[assignment]
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        try:
            app_config.validate_config(settings)
        except SystemExit:
            pass  # acceptable — other dev gates can fire
    finally:
        root.removeHandler(handler)
    msgs = [r.getMessage() for r in caplog_records]
    assert not any(
        "POLICY_ENFORCEMENT=false is not permitted in production" in m
        for m in msgs
    )


# ─── B2 — AI gateway upstream error body scrubber ───


def test_b2_scrub_strips_anthropic_key_prefix():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = (
        '{"error":{"type":"authentication_error","message":'
        '"Incorrect API key provided: sk-ant-api03-DEADBEEFDEADBEEFDEADBEEFDEADBEEF"}}'
    )
    out = scrub_secrets(body)
    assert "sk-ant-" not in out
    assert "[REDACTED]" in out
    # Non-secret context preserved for ops debugging.
    assert "authentication_error" in out


def test_b2_scrub_strips_openai_project_key():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = "Incorrect API key: sk-proj-abc123def456ghi789jkl012mno345"
    out = scrub_secrets(body)
    assert "sk-proj-" not in out
    assert "[REDACTED]" in out


def test_b2_scrub_strips_gemini_key():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = "Bad key: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
    out = scrub_secrets(body)
    assert "AIza" not in out
    assert "[REDACTED]" in out


def test_b2_scrub_strips_aws_access_key_id():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = "Invalid AKIAIOSFODNN7EXAMPLE in request"
    out = scrub_secrets(body)
    assert "AKIA" not in out
    assert "[REDACTED]" in out


def test_b2_scrub_strips_bearer_header():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = "Authorization header was Bearer eyJhbGciOiJIUzI1NiJ9.foo.bar"
    out = scrub_secrets(body)
    assert "Bearer eyJ" not in out
    assert "[REDACTED]" in out


def test_b2_scrub_strips_culk_token():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = "Token culk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 rejected"
    out = scrub_secrets(body)
    assert "culk_" not in out
    assert "[REDACTED]" in out


def test_b2_scrub_idempotent_on_non_secret_body():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    body = '{"error":"rate_limit_exceeded","retry_after":42}'
    assert scrub_secrets(body) == body


def test_b2_scrub_handles_none_and_empty():
    from mcp_proxy.egress.ai_gateway import scrub_secrets
    assert scrub_secrets(None) is None
    assert scrub_secrets("") == ""


# ─── C3 — admin mint principal_id validation ───


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "qw.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import init_db, dispose_db
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


async def _seed_user(principal_id: str = "acme::user::alice") -> None:
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    name = principal_id.split("::")[-1]
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_user_principals "
                "(principal_id, user_name, reach, surface, created_at) "
                "VALUES (:pid, :name, 'intra', NULL, :now)"
            ),
            {
                "pid": principal_id, "name": name,
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )


@pytest.mark.asyncio
async def test_c3_mint_rejects_unknown_principal(proxy_db):
    """Pre-fix: any principal_id minted. Post-fix: 400 if no row."""
    from mcp_proxy.db import mint_user_api_token
    with pytest.raises(ValueError, match="not registered"):
        await mint_user_api_token(
            principal_id="acme::user::ghost",
            label="cursor",
            created_by="admin",
        )


@pytest.mark.asyncio
async def test_c3_mint_rejects_non_user_principal(proxy_db):
    """ADR-027 Phase 1 = user-only. Workload / agent shapes refuse."""
    from mcp_proxy.db import mint_user_api_token
    for bad in ("acme::workload::etl", "acme::daniele", "acme", "ghost"):
        with pytest.raises(ValueError, match="user principal"):
            await mint_user_api_token(
                principal_id=bad,
                label="cursor",
                created_by="admin",
            )


@pytest.mark.asyncio
async def test_c3_mint_rejects_foreign_org_principal(proxy_db):
    """Mastio is org=acme; minting for orgB user is impersonation in
    audit trail."""
    await _seed_user("acme::user::alice")  # populate so the row check passes if reached
    from mcp_proxy.db import mint_user_api_token
    with pytest.raises(ValueError, match="not in this Mastio's org"):
        await mint_user_api_token(
            principal_id="orgb::user::alice",
            label="cursor",
            created_by="admin",
        )


@pytest.mark.asyncio
async def test_c3_mint_succeeds_for_registered_user_in_own_org(proxy_db):
    """Happy path — user pre-created via /v1/admin/users, same org,
    user shape — mint returns the cleartext token once."""
    await _seed_user("acme::user::alice")
    from mcp_proxy.db import mint_user_api_token
    minted = await mint_user_api_token(
        principal_id="acme::user::alice",
        label="cursor laptop",
        created_by="admin",
    )
    assert minted["principal_id"] == "acme::user::alice"
    assert minted["token"].startswith("culk_")
    assert len(minted["token_last4"]) == 4
