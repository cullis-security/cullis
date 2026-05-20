"""F-A-208 (audit 2026-05-20) — rate-limit regression for the two
``/v1/principals/connector-login*`` endpoints.

Pre-fix, both endpoints trusted the body's ``user_subject_sso`` /
``local_subject`` after the device-cert gate and minted ``user_sessions``
rows without any throttle. A compromised Connector could enumerate SSO
subjects + flood-mint sessions. This file pins the three sliding-window
buckets introduced by the fix:

  * per-agent_id         — 60/min
  * per-client-IP        — 30/min
  * per (agent, subject) — 5/min  (the tightest bucket, exercised here)

OWASP A05, CWE-307. The buckets share the existing in-memory
``InMemoryAgentRateLimiter`` so the test resets it between cases.
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
from fastapi.testclient import TestClient

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.models import TokenPayload


pytestmark = pytest.mark.asyncio


def _fake_agent(
    *, org: str = "acme", agent_id: str = "acme::connector",
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}",
        scope=[],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "rate_limit.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    # Force a fresh in-memory bucket map so neighbouring tests can't
    # pre-fill the per-agent/per-IP windows under -n auto.
    reset_agent_rate_limiter()
    try:
        yield url
    finally:
        await dispose_db()
        reset_agent_rate_limiter()
        get_settings.cache_clear()


@pytest.fixture
def app_client(proxy_db):
    from mcp_proxy.main import app

    app.dependency_overrides[get_authenticated_agent] = lambda: _fake_agent()
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_authenticated_agent, None)


def _sso_body(subject: str = "alice@acme.com") -> dict:
    return {
        "user_subject_sso": subject,
        "display_name": "Alice Smith",
        "idp_issuer": "https://idp.example.com",
        "device_cert_thumbprint": "a" * 64,
    }


def _local_body(subject: str = "alice") -> dict:
    return {
        "local_subject": subject,
        "display_name": "Alice Smith",
        "device_cert_thumbprint": "a" * 64,
        "auth_mode": "local",
    }


# Per-(agent, subject) ceiling is 5/min — six identical hits trip 429.
_SUBJECT_CEILING = 5


async def test_sso_login_per_subject_bucket_triggers_429(
    app_client, monkeypatch,
):
    """Six rapid logins from the same (agent, subject) → 6th returns 429.

    Pins the tightest bucket: re-posting the *same* SSO subject from the
    *same* agent is what an enumeration attacker does. Legit re-login
    cadence is on the order of once per hour (token TTL), so 5/min has
    multiple orders of magnitude of headroom.
    """
    # ADR-013 layer 3 — the gate must also emit an audit-grade warning
    # so SOC tooling can alert without scraping the DB. The mcp_proxy
    # logger has ``propagate=False``, so caplog never sees it; spy on
    # ``_log.warning`` directly, matching the
    # ``feedback_mcp_proxy_logger_caplog`` memory pattern.
    from mcp_proxy.registry import connector_login_router as router_mod
    seen: list[str] = []
    original = router_mod._log.warning

    def _spy(msg, *args, **kwargs):
        try:
            rendered = msg % args if args else msg
        except Exception:  # noqa: BLE001
            rendered = str(msg)
        seen.append(rendered)
        return original(msg, *args, **kwargs)

    monkeypatch.setattr(router_mod._log, "warning", _spy)

    body = _sso_body()
    for i in range(_SUBJECT_CEILING):
        resp = app_client.post("/v1/principals/connector-login", json=body)
        assert resp.status_code == 201, (
            f"call {i} unexpectedly throttled: {resp.status_code} {resp.text}"
        )

    over = app_client.post("/v1/principals/connector-login", json=body)
    assert over.status_code == 429, over.text
    assert over.headers.get("Retry-After") == "60"
    assert "rate limit" in over.json()["detail"].lower()
    assert any(
        "rate limit exceeded" in line.lower() for line in seen
    ), f"no rate-limit warning emitted; seen={seen}"


async def test_local_attribution_per_subject_bucket_triggers_429(app_client):
    """Same shape, the local-auth sibling. Different subject string, same
    bucket: the helper is shared, so this proves the wiring on both
    routes, not just the SSO path."""
    body = _local_body()
    for i in range(_SUBJECT_CEILING):
        resp = app_client.post(
            "/v1/principals/connector-login-local-attribution", json=body,
        )
        assert resp.status_code == 201, (
            f"call {i} unexpectedly throttled: {resp.status_code} {resp.text}"
        )

    over = app_client.post(
        "/v1/principals/connector-login-local-attribution", json=body,
    )
    assert over.status_code == 429, over.text
    assert over.headers.get("Retry-After") == "60"


async def test_distinct_subjects_isolated_under_subject_bucket(app_client):
    """Per-(agent, subject) bucket must not collateral-damage *other*
    subjects from the same agent. Five hits on subject A then one hit
    on subject B succeeds — the per-agent ceiling (60/min) is far above
    the six-call burst, so only the per-subject window of A would have
    closed."""
    for _ in range(_SUBJECT_CEILING):
        ok = app_client.post(
            "/v1/principals/connector-login",
            json=_sso_body("alice@acme.com"),
        )
        assert ok.status_code == 201, ok.text

    # Subject A's per-(agent, subject) bucket is now at the ceiling, but
    # subject B has its own bucket and must still succeed.
    other = app_client.post(
        "/v1/principals/connector-login",
        json=_sso_body("bob@acme.com"),
    )
    assert other.status_code == 201, other.text


async def test_429_does_not_write_user_session_row(app_client):
    """The throttle must short-circuit before the DB write — otherwise
    the storage-exhaustion arm of F-A-208 (``user_sessions`` flooding)
    is only mitigated, not closed. Count rows for the throttled subject
    and assert it does not grow past the ceiling."""
    from mcp_proxy.db import get_db
    from sqlalchemy import text

    body = _sso_body("victim@acme.com")
    for _ in range(_SUBJECT_CEILING):
        ok = app_client.post("/v1/principals/connector-login", json=body)
        assert ok.status_code == 201

    over = app_client.post("/v1/principals/connector-login", json=body)
    assert over.status_code == 429

    async with get_db() as conn:
        count = (await conn.execute(
            text(
                "SELECT COUNT(*) FROM user_sessions "
                "WHERE sso_subject = :sub"
            ),
            {"sub": "victim@acme.com"},
        )).scalar_one()
    # Exactly the ceiling, never the ceiling + 1.
    assert count == _SUBJECT_CEILING
