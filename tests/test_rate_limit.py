"""
Test rate limiting — verifies that limits are enforced.

Tests reset the limiter before each run to avoid interference
with other tests that use the same agents/orgs.
"""
import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.rate_limit.limiter import SlidingWindowLimiter, rate_limiter
from tests.cert_factory import make_assertion, get_org_ca_pem, sign_message
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio

RL_ORG = "rl-org"
RL_AGENT = "rl-org::agent"
RL_SECRET = "rl-org-secret"

RL_ORG_B = "rl-org-b"
RL_AGENT_B = "rl-org-b::agent"
RL_SECRET_B = "rl-org-b-secret"


def _reset_limiter() -> None:
    """Flush all limiter buckets between tests."""
    rate_limiter._windows.clear()


async def _setup_agent(client: AsyncClient, agent_id: str, org_id: str, secret: str, dpop) -> str:
    """Register org + agent + binding + policy; return access token."""
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['order.read'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await client.post("/v1/policy/rules",
        json={
            "policy_id": f"{org_id}::allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def test_auth_token_rate_limit(client: AsyncClient, dpop):
    """POST /auth/token: 429 after 10 requests from the same IP in the same window."""
    _reset_limiter()

    # Register the org only once
    await client.post("/v1/registry/orgs", json={
        "org_id": "rl-token-org", "display_name": "rl-token-org", "secret": "s",
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem("rl-token-org")
    await client.post("/v1/registry/orgs/rl-token-org/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )
    await seed_court_agent(
        agent_id='rl-token-org::agent',
        org_id='rl-token-org',
        display_name='x',
        capabilities=[],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": "rl-token-org", "agent_id": "rl-token-org::agent", "scope": []},
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )
    await client.post(f"/v1/registry/bindings/{resp.json()['id']}/approve",
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )

    # 10 valid requests → all 200
    for _ in range(10):
        assertion = make_assertion("rl-token-org::agent", "rl-token-org")
        r = await client.post(
            "/v1/auth/token",
            json={"client_assertion": assertion},
            headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
        )
        assert r.status_code == 200

    # The eleventh must be blocked
    assertion = make_assertion("rl-token-org::agent", "rl-token-org")
    r = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert r.status_code == 429


async def test_message_rate_limit(client: AsyncClient, dpop):
    """POST /broker/sessions/{id}/messages: 429 after 60 messages/min per agent."""
    _reset_limiter()

    token_a = await _setup_agent(client, RL_AGENT, RL_ORG, RL_SECRET, dpop)
    token_b = await _setup_agent(client, RL_AGENT_B, RL_ORG_B, RL_SECRET_B, dpop)

    # Create and activate session
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": RL_AGENT_B,
        "target_org_id": RL_ORG_B,
        "requested_capabilities": ["order.read"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    await client.post(
        f"/v1/broker/sessions/{session_id}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b),
    )

    import uuid

    # 60 messages → accepted
    for _ in range(60):
        nonce = str(uuid.uuid4())
        _sig, _ts = sign_message(RL_AGENT, RL_ORG, session_id, RL_AGENT, nonce, {"x": 1})
        r = await client.post(
            f"/v1/broker/sessions/{session_id}/messages",
            json={
                "session_id": session_id,
                "sender_agent_id": RL_AGENT,
                "payload": {"x": 1},
                "nonce": nonce,
                "timestamp": _ts,
                "signature": _sig,
            },
            headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a),
        )
        assert r.status_code == 202

    # The 61st is blocked
    nonce = str(uuid.uuid4())
    _sig, _ts = sign_message(RL_AGENT, RL_ORG, session_id, RL_AGENT, nonce, {"x": 1})
    r = await client.post(
        f"/v1/broker/sessions/{session_id}/messages",
        json={
            "session_id": session_id,
            "sender_agent_id": RL_AGENT,
            "payload": {"x": 1},
            "nonce": nonce,
            "timestamp": _ts,
            "signature": _sig,
        },
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a),
    )
    assert r.status_code == 429


async def test_session_rate_limit(client: AsyncClient, dpop):
    """POST /broker/sessions: 429 after 20 requests/min per agent."""
    _reset_limiter()

    token_a = await _setup_agent(client, "rl-sess-a::agent", "rl-sess-a", "rl-sess-a-secret", dpop)
    await _setup_agent(client, "rl-sess-b::agent", "rl-sess-b", "rl-sess-b-secret", dpop)

    # 20 requests → pass (some may fail for policy/other reasons, but not for rate limit)
    for _ in range(20):
        await client.post("/v1/broker/sessions", json={
            "target_agent_id": "rl-sess-b::agent",
            "target_org_id": "rl-sess-b",
            "requested_capabilities": [],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))

    # The 21st must be blocked by the rate limiter
    r = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "rl-sess-b::agent",
        "target_org_id": "rl-sess-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert r.status_code == 429


# ─────────────────────────────────────────────────────────────────────────────
# Audit F-D-2 — fail-open behaviour when Redis is unavailable
#
# Rate limiting is a best-effort DoS control, not an auth gate. When Redis
# is unreachable the limiter must log at WARNING and allow the request
# through rather than returning 500 (which would convert a cache outage
# into a wider DoS).
# ─────────────────────────────────────────────────────────────────────────────


def _limiter_with_fake_redis(fake_redis) -> SlidingWindowLimiter:
    """Build a fresh limiter already bound to a fake Redis backend."""
    limiter = SlidingWindowLimiter()
    limiter.register("test.bucket", window_seconds=60, max_requests=5)
    limiter._use_redis = True
    limiter._redis = fake_redis
    # Pre-seed the SHA so the limiter does not try to load the Lua script
    # (script_load would be the first call hitting the mock).
    limiter._lua_sha = "deadbeef"
    return limiter


async def test_failopen_on_redis_connection_error():
    """Redis ConnectionError → request passes (audit F-D-2).

    Asserting on the failure counter rather than the WARNING log:
    the log emit races with caplog under xdist workers and produces
    empty records, but the counter increment is a deterministic
    invariant of the fail-open path.
    """
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = RedisConnectionError("connection refused")
    limiter = _limiter_with_fake_redis(fake_redis)

    # Must not raise — fail-open: request is allowed.
    await limiter.check("subject-A", "test.bucket")

    assert limiter._redis_failure_count == 1


async def test_failopen_on_redis_timeout_error():
    """Redis TimeoutError → request passes (audit F-D-2)."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = RedisTimeoutError("timed out")
    limiter = _limiter_with_fake_redis(fake_redis)

    await limiter.check("subject-B", "test.bucket")

    assert limiter._redis_failure_count == 1


async def test_failopen_on_asyncio_timeout():
    """asyncio.TimeoutError (socket-level) → fail-open (audit F-D-2)."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = asyncio.TimeoutError()
    limiter = _limiter_with_fake_redis(fake_redis)

    await limiter.check("subject-C", "test.bucket")

    assert limiter._redis_failure_count == 1


async def test_redis_healthy_still_enforces_limit():
    """Regression: when Redis answers normally the limit is still enforced."""
    fake_redis = AsyncMock()
    # evalsha returns 0 → the Lua script says "over limit".
    fake_redis.evalsha.return_value = 0
    limiter = _limiter_with_fake_redis(fake_redis)

    with pytest.raises(HTTPException) as exc_info:
        await limiter.check("subject-D", "test.bucket")

    assert exc_info.value.status_code == 429
    # Genuine 429 must NOT be counted as a Redis failure.
    assert limiter._redis_failure_count == 0


async def test_failure_counter_resets_after_recovery():
    """After a transient outage the counter resets once Redis answers OK."""
    fake_redis = AsyncMock()
    # First call fails, second succeeds (returns 1 = allowed).
    fake_redis.evalsha.side_effect = [
        RedisConnectionError("boom"),
        1,
    ]
    limiter = _limiter_with_fake_redis(fake_redis)

    await limiter.check("subject-E", "test.bucket")  # fails → fail-open
    assert limiter._redis_failure_count == 1
    await limiter.check("subject-E", "test.bucket")  # succeeds → reset

    assert limiter._redis_failure_count == 0


# ── Bucket registration coverage (audit 2026-04-30 C1) ────────────────


@pytest.mark.parametrize(
    "bucket",
    [
        # Pre-existing
        "auth.token",
        "broker.session",
        "broker.message",
        "dashboard.login",
        "onboarding.join",
        "onboarding.rotate_mastio_pubkey",
        "broker.rfq",
        "broker.rfq_respond",
        # Audit 2026-04-30 C1: previously called but never registered
        "broker.oneshot",
        "broker.oneshot_inbound",
        "broker.oneshot_inbox",
        "broker.poll",
        "onboarding.invite_inspect",
        "onboarding.attach",
    ],
)
async def test_every_called_bucket_is_registered(bucket):
    """Every bucket name passed to rate_limiter.check() must be registered.

    Before this test landed, six buckets (broker.oneshot family +
    onboarding.invite_inspect/attach) were referenced in routers but never
    registered, making rate_limiter.check() a silent no-op for them.
    """
    assert bucket in rate_limiter._configs, (
        f"bucket {bucket!r} not registered in rate_limiter; check() would silently "
        "fail-open on it"
    )


async def test_unknown_bucket_logs_warning_once(monkeypatch):
    """check() with an unregistered bucket logs a one-time warning, not silent.

    Patches ``_log.warning`` directly: the ``agent_trust`` logger config in
    CI varies (propagate flag, handler chain) and ``caplog`` has been
    flaky on it before, see ``feedback_mcp_proxy_logger_caplog``.
    """
    from app.rate_limit import limiter as limiter_module

    limiter = SlidingWindowLimiter()
    captured: list[tuple] = []

    def _capture_warning(msg, *args, **kwargs):
        captured.append((msg % args) if args else msg)

    monkeypatch.setattr(limiter_module._log, "warning", _capture_warning)

    await limiter.check("subject", "totally.unknown.bucket")
    assert any(
        "totally.unknown.bucket" in msg and "not registered" in msg
        for msg in captured
    ), f"expected warning, got {captured!r}"

    before = len(captured)
    await limiter.check("subject", "totally.unknown.bucket")
    assert len(captured) == before, "second call should NOT log again"
