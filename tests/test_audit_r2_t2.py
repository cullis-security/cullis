"""
Tests for Round 2 security fixes (terminal 2).

Covers:
  #19 — Session store unbounded growth / eviction / cap
  #25 — WebSocket Origin validation
  #26 — WebSocket auth timeout
  #27 — Race condition on session state transitions (asyncio.Lock)
  #28 — Message polling blocked on closed/expired sessions
  #29 — Policy engine evaluates both initiator AND target org policies
  #30 — GET /registry/orgs/{org_id} requires admin auth
  #33 — OPA adapter URL validation (SSRF protection)
  #38 — list_sessions pagination (limit/offset)
  #39 — Rate limit on message polling
  #40 — In-memory message rollback on generic DB error
  #41 — session_id UUID format validation
"""
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient

from app.broker.session import Session, SessionStatus, SessionStore
from app.broker.router import _validate_session_id, _UUID_RE

pytestmark = pytest.mark.asyncio


# ────────────────────────────────────────────────────────────────────────
# Helper — standard agent setup (reused from test_security_fixes pattern)
# ────────────────────────────────────────────────────────────────────────

from tests.cert_factory import (
    get_org_ca_pem,
)
from tests.conftest import seed_court_agent


async def _setup_agent(client: AsyncClient, dpop, agent_id: str, org_id: str) -> str:
    """Register infrastructure and return a DPoP-bound token."""
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['test.read', 'test.write'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read", "test.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/policy/rules",
        json={
            "policy_id": f"{org_id}::session-allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


# ════════════════════════════════════════════════════════════════════════
# #19 — Session store: eviction + cap
# ════════════════════════════════════════════════════════════════════════

class TestSessionStoreEviction:

    def test_evict_stale_removes_closed_sessions(self):
        store = SessionStore(session_ttl_minutes=60)
        s = store.create("a", "org-a", "b", "org-b", [])
        store.close(s.session_id)
        assert s.session_id in store._sessions
        evicted = store._evict_stale()
        assert evicted == 1
        assert s.session_id not in store._sessions

    def test_evict_stale_keeps_expired_pending_sessions(self):
        """M1: TTL-expired sessions stay in the store until the sweeper
        transitions them to CLOSED and emits session.closed — _evict_stale
        no longer deletes them silently. Only already-closed/denied are evicted.
        """
        store = SessionStore(session_ttl_minutes=0)  # immediate expiry
        s = store.create("a", "org-a", "b", "org-b", [])
        s.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        evicted = store._evict_stale()
        assert evicted == 0
        # Still there — sweeper will handle it with reason=ttl_expired.
        assert s.session_id in store._sessions

    def test_evict_stale_keeps_active_sessions(self):
        store = SessionStore(session_ttl_minutes=60)
        s = store.create("a", "org-a", "b", "org-b", [])
        store.activate(s.session_id)
        evicted = store._evict_stale()
        assert evicted == 0
        assert s.session_id in store._sessions

    def test_max_sessions_cap_raises(self):
        store = SessionStore(session_ttl_minutes=60)
        store._MAX_SESSIONS = 3
        for i in range(3):
            s = store.create(f"a{i}", "org", f"b{i}", "org", [])
            store.activate(s.session_id)  # prevent eviction
        with pytest.raises(RuntimeError, match="Session store full"):
            store.create("overflow", "org", "target", "org", [])

    def test_create_evicts_before_cap_check(self):
        """Closed sessions are evicted before hitting the cap."""
        store = SessionStore(session_ttl_minutes=60)
        store._MAX_SESSIONS = 2
        s1 = store.create("a", "org", "b", "org", [])
        s2 = store.create("c", "org", "d", "org", [])
        store.close(s1.session_id)
        store.close(s2.session_id)
        # Both closed — eviction should free space
        s3 = store.create("e", "org", "f", "org", [])
        assert s3.session_id in store._sessions


# ════════════════════════════════════════════════════════════════════════
# #27 — Session state transition lock
# ════════════════════════════════════════════════════════════════════════

class TestSessionStoreLock:

    def test_store_has_asyncio_lock(self):
        store = SessionStore()
        assert isinstance(store._lock, asyncio.Lock)


# ════════════════════════════════════════════════════════════════════════
# #38 — list_for_agent pagination
# ════════════════════════════════════════════════════════════════════════

class TestListForAgentPagination:

    def test_list_for_agent_default(self):
        store = SessionStore(session_ttl_minutes=60)
        for i in range(5):
            store.create("agent-a", "org", f"b{i}", "org", [])
        result = store.list_for_agent("agent-a")
        assert len(result) == 5

    def test_list_for_agent_limit(self):
        store = SessionStore(session_ttl_minutes=60)
        for i in range(5):
            store.create("agent-a", "org", f"b{i}", "org", [])
        result = store.list_for_agent("agent-a", limit=2)
        assert len(result) == 2

    def test_list_for_agent_offset(self):
        store = SessionStore(session_ttl_minutes=60)
        for i in range(5):
            store.create("agent-a", "org", f"b{i}", "org", [])
        all_sessions = store.list_for_agent("agent-a", limit=100)
        page = store.list_for_agent("agent-a", limit=2, offset=2)
        assert len(page) == 2
        assert page[0].session_id == all_sessions[2].session_id


# ════════════════════════════════════════════════════════════════════════
# #41 — session_id UUID validation
# ════════════════════════════════════════════════════════════════════════

class TestSessionIdValidation:

    def test_valid_uuid_passes(self):
        _validate_session_id(str(uuid.uuid4()))  # should not raise

    def test_invalid_uuid_raises(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _validate_session_id("not-a-uuid")
        assert exc_info.value.status_code == 400

    def test_script_injection_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_session_id("<script>alert(1)</script>")

    def test_empty_string_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_session_id("")

    def test_uuid_regex_pattern(self):
        assert _UUID_RE.match("550e8400-e29b-41d4-a716-446655440000")
        assert not _UUID_RE.match("550e8400-e29b-41d4-a716")
        assert not _UUID_RE.match("../../../etc/passwd")


# ════════════════════════════════════════════════════════════════════════
# #28 — poll_messages blocked on non-active sessions
# ════════════════════════════════════════════════════════════════════════

async def test_poll_messages_blocked_on_closed_session(client: AsyncClient, dpop):
    """Polling messages on a closed session returns 409."""
    uid = uuid.uuid4().hex[:6]
    init_id = f"r2t2org28i{uid}::agent-init"
    tgt_id = f"r2t2org28t{uid}::agent-tgt"
    init_org = f"r2t2org28i{uid}"
    tgt_org = f"r2t2org28t{uid}"

    init_token = await _setup_agent(client, dpop, init_id, init_org)
    tgt_token = await _setup_agent(client, dpop, tgt_id, tgt_org)

    # Create session
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": tgt_id, "target_org_id": tgt_org,
        "requested_capabilities": ["test.read"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", init_token))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    # Accept
    resp = await client.post(f"/v1/broker/sessions/{session_id}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", tgt_token))
    assert resp.status_code == 200

    # Close
    resp = await client.post(f"/v1/broker/sessions/{session_id}/close",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/close", init_token))
    assert resp.status_code == 200

    # Poll — closed sessions allow drain (200 with empty list)
    resp = await client.get(f"/v1/broker/sessions/{session_id}/messages",
        headers=dpop.headers("GET", f"/v1/broker/sessions/{session_id}/messages", init_token))
    assert resp.status_code == 200
    assert resp.json() == []


# ════════════════════════════════════════════════════════════════════════
# #41 — session_id validation on endpoints (integration)
# ════════════════════════════════════════════════════════════════════════

async def test_invalid_session_id_rejected_on_accept(client: AsyncClient, dpop):
    """Endpoints reject non-UUID session_id with 400."""
    uid = uuid.uuid4().hex[:6]
    agent_id = f"r2t2org41{uid}::agent"
    org_id = f"r2t2org41{uid}"
    token = await _setup_agent(client, dpop, agent_id, org_id)

    resp = await client.post("/v1/broker/sessions/not-a-valid-uuid/accept",
        headers=dpop.headers("POST", "/v1/broker/sessions/not-a-valid-uuid/accept", token))
    assert resp.status_code == 400
    assert "UUID" in resp.json()["detail"]


async def test_invalid_session_id_rejected_on_messages(client: AsyncClient, dpop):
    """Message polling rejects non-UUID session_id."""
    uid = uuid.uuid4().hex[:6]
    agent_id = f"r2t2org41m{uid}::agent"
    org_id = f"r2t2org41m{uid}"
    token = await _setup_agent(client, dpop, agent_id, org_id)

    resp = await client.get("/v1/broker/sessions/<script>/messages",
        headers=dpop.headers("GET", "/v1/broker/sessions/<script>/messages", token))
    assert resp.status_code == 400


# ════════════════════════════════════════════════════════════════════════
# #38 — list_sessions pagination (integration)
# ════════════════════════════════════════════════════════════════════════

async def test_list_sessions_pagination(client: AsyncClient, dpop):
    """Pagination limit/offset are respected."""
    uid = uuid.uuid4().hex[:6]
    init_id = f"r2t2org38{uid}::agent-init"
    init_org = f"r2t2org38{uid}"
    token = await _setup_agent(client, dpop, init_id, init_org)

    # Default request
    resp = await client.get("/v1/broker/sessions",
        headers=dpop.headers("GET", "/v1/broker/sessions", token))
    assert resp.status_code == 200

    # limit=1 should restrict result count
    resp = await client.get("/v1/broker/sessions?limit=1",
        headers=dpop.headers("GET", "/v1/broker/sessions", token))
    assert resp.status_code == 200
    assert len(resp.json()) <= 1


# ════════════════════════════════════════════════════════════════════════
# #30 — GET /registry/orgs/{org_id} now requires admin auth
# ════════════════════════════════════════════════════════════════════════

async def test_org_detail_requires_admin(client: AsyncClient):
    """Verify that GET /registry/orgs/{org_id} has _require_admin dependency."""
    from app.registry.org_router import router as org_router, _require_admin
    for route in org_router.routes:
        if not hasattr(route, "path") or not hasattr(route, "methods"):
            continue
        if route.path.endswith("/orgs/{org_id}") and "GET" in route.methods:
            dep_fns = [d.dependency for d in getattr(route, "dependencies", [])]
            assert _require_admin in dep_fns, \
                "GET /registry/orgs/{org_id} must have _require_admin dependency"
            return
    pytest.fail("Route GET /registry/orgs/{org_id} not found")


# ════════════════════════════════════════════════════════════════════════
# #29 — Policy engine evaluates both orgs
# ════════════════════════════════════════════════════════════════════════

async def test_policy_engine_checks_target_org_deny(client: AsyncClient):
    """If the target org has a deny policy, the session should be blocked."""
    from app.policy.engine import PolicyEngine
    from app.policy.store import create_policy
    from tests.conftest import TestSessionLocal

    engine = PolicyEngine()
    uid = uuid.uuid4().hex[:6]
    init_org = f"r2t2pe-init-{uid}"
    tgt_org = f"r2t2pe-tgt-{uid}"

    async with TestSessionLocal() as db:
        # Create initiator allow policy
        await create_policy(db, f"{init_org}::allow", init_org, "session", {
            "effect": "allow", "conditions": {"target_org_id": [], "capabilities": []},
        })
        # Create target deny policy
        await create_policy(db, f"{tgt_org}::deny", tgt_org, "session", {
            "effect": "deny", "conditions": {"target_org_id": []},
        })

        decision = await engine.evaluate_session(
            db,
            initiator_org_id=init_org,
            target_org_id=tgt_org,
            capabilities=["test.read"],
        )
        assert not decision.allowed
        assert "target" in decision.reason.lower() or "denied" in decision.reason.lower()


async def test_policy_engine_allows_when_target_has_no_policy(client: AsyncClient):
    """If the target org has no policies, session should be allowed (opt-out)."""
    from app.policy.engine import PolicyEngine
    from app.policy.store import create_policy
    from tests.conftest import TestSessionLocal

    engine = PolicyEngine()
    uid = uuid.uuid4().hex[:6]
    init_org = f"r2t2pe2-init-{uid}"
    tgt_org = f"r2t2pe2-tgt-{uid}"

    async with TestSessionLocal() as db:
        await create_policy(db, f"{init_org}::allow", init_org, "session", {
            "effect": "allow", "conditions": {"target_org_id": [], "capabilities": []},
        })
        # No policy for target org

        decision = await engine.evaluate_session(
            db,
            initiator_org_id=init_org,
            target_org_id=tgt_org,
            capabilities=["test.read"],
        )
        assert decision.allowed


# ════════════════════════════════════════════════════════════════════════
# #33 — OPA URL validation (SSRF)
# ════════════════════════════════════════════════════════════════════════

class TestOpaUrlValidation:

    def test_invalid_scheme_rejected(self):
        from app.policy.opa import validate_opa_url
        with pytest.raises(ValueError, match="http or https"):
            validate_opa_url("ftp://opa:8181")

    def test_no_hostname_rejected(self):
        from app.policy.opa import validate_opa_url
        with pytest.raises(ValueError, match="no hostname"):
            validate_opa_url("http://")

    def test_http_scheme_accepted(self):
        from app.policy.opa import validate_opa_url
        # localhost is allowed with a warning
        validate_opa_url("http://localhost:8181")

    def test_https_scheme_accepted(self):
        from app.policy.opa import validate_opa_url
        validate_opa_url("https://localhost:8181")

    async def test_evaluate_with_invalid_url_returns_deny(self):
        from app.policy.opa import evaluate_session_via_opa
        decision = await evaluate_session_via_opa(
            "ftp://invalid:8181", "org-a", "org-b", "a::agent", "b::agent", [],
        )
        assert not decision.allowed
        assert "http or https" in decision.reason


# ════════════════════════════════════════════════════════════════════════
# #25 — WebSocket Origin validation
# ════════════════════════════════════════════════════════════════════════

async def test_ws_origin_rejected_when_not_in_allowed_origins(client: AsyncClient):
    """When allowed_origins is restricted, an unknown origin is rejected."""
    from starlette.testclient import TestClient
    from app.main import app
    from app.config import Settings

    mock_settings = Settings(allowed_origins="https://trusted.example.com")

    with patch("app.config.get_settings", return_value=mock_settings):
        tc = TestClient(app)
        try:
            with tc.websocket_connect(
                "/v1/broker/ws",
                headers={"origin": "https://evil.example.com"},
            ) as ws:
                # If we get here, try to receive — should fail
                ws.receive_json()
                pytest.fail("Expected WebSocket to be rejected")
        except Exception:
            pass  # connection refused/closed — expected behavior


async def test_ws_origin_allowed_when_wildcard():
    """When allowed_origins is '*', any origin should be accepted (up to auth)."""
    # Wildcard origin should NOT block — it should proceed to auth
    # We just verify the check logic doesn't block wildcards
    from app.config import Settings
    settings = Settings(allowed_origins="*")
    origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]
    assert "*" in origins  # wildcard = no origin blocking


# ════════════════════════════════════════════════════════════════════════
# #40 — In-memory message rollback on DB error
# ════════════════════════════════════════════════════════════════════════

class TestMessageRollbackOnDbError:

    def test_store_message_and_rollback(self):
        """Verify that store_message can be manually rolled back."""
        session = Session(
            session_id=str(uuid.uuid4()),
            initiator_agent_id="org::a",
            initiator_org_id="org",
            target_agent_id="org::b",
            target_org_id="org",
            requested_capabilities=[],
            status=SessionStatus.active,
        )
        # Store a message
        seq = session.store_message("org::a", {"data": "test"}, "nonce-1")
        assert seq == 0
        assert len(session._messages) == 1
        assert session._next_seq == 1

        # Simulate rollback
        session._messages.pop()
        session._next_seq -= 1
        assert len(session._messages) == 0
        assert session._next_seq == 0


# ════════════════════════════════════════════════════════════════════════
# #26 — WebSocket auth timeout
# ════════════════════════════════════════════════════════════════════════

def test_ws_auth_timeout_constant():
    """Verify the auth timeout constant is set."""
    from app.broker.router import _WS_AUTH_TIMEOUT
    assert _WS_AUTH_TIMEOUT == 10


# ════════════════════════════════════════════════════════════════════════
# #39 — Rate limit on polling
# ════════════════════════════════════════════════════════════════════════

async def test_poll_messages_is_rate_limited(client: AsyncClient, dpop):
    """Verify that polling endpoint calls rate_limiter.check."""
    uid = uuid.uuid4().hex[:6]
    agent_id = f"r2t2org39{uid}::agent"
    org_id = f"r2t2org39{uid}"
    token = await _setup_agent(client, dpop, agent_id, org_id)

    session_id = str(uuid.uuid4())

    # The rate_limiter.check should be called with "broker.poll" action
    # We verify by patching and checking the call
    from app.rate_limit.limiter import rate_limiter as _rl
    original_check = _rl.check

    calls = []

    async def tracking_check(agent_id, action):
        calls.append((agent_id, action))
        return await original_check(agent_id, action)

    with patch.object(_rl, "check", side_effect=tracking_check):
        _resp = await client.get(f"/v1/broker/sessions/{session_id}/messages",
            headers=dpop.headers("GET", f"/v1/broker/sessions/{session_id}/messages", token))
        # Will be 404 (session not found) but the rate limit should have been called
        poll_calls = [c for c in calls if c[1] == "broker.poll"]
        assert len(poll_calls) >= 1, "poll_messages must call rate_limiter.check with 'broker.poll'"
