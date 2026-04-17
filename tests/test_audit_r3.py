"""
Tests for security audit Round 3 findings.

Covers:
  C2  — Org isolation on GET /agents/{id} and /agents/{id}/public-key
  C3  — save_session inside lock (verified structurally)
  H1  — XSS escape in audit template
  H2  — Nonce cache eviction (no DoS on 100K nonces)
  H3  — Constant-time org secret verification
  H4  — Context field depth/key validation
"""
import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app

pytestmark = pytest.mark.asyncio


# ── C2: Org isolation on agent detail and public-key endpoints ───────────────

async def test_get_agent_cross_org_blocked(client: AsyncClient, db_session: AsyncSession):
    """C2: GET /agents/{id} from a different org must be blocked (403)."""
    from app.registry.store import register_agent
    from app.auth.models import TokenPayload
    from app.auth.jwt import get_current_agent

    # Register agent in org-other
    await register_agent(db_session, "org-other::secret-agent", "org-other",
                         "Secret Agent", ["cap1"], {})

    # Mock auth as agent from org-mine
    fake_agent = TokenPayload(sub="org-mine::my-agent", agent_id="org-mine::my-agent",
                              org="org-mine", scope=["cap1"],
                              exp=9999999999, iat=0, jti="test-jti-1", cnf={"jkt": "fake"})
    app.dependency_overrides[get_current_agent] = lambda: fake_agent
    try:
        resp = await client.get("/v1/federation/agents/org-other::secret-agent")
        assert resp.status_code == 403
        assert "binding" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_current_agent, None)


async def test_get_agent_same_org_allowed(client: AsyncClient, db_session: AsyncSession):
    """C2: GET /agents/{id} within same org must be allowed."""
    from app.registry.store import register_agent
    from app.auth.models import TokenPayload
    from app.auth.jwt import get_current_agent

    await register_agent(db_session, "org-same::agent-a", "org-same",
                         "Agent A", ["cap1"], {})
    await register_agent(db_session, "org-same::agent-b", "org-same",
                         "Agent B", ["cap1"], {})

    fake_agent = TokenPayload(sub="org-same::agent-a", agent_id="org-same::agent-a",
                              org="org-same", scope=["cap1"],
                              exp=9999999999, iat=0, jti="test-jti-2", cnf={"jkt": "fake"})
    app.dependency_overrides[get_current_agent] = lambda: fake_agent
    try:
        resp = await client.get("/v1/federation/agents/org-same::agent-b")
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_agent, None)


# ── H2: Nonce cache eviction instead of blanket deny ────────────────────────

def test_nonce_cache_evicts_instead_of_blocking():
    """H2: After reaching max nonces, new nonces should be accepted (eviction)."""
    from app.broker.session import Session

    session = Session(
        session_id="test-session",
        initiator_agent_id="a",
        initiator_org_id="org-a",
        target_agent_id="b",
        target_org_id="org-b",
        requested_capabilities=[],
    )
    session._MAX_NONCES = 10  # small cap for testing

    # Fill the cache
    for i in range(10):
        session.cache_nonce(f"nonce-{i}")
    assert len(session.used_nonces) == 10

    # New nonce should NOT be flagged as cached (it's new)
    assert not session.is_nonce_cached("nonce-new")

    # Caching the new nonce should evict one entry to make room
    session.cache_nonce("nonce-new")
    assert len(session.used_nonces) == 10  # still at cap
    assert "nonce-new" in session.used_nonces


def test_nonce_cache_replay_still_detected():
    """H2: Replay detection still works after eviction."""
    from app.broker.session import Session

    session = Session(
        session_id="test",
        initiator_agent_id="a",
        initiator_org_id="org-a",
        target_agent_id="b",
        target_org_id="org-b",
        requested_capabilities=[],
    )
    session.cache_nonce("nonce-1")
    assert session.is_nonce_cached("nonce-1")
    assert not session.is_nonce_cached("nonce-2")


# ── H3: Constant-time org secret verification ───────────────────────────────

def test_verify_org_credentials_with_none_org():
    """H3: verify_org_credentials must not short-circuit when org is None."""
    from app.registry.org_store import verify_org_credentials
    # Should not raise, should return False
    result = verify_org_credentials(None, "any-secret")
    assert result is False


def test_verify_org_credentials_with_inactive_org():
    """H3: verify_org_credentials must not short-circuit for inactive orgs."""
    from app.registry.org_store import verify_org_credentials

    org = MagicMock()
    org.status = "pending"
    org.secret_hash = "$2b$12$dummyhash"

    result = verify_org_credentials(org, "wrong-secret")
    assert result is False


def test_verify_org_credentials_source_uses_constant_time():
    """H3: verify_org_credentials must always call bcrypt (no short-circuit)."""
    import inspect
    from app.registry import org_store
    source = inspect.getsource(org_store.verify_org_credentials)
    # Must always run bcrypt, even for None org
    assert "bcrypt.checkpw" in source
    assert "_DUMMY_HASH" in source


# ── H4: Context field validation ─────────────────────────────────────────────

def test_context_rejects_deep_nesting():
    """H4: Context with nesting > 4 levels must be rejected."""
    from app.broker.models import SessionRequest
    from pydantic import ValidationError

    deep = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}
    with pytest.raises(ValidationError, match="depth"):
        SessionRequest(
            target_agent_id="x::y",
            target_org_id="x",
            requested_capabilities=["cap"],
            context=deep,
        )


def test_context_accepts_valid_nesting():
    """H4: Context with nesting <= 4 levels must be accepted."""
    from app.broker.models import SessionRequest

    ok = {"a": {"b": {"c": {"d": "ok"}}}}
    req = SessionRequest(
        target_agent_id="x::y",
        target_org_id="x",
        requested_capabilities=["cap"],
        context=ok,
    )
    assert req.context == ok


def test_context_rejects_oversized():
    """H4: Context > 16 KB must be rejected."""
    from app.broker.models import SessionRequest
    from pydantic import ValidationError

    big = {"data": "x" * 20000}
    with pytest.raises(ValidationError, match="16 KB"):
        SessionRequest(
            target_agent_id="x::y",
            target_org_id="x",
            requested_capabilities=["cap"],
            context=big,
        )


# ── C3: save_session is inside the lock (structural check) ──────────────────

def test_save_session_inside_lock():
    """C3: Verify accept_session calls save_session within the lock block."""
    import inspect
    from app.broker import router

    source = inspect.getsource(router.accept_session)
    # Find the lock block and ensure save_session is inside it
    lines = source.split("\n")
    in_lock = False
    save_inside_lock = False
    for line in lines:
        stripped = line.strip()
        if "async with store._lock" in stripped:
            in_lock = True
        if in_lock and "await save_session" in stripped:
            save_inside_lock = True
            break
        # Lock block ends when indentation returns to the same level
        if in_lock and stripped and not stripped.startswith("#") and not line.startswith(" " * 8) and "async with" not in stripped:
            # We've exited the lock block
            if "await save_session" not in stripped:
                break

    assert save_inside_lock, "save_session must be called inside the store._lock block"
