"""
Postgres integration tests — sessions and signed messages.

Uses the real Postgres engine (not the SQLite override from conftest).
Requires the agent-trust-db container running on localhost:5432.

Run with:
  pytest tests/test_postgres_integration.py -v -s
"""
import uuid
import pytest
import pytest_asyncio

from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.db.database import Base, get_db
from app.auth.jti_blacklist import JtiBlacklist as _JBL        # noqa
from app.broker.db_models import SessionRecord, SessionMessageRecord  # noqa
from app.broker.session import session_store
from app.broker.persistence import restore_sessions
from tests.cert_factory import get_org_ca_pem, sign_message, DPoPHelper
from tests.conftest import ADMIN_HEADERS, seed_court_agent

POSTGRES_URL = "postgresql+asyncpg://agent:trustme@localhost:5432/agent_trust"

# Skip entire module if Postgres is not available
import socket
def _pg_available():
    try:
        s = socket.create_connection(("localhost", 5432), timeout=1)
        s.close()
        return True
    except OSError:
        return False

pytestmark = pytest.mark.skipif(not _pg_available(), reason="Postgres not available")

pg_engine = create_async_engine(POSTGRES_URL, echo=False, poolclass=NullPool)
PgSession = async_sessionmaker(pg_engine, expire_on_commit=False)


async def override_get_db():
    async with PgSession() as session:
        yield session


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_pg_db():
    """Create tables on Postgres and clean up at the end."""
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app.dependency_overrides[get_db] = override_get_db

    import app.db.database as db_module
    import app.main as main_module
    _orig_engine = db_module.engine
    _orig_session = db_module.AsyncSessionLocal
    _orig_main = main_module.AsyncSessionLocal

    db_module.engine = pg_engine
    db_module.AsyncSessionLocal = PgSession
    main_module.AsyncSessionLocal = PgSession

    yield

    db_module.engine = _orig_engine
    db_module.AsyncSessionLocal = _orig_session
    main_module.AsyncSessionLocal = _orig_main
    app.dependency_overrides.pop(get_db, None)

    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await pg_engine.dispose()


@pytest_asyncio.fixture
async def pg_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _setup_agent(client: AsyncClient, agent_id: str, org_id: str) -> str:
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['order.read', 'order.write'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read", "order.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/policy/rules", json={
        "policy_id": f"{org_id}::allow-all",
        "org_id": org_id,
        "policy_type": "session",
        "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})

    dpop = DPoPHelper()
    return await dpop.get_token(client, agent_id, org_id)


# ── Test ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pg_session_and_signed_messages(pg_client):
    """Active session + signed messages persisted on Postgres and retrieved after restart."""
    token_a = await _setup_agent(pg_client, "pg-org-a::agent", "pg-org-a")
    token_b = await _setup_agent(pg_client, "pg-org-b::agent", "pg-org-b")

    # Create session
    resp = await pg_client.post("/v1/broker/sessions", json={
        "target_agent_id": "pg-org-b::agent",
        "target_org_id": "pg-org-b",
        "requested_capabilities": ["order.read"],
    }, headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 201, resp.text
    session_id = resp.json()["session_id"]

    # Accept
    resp = await pg_client.post(f"/v1/broker/sessions/{session_id}/accept",
                                headers={"Authorization": f"Bearer {token_b}"})
    assert resp.status_code == 200, resp.text

    # Send 3 signed messages
    payloads = [
        {"type": "order", "item": "bulloni M8", "qty": 1000},
        {"type": "order", "item": "viti M6",    "qty": 500},
        {"type": "confirm", "ref": "PO-42"},
    ]
    nonces = [str(uuid.uuid4()) for _ in payloads]
    for payload, nonce in zip(payloads, nonces):
        sig, _ts = sign_message("pg-org-a::agent", "pg-org-a", session_id, "pg-org-a::agent", nonce, payload)
        resp = await pg_client.post(f"/v1/broker/sessions/{session_id}/messages", json={
            "session_id": session_id,
            "sender_agent_id": "pg-org-a::agent",
            "payload": payload,
            "nonce": nonce,
            "timestamp": _ts,
            "signature": sig,
        }, headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code == 202, resp.text

    # Verify that records are on Postgres (session opened and closed within the test)
    async with PgSession() as db:
        result = await db.execute(
            select(SessionMessageRecord).where(SessionMessageRecord.session_id == session_id)
        )
        rows = result.scalars().all()
        assert len(rows) == 3
        for row in rows:
            assert row.signature is not None
            assert row.nonce in nonces

    # ── Simulate restart ──────────────────────────────────────────────────────
    session_store._sessions.clear()
    async with PgSession() as db:
        restored = await restore_sessions(db, session_store)
    assert restored >= 1

    # Session still active
    resp = await pg_client.get("/v1/broker/sessions",
                               headers={"Authorization": f"Bearer {token_a}"})
    sessions = resp.json()
    match = next((s for s in sessions if s["session_id"] == session_id), None)
    assert match is not None
    assert match["status"] == "active"

    # Messages retrievable with signatures
    resp = await pg_client.get(f"/v1/broker/sessions/{session_id}/messages",
                               params={"after": -1},
                               headers={"Authorization": f"Bearer {token_b}"})
    assert resp.status_code == 200
    msgs = resp.json()
    assert len(msgs) == 3
    for msg in msgs:
        assert msg["signature"] is not None


@pytest.mark.asyncio
async def test_pg_nonce_replay_blocked(pg_client):
    """Replay of the same nonce must be blocked even after restart on Postgres."""
    token_a = await _setup_agent(pg_client, "pg-replay-a::agent", "pg-replay-a")
    token_b = await _setup_agent(pg_client, "pg-replay-b::agent", "pg-replay-b")

    resp = await pg_client.post("/v1/broker/sessions", json={
        "target_agent_id": "pg-replay-b::agent",
        "target_org_id": "pg-replay-b",
        "requested_capabilities": [],
    }, headers={"Authorization": f"Bearer {token_a}"})
    session_id = resp.json()["session_id"]
    await pg_client.post(f"/v1/broker/sessions/{session_id}/accept",
                         headers={"Authorization": f"Bearer {token_b}"})

    nonce = str(uuid.uuid4())
    payload = {"msg": "primo"}
    sig, _ts = sign_message("pg-replay-a::agent", "pg-replay-a", session_id, "pg-replay-a::agent", nonce, payload)
    await pg_client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id, "sender_agent_id": "pg-replay-a::agent",
        "payload": payload, "nonce": nonce, "timestamp": _ts, "signature": sig,
    }, headers={"Authorization": f"Bearer {token_a}"})

    # Restart
    session_store._sessions.clear()
    async with PgSession() as db:
        await restore_sessions(db, session_store)

    # Replay — must be blocked
    payload2 = {"msg": "replay"}
    sig2, _ts2 = sign_message("pg-replay-a::agent", "pg-replay-a", session_id, "pg-replay-a::agent", nonce, payload2)
    resp = await pg_client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id, "sender_agent_id": "pg-replay-a::agent",
        "payload": payload2, "nonce": nonce, "timestamp": _ts2, "signature": sig2,
    }, headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 409
