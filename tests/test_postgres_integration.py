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

@pytest_asyncio.fixture(autouse=True)
async def setup_pg_db():
    """Create tables on Postgres and clean up after every test.

    Function-scoped (audit-2026-05-15 quick win #1). The previous
    ``scope="module"`` made the two tests share both ``app.dependency_
    overrides[get_db]`` and the module-level engine pointers. Under
    ``pytest -n auto --dist=loadfile`` both tests do land on the
    same worker, but other tests on that worker also mutate
    ``app.dependency_overrides`` via the conftest SQLite override
    fixture — an interleaving where the SQLite fixture pop'ed the
    override mid-postgres-test caused two tests to flake recurrently
    (PR #720 / #722 / #723 / #725 / #727 / #728 / #729 / #730 / #731).
    Function scope makes the override lifecycle local to each test,
    and the drop_all + dispose teardown wipes Postgres rows so the
    two tests can't accidentally see each other's seeded agents.

    The captured originals are restored even on test failure so a
    pytest abort never leaves another worker's test pointing at the
    Postgres engine.
    """
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    import app.db.database as db_module
    import app.main as main_module
    _orig_engine = db_module.engine
    _orig_session = db_module.AsyncSessionLocal
    _orig_main = main_module.AsyncSessionLocal
    _had_override = get_db in app.dependency_overrides
    _orig_override = app.dependency_overrides.get(get_db)

    app.dependency_overrides[get_db] = override_get_db
    db_module.engine = pg_engine
    db_module.AsyncSessionLocal = PgSession
    main_module.AsyncSessionLocal = PgSession

    try:
        yield
    finally:
        db_module.engine = _orig_engine
        db_module.AsyncSessionLocal = _orig_session
        main_module.AsyncSessionLocal = _orig_main
        if _had_override:
            app.dependency_overrides[get_db] = _orig_override
        else:
            app.dependency_overrides.pop(get_db, None)
        async with pg_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def pg_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _setup_agent(
    client: AsyncClient, agent_id: str, org_id: str
) -> tuple[str, DPoPHelper]:
    """Setup helper: create org, upload CA, seed court agent, create binding.

    Returns ``(access_token, dpop_helper)``. The helper holds the JWK the
    token is bound to (cnf.jkt), so callers must build per-request DPoP
    proofs via ``dpop.headers(method, path, token)`` instead of plain
    ``Authorization: Bearer`` (rejected by ``app/auth/jwt.py:204-210``).

    Asserts status_code on every HTTP step so a future regression on any
    of these endpoints surfaces here with the actual status + body
    instead of a distant ``KeyError`` on the binding response shape (the
    2026-05-16 postgres drift investigation took 2h to root-cause for
    exactly this reason).
    """
    org_secret = org_id + "-secret"
    resp = await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    assert resp.status_code in (200, 201), (
        f"orgs create failed: {resp.status_code} {resp.text!r}"
    )
    ca_pem = get_org_ca_pem(org_id)
    resp = await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code in (200, 201), (
        f"cert upload failed: {resp.status_code} {resp.text!r}"
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['order.read', 'order.write'],
        session_factory=PgSession,
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read", "order.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code in (200, 201), (
        f"binding create failed: {resp.status_code} {resp.text!r}"
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
    token = await dpop.get_token(client, agent_id, org_id)
    return token, dpop


# ── Test ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pg_session_and_signed_messages(pg_client):
    """Active session + signed messages persisted on Postgres and retrieved after restart."""
    token_a, dpop_a = await _setup_agent(pg_client, "pg-org-a::agent", "pg-org-a")
    token_b, dpop_b = await _setup_agent(pg_client, "pg-org-b::agent", "pg-org-b")

    # Create session
    resp = await pg_client.post("/v1/broker/sessions", json={
        "target_agent_id": "pg-org-b::agent",
        "target_org_id": "pg-org-b",
        "requested_capabilities": ["order.read"],
    }, headers=dpop_a.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 201, resp.text
    session_id = resp.json()["session_id"]

    # Accept
    accept_path = f"/v1/broker/sessions/{session_id}/accept"
    resp = await pg_client.post(accept_path,
                                headers=dpop_b.headers("POST", accept_path, token_b))
    assert resp.status_code == 200, resp.text

    # Send 3 signed messages
    payloads = [
        {"type": "order", "item": "bulloni M8", "qty": 1000},
        {"type": "order", "item": "viti M6",    "qty": 500},
        {"type": "confirm", "ref": "PO-42"},
    ]
    nonces = [str(uuid.uuid4()) for _ in payloads]
    messages_path = f"/v1/broker/sessions/{session_id}/messages"
    for payload, nonce in zip(payloads, nonces):
        sig, _ts = sign_message("pg-org-a::agent", "pg-org-a", session_id, "pg-org-a::agent", nonce, payload)
        resp = await pg_client.post(messages_path, json={
            "session_id": session_id,
            "sender_agent_id": "pg-org-a::agent",
            "payload": payload,
            "nonce": nonce,
            "timestamp": _ts,
            "signature": sig,
        }, headers=dpop_a.headers("POST", messages_path, token_a))
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
                               headers=dpop_a.headers("GET", "/v1/broker/sessions", token_a))
    sessions = resp.json()
    match = next((s for s in sessions if s["session_id"] == session_id), None)
    assert match is not None
    assert match["status"] == "active"

    # Messages retrievable with signatures
    resp = await pg_client.get(messages_path,
                               params={"after": -1},
                               headers=dpop_b.headers("GET", messages_path, token_b))
    assert resp.status_code == 200
    msgs = resp.json()
    assert len(msgs) == 3
    for msg in msgs:
        assert msg["signature"] is not None


@pytest.mark.asyncio
async def test_pg_nonce_replay_blocked(pg_client):
    """Replay of the same nonce must be blocked even after restart on Postgres."""
    token_a, dpop_a = await _setup_agent(pg_client, "pg-replay-a::agent", "pg-replay-a")
    token_b, dpop_b = await _setup_agent(pg_client, "pg-replay-b::agent", "pg-replay-b")

    resp = await pg_client.post("/v1/broker/sessions", json={
        "target_agent_id": "pg-replay-b::agent",
        "target_org_id": "pg-replay-b",
        "requested_capabilities": [],
    }, headers=dpop_a.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    accept_path = f"/v1/broker/sessions/{session_id}/accept"
    await pg_client.post(accept_path,
                         headers=dpop_b.headers("POST", accept_path, token_b))

    messages_path = f"/v1/broker/sessions/{session_id}/messages"
    nonce = str(uuid.uuid4())
    payload = {"msg": "primo"}
    sig, _ts = sign_message("pg-replay-a::agent", "pg-replay-a", session_id, "pg-replay-a::agent", nonce, payload)
    await pg_client.post(messages_path, json={
        "session_id": session_id, "sender_agent_id": "pg-replay-a::agent",
        "payload": payload, "nonce": nonce, "timestamp": _ts, "signature": sig,
    }, headers=dpop_a.headers("POST", messages_path, token_a))

    # Restart
    session_store._sessions.clear()
    async with PgSession() as db:
        await restore_sessions(db, session_store)

    # Replay — must be blocked
    payload2 = {"msg": "replay"}
    sig2, _ts2 = sign_message("pg-replay-a::agent", "pg-replay-a", session_id, "pg-replay-a::agent", nonce, payload2)
    resp = await pg_client.post(messages_path, json={
        "session_id": session_id, "sender_agent_id": "pg-replay-a::agent",
        "payload": payload2, "nonce": nonce, "timestamp": _ts2, "signature": sig2,
    }, headers=dpop_a.headers("POST", messages_path, token_a))
    assert resp.status_code == 409
