"""
Test transaction tokens — single-use, short-lived tokens for authorized operations.

Covers:
1. Transaction token issuance
2. Transaction token single-use enforcement
3. Transaction token expiry
4. Transaction token payload hash mismatch
5. Transaction token requires auth
6. Full chain: issue token → use in message send
"""
import hashlib
import json
import pytest
from httpx import AsyncClient
from tests.cert_factory import get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio


async def _setup(client: AsyncClient, org_id: str, agent_id: str,
                 capabilities: list[str], dpop) -> str:
    """Register org + CA + agent + approved binding. Returns the JWT."""
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=capabilities,
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


def _payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def test_transaction_token_issuance(client: AsyncClient, dpop):
    """Transaction token is created with correct claims."""
    token = await _setup(client, "tt-org1", "tt-org1::agent",
                         ["order.read"], dpop)

    payload = {"item": "BLT-M10", "qty": 2000, "price": 0.08}
    resp = await client.post("/v1/auth/token/transaction",
        json={
            "agent_id": "tt-org1::agent",
            "txn_type": "CREATE_ORDER",
            "payload_hash": _payload_hash(payload),
            "target_agent_id": "tt-sup1::agent",
            "ttl_seconds": 60,
        },
        headers=dpop.headers("POST", "/v1/auth/token/transaction", token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["txn_type"] == "CREATE_ORDER"
    assert data["expires_in"] == 60
    assert "jti" in data
    assert "transaction_token" in data


async def test_transaction_token_wrong_agent(client: AsyncClient, dpop):
    """Cannot request a transaction token for a different agent."""
    token = await _setup(client, "tt-org2", "tt-org2::agent",
                         ["order.read"], dpop)

    resp = await client.post("/v1/auth/token/transaction",
        json={
            "agent_id": "other-org::other-agent",
            "txn_type": "CREATE_ORDER",
            "payload_hash": "abc123",
        },
        headers=dpop.headers("POST", "/v1/auth/token/transaction", token),
    )
    assert resp.status_code == 403


async def test_transaction_token_requires_auth(client: AsyncClient):
    """Transaction token without auth returns 401."""
    resp = await client.post("/v1/auth/token/transaction",
        json={
            "agent_id": "any::agent",
            "txn_type": "CREATE_ORDER",
            "payload_hash": "abc123",
        },
    )
    assert resp.status_code in (401, 403)


async def test_transaction_token_single_use(client: AsyncClient, dpop, db_session):
    """Transaction token can only be consumed once."""
    from app.auth.transaction_token import (
        create_transaction_token, validate_and_consume_transaction_token,
    )
    from app.auth.models import TokenPayload

    payload = {"item": "test", "qty": 1}
    ph = _payload_hash(payload)

    token_str, record = await create_transaction_token(
        db_session,
        agent_id="tt-single::agent",
        org_id="tt-single",
        txn_type="CREATE_ORDER",
        payload_hash=ph,
        approved_by="admin@acme.com",
    )

    # Build a mock TokenPayload instead of decoding (avoids DPoP verification)
    tp = TokenPayload(
        sub="spiffe://cullis.local/tt-single/agent",
        agent_id="tt-single::agent",
        org="tt-single",
        exp=int(record.expires_at.timestamp()),
        iat=int(record.created_at.timestamp()),
        jti=record.jti,
        token_type="transaction",
        txn_type="CREATE_ORDER",
        payload_hash=ph,
    )

    # First consumption — succeeds
    consumed = await validate_and_consume_transaction_token(db_session, tp, ph)
    assert consumed.status == "consumed"

    # Second consumption — fails
    with pytest.raises(ValueError, match="already consumed"):
        await validate_and_consume_transaction_token(db_session, tp, ph)


async def test_transaction_token_payload_hash_mismatch(client: AsyncClient, dpop, db_session):
    """Transaction token rejected when payload doesn't match."""
    from app.auth.transaction_token import (
        create_transaction_token, validate_and_consume_transaction_token,
    )
    from app.auth.models import TokenPayload

    correct_hash = _payload_hash({"item": "A"})
    wrong_hash = _payload_hash({"item": "B"})

    _, record = await create_transaction_token(
        db_session,
        agent_id="tt-hash::agent",
        org_id="tt-hash",
        txn_type="CREATE_ORDER",
        payload_hash=correct_hash,
        approved_by="admin@acme.com",
    )

    tp = TokenPayload(
        sub="spiffe://cullis.local/tt-hash/agent",
        agent_id="tt-hash::agent",
        org="tt-hash",
        exp=int(record.expires_at.timestamp()),
        iat=int(record.created_at.timestamp()),
        jti=record.jti,
        token_type="transaction",
        txn_type="CREATE_ORDER",
        payload_hash=correct_hash,
    )

    with pytest.raises(ValueError, match="hash mismatch"):
        await validate_and_consume_transaction_token(db_session, tp, wrong_hash)


async def test_transaction_token_expired(client: AsyncClient, dpop, db_session):
    """Expired transaction token is rejected."""
    from app.auth.transaction_token import (
        create_transaction_token, validate_and_consume_transaction_token,
    )
    from app.auth.models import TokenPayload

    ph = _payload_hash({"test": True})

    _, record = await create_transaction_token(
        db_session,
        agent_id="tt-exp::agent",
        org_id="tt-exp",
        txn_type="CREATE_ORDER",
        payload_hash=ph,
        approved_by="admin@acme.com",
        ttl_seconds=1,
    )

    # Wait for expiry
    import asyncio
    await asyncio.sleep(1.5)

    tp = TokenPayload(
        sub="spiffe://cullis.local/tt-exp/agent",
        agent_id="tt-exp::agent",
        org="tt-exp",
        exp=int(record.expires_at.timestamp()),
        iat=int(record.created_at.timestamp()),
        jti=record.jti,
        token_type="transaction",
        txn_type="CREATE_ORDER",
        payload_hash=ph,
    )

    with pytest.raises(ValueError, match="expired"):
        await validate_and_consume_transaction_token(db_session, tp, ph)
