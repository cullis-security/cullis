"""
Tests for the admin audit export endpoint.
"""
import json
import pytest

from app.config import get_settings
from app.db.audit import log_event


_EXPORT_ORG = "export-test-org"
_EXPORT_ORG_B = "export-test-org-b"


@pytest.fixture
async def seed_audit(db_session):
    """Insert sample audit entries for export tests."""
    await log_event(db_session, "auth.token", "ok", agent_id=f"{_EXPORT_ORG}::agent1", org_id=_EXPORT_ORG)
    await log_event(db_session, "session.create", "ok", agent_id=f"{_EXPORT_ORG}::agent1", session_id="sess-export-1", org_id=_EXPORT_ORG)
    await log_event(db_session, "auth.token", "denied", agent_id=f"{_EXPORT_ORG_B}::agent2", org_id=_EXPORT_ORG_B)
    await log_event(db_session, "policy.evaluate", "ok", session_id="sess-export-1", org_id=_EXPORT_ORG)
    return 4  # number of entries in this batch


def _admin_headers():
    return {"X-Admin-Secret": get_settings().admin_secret}


@pytest.mark.asyncio
async def test_export_json_default(client, seed_audit):
    """Default export returns NDJSON."""
    resp = await client.get(
        f"/v1/admin/audit/export?org_id={_EXPORT_ORG}", headers=_admin_headers()
    )
    assert resp.status_code == 200
    assert "application/x-ndjson" in resp.headers["content-type"]
    lines = [line for line in resp.text.strip().split("\n") if line]
    assert len(lines) >= 3  # at least our 3 org-a entries
    for line in lines:
        obj = json.loads(line)
        assert "event_type" in obj
        assert "entry_hash" in obj
        assert obj["org_id"] == _EXPORT_ORG


@pytest.mark.asyncio
async def test_export_csv(client, seed_audit):
    """CSV export includes header row and data rows."""
    resp = await client.get(
        f"/v1/admin/audit/export?format=csv&org_id={_EXPORT_ORG}", headers=_admin_headers()
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = resp.text.strip().split("\n")
    assert lines[0].startswith("id,timestamp")  # header row
    assert len(lines) >= 4  # header + at least 3 data rows


@pytest.mark.asyncio
async def test_export_filter_org_id(client, seed_audit):
    """Filter by org_id returns only matching entries."""
    resp = await client.get(
        f"/v1/admin/audit/export?org_id={_EXPORT_ORG_B}", headers=_admin_headers()
    )
    assert resp.status_code == 200
    lines = [line for line in resp.text.strip().split("\n") if line]
    assert len(lines) >= 1
    for line in lines:
        obj = json.loads(line)
        assert obj["org_id"] == _EXPORT_ORG_B


@pytest.mark.asyncio
async def test_export_filter_event_type(client, seed_audit):
    """Filter by event_type returns only matching entries."""
    resp = await client.get(
        f"/v1/admin/audit/export?event_type=auth.token&org_id={_EXPORT_ORG}", headers=_admin_headers()
    )
    assert resp.status_code == 200
    lines = [line for line in resp.text.strip().split("\n") if line]
    assert len(lines) >= 1
    for line in lines:
        obj = json.loads(line)
        assert obj["event_type"] == "auth.token"
        assert obj["org_id"] == _EXPORT_ORG


@pytest.mark.asyncio
async def test_export_limit(client, seed_audit):
    """Limit parameter caps number of returned entries."""
    resp = await client.get(
        "/v1/admin/audit/export?limit=1", headers=_admin_headers()
    )
    assert resp.status_code == 200
    lines = [line for line in resp.text.strip().split("\n") if line]
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_export_requires_admin(client, seed_audit):
    """Export without admin secret returns 422 (missing header)."""
    resp = await client.get("/v1/admin/audit/export")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_export_wrong_admin_secret(client, seed_audit):
    """Export with wrong admin secret returns 403."""
    resp = await client.get(
        "/v1/admin/audit/export", headers={"X-Admin-Secret": "wrong"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_export_hash_chain_intact(client, seed_audit):
    """Exported entries within one org form a contiguous per-org chain."""
    resp = await client.get(
        f"/v1/admin/audit/export?org_id={_EXPORT_ORG}", headers=_admin_headers()
    )
    lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
    # Filter down to only this test's seeded entries (order preserved by id).
    seeded = [
        entry for entry in lines
        if entry.get("agent_id") == f"{_EXPORT_ORG}::agent1"
        or entry.get("session_id") == "sess-export-1"
    ]
    assert len(seeded) >= 3
    for i, entry in enumerate(seeded):
        assert entry["entry_hash"] is not None
        if i > 0:
            assert entry["previous_hash"] == seeded[i - 1]["entry_hash"]
