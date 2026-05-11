"""Wave B PR8 / D1 — Mastio audit replication publisher (Mastio side).

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md F-3.

Tests the publisher loop in mcp_proxy/federation/audit_publisher.py:
  * Reads ``proxy_config[last_replicated_local_audit_id]`` cursor
  * SELECTs new local_audit rows ordered by id
  * Groups by org_id (Court receiver expects single-org batches)
  * POSTs ECDSA-countersigned bodies to Court
  * Advances cursor on success
  * Leaves cursor pinned on failure (retry safety)
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text

from mcp_proxy.federation.audit_publisher import _read_cursor, _tick


pytestmark = pytest.mark.asyncio


# ── helpers ────────────────────────────────────────────────────────────


class _FakeMgr:
    """Minimal AgentManager — only ``countersign`` + ``mastio_loaded``.
    Mirrors tests/test_federation_publisher.py:_FakeMgr."""

    def __init__(self):
        self.mastio_loaded = True
        self._key = ec.generate_private_key(ec.SECP256R1())

    def countersign(self, data: bytes) -> str:
        sig = self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


class _AppState:
    def __init__(self, mgr, broker_url: str, client: httpx.AsyncClient):
        self.agent_manager = mgr
        self.reverse_proxy_broker_url = broker_url
        self.reverse_proxy_client = client


def _make_local_audit_row(
    chain_seq: int, *, org_id: str, previous_hash: str | None,
    event_type: str = "session.opened",
) -> dict:
    """Build the row fields a real ``append_local_audit`` would write."""
    canonical = (
        f"v2|{datetime.now(timezone.utc).isoformat()}|{event_type}|"
        f"||x|{org_id}|ok||{previous_hash or 'genesis'}|"
        f"seq={chain_seq}|peer="
    )
    entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "agent_id": None,
        "session_id": "x",
        "org_id": org_id,
        "details": None,
        "result": "ok",
        "previous_hash": previous_hash,
        "chain_seq": chain_seq,
        "entry_hash": entry_hash,
        "hash_format": "v2",
    }


async def _seed_local_audit(tmp_path, monkeypatch, rows: list[dict]):
    """Boot an isolated proxy DB + insert local_audit rows in order."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import init_db, get_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")

    async with get_db() as conn:
        for r in rows:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_audit (
                        timestamp, event_type, agent_id, session_id, org_id,
                        details, result, previous_hash, chain_seq,
                        peer_org_id, peer_row_hash, entry_hash, hash_format
                    ) VALUES (
                        :timestamp, :event_type, :agent_id, :session_id, :org_id,
                        :details, :result, :previous_hash, :chain_seq,
                        NULL, NULL, :entry_hash, :hash_format
                    )
                    """
                ),
                r,
            )


async def _build_chain(rows_per_org: dict[str, int]) -> list[dict]:
    """Build a fully-chained set of local_audit rows."""
    out: list[dict] = []
    for org_id, n in rows_per_org.items():
        prev = None
        for i in range(1, n + 1):
            row = _make_local_audit_row(
                chain_seq=i, org_id=org_id, previous_hash=prev,
                event_type=f"e{i}",
            )
            out.append(row)
            prev = row["entry_hash"]
    return out


# ── tests ──────────────────────────────────────────────────────────────


async def test_first_run_sends_all_rows(tmp_path, monkeypatch):
    """Cold start (no cursor) → all chained rows sent in one batch."""
    rows = await _build_chain({"orga": 3})
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    captured: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        captured.append(body)
        return httpx.Response(200, json={
            "mastio_org_id": body["mastio_org_id"],
            "stored": len(body["entries"]),
            "already_present": 0,
            "last_chain_seq": body["entries"][-1]["chain_seq"],
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 3
    assert len(captured) == 1
    assert captured[0]["mastio_org_id"] == "orga"
    assert [e["chain_seq"] for e in captured[0]["entries"]] == [1, 2, 3]

    # Cursor should now point at the last row's id (3).
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        cursor = await _read_cursor(conn)
    assert cursor == 3

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_second_run_with_no_new_rows_is_noop(tmp_path, monkeypatch):
    """Cursor already at tail → publisher posts nothing."""
    rows = await _build_chain({"orga": 2})
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    captured: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        captured.append(json.loads(req.content))
        return httpx.Response(200, json={
            "mastio_org_id": "orga", "stored": 2,
            "already_present": 0, "last_chain_seq": 2,
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked1 = await _tick(state)
        # Second tick — no new rows
        acked2 = await _tick(state)

    assert acked1 == 2
    assert acked2 == 0
    assert len(captured) == 1  # only the first tick made an HTTP call

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_groups_per_org(tmp_path, monkeypatch):
    """Two orgs with rows interleaved by id → one batch per org."""
    chain_a = await _build_chain({"orga": 2})
    chain_b = await _build_chain({"orgb": 2})
    # Interleave so id ordering doesn't trivially preserve org order.
    interleaved = [chain_a[0], chain_b[0], chain_a[1], chain_b[1]]
    await _seed_local_audit(tmp_path, monkeypatch, interleaved)

    captured: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        captured.append(body)
        return httpx.Response(200, json={
            "mastio_org_id": body["mastio_org_id"],
            "stored": len(body["entries"]),
            "already_present": 0,
            "last_chain_seq": body["entries"][-1]["chain_seq"],
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 4
    assert len(captured) == 2
    by_org = {b["mastio_org_id"]: b for b in captured}
    assert set(by_org) == {"orga", "orgb"}
    # Each batch should be sorted by chain_seq
    assert [e["chain_seq"] for e in by_org["orga"]["entries"]] == [1, 2]
    assert [e["chain_seq"] for e in by_org["orgb"]["entries"]] == [1, 2]

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_5xx_failure_leaves_cursor(tmp_path, monkeypatch):
    """Court 5xx → cursor stays put for next-tick retry."""
    rows = await _build_chain({"orga": 2})
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream busy")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 0
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        cursor = await _read_cursor(conn)
    assert cursor == 0  # untouched

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_4xx_failure_leaves_cursor(tmp_path, monkeypatch):
    """Court 4xx (e.g. countersig wrong) → cursor stays put. Operator
    must inspect; advancing would skip rows forever."""
    rows = await _build_chain({"orga": 1})
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="bad signature")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 0
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        cursor = await _read_cursor(conn)
    assert cursor == 0

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_skips_rows_without_chain_seq(tmp_path, monkeypatch):
    """Pre-chain-migration rows (chain_seq IS NULL) are not replicated."""
    rows = [
        # legacy row (no chain_seq) — should be skipped
        {
            "timestamp": "2026-04-01T00:00:00+00:00",
            "event_type": "legacy", "agent_id": None, "session_id": None,
            "org_id": "orga", "details": None, "result": "ok",
            "previous_hash": None, "chain_seq": None,
            "entry_hash": None, "hash_format": None,
        },
        *await _build_chain({"orga": 1}),
    ]
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    captured: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        captured.append(body)
        return httpx.Response(200, json={
            "mastio_org_id": body["mastio_org_id"],
            "stored": len(body["entries"]),
            "already_present": 0,
            "last_chain_seq": body["entries"][-1]["chain_seq"],
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 1  # only the chained row, not the legacy one
    assert len(captured) == 1
    assert len(captured[0]["entries"]) == 1
    assert captured[0]["entries"][0]["chain_seq"] == 1

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_standalone_proxy_skips(tmp_path, monkeypatch):
    """Without broker_url (standalone proxy) the loop is a no-op."""
    rows = await _build_chain({"orga": 1})
    await _seed_local_audit(tmp_path, monkeypatch, rows)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(500))
    ) as cli:
        state = _AppState(_FakeMgr(), broker_url=None, client=cli)
        acked = await _tick(state)

    assert acked == 0

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
