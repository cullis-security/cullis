"""ADR-010 Phase 3 — federation publisher loop unit tests.

No real Court; uses httpx MockTransport + a fake AgentManager. Covers:
  - Only federated rows with revision > last_pushed_revision get pushed
  - Successful 2xx push bumps last_pushed_revision to federation_revision
  - 4xx "poison" response is also acknowledged (so we don't spin)
  - 5xx transient errors leave last_pushed_revision untouched (retry)
  - Connection error leaves row pending
  - Revoked (is_active=0) rows produce revoked=true payload
"""
from __future__ import annotations

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.federation.publisher import _collect_stats, _publish_stats_once, _tick


pytestmark = pytest.mark.asyncio


# ── helpers ─────────────────────────────────────────────────────────────

class _FakeMgr:
    """Minimal drop-in for AgentManager that only answers ``countersign``
    and advertises ``mastio_loaded=True``. Signatures are real ES256 so the
    transport assertion can verify them."""

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


async def _seed_agents(tmp_path, monkeypatch, rows: list[dict]):
    """Boot an isolated proxy DB + populate internal_agents with the rows."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import init_db, get_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")

    async with get_db() as conn:
        from sqlalchemy import text
        for r in rows:
            await conn.execute(
                text(
                    """
                    INSERT INTO internal_agents (
                        agent_id, display_name, capabilities, cert_pem, created_at, is_active,
                        federated, federated_at, federation_revision,
                        last_pushed_revision
                    ) VALUES (
                        :aid, :name, :caps,
                        :cert, :created, :active,
                        :fed, :fed_at, :rev, :last
                    )
                    """
                ),
                {
                    "aid": r["agent_id"],
                    "name": r.get("display_name", r["agent_id"]),
                    "caps": json.dumps(r.get("capabilities", [])),
                    "cert": r.get("cert_pem", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"),
                    "created": "2026-04-17T00:00:00+00:00",
                    "active": 1 if r.get("is_active", True) else 0,
                    "fed": 1 if r.get("federated", True) else 0,
                    "fed_at": r.get("federated_at"),
                    "rev": r.get("federation_revision", 1),
                    "last": r.get("last_pushed_revision", 0),
                },
            )


async def _fetch_last_pushed(agent_id: str) -> int:
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT last_pushed_revision FROM internal_agents WHERE agent_id = :aid"),
            {"aid": agent_id},
        )).first()
        return int(row[0]) if row else -1


# ── tests ───────────────────────────────────────────────────────────────

async def test_publishes_federated_rows_only(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::alice", "federated": True,  "federation_revision": 3},
        {"agent_id": "orga::bob",   "federated": False, "federation_revision": 2},
    ])
    seen: list[str] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body["agent_id"])
        return httpx.Response(200, json={
            "agent_id": body["agent_id"], "org_id": "orga",
            "status": "created", "cert_thumbprint": "x",
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 1
    assert seen == ["orga::alice"]
    assert await _fetch_last_pushed("orga::alice") == 3
    assert await _fetch_last_pushed("orga::bob") == 0

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_ack_at_4xx_prevents_infinite_retry(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::carol", "federated": True, "federation_revision": 5},
    ])

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "bad shape"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 1
    # 4xx is still "ack": the Court will never accept this row as-is.
    assert await _fetch_last_pushed("orga::carol") == 5

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_5xx_leaves_row_pending(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::dave", "federated": True, "federation_revision": 7},
    ])

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 0
    assert await _fetch_last_pushed("orga::dave") == 0  # still pending

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_connection_error_leaves_row_pending(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::eve", "federated": True, "federation_revision": 2},
    ])

    def _handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 0
    assert await _fetch_last_pushed("orga::eve") == 0

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_revoked_row_pushes_revoked_true(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {
            "agent_id": "orga::frank",
            "federated": True,
            "is_active": False,
            "federated_at": "2026-04-17T00:00:00+00:00",
            "federation_revision": 2,
        },
    ])
    payloads: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        payloads.append(json.loads(req.content))
        return httpx.Response(200, json={
            "agent_id": "orga::frank", "org_id": "orga",
            "status": "revoked", "cert_thumbprint": "x",
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppState(_FakeMgr(), "http://broker", cli)
        acked = await _tick(state)

    assert acked == 1
    assert payloads[0]["revoked"] is True

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_standalone_is_noop(tmp_path, monkeypatch):
    """Without broker_url + mastio_loaded the publisher does nothing."""
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::ghost", "federated": True, "federation_revision": 1},
    ])

    class _NoMgr:
        mastio_loaded = False

    async with httpx.AsyncClient() as cli:
        state = _AppState(_NoMgr(), "", cli)
        acked = await _tick(state)
    assert acked == 0

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── stats publisher ────────────────────────────────────────────────────


async def _seed_backend(enabled: int, name: str = "b1") -> None:
    """Insert a ``local_mcp_resources`` row used by _collect_stats."""
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    import uuid
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_mcp_resources (
                    resource_id, org_id, name, endpoint_url,
                    auth_type, allowed_domains, enabled,
                    created_at, updated_at
                ) VALUES (
                    :rid, :org, :name, 'http://svc:8080',
                    'none', '[]', :enabled,
                    '2026-04-17T00:00:00+00:00', '2026-04-17T00:00:00+00:00'
                )
                """
            ),
            {
                "rid": str(uuid.uuid4()), "org": "orga",
                "name": name, "enabled": enabled,
            },
        )


class _AppStateStats(_AppState):
    def __init__(self, mgr, broker_url, client, org_id):
        super().__init__(mgr, broker_url, client)
        self.org_id = org_id


async def test_collect_stats_counts_agents_and_enabled_backends(
    tmp_path, monkeypatch,
):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::a1", "is_active": True},
        {"agent_id": "orga::a2", "is_active": True},
        {"agent_id": "orga::a3", "is_active": False},
    ])
    await _seed_backend(enabled=1, name="postgres")
    await _seed_backend(enabled=1, name="github")
    await _seed_backend(enabled=0, name="disabled")

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        stats = await _collect_stats(conn, org_id="orga")

    assert stats == {
        "org_id": "orga",
        "agent_active_count": 2,
        "agent_total_count": 3,
        "backend_count": 2,  # disabled row excluded
    }

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_publish_stats_once_sends_signed_payload(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::a1", "is_active": True},
    ])
    await _seed_backend(enabled=1)

    captured: dict = {}

    def _handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["sig"] = req.headers.get("x-cullis-mastio-signature")
        captured["body"] = json.loads(req.content)
        return httpx.Response(200, json={
            "org_id": "orga", "stored_at": "2026-04-17T12:00:00+00:00",
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppStateStats(_FakeMgr(), "http://broker", cli, "orga")
        ok = await _publish_stats_once(state)

    assert ok is True
    assert captured["url"] == "http://broker/v1/federation/publish-stats"
    assert captured["sig"]  # non-empty counter-sig header
    assert captured["body"] == {
        "org_id": "orga",
        "agent_active_count": 1,
        "agent_total_count": 1,
        "backend_count": 1,
    }

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_publish_stats_once_skips_when_standalone(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::a1", "is_active": True},
    ])

    class _NoMgr:
        mastio_loaded = False

    async with httpx.AsyncClient() as cli:
        state = _AppStateStats(_NoMgr(), "", cli, "orga")
        assert await _publish_stats_once(state) is False

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_publish_stats_once_returns_false_on_5xx(tmp_path, monkeypatch):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::a1", "is_active": True},
    ])

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppStateStats(_FakeMgr(), "http://broker", cli, "orga")
        ok = await _publish_stats_once(state)
    assert ok is False

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_publish_stats_once_survives_connection_error(
    tmp_path, monkeypatch,
):
    await _seed_agents(tmp_path, monkeypatch, [
        {"agent_id": "orga::a1", "is_active": True},
    ])

    def _handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("broker down")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as cli:
        state = _AppStateStats(_FakeMgr(), "http://broker", cli, "orga")
        ok = await _publish_stats_once(state)
    assert ok is False

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
