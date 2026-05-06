"""Migration 0013 device_info contract — unit-level coverage.

Two entry points:
  1. ``_parse_device_info`` — dashboard Jinja filter. Pure function over
     the raw JSON column, with fallbacks for malformed input.
  2. ``enrollment.service.approve`` — copies ``pending_enrollments.device_info``
     verbatim into the new ``internal_agents.device_info`` column on admin
     approval. Covers the SDK contract: whatever the Connector sent at
     enrollment-start survives to the Agents dashboard.
"""
from __future__ import annotations

import json

import pytest

from mcp_proxy.dashboard.router import _parse_device_info


# ── Filter: pure-function behaviors ────────────────────────────────────


def test_parse_device_none_and_empty_return_none():
    assert _parse_device_info(None) is None
    assert _parse_device_info("") is None


def test_parse_device_malformed_json_returns_none():
    assert _parse_device_info("not-json") is None
    # JSON that isn't a dict (array / string / number) is also None — we
    # don't want the template to receive the raw value and try to
    # index it.
    assert _parse_device_info("[]") is None
    assert _parse_device_info('"scalar"') is None


def test_parse_device_picks_canonical_keys():
    raw = json.dumps({
        "os": "macOS 14.5",
        "hostname": "laptop.local",
        "version": "0.2.0",
    })
    assert _parse_device_info(raw) == {
        "os": "macOS 14.5",
        "hostname": "laptop.local",
        "version": "0.2.0",
    }


def test_parse_device_falls_back_through_aliases():
    # Older connectors may send these keys; the filter normalises them.
    raw = json.dumps({"platform": "linux", "host": "srv-01"})
    assert _parse_device_info(raw) == {
        "os": "linux",
        "hostname": "srv-01",
        "version": None,
    }


def test_parse_device_skips_empty_strings():
    """Empty strings should fall through to the next alias rather than
    pinning ``""`` on the template."""
    raw = json.dumps({"os": "", "platform": "windows", "hostname": "",
                      "host": "desktop-01", "version": "1.3.0"})
    assert _parse_device_info(raw) == {
        "os": "windows",
        "hostname": "desktop-01",
        "version": "1.3.0",
    }


def test_parse_device_coerces_non_string_values():
    """Some SDKs send numbers for version. Coerce rather than drop — the
    operator still wants to see the value."""
    raw = json.dumps({"os": "freebsd", "version": 1})
    out = _parse_device_info(raw)
    assert out["version"] == "1"


# ── Enrollment: device_info survives approve() into internal_agents ───


@pytest.fixture
async def _proxy_db(tmp_path, monkeypatch):
    """Isolated SQLite DB for the enrollment carry-over test."""
    db_file = tmp_path / "approve.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import init_db, dispose_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")
    yield
    await dispose_db()
    get_settings.cache_clear()


class _FakeAgentManager:
    """Minimal stand-in for AgentManager. ``approve`` reads ``ca_loaded``,
    ``sign_external_pubkey``, ``org_id`` and ``trust_domain`` (the last
    two added when device-code approval started persisting ``spiffe_id``
    on ``internal_agents``)."""

    ca_loaded = True
    org_id = "testorg"
    trust_domain = "testorg.test"

    def sign_external_pubkey(self, *, pubkey_pem: str, agent_name: str) -> str:
        # Not a real cert — approve() only stores it on the row.
        return f"-----BEGIN CERTIFICATE-----\nstub-{agent_name}\n-----END CERTIFICATE-----\n"


def _fresh_pubkey_pem() -> str:
    """Generate a real ECDSA P-256 public key PEM; start_enrollment() parses
    it to fingerprint, so a stub string gets rejected."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@pytest.mark.asyncio
async def test_approve_copies_device_info_to_internal_agents(_proxy_db):
    """A device_info blob submitted at enrollment-start must land in
    ``internal_agents.device_info`` on approval — the admin dashboard
    relies on it for the Agents table Device column."""
    from mcp_proxy.db import get_db
    from mcp_proxy.enrollment.service import start_enrollment, approve

    device_json = json.dumps({
        "os": "linux",
        "hostname": "dev-laptop-01",
        "version": "0.2.3",
    })

    async with get_db() as conn:
        started = await start_enrollment(
            conn,
            pubkey_pem=_fresh_pubkey_pem(),
            requester_name="alice",
            requester_email="alice@example.com",
            reason=None,
            device_info=device_json,
        )

    async with get_db() as conn:
        await approve(
            conn,
            session_id=started.session_id,
            agent_id="testorg::alice",
            capabilities=["order.read"],
            groups=[],
            admin_name="admin",
            agent_manager=_FakeAgentManager(),
        )

    # Verify device_info lands verbatim (we store the raw JSON string —
    # parsing happens at display time via the Jinja filter).
    from mcp_proxy.db import get_agent
    row = await get_agent("testorg::alice")
    assert row is not None
    assert row["device_info"] == device_json


@pytest.mark.asyncio
async def test_approve_without_device_info_yields_null(_proxy_db):
    """Connectors that don't advertise device metadata (CLI enrollments,
    legacy SDK versions) must still approve cleanly — the column stays
    NULL and the template shows a dash."""
    from mcp_proxy.db import get_db
    from mcp_proxy.enrollment.service import start_enrollment, approve

    async with get_db() as conn:
        started = await start_enrollment(
            conn,
            pubkey_pem=_fresh_pubkey_pem(),
            requester_name="bob",
            requester_email="bob@example.com",
            reason=None,
            device_info=None,
        )

    async with get_db() as conn:
        await approve(
            conn,
            session_id=started.session_id,
            agent_id="testorg::bob",
            capabilities=[],
            groups=[],
            admin_name="admin",
            agent_manager=_FakeAgentManager(),
        )

    from mcp_proxy.db import get_agent
    row = await get_agent("testorg::bob")
    assert row is not None
    assert row["device_info"] is None
