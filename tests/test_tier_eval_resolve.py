"""ADR-032 Decision E / F5 — server-side ``resolve_effective_tier``.

The Connector's claim is advisory; this helper is the authoritative
read. Pins:

* No agent row OR no ``last_attestation`` → ``"untrusted"`` (deny-by-
  default).
* Malformed JSON → ``"untrusted"``.
* Stale claim → forced to ``compliance=unknown`` per schema sez. 5,
  then tier recomputed — a stale ``managed_attested`` should
  collapse to ``byod_attested`` or lower depending on the strength
  field.
* Server recomputes tier from input fields, not the claim's stored
  ``effective_tier``. A forged claim cannot raise the tier.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.attestation.tier import build_attestation_claim
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.policy.tier_eval import resolve_effective_tier


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "tier_eval.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


async def _seed_agent(agent_id: str, last_attestation: str | None) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO internal_agents (
                       agent_id, display_name, capabilities, cert_pem,
                       created_at, is_active, last_attestation
                   ) VALUES (
                       :aid, 'Test Agent', '[]', '',
                       :ts, 1, :att
                   )"""
            ),
            {
                "aid": agent_id,
                "ts": datetime.now(timezone.utc).isoformat(),
                "att": last_attestation,
            },
        )


async def test_resolve_returns_untrusted_when_agent_missing(proxy_db):
    tier, claim = await resolve_effective_tier("acme::unknown")
    assert tier == "untrusted"
    assert claim is None


async def test_resolve_returns_untrusted_when_no_claim(proxy_db):
    await _seed_agent("acme::clean", last_attestation=None)
    tier, claim = await resolve_effective_tier("acme::clean")
    assert tier == "untrusted"
    assert claim is None


async def test_resolve_returns_untrusted_when_claim_malformed(proxy_db):
    await _seed_agent("acme::corrupt", last_attestation="{not valid json")
    tier, claim = await resolve_effective_tier("acme::corrupt")
    assert tier == "untrusted"
    assert claim is None


async def test_resolve_returns_managed_attested_for_compliant_hw_claim(proxy_db):
    claim = build_attestation_claim(
        mdm="intune",
        device_id="dev-001",
        compliance="compliant",
        manufacturer="Infineon",
        verified_at=datetime.now(timezone.utc),
        hardware="tpm_2.0",
        strength="hw_attested",
    )
    await _seed_agent("acme::topshelf", last_attestation=json.dumps(claim))
    tier, returned = await resolve_effective_tier("acme::topshelf")
    assert tier == "managed_attested"
    assert returned is not None
    assert returned["device_attestation"]["mdm"] == "intune"


async def test_resolve_recomputes_tier_ignoring_claim_stored_value(proxy_db):
    """Server-side recompute. A claim that LIES about its tier (soft
    strength + ``effective_tier=managed_attested``) must collapse back
    to ``untrusted`` because the recompute uses the inputs, not the
    cached output."""
    forged = {
        "device_attestation": {
            "mdm": None,
            "device_id": None,
            "compliance": "compliant",  # ignored because mdm=None
            "hardware": None,
            "strength": "soft_only",
            "manufacturer": None,
            "verified_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ",
            ),
            "stale_seconds": 0,
        },
        "effective_tier": "managed_attested",  # forged
    }
    await _seed_agent("acme::liar", last_attestation=json.dumps(forged))
    tier, _ = await resolve_effective_tier("acme::liar")
    assert tier == "untrusted"


async def test_resolve_stale_claim_downgrades_to_unknown_then_drops_tier(
    monkeypatch, proxy_db,
):
    """Stale claim → compliance forced to ``unknown`` → tier
    recomputed. A managed_attested claim that has gone stale should
    drop because ``has_mdm`` evaluates against ``compliant`` only."""
    # Tighten the threshold so a claim with stale_seconds=999 trips.
    monkeypatch.setenv(
        "MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS", "60",
    )

    stale = {
        "device_attestation": {
            "mdm": "intune",
            "device_id": "dev-stale",
            "compliance": "compliant",
            "hardware": "tpm_2.0",
            "strength": "hw_attested",
            "manufacturer": "Infineon",
            "verified_at": "2026-01-01T00:00:00Z",
            "stale_seconds": 999_999,  # very stale
        },
        "effective_tier": "managed_attested",
    }
    await _seed_agent("acme::stale", last_attestation=json.dumps(stale))
    tier, _ = await resolve_effective_tier("acme::stale")
    # After stale-downgrade: mdm=intune, compliance=unknown → has_mdm=False.
    # strength=hw_attested → byod_attested.
    assert tier == "byod_attested"
