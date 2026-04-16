"""ADR-006 §2.2 — deterministic org_id derived from Org CA public key.

The proxy boots standalone, generates its self-signed CA, and the org_id
comes out as sha256(pubkey_DER).hex()[:16]. Two consecutive boots with
the same persisted CA must produce the same org_id. The overview
dashboard exposes it so the admin can paste it into a broker attach-ca
invite (the identity pin in ADR-006 §2.2).
"""
from __future__ import annotations

import hashlib

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

from mcp_proxy.db import dispose_db, get_config, init_db
from mcp_proxy.egress.agent_manager import AgentManager


async def _boot_fresh_db(tmp_path):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    return url


@pytest_asyncio.fixture
async def fresh_db(tmp_path):
    await _boot_fresh_db(tmp_path)
    yield
    await dispose_db()


def _hash_pubkey(cert_pem: str) -> str:
    cert = load_pem_x509_certificate(cert_pem.encode())
    pubkey_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pubkey_der).hexdigest()[:16]


@pytest.mark.asyncio
async def test_derive_flag_sets_org_id_from_pubkey_hash(fresh_db):
    mgr = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr.generate_org_ca(derive_org_id=True)

    assert len(mgr.org_id) == 16
    persisted = await get_config("org_id")
    assert persisted == mgr.org_id

    # The persisted value must match the hash recomputed from the stored CA.
    ca_cert_pem = await get_config("org_ca_cert")
    assert _hash_pubkey(ca_cert_pem) == mgr.org_id


@pytest.mark.asyncio
async def test_derive_off_preserves_operator_provided_org_id(fresh_db):
    mgr = AgentManager(org_id="acme-prod", trust_domain="cullis.local")
    await mgr.generate_org_ca(derive_org_id=False)

    # Operator value wins — derive_org_id=False.
    assert mgr.org_id == "acme-prod"
    assert await get_config("org_id") is None  # not persisted through this path


@pytest.mark.asyncio
async def test_derive_org_id_from_ca_helper_matches_persisted(fresh_db):
    mgr = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr.generate_org_ca(derive_org_id=True)

    # Helper recomputes from the loaded cert — must match what we persisted.
    assert mgr.derive_org_id_from_ca() == mgr.org_id


@pytest.mark.asyncio
async def test_derive_helper_returns_none_without_ca(fresh_db):
    mgr = AgentManager(org_id="acme", trust_domain="cullis.local")
    assert mgr.derive_org_id_from_ca() is None


@pytest.mark.asyncio
async def test_org_id_stable_across_reload(tmp_path):
    """Restart simulation: generate CA, derive org_id, then reload a
    fresh AgentManager from the same DB — org_id must stay the same."""
    await _boot_fresh_db(tmp_path)

    mgr1 = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr1.generate_org_ca(derive_org_id=True)
    first = mgr1.org_id

    # Simulate restart: new AgentManager reading CA from DB.
    mgr2 = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr2.load_org_ca_from_config()
    assert mgr2.derive_org_id_from_ca() == first

    persisted = await get_config("org_id")
    assert persisted == first

    await dispose_db()
