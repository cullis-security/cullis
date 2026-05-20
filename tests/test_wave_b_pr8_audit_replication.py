"""Wave B PR8 / D1 — Court receiver for Mastio audit replication.

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md F-3.

Pre-fix gap: CLAUDE.md + ADR-008 claimed "non-ripudio cross-org dal
dual-write Mastio". The federation publisher only forwarded agent
records (publish-agent). No Mastio audit dual-write existed; an
assessor querying for the evidence would find none.

Post-fix:
  * Mastio publisher (mcp_proxy/federation/audit_publisher.py) reads
    local_audit, ECDSA-signs the batch with the leaf key, POSTs to
    POST /v1/federation/audit/replicate.
  * Court (this module's tests) verifies the countersig, enforces
    chain_seq continuity (within batch + against stored tail), and
    persists into mastio_audit_replica.
  * UNIQUE(mastio_org_id, chain_seq) keeps the receiver idempotent.
  * Append-only via DB trigger from migration s9n0o1p2q3r4_replica.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient
from sqlalchemy import select

from tests.cert_factory import get_org_ca_pem
from tests.conftest import ADMIN_HEADERS

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.mastio_strict,
    pytest.mark.xdist_group(name="serial_wave_b_pr8_audit_replication"),
]


def _gen_mastio_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _sign(priv, data: bytes) -> str:
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


async def _onboard_org_with_mastio(
    client: AsyncClient, org_id: str, mastio_pubkey_pem: str,
) -> None:
    org_secret = f"{org_id}-secret"
    r = await client.post(
        "/v1/registry/orgs",
        json={"org_id": org_id, "display_name": org_id, "secret": org_secret},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code in (201, 409), r.text
    ca_pem = get_org_ca_pem(org_id)
    r = await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert r.status_code in (200, 201), r.text
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import update_org_mastio_pubkey
    async with AsyncSessionLocal() as db:
        await update_org_mastio_pubkey(db, org_id, mastio_pubkey_pem)


def _make_entry(
    *, chain_seq: int, previous_hash: str | None,
    org_id: str, event_type: str = "session.opened",
    session_id: str | None = "sess-x", details: str | None = None,
) -> dict:
    """Build a mock local_audit-shaped entry. ``entry_hash`` is a
    deterministic hash so the test can chain entries by feeding the
    prior entry's hash into the next entry's previous_hash.

    PR #5 audit 2026-05-20 (F-A-401): use ONE timestamp instance both
    inside the canonical input and on the entry wire field, so the
    receiver's recompute matches. Prior version called
    ``datetime.now()`` twice and got two slightly different timestamps,
    which the new recompute step would reject."""
    ts = datetime.now(timezone.utc).isoformat()
    canonical = (
        f"v2|{ts}|{event_type}|"
        f"|{session_id or ''}|{org_id}|ok|{details or ''}|"
        f"{previous_hash or 'genesis'}|seq={chain_seq}|peer="
    )
    entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
    return {
        "chain_seq": chain_seq,
        "entry_hash": entry_hash,
        "previous_hash": previous_hash,
        "timestamp": ts,
        "event_type": event_type,
        "agent_id": None,
        "session_id": session_id,
        "details": details,
        "result": "ok",
        "principal_type": None,
        "hash_format": "v2",
    }


def _build_chain(*, n: int, org_id: str, start_seq: int = 1,
                 previous_hash: str | None = None) -> list[dict]:
    entries = []
    prev = previous_hash
    for i in range(n):
        e = _make_entry(
            chain_seq=start_seq + i, previous_hash=prev, org_id=org_id,
            event_type=f"event.{start_seq + i}",
        )
        entries.append(e)
        prev = e["entry_hash"]
    return entries


async def _fetch_replicas(org_id: str) -> list:
    from app.db.audit import MastioAuditReplica
    from app.db.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(MastioAuditReplica)
                .where(MastioAuditReplica.mastio_org_id == org_id)
                .order_by(MastioAuditReplica.chain_seq.asc())
            )
        ).scalars().all()
    return list(rows)


# ── happy path ────────────────────────────────────────────────────────


async def test_replicate_creates_rows(client: AsyncClient):
    """Mastio publishes a fresh chain → Court stores all rows."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-create"
    await _onboard_org_with_mastio(client, org_id, pub)

    entries = _build_chain(n=3, org_id=org_id)
    body = {"mastio_org_id": org_id, "entries": entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["mastio_org_id"] == org_id
    assert data["stored"] == 3
    assert data["already_present"] == 0
    assert data["last_chain_seq"] == 3

    rows = await _fetch_replicas(org_id)
    assert len(rows) == 3
    assert [r.chain_seq for r in rows] == [1, 2, 3]
    for stored, sent in zip(rows, entries, strict=True):
        assert stored.entry_hash == sent["entry_hash"]
        assert stored.previous_hash == sent["previous_hash"]


async def test_replicate_is_idempotent(client: AsyncClient):
    """Re-publishing the same batch returns already_present, no dups."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-idempo"
    await _onboard_org_with_mastio(client, org_id, pub)

    entries = _build_chain(n=2, org_id=org_id)
    body = {"mastio_org_id": org_id, "entries": entries}
    raw = json.dumps(body).encode()
    sig = _sign(priv, raw)

    r1 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": sig,
        },
    )
    assert r1.status_code == 200
    assert r1.json()["stored"] == 2

    # Same batch again — countersig is over the same body so resign
    # produces the same payload (ECDSA is non-deterministic; we resign).
    r2 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2["stored"] == 0
    assert body2["already_present"] == 2

    rows = await _fetch_replicas(org_id)
    assert len(rows) == 2  # no duplicates


async def test_replicate_continues_from_tail(client: AsyncClient):
    """Second batch chain_seq=3,4 builds on stored tail (seq=2)."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-tail"
    await _onboard_org_with_mastio(client, org_id, pub)

    chain = _build_chain(n=4, org_id=org_id)
    first_batch = chain[:2]
    second_batch = chain[2:]

    body1 = {"mastio_org_id": org_id, "entries": first_batch}
    raw1 = json.dumps(body1).encode()
    r1 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw1,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw1),
        },
    )
    assert r1.status_code == 200

    body2 = {"mastio_org_id": org_id, "entries": second_batch}
    raw2 = json.dumps(body2).encode()
    r2 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw2,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw2),
        },
    )
    assert r2.status_code == 200
    assert r2.json()["last_chain_seq"] == 4
    rows = await _fetch_replicas(org_id)
    assert [r.chain_seq for r in rows] == [1, 2, 3, 4]


# ── negative paths ────────────────────────────────────────────────────


async def test_missing_signature_rejected(client: AsyncClient):
    _, pub = _gen_mastio_keypair()
    org_id = "fed-aud-nosig"
    await _onboard_org_with_mastio(client, org_id, pub)
    entries = _build_chain(n=1, org_id=org_id)
    body = {"mastio_org_id": org_id, "entries": entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 403
    assert "signature" in r.text.lower() or "header" in r.text.lower()


async def test_wrong_signature_key_rejected(client: AsyncClient):
    _, pub = _gen_mastio_keypair()
    org_id = "fed-aud-badkey"
    await _onboard_org_with_mastio(client, org_id, pub)

    # Sign with the wrong private key.
    other_priv, _ = _gen_mastio_keypair()
    entries = _build_chain(n=1, org_id=org_id)
    body = {"mastio_org_id": org_id, "entries": entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(other_priv, raw),
        },
    )
    assert r.status_code == 403


async def test_chain_seq_gap_within_batch_rejected(client: AsyncClient):
    """Batch with chain_seq=1,3 (missing 2) → 400."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-gap"
    await _onboard_org_with_mastio(client, org_id, pub)

    # Build a 3-row chain then drop the middle row, keeping the third
    # row's previous_hash pointing at the dropped second row's hash.
    full = _build_chain(n=3, org_id=org_id)
    bad_entries = [full[0], full[2]]
    body = {"mastio_org_id": org_id, "entries": bad_entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 400
    assert "chain_seq gap" in r.text or "gap" in r.text.lower()


async def test_previous_hash_break_within_batch_rejected(client: AsyncClient):
    """Two adjacent chain_seq but second's previous_hash doesn't match
    first's entry_hash → 400."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-prevbreak"
    await _onboard_org_with_mastio(client, org_id, pub)

    e1 = _make_entry(chain_seq=1, previous_hash=None, org_id=org_id,
                     event_type="e1")
    e2 = _make_entry(chain_seq=2,
                     previous_hash="0" * 64,  # bogus — not e1.entry_hash
                     org_id=org_id, event_type="e2")
    body = {"mastio_org_id": org_id, "entries": [e1, e2]}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 400
    assert "previous_hash" in r.text


async def test_tail_gap_with_stored_rejected(client: AsyncClient):
    """First batch lands seq=1,2. Second batch starts at seq=4 → 400."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-tailgap"
    await _onboard_org_with_mastio(client, org_id, pub)

    full = _build_chain(n=4, org_id=org_id)
    body1 = {"mastio_org_id": org_id, "entries": full[:2]}
    raw1 = json.dumps(body1).encode()
    r1 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw1,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw1),
        },
    )
    assert r1.status_code == 200

    # Skip seq=3 — try to land seq=4 directly. Use a fresh chain
    # whose previous_hash links to "0"*64 (anything that isn't seq=2's
    # entry_hash) so the tail check is what trips, not within-batch.
    isolated = full[3:]
    body2 = {"mastio_org_id": org_id, "entries": isolated}
    raw2 = json.dumps(body2).encode()
    r2 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw2,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw2),
        },
    )
    assert r2.status_code == 400
    assert "tail" in r2.text.lower() or "gap" in r2.text.lower()


async def test_chain_fork_rejected(client: AsyncClient):
    """Same chain_seq submitted with different entry_hash → 409
    (chain fork). This is the fatal Mastio-side incoherence signal."""
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-aud-fork"
    await _onboard_org_with_mastio(client, org_id, pub)

    e1 = _make_entry(chain_seq=1, previous_hash=None, org_id=org_id,
                     event_type="real")
    body1 = {"mastio_org_id": org_id, "entries": [e1]}
    raw1 = json.dumps(body1).encode()
    r1 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw1,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw1),
        },
    )
    assert r1.status_code == 200

    # A different entry at chain_seq=1 — same chain_seq, different hash.
    e1_alt = _make_entry(chain_seq=1, previous_hash=None, org_id=org_id,
                         event_type="forked")
    assert e1_alt["entry_hash"] != e1["entry_hash"]
    body2 = {"mastio_org_id": org_id, "entries": [e1_alt]}
    raw2 = json.dumps(body2).encode()
    r2 = await client.post(
        "/v1/federation/audit/replicate",
        content=raw2,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw2),
        },
    )
    assert r2.status_code == 409
    assert "fork" in r2.text.lower()


async def test_unknown_org_rejected(client: AsyncClient):
    """Mastio_org_id that doesn't exist on the Court → 404."""
    priv, _ = _gen_mastio_keypair()
    entries = _build_chain(n=1, org_id="fed-aud-unknown")
    body = {"mastio_org_id": "fed-aud-unknown", "entries": entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 404


async def test_org_without_pinned_pubkey_rejected(client: AsyncClient):
    """Org exists but mastio_pubkey is NULL → 403."""
    priv, _ = _gen_mastio_keypair()
    org_id = "fed-aud-nopin"
    org_secret = f"{org_id}-secret"
    r = await client.post(
        "/v1/registry/orgs",
        json={"org_id": org_id, "display_name": org_id, "secret": org_secret},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code in (201, 409)
    # No update_org_mastio_pubkey → pubkey stays NULL.

    entries = _build_chain(n=1, org_id=org_id)
    body = {"mastio_org_id": org_id, "entries": entries}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/audit/replicate",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 403
    assert "pubkey" in r.text.lower() or "pinned" in r.text.lower()


@pytest_asyncio.fixture(autouse=True)
async def _drop_replica_triggers_after_test():
    """Mirror of the cleanup in test_wave_b_pr5: drop the
    ``mastio_audit_replica`` append-only triggers after each test so
    they don't leak into other tests on the same xdist worker (which
    would break any DELETE/UPDATE on the replica table).
    """
    yield
    from sqlalchemy import text
    from app.db.database import engine

    is_pg = engine.dialect.name == "postgresql"
    async with engine.begin() as conn:
        if is_pg:
            await conn.execute(text(
                "DROP TRIGGER IF EXISTS mastio_audit_replica_no_update_or_delete "
                "ON mastio_audit_replica"
            ))
        else:
            await conn.execute(text(
                "DROP TRIGGER IF EXISTS mastio_audit_replica_no_update"
            ))
            await conn.execute(text(
                "DROP TRIGGER IF EXISTS mastio_audit_replica_no_delete"
            ))


async def _install_replica_triggers():
    """Install the append-only triggers from migration
    ``s9n0o1p2q3r4_replica``. Required because the test conftest sets
    ``SKIP_ALEMBIC=1`` and uses Base.metadata.create_all, which never
    runs the migration's trigger DDL. Idempotent (CREATE TRIGGER IF
    NOT EXISTS on SQLite, DROP+CREATE on Postgres)."""
    from sqlalchemy import text
    from app.db.database import engine

    is_pg = engine.dialect.name == "postgresql"
    async with engine.begin() as conn:
        if is_pg:
            await conn.execute(text("""
                CREATE OR REPLACE FUNCTION mastio_audit_replica_no_mutate()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'mastio_audit_replica is append-only — UPDATE/DELETE blocked'
                      USING ERRCODE = 'check_violation';
                END;
                $$ LANGUAGE plpgsql;
            """))
            await conn.execute(text(
                "DROP TRIGGER IF EXISTS mastio_audit_replica_no_update_or_delete "
                "ON mastio_audit_replica"
            ))
            await conn.execute(text("""
                CREATE TRIGGER mastio_audit_replica_no_update_or_delete
                BEFORE UPDATE OR DELETE ON mastio_audit_replica
                FOR EACH ROW EXECUTE FUNCTION mastio_audit_replica_no_mutate();
            """))
        else:
            await conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS mastio_audit_replica_no_update
                BEFORE UPDATE ON mastio_audit_replica
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT,
                        'mastio_audit_replica is append-only — UPDATE blocked');
                END;
            """))
            await conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS mastio_audit_replica_no_delete
                BEFORE DELETE ON mastio_audit_replica
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT,
                        'mastio_audit_replica is append-only — DELETE blocked');
                END;
            """))


async def test_append_only_trigger_blocks_update():
    """The DB-level trigger from migration s9n0o1p2q3r4_replica blocks
    UPDATE on a stored row. Same posture as audit_log."""
    from sqlalchemy import update
    from sqlalchemy.exc import DBAPIError

    from app.db.audit import MastioAuditReplica
    from app.db.database import AsyncSessionLocal

    await _install_replica_triggers()

    # Seed a row directly (bypass the endpoint — we're testing the
    # trigger, not the receiver). Use a unique org id so this test
    # doesn't collide with other tests in the shard.
    async with AsyncSessionLocal() as db:
        replica = MastioAuditReplica(
            mastio_org_id="fed-aud-trigger-test",
            chain_seq=1,
            entry_hash="a" * 64,
            previous_hash=None,
            timestamp="2026-05-12T00:00:00+00:00",
            event_type="trigger.test",
            agent_id=None,
            session_id=None,
            details=None,
            result="ok",
            principal_type=None,
            hash_format="v2",
            signature_b64="sig",
            received_at="2026-05-12T00:00:00+00:00",
        )
        db.add(replica)
        await db.commit()

    async with AsyncSessionLocal() as db:
        with pytest.raises(DBAPIError):
            await db.execute(
                update(MastioAuditReplica)
                .where(MastioAuditReplica.mastio_org_id == "fed-aud-trigger-test")
                .values(entry_hash="b" * 64)
            )
            await db.commit()
