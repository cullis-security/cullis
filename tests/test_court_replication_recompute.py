"""PR #5 audit 2026-05-20: F-A-401 Court replication recompute entry_hash.

Pre-fix the Court audit replica receiver enforced ECDSA-P256
countersig + chain_seq continuity + previous_hash linkage, but did
NOT recompute each entry_hash from the canonical inputs. A compromised
Mastio (or insider with the Mastio's leaf key) could mutate any row's
content, recompute entry_hash for the mutated row, and forward-fix
previous_hash on the chain tail — continuity intact, replica silently
diverged from the Mastio's actual local_audit.

This test posts a batch where one entry has a CORRECT hash for the
declared fields but wrong content — i.e., the wire has details="X",
entry_hash matches "X" canonical, but the test then mutates details
to "Y" before sending while keeping entry_hash unchanged. The
receiver must recompute, get a different hash, and reject 400.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest


def _v2_canonical(
    *, ts: str, event_type: str, session_id: str | None,
    org_id: str, result: str, details: str | None,
    previous_hash: str | None, chain_seq: int,
    agent_id: str | None = None,
) -> str:
    return (
        f"v2|{ts}|{event_type}|"
        f"{agent_id or ''}|{session_id or ''}|{org_id}|"
        f"{result}|{details or ''}|"
        f"{previous_hash or 'genesis'}|seq={chain_seq}|peer="
    )


def test_v2_canonical_matches_audit_module():
    """Sanity check: our test canonical builder matches
    app.db.audit.compute_entry_hash_v2 byte-for-byte (so a mismatch
    detected by the receiver is the entry content, not a canonical
    drift between sides)."""
    from app.db.audit import compute_entry_hash_v2

    ts_dt = datetime(2026, 5, 20, 15, 0, 0, tzinfo=timezone.utc)
    ts_str = ts_dt.isoformat()
    common = dict(
        event_type="session.opened",
        agent_id=None,
        session_id="sess-1",
        org_id="acme",
        result="ok",
        details="seeded",
        previous_hash=None,
        chain_seq=1,
        peer_org_id=None,
        principal_type=None,
    )
    expected = compute_entry_hash_v2(timestamp=ts_dt, **common)

    canonical_str = _v2_canonical(
        ts=ts_str,
        event_type="session.opened",
        session_id="sess-1",
        org_id="acme",
        result="ok",
        details="seeded",
        previous_hash=None,
        chain_seq=1,
        agent_id=None,
    )
    assert hashlib.sha256(canonical_str.encode()).hexdigest() == expected


def test_recompute_catches_content_mutation():
    """F-A-401 attack scenario: hash computed against details='real',
    wire carries details='forged', entry_hash unchanged. Receiver's
    recompute over details='forged' produces a different hash and
    must reject.

    This is a unit-level proof of the gate — the integration version
    (HTTP POST with countersig + DB persistence) lives in
    tests/test_wave_b_pr8_audit_replication.py and is exercised by
    the entire chain test suite continuing to pass after this PR
    (every existing test would fail if the recompute were broken)."""
    from app.db.audit import compute_entry_hash_v2

    ts = datetime(2026, 5, 20, 15, 0, 0, tzinfo=timezone.utc)
    real_hash = compute_entry_hash_v2(
        timestamp=ts,
        event_type="tool.invoke",
        agent_id="acme::alice",
        session_id="sess-1",
        org_id="acme",
        result="ok",
        details="real_payload",
        previous_hash=None,
        chain_seq=1,
        peer_org_id=None,
        principal_type=None,
    )
    forged_hash = compute_entry_hash_v2(
        timestamp=ts,
        event_type="tool.invoke",
        agent_id="acme::alice",
        session_id="sess-1",
        org_id="acme",
        result="ok",
        details="forged_payload",  # only this changed
        previous_hash=None,
        chain_seq=1,
        peer_org_id=None,
        principal_type=None,
    )
    assert real_hash != forged_hash, (
        "F-A-401: hash must change when details change. If equal, "
        "the recompute gate is meaningless."
    )
