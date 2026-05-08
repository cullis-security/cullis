"""Audit W1.6 — broker preserves the signer's wire timestamp on
``store_message`` instead of silently overwriting with broker-side now().

The pre-fix behaviour discarded ``MessageEnvelope.timestamp`` and stamped
the StoredMessage with whatever the broker clock said at insert time.
SDK consumers (session-poll, ordering-by-timestamp) need the signer's
claim, not the broker's local clock.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from app.broker.session import Session, SessionStatus


def _make_session() -> Session:
    return Session(
        session_id="sess-w16",
        initiator_agent_id="orga::a",
        initiator_org_id="orga",
        target_agent_id="orgb::b",
        target_org_id="orgb",
        requested_capabilities=[],
        status=SessionStatus.active,
    )


def test_store_message_preserves_caller_timestamp():
    sess = _make_session()
    signed_at = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    seq = sess.store_message(
        sender_agent_id="orga::a",
        payload={"hello": "world"},
        nonce="nonce-1",
        signature="sig-1",
        timestamp=signed_at,
    )
    stored = sess._messages[seq]
    assert stored.timestamp == signed_at, (
        "broker must store the signer's wire timestamp verbatim"
    )


def test_store_message_falls_back_to_now_when_timestamp_omitted():
    """Legacy callers (transaction tokens, internal injections) that
    don't carry a signed timestamp keep the broker-now behaviour."""
    sess = _make_session()
    before = datetime.now(timezone.utc)
    seq = sess.store_message(
        sender_agent_id="orga::a",
        payload={"x": 1},
        nonce="nonce-fallback",
        signature="sig-fallback",
    )
    after = datetime.now(timezone.utc)
    stored = sess._messages[seq]
    # Bracketed by the call window — proves default_factory ran.
    assert before - timedelta(seconds=1) <= stored.timestamp <= after + timedelta(seconds=1)


def test_store_message_timestamp_independent_per_message():
    """Two consecutive sends with different signer clocks must not
    collide on the broker's now()."""
    sess = _make_session()
    ts1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
    seq1 = sess.store_message(
        sender_agent_id="orga::a", payload={}, nonce="n1",
        signature="s1", timestamp=ts1,
    )
    seq2 = sess.store_message(
        sender_agent_id="orga::a", payload={}, nonce="n2",
        signature="s2", timestamp=ts2,
    )
    assert sess._messages[seq1].timestamp == ts1
    assert sess._messages[seq2].timestamp == ts2
