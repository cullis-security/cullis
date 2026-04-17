"""Pydantic-level tests for the payload depth / key-count caps (audit F-C-1).

These test the MODEL validators directly — no broker spin-up needed.
The round-trip integration test lives with the rest of the session
messaging suite.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.broker.models import MessageEnvelope, RfqRequest, SessionRequest
from app.broker.oneshot_router import ForwardOneShotRequest


def _deep_payload(depth: int) -> dict:
    """Build a nested-dict payload whose deepest scalar sits at the given
    depth. ``depth=8`` ⇒ root.n.n.n.n.n.n.n.leaf — 8 levels of nesting,
    scalar at depth 8."""
    root: dict = {}
    cur = root
    for _ in range(depth - 1):
        cur["n"] = {}
        cur = cur["n"]
    cur["leaf"] = 1
    return root


def _valid_envelope_kwargs() -> dict:
    return dict(
        session_id="s-1",
        sender_agent_id="a",
        payload={"ok": True},
        nonce="n-1",
        timestamp=1,
        signature="x" * 10,
    )


def _valid_oneshot_kwargs() -> dict:
    return dict(
        recipient_agent_id="recipient",
        correlation_id="00000000-0000-0000-0000-000000000000",
        payload={"ok": True},
        signature="x" * 10,
        nonce="n-1",
        timestamp=1,
    )


class TestMessageEnvelopeDepth:
    def test_valid_shallow_payload_passes(self):
        MessageEnvelope(**_valid_envelope_kwargs())

    def test_depth_8_passes(self):
        kw = _valid_envelope_kwargs()
        kw["payload"] = _deep_payload(8)
        MessageEnvelope(**kw)

    def test_depth_9_rejected(self):
        kw = _valid_envelope_kwargs()
        kw["payload"] = _deep_payload(9)
        with pytest.raises(ValidationError, match="depth"):
            MessageEnvelope(**kw)

    def test_key_count_over_cap_rejected(self):
        kw = _valid_envelope_kwargs()
        kw["payload"] = {f"k{i}": i for i in range(1025)}
        with pytest.raises(ValidationError, match="1024"):
            MessageEnvelope(**kw)

    def test_deep_list_rejected(self):
        kw = _valid_envelope_kwargs()
        nested: list = []
        inner = nested
        for _ in range(10):
            new: list = []
            inner.append(new)
            inner = new
        kw["payload"] = {"top": nested}
        with pytest.raises(ValidationError, match="depth"):
            MessageEnvelope(**kw)


class TestRfqRequestDepth:
    def test_depth_9_rejected(self):
        with pytest.raises(ValidationError, match="depth"):
            RfqRequest(
                capability_filter=["cap.a"],
                payload=_deep_payload(9),
            )


class TestForwardOneShotDepth:
    def test_depth_9_rejected(self):
        kw = _valid_oneshot_kwargs()
        kw["payload"] = _deep_payload(9)
        with pytest.raises(ValidationError, match="depth"):
            ForwardOneShotRequest(**kw)

    def test_depth_8_passes(self):
        kw = _valid_oneshot_kwargs()
        kw["payload"] = _deep_payload(8)
        ForwardOneShotRequest(**kw)


class TestSessionRequestContextDepth:
    # Strictly already covered by the pre-existing validator, but make
    # sure we didn't regress it while refactoring.

    def test_context_depth_4_passes(self):
        SessionRequest(
            target_agent_id="a", target_org_id="o",
            context=_deep_payload(4),
        )

    def test_context_depth_5_rejected(self):
        with pytest.raises(ValidationError, match="depth"):
            SessionRequest(
                target_agent_id="a", target_org_id="o",
                context=_deep_payload(5),
            )
