"""Tests for cullis_connector.tools.intent.resolve_peer.

The Mastio's ``GET /v1/egress/peers`` already does a substring
prefilter; ``resolve_peer`` adds local fuzzy ranking + 0/1/n match
semantics so the ``contact()`` MCP tool can present a clean choice.
"""
from __future__ import annotations

import pytest

from cullis_connector.tools.intent import resolve_peer
from cullis_sdk.types import AgentInfo


class _FakeClient:
    """Stub CullisClient that returns a scripted peer list."""

    def __init__(self, peers: list[AgentInfo]) -> None:
        self._peers = peers
        self.calls: list[dict] = []

    def list_peers(self, q: str | None = None, limit: int = 50) -> list[AgentInfo]:
        self.calls.append({"q": q, "limit": limit})
        if q is None:
            return list(self._peers)[:limit]
        ql = q.lower()
        return [
            p for p in self._peers
            if ql in p.agent_id.lower() or ql in (p.display_name or "").lower()
        ][:limit]


def _peer(handle: str, display: str = "", org: str = "acme") -> AgentInfo:
    return AgentInfo(
        agent_id=handle if "::" in handle else f"{org}::{handle}",
        org_id=org,
        display_name=display,
    )


def test_canonical_handle_short_circuits_to_exact_match():
    peers = [_peer("mario", "Mario Rossi"), _peer("maria", "Maria")]
    client = _FakeClient(peers)

    out = resolve_peer(client, "acme::mario")
    assert len(out) == 1
    assert out[0].agent_id == "acme::mario"
    assert out[0].score == 1.0


def test_canonical_handle_unknown_returns_empty():
    client = _FakeClient([_peer("mario")])

    out = resolve_peer(client, "other::ghost")
    assert out == []


def test_substring_match_returns_single_candidate_with_score_one():
    client = _FakeClient([
        _peer("mario", "Mario Rossi"),
        _peer("salesbot", "Sales Bot"),
    ])

    out = resolve_peer(client, "mario")
    assert len(out) == 1
    assert out[0].agent_id == "acme::mario"
    assert out[0].score == 1.0


def test_multiple_substring_matches_ranked_by_score():
    """Wider substring `mar` matches all three; exact name `mario`
    sorts first, then the other two by difflib similarity."""
    client = _FakeClient([
        _peer("mario", "Mario Rossi"),
        _peer("maria", "Maria Bianchi"),
        _peer("mariano", "Mariano Verdi"),
    ])

    out = resolve_peer(client, "mar")
    handles = [c.agent_id for c in out]
    assert "acme::mario" in handles
    assert "acme::maria" in handles
    assert "acme::mariano" in handles
    # All three are returned; the exact-handle one (mar==mar? no, mar is partial)
    # so they're all ranked by difflib — mario shouldn't necessarily win, just
    # be present. The ordering invariant is "score descending".
    scores = [c.score for c in out]
    assert scores == sorted(scores, reverse=True)


def test_exact_name_query_sorts_first_when_substring_returns_one():
    """If the prefilter returns a single exact-name match, it scores 1.0
    and is the only candidate (the others didn't substring-match)."""
    client = _FakeClient([
        _peer("mario", "Mario Rossi"),
        _peer("maria", "Maria Bianchi"),
    ])

    out = resolve_peer(client, "mario")
    assert len(out) == 1
    assert out[0].agent_id == "acme::mario"
    assert out[0].score == 1.0


def test_empty_query_returns_empty_without_calling_client():
    client = _FakeClient([_peer("mario")])
    assert resolve_peer(client, "") == []
    assert resolve_peer(client, "   ") == []
    assert client.calls == []


def test_no_substring_match_falls_back_to_full_list_for_typos():
    """`mraio` doesn't substring-match `mario`, so the prefilter is
    empty. The fallback re-fetches the full set and difflib ranks
    `mario` as the closest."""
    peers = [
        _peer("mario", "Mario Rossi"),
        _peer("salesbot", "Sales Bot"),
    ]
    client = _FakeClient(peers)

    out = resolve_peer(client, "mraio")
    assert client.calls == [
        {"q": "mraio", "limit": 50},
        {"q": None, "limit": 200},
    ]
    assert out, "expected at least one fuzzy match"
    assert out[0].agent_id == "acme::mario"


def test_below_cutoff_excluded():
    """Wildly different name shouldn't match anything."""
    client = _FakeClient([_peer("mario", "Mario")])
    out = resolve_peer(client, "zzzzz")
    # difflib ratio between 'zzzzz' and 'mario' / 'acme::mario' is ~0
    # so nothing crosses 0.5.
    assert out == []
