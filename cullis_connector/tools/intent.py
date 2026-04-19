"""Intent-level MCP tools for natural-language peer interaction.

Wraps the low-level ``send_oneshot`` / ``receive_oneshot`` / ``discover``
primitives so the user can write "contact mario" / "send him hello"
instead of remembering SPIFFE handles. The low-level tools stay
exposed for power users and tests; nothing here changes the wire
format or the broker contract.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cullis_sdk.types import AgentInfo

if TYPE_CHECKING:
    pass


@dataclass(frozen=True)
class PeerCandidate:
    """A single peer match returned by :func:`resolve_peer`."""
    agent_id: str          # always canonical "<org>::<name>"
    display_name: str
    org_id: str
    score: float           # 1.0 == exact, lower == fuzzier
    scope: str             # "intra-org" | "cross-org"


def _name_only(agent_id: str) -> str:
    """Strip the org prefix from a canonical handle, if present."""
    return agent_id.split("::", 1)[1] if "::" in agent_id else agent_id


def _candidate(info: AgentInfo, score: float) -> PeerCandidate:
    return PeerCandidate(
        agent_id=info.agent_id,
        display_name=info.display_name or _name_only(info.agent_id),
        org_id=info.org_id,
        score=score,
        scope="cross-org" if info.org_id and "::" in info.agent_id and not info.agent_id.startswith(f"{info.org_id}::") else (
            "intra-org" if info.org_id else "intra-org"
        ),
    )


def resolve_peer(client, query: str, *, fuzzy_cutoff: float = 0.5) -> list[PeerCandidate]:
    """Look up peers matching ``query`` via the local Mastio.

    Strategy (cheapest first):
      1. Server-side prefilter via ``client.list_peers(q=query)``
         (substring match on agent_id / display_name).
      2. If the prefilter returned >1 candidate, rank locally with
         ``difflib.SequenceMatcher`` against name + agent_id and keep
         only candidates above ``fuzzy_cutoff``.
      3. If the prefilter returned 0, fall back to listing the full
         visible peer set and re-running the fuzzy ranker — covers
         typos like "marioo" / "mraio" that don't substring-match.

    The returned list is sorted by score descending. Caller decides
    how to handle 0 / 1 / many matches (the ``contact`` MCP tool
    presents disambiguation).
    """
    qnorm = query.strip()
    if not qnorm:
        return []

    # If the caller already typed a canonical handle, short-circuit —
    # we don't need to invent fuzziness when they meant exactly this.
    if "::" in qnorm:
        peers = client.list_peers(q=qnorm, limit=10)
        for p in peers:
            if p.agent_id == qnorm:
                return [_candidate(p, score=1.0)]
        # Canonical handle that the Mastio doesn't know — let the
        # caller decide what to do (404 vs typo).
        return []

    # 1. Substring prefilter on the server.
    candidates = client.list_peers(q=qnorm, limit=50)

    # 2. If the prefilter is empty, broaden to the full set and
    #    rely on difflib for typos.
    if not candidates:
        candidates = client.list_peers(limit=200)

    # 3. Rank with difflib against both name-only and full handle.
    scored: list[PeerCandidate] = []
    qlower = qnorm.lower()
    for info in candidates:
        name = (info.display_name or _name_only(info.agent_id)).lower()
        handle = info.agent_id.lower()

        if qlower == _name_only(handle) or qlower == handle:
            score = 1.0
        else:
            name_ratio = difflib.SequenceMatcher(None, qlower, name).ratio()
            handle_ratio = difflib.SequenceMatcher(None, qlower, _name_only(handle)).ratio()
            score = max(name_ratio, handle_ratio)

        if score >= fuzzy_cutoff:
            scored.append(_candidate(info, score=score))

    scored.sort(key=lambda c: c.score, reverse=True)
    return scored
