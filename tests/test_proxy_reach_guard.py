"""Unit tests for ``mcp_proxy.egress.reach_guard``.

Separate from the integration tests (``test_proxy_reach_enforcement``)
on purpose: this file exercises the parsing + decision logic directly
without any DB or FastAPI plumbing, so failures point at the helper
and not the handler wiring.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from mcp_proxy.egress.reach_guard import check_reach, resolve_target_org
from mcp_proxy.models import InternalAgent


def _agent(agent_id: str = "orga::alice", reach: str = "both") -> InternalAgent:
    return InternalAgent(
        agent_id=agent_id,
        display_name="Alice",
        capabilities=["x"],
        created_at="2026-04-18T00:00:00Z",
        is_active=True,
        reach=reach,
    )


# ──────────────────────────────────────────────────────────────────────
# resolve_target_org — parsing
# ──────────────────────────────────────────────────────────────────────


def test_resolve_org_from_bare_form():
    assert resolve_target_org("orga::agent-a") == "orga"


def test_resolve_org_from_spiffe_with_path_segments():
    # ADR-011 SPIRE entries use spiffe://<td>/<org>/<agent>
    assert resolve_target_org("spiffe://cullis.local/orgb/agent-b") == "orgb"


def test_resolve_org_from_spiffe_with_org_in_trust_domain():
    # Sandbox uses spiffe://<org>.test/<agent>
    assert resolve_target_org("spiffe://orga.test/byoca-bot") == "orga"


def test_resolve_explicit_wins_over_parse():
    # target_org_id from the request body is authoritative
    assert resolve_target_org("orga::x", explicit_org="orgb") == "orgb"


def test_resolve_empty_returns_none():
    assert resolve_target_org("") is None
    assert resolve_target_org("just-a-bare-name") is None


# ──────────────────────────────────────────────────────────────────────
# check_reach — the 9 decision cells
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("reach", ["intra", "cross", "both"])
def test_reach_both_always_allows(reach):
    """``both`` accepts any direction."""
    # sanity: ensure the parametrize doesn't mask the both case
    check_reach(_agent(reach="both"), "orgb", "orga")  # cross-org
    check_reach(_agent(reach="both"), "orga", "orga")  # intra-org


def test_reach_intra_allows_intra():
    check_reach(_agent(reach="intra"), "orga", "orga")


def test_reach_intra_denies_cross():
    with pytest.raises(HTTPException) as exc:
        check_reach(_agent(reach="intra"), "orgb", "orga")
    assert exc.value.status_code == 403
    assert "reach='intra'" in exc.value.detail
    assert "cross-org" in exc.value.detail


def test_reach_cross_allows_cross():
    check_reach(_agent(reach="cross"), "orgb", "orga")


def test_reach_cross_denies_intra():
    with pytest.raises(HTTPException) as exc:
        check_reach(_agent(reach="cross"), "orga", "orga")
    assert exc.value.status_code == 403
    assert "reach='cross'" in exc.value.detail
    assert "intra-org" in exc.value.detail


# ──────────────────────────────────────────────────────────────────────
# Soft-pass paths — the gate intentionally does not second-guess
# ──────────────────────────────────────────────────────────────────────


def test_none_target_org_is_soft_pass():
    """When the recipient handle can't be parsed we don't block — the
    downstream resolver will 404 with a clearer error."""
    check_reach(_agent(reach="intra"), None, "orga")
    check_reach(_agent(reach="cross"), None, "orga")


def test_empty_local_org_is_soft_pass():
    """Proxy in unconfigured state (Setup wizard incomplete) has no
    notion of own-org; reach can't be framed."""
    check_reach(_agent(reach="intra"), "orga", "")


def test_unknown_reach_defaults_to_both():
    """Corrupted / pre-migration row: don't block on undefined values."""
    check_reach(_agent(reach="weird"), "orgb", "orga")
    check_reach(_agent(reach=""), "orgb", "orga")
