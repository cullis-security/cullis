"""ADR-001 Phase 2 — SPIFFE routing decision in the proxy.

Verifies:
  - `mcp_proxy.spiffe.parse_recipient` accepts both SPIFFE URIs and the
    internal `org::agent` form, rejects malformed input.
  - `mcp_proxy.egress.routing.decide_route` classifies recipients as intra
    vs cross-org correctly.
  - `BrokerBridge.send_message` honors the `intra_org_routing` feature flag:
    off → forwards; on + intra → 501; on + cross → forwards.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from mcp_proxy.egress.broker_bridge import BrokerBridge
from mcp_proxy.egress.routing import decide_route
from mcp_proxy.spiffe import InvalidRecipient, parse_recipient


# ── parse_recipient ──────────────────────────────────────────────────

def test_parse_recipient_spiffe():
    td, org, agent = parse_recipient("spiffe://cullis.local/acme/sales-bot")
    assert (td, org, agent) == ("cullis.local", "acme", "sales-bot")


def test_parse_recipient_internal():
    td, org, agent = parse_recipient("acme::sales-bot")
    assert td is None
    assert (org, agent) == ("acme", "sales-bot")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "spiffe://",
        "spiffe:///acme/bot",
        "spiffe://cullis.local/toomany/levels/here",
        "spiffe://cullis.local/onlyorg",
        "spiffe://CULLIS.LOCAL/acme/bot",  # trust domain must be lowercase
        "acme::",
        "::bot",
        "no-separator",
        "spiffe://cullis.local/acme/bot?query=1",
    ],
)
def test_parse_recipient_invalid(bad):
    with pytest.raises(InvalidRecipient):
        parse_recipient(bad)


# ── decide_route ─────────────────────────────────────────────────────

def test_decide_route_intra_spiffe_match():
    assert decide_route(
        "spiffe://cullis.local/acme/bot",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "intra"


def test_decide_route_intra_internal_match():
    assert decide_route(
        "acme::bot",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "intra"


def test_decide_route_cross_different_org():
    assert decide_route(
        "spiffe://cullis.local/beta-corp/bot",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "cross"


def test_decide_route_cross_different_trust_domain():
    assert decide_route(
        "spiffe://beta-corp.com/acme/bot",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "cross"


def test_decide_route_internal_different_org():
    assert decide_route(
        "beta-corp::bot",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "cross"


def test_decide_route_unparseable_falls_through_to_cross():
    # Safe default: let the broker reject malformed ids downstream.
    assert decide_route(
        "not a valid id",
        local_org="acme",
        local_trust_domain="cullis.local",
    ) == "cross"


# ── BrokerBridge.send_message feature flag ───────────────────────────

def _make_bridge(*, intra_org_routing: bool) -> BrokerBridge:
    bridge = BrokerBridge(
        broker_url="https://broker.test",
        org_id="acme",
        agent_manager=MagicMock(),
        trust_domain="cullis.local",
        intra_org_routing=intra_org_routing,
    )
    # Inject a fake authenticated client so we don't touch the real network.
    fake_client = MagicMock()
    fake_client.send = MagicMock(return_value=None)
    bridge._clients["sender-bot"] = fake_client
    return bridge


@pytest.mark.asyncio
async def test_send_message_flag_off_forwards_even_for_intra_target():
    bridge = _make_bridge(intra_org_routing=False)
    await bridge.send_message(
        agent_id="sender-bot",
        session_id="sess-1",
        payload={"hello": "world"},
        recipient_agent_id="acme::peer-bot",
    )
    bridge._clients["sender-bot"].send.assert_called_once()


@pytest.mark.asyncio
async def test_send_message_flag_on_intra_raises_501():
    bridge = _make_bridge(intra_org_routing=True)
    with pytest.raises(HTTPException) as exc:
        await bridge.send_message(
            agent_id="sender-bot",
            session_id="sess-1",
            payload={"hello": "world"},
            recipient_agent_id="acme::peer-bot",
        )
    assert exc.value.status_code == 501
    assert "Phase 3" in exc.value.detail
    bridge._clients["sender-bot"].send.assert_not_called()


@pytest.mark.asyncio
async def test_send_message_flag_on_cross_forwards():
    bridge = _make_bridge(intra_org_routing=True)
    await bridge.send_message(
        agent_id="sender-bot",
        session_id="sess-1",
        payload={"hello": "world"},
        recipient_agent_id="beta-corp::peer-bot",
    )
    bridge._clients["sender-bot"].send.assert_called_once()


@pytest.mark.asyncio
async def test_send_message_flag_on_spiffe_cross_trust_domain_forwards():
    bridge = _make_bridge(intra_org_routing=True)
    await bridge.send_message(
        agent_id="sender-bot",
        session_id="sess-1",
        payload={"hello": "world"},
        recipient_agent_id="spiffe://beta-corp.com/acme/peer-bot",
    )
    # Same org string "acme" but different trust domain → cross → forward.
    bridge._clients["sender-bot"].send.assert_called_once()


# ── Config flag parsing ──────────────────────────────────────────────

def test_proxy_settings_env_overrides(monkeypatch):
    from mcp_proxy.config import ProxySettings

    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "acme.com")
    settings = ProxySettings()
    assert settings.intra_org_routing is True
    assert settings.trust_domain == "acme.com"


def test_proxy_settings_flag_defaults_off(monkeypatch):
    from mcp_proxy.config import ProxySettings

    monkeypatch.delenv("PROXY_INTRA_ORG", raising=False)
    monkeypatch.delenv("PROXY_TRUST_DOMAIN", raising=False)
    # PR-D flipped the standalone default to True; standalone auto-enables
    # intra_org_routing (config.py:_apply_routing_overrides). This test
    # asserts the federated default for the flag, so opt out of standalone
    # explicitly.
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")
    settings = ProxySettings()
    assert settings.intra_org_routing is False
    assert settings.trust_domain == "cullis.local"
