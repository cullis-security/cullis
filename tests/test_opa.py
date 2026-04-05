"""
Tests for OPA policy adapter and backend dispatcher.
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

import httpx

from app.policy.webhook import WebhookDecision

# Patch validate_opa_url to skip DNS resolution in tests (OPA hostname is fake)
_noop_validate = patch("app.policy.opa.validate_opa_url", return_value=None)


def _opa_response(result_data, status_code=200):
    """Create an httpx.Response mimicking OPA."""
    body = {"result": result_data} if status_code == 200 else {}
    return httpx.Response(status_code, json=body, request=httpx.Request("POST", "http://opa:8181"))


# ── OPA adapter unit tests ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_opa_allow(client):
    """OPA returning allow=true produces an allow decision."""
    from app.policy.opa import evaluate_session_via_opa

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", new=AsyncMock(return_value=_opa_response({"allow": True, "reason": "policy matched"}))):
        decision = await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="org-a::buyer", target_agent_id="org-b::supplier",
            capabilities=["order.read"],
        )
    assert decision.allowed is True
    assert decision.org_id == "opa"


@pytest.mark.asyncio
async def test_opa_deny(client):
    """OPA returning allow=false produces a deny decision."""
    from app.policy.opa import evaluate_session_via_opa

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", new=AsyncMock(return_value=_opa_response({"allow": False, "reason": "blocked org"}))):
        decision = await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="org-a::buyer", target_agent_id="org-b::supplier",
            capabilities=["order.read"],
        )
    assert decision.allowed is False
    assert "blocked org" in decision.reason


@pytest.mark.asyncio
async def test_opa_boolean_result(client):
    """OPA returning a bare boolean (not dict) is handled."""
    from app.policy.opa import evaluate_session_via_opa

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", new=AsyncMock(return_value=_opa_response(True))):
        decision = await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=[],
        )
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_opa_timeout(client):
    """OPA timeout produces a deny decision (default-deny)."""
    from app.policy.opa import evaluate_session_via_opa

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", new=AsyncMock(side_effect=httpx.TimeoutException("timed out"))):
        decision = await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=[],
        )
    assert decision.allowed is False
    assert "timed out" in decision.reason


@pytest.mark.asyncio
async def test_opa_http_error(client):
    """OPA returning non-200 HTTP produces a deny decision."""
    from app.policy.opa import evaluate_session_via_opa

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", new=AsyncMock(return_value=_opa_response(None, status_code=500))):
        decision = await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=[],
        )
    assert decision.allowed is False
    assert "500" in decision.reason


@pytest.mark.asyncio
async def test_opa_sends_correct_input(client):
    """OPA adapter sends the correct input document."""
    from app.policy.opa import evaluate_session_via_opa

    captured = {}

    async def capture_post(self, url, **kwargs):
        captured["url"] = str(url)
        captured["body"] = kwargs.get("json", {})
        return _opa_response({"allow": True})

    with _noop_validate, \
         patch.object(httpx.AsyncClient, "post", capture_post):
        await evaluate_session_via_opa(
            opa_url="http://opa:8181",
            initiator_org_id="org-a", target_org_id="org-b",
            initiator_agent_id="org-a::buyer", target_agent_id="org-b::supplier",
            capabilities=["order.read", "order.write"],
        )

    assert captured["url"] == "http://opa:8181/v1/data/atn/session/allow"
    body = captured["body"]
    assert body["input"]["initiator_org_id"] == "org-a"
    assert body["input"]["target_org_id"] == "org-b"
    assert body["input"]["capabilities"] == ["order.read", "order.write"]


# ── Backend dispatcher tests ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_backend_default_webhook(client):
    """Default POLICY_BACKEND=webhook dispatches to webhook evaluator."""
    from app.policy.backend import evaluate_session_policy

    allow = WebhookDecision(allowed=True, reason="mock", org_id="broker")
    with patch("app.policy.webhook.evaluate_session_via_webhooks", new=AsyncMock(return_value=allow)):
        decision = await evaluate_session_policy(
            initiator_org_id="org-a", initiator_webhook_url="http://pdp-a:9000/policy",
            target_org_id="org-b", target_webhook_url="http://pdp-b:9000/policy",
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=["order.read"],
        )
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_backend_opa_dispatch(client):
    """POLICY_BACKEND=opa dispatches to OPA evaluator."""
    from app.policy.backend import evaluate_session_policy

    allow = WebhookDecision(allowed=True, reason="opa allow", org_id="opa")
    with patch("app.policy.opa.evaluate_session_via_opa", new=AsyncMock(return_value=allow)), \
         patch("app.config.get_settings") as mock_settings:
        s = MagicMock()
        s.policy_backend = "opa"
        s.opa_url = "http://opa:8181"
        mock_settings.return_value = s

        decision = await evaluate_session_policy(
            initiator_org_id="org-a", initiator_webhook_url=None,
            target_org_id="org-b", target_webhook_url=None,
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=["order.read"],
        )
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_backend_opa_no_url_denies(client):
    """POLICY_BACKEND=opa without OPA_URL returns deny."""
    from app.policy.backend import evaluate_session_policy

    with patch("app.config.get_settings") as mock_settings:
        s = MagicMock()
        s.policy_backend = "opa"
        s.opa_url = ""
        mock_settings.return_value = s

        decision = await evaluate_session_policy(
            initiator_org_id="org-a", initiator_webhook_url=None,
            target_org_id="org-b", target_webhook_url=None,
            initiator_agent_id="a::b", target_agent_id="c::d",
            capabilities=[],
        )
    assert decision.allowed is False
    assert "not configured" in decision.reason
