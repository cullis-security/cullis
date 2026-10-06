"""Policy storage and runtime failures must not become permissive defaults."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from mcp_proxy.integrations import policy_bridge
from mcp_proxy.policy import tool_call


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["pdp", "bridge_session", "bridge_tool", "legacy_tool"])
@pytest.mark.parametrize("raw,store_error", [
    ("{broken", False), ("null", False), ("[]", False), (None, True),
])
async def test_unreadable_configuration_denied(monkeypatch, surface, raw, store_error):
    config = AsyncMock(
        return_value=raw,
        side_effect=RuntimeError("synthetic-sensitive-config") if store_error else None,
    )
    monkeypatch.setattr(policy_bridge, "get_config", config)
    monkeypatch.setattr(tool_call, "get_config", config)
    monkeypatch.setattr("mcp_proxy.db.get_config", config)
    decision = await _decide(monkeypatch, surface)
    assert decision == {"decision": "deny", "reason": "policy_configuration_error"}


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["pdp", "bridge_session", "bridge_tool"])
@pytest.mark.parametrize("rules,reason", [
    ({"rego": "package cullis.policy"}, "rego_artifact_error"),
    ({"rego_wasm_base64": "invalid!"}, "rego_artifact_error"),
    ({"rego_wasm_base64": "ZmFrZQ=="}, "rego_evaluation_error"),
])
async def test_broken_rego_cannot_fall_through_to_empty_allowlist(monkeypatch, surface, rules, reason):
    config = AsyncMock(return_value=json.dumps(rules))
    monkeypatch.setattr(policy_bridge, "get_config", config)
    monkeypatch.setattr("mcp_proxy.db.get_config", config)
    monkeypatch.setattr("mcp_proxy.policy.rego_engine.RegoEngine.evaluate", lambda *a, **kw: None)
    assert await _decide(monkeypatch, surface) == {"decision": "deny", "reason": reason}


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["pdp", "bridge_session", "bridge_tool", "legacy_tool"])
async def test_readable_absent_policy_preserves_legacy_behavior(monkeypatch, surface):
    config = AsyncMock(return_value=None)
    monkeypatch.setattr(policy_bridge, "get_config", config)
    monkeypatch.setattr(tool_call, "get_config", config)
    monkeypatch.setattr("mcp_proxy.db.get_config", config)
    assert (await _decide(monkeypatch, surface))["decision"] == "allow"


async def _decide(monkeypatch, surface):
    body = {
        "initiator_agent_id": "acme::a", "target_agent_id": "acme::b",
        "session_context": "initiator", "agent_id": "acme::a",
        "tool_name": "refund", "arguments": {"amount_cents": 50000},
    }
    if surface == "bridge_session":
        return await policy_bridge._evaluate_session_policy(body)
    if surface == "bridge_tool":
        return await policy_bridge._evaluate_tool_call_policy(body)
    if surface == "legacy_tool":
        result = await tool_call.evaluate_tool_call_policy(
            principal_id="acme::a", principal_type="agent", model=None,
            target=None, invocation={"tool_name": "refund"}, context=None,
        )
        return {"decision": "allow" if result.allowed else "deny", "reason": result.reason}

    import mcp_proxy.main as main
    # Authenticate the synthetic webhook with its configured HMAC, if any.
    import hashlib
    import hmac
    raw = json.dumps(body).encode()
    signature = hmac.new(main.settings.pdp_webhook_hmac_secret.encode(), raw, hashlib.sha256).hexdigest()
    request = Request(
        {"type": "http", "headers": [(b"x-atn-signature", signature.encode())]},
        receive=AsyncMock(return_value={"type": "http.request", "body": raw}),
    )
    response = await main.pdp_policy(request)
    return json.loads(response.body)
