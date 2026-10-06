"""All operator policy surfaces enforce static denial before Rego conditions."""
from unittest.mock import MagicMock

import pytest

from mcp_proxy.policy.composition import session_decision, tool_decision


@pytest.mark.parametrize("rules", [
    {"blocked_agents": ["acme::tickets"]},
    {"tool_rules": {"blocked_tools": ["refund"]}},
    {"tool_rules": {"allowed_tools": ["ticket"]}},
    {"tool_rules": {"ticket": {}}},
    {"tool_rules": {"refund": {"allowed_principals": []}}},
    {"tool_rules": {"refund": {"allowed_principals": ["acme::refund"]}}},
    {"tool_rules": {"refund": {"denied_principals": ["acme::tickets"]}}},
    {"tool_rules": {"refund": {"allowed_mcp_servers": ["finance"]}}},
    {"tool_rules": {"refund": {"allowed_models": ["approved"]}}},
    {"tool_rules": {"refund": {"delegations": {}}}},
])
def test_static_tool_denial_never_reaches_permissive_rego(monkeypatch, rules):
    rego = MagicMock(return_value={"decision": "allow"})
    monkeypatch.setattr("mcp_proxy.policy.try_rego_decision", rego)
    result = tool_decision(rules, {"agent_id": "acme::tickets", "tool_name": "refund"})
    assert result["decision"] == "deny"
    rego.assert_not_called()


@pytest.mark.parametrize("rules", [
    {"blocked_agents": ["a"]}, {"allowed_orgs": ["approved"]}, {"capabilities": ["read"]},
])
def test_static_session_denial_never_reaches_rego(monkeypatch, rules):
    rego = MagicMock(return_value={"decision": "allow"})
    monkeypatch.setattr("mcp_proxy.policy.try_rego_decision", rego)
    assert session_decision(rules, {"initiator_agent_id": "a", "capabilities": ["write"]})["decision"] == "deny"
    rego.assert_not_called()


@pytest.mark.parametrize("rules", [{}, {"tool_rules": {}}, {"tool_rules": {"refund": {}}}])
def test_sensitive_resource_requires_delegation_even_after_policy_deletion(rules):
    assert tool_decision(rules, {"tool_name": "refund", "agent_id": "a"}, requires_delegation=True) == {
        "decision": "deny", "reason": "delegation_missing",
    }


def test_delegation_without_rego_is_not_permission():
    rules = {"tool_rules": {"refund": {"delegations": {"a": {"limit": 100}}}}}
    assert tool_decision(rules, {"tool_name": "refund", "agent_id": "a"}) == {
        "decision": "deny", "reason": "delegation_policy_missing",
    }


@pytest.mark.parametrize("principal,limit", [("a", 100), ("b", 1000)])
def test_gateway_selects_delegation_not_caller_arguments(monkeypatch, principal, limit):
    rego = MagicMock(return_value={"decision": "allow"})
    monkeypatch.setattr("mcp_proxy.policy.try_rego_decision", rego)
    rules = {"tool_rules": {"refund": {"delegations": {"a": {"limit": 100}, "b": {"limit": 1000}}}}}
    assert tool_decision(rules, {
        "tool_name": "refund", "agent_id": principal, "delegation": {"limit": 999999},
        "arguments": {"agent_id": "b", "delegation": {"limit": 999999}},
    })["decision"] == "allow"
    assert rego.call_args.args[1]["delegation"] == {"limit": limit}
    assert rego.call_args.args[1]["agent_id"] == principal


@pytest.mark.parametrize("rules", [
    {"tool_rules": []}, {"tool_rules": {"refund": []}},
    {"tool_rules": {"allowed_tools": "refund"}},
    {"tool_rules": {"refund": {"allowed_principals": "a"}}},
    {"tool_rules": {"refund": {"delegations": []}}},
    {"tool_rules": {"refund": {"require_delegation": "false"}}},
])
def test_malformed_static_rules_fail_closed(rules):
    assert tool_decision(rules, {"tool_name": "refund", "agent_id": "a"})["decision"] == "deny"
