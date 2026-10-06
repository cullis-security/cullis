"""Cumulative operator rules: static permissions, delegation, then Rego."""
from __future__ import annotations

from mcp_proxy.policy import policy_error_decision
import mcp_proxy.policy as policy


def _deny(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ValueError("Invalid policy list")
    return value


def session_decision(rules: dict, document: dict) -> dict:
    """Rego can restrict, but cannot override a static session denial."""
    try:
        blocked = _strings(rules.get("blocked_agents", []))
        if any(document.get(k) in blocked for k in ("initiator_agent_id", "target_agent_id")):
            return _deny("Agent blocked by policy")
        orgs = _strings(rules.get("allowed_orgs", []))
        peer = "initiator_org_id" if document.get("session_context") == "target" else "target_org_id"
        if orgs and document.get(peer) not in orgs:
            return _deny(f"Organization '{document.get(peer, '')}' not in allowed list")
        caps = rules.get("capabilities", [])
        # The original dashboard emitted {} for an empty capability restriction.
        caps = _strings([] if caps == {} else caps)
        requested = _strings(document.get("capabilities", []) or [])
        if caps and any(c not in caps for c in requested):
            return _deny(f"Capabilities not allowed: {[c for c in requested if c not in caps]}")
    except (ValueError, TypeError):
        return policy_error_decision("policy_configuration_error")
    return policy.try_rego_decision(rules, document, surface="session") or {"decision": "allow"}


def tool_decision(rules: dict, document: dict, *, requires_delegation: bool = False) -> dict:
    """Evaluate all tool surfaces using authoritative identity and tool metadata.

    Execution callers supply identity from authentication and resource metadata
    from the registry. PDP callers must be authenticated gateways. Arguments
    never supply identity, server identity or delegation. Delegations are keyed
    by exact principal ID within each tool rule; their contents are Rego input.
    """
    principal = document.get("agent_id", "")
    tool = document.get("tool_name", "")
    try:
        if principal in _strings(rules.get("blocked_agents", [])):
            return _deny("Agent blocked by policy")
        tool_rules = rules.get("tool_rules", {})
        if not isinstance(tool_rules, dict):
            raise ValueError("Invalid tool rules")
        blocked = _strings(tool_rules.get("blocked_tools", []))
        allowed = _strings(tool_rules.get("allowed_tools", []))
        if tool in blocked:
            return _deny(f"Tool '{tool}' is in the operator blocklist")
        if allowed and tool not in allowed:
            return _deny(f"Tool '{tool}' is not in the operator allowlist")
        named = {k: v for k, v in tool_rules.items() if k not in ("blocked_tools", "allowed_tools")}
        if named and tool not in named:
            return _deny(f"tool '{tool}' not in tool_rules (explicit-allow mode)")
        rule = named.get(tool, {})
        if not isinstance(rule, dict):
            raise ValueError("Invalid tool rule")
        if principal in _strings(rule.get("denied_principals", [])):
            return _deny("Principal in tool denied_principals")
        if "allowed_principals" in rule and principal not in _strings(rule["allowed_principals"]):
            return _deny("Principal not in tool allowed_principals")
        for key, actual in (("allowed_models", document.get("model_id")),
                            ("allowed_mcp_servers", document.get("mcp_server_id"))):
            values = _strings(rule.get(key, []))
            if values and actual not in values:
                return _deny(f"Call not in tool {key}")
        required = rule.get("require_delegation", False)
        if not isinstance(required, bool):
            raise ValueError("Invalid delegation requirement")
        required = requires_delegation or required or "delegations" in rule
        delegation = None
        if required:
            delegations = rule.get("delegations", {})
            if not isinstance(delegations, dict):
                raise ValueError("Invalid delegations")
            delegation = delegations.get(principal)
            if not isinstance(delegation, dict) or not delegation:
                return _deny("delegation_missing")
        rego_input = dict(document)
        # Discard any caller-supplied top-level delegation on external PDP input.
        rego_input.pop("delegation", None)
        if delegation is not None:
            rego_input["delegation"] = delegation
        decision = policy.try_rego_decision(rules, rego_input, surface="tool_call")
        if decision is None:
            if required:
                return _deny("delegation_policy_missing")
            decision = {"decision": "allow"}
        if decision["decision"] == "allow":
            # Advisory PDP metadata; enforcement of conditions belongs in Rego.
            decision = dict(decision)
            for key in ("scope", "rate_limit", "obligations"):
                if isinstance(rule.get(key), dict):
                    decision[key] = rule[key]
        return decision
    except (ValueError, TypeError):
        return policy_error_decision("policy_configuration_error")
