"""ADR-029 Phase C, tool-level PDP evaluation for the Mastio.

Called from the ``POST /v1/policy/tool-call`` endpoint when the
Connector ambassador wants to invoke a tool inside a chat completion
turn. Evaluates against the same ``policy_rules`` config row that
``/pdp/policy`` reads for session-open decisions, but consults a new
``tool_rules`` subtree introduced by ADR-029 so admins can write
per-tool / per-model / per-server policy:

    {
      "tool_rules": {
        "acme.catalog.search": {
          "allowed_principals": ["acme::user::mario@acme.local", ...],
          "denied_principals":  [...],
          "allowed_models":     ["claude-haiku-4-5", "qwen-72b-chat"],
          "allowed_mcp_servers": ["acme-catalog-prod"],
          "scope":              {...},   // echoed in response
          "rate_limit":         {...},
          "obligations":        {...}
        },
        "acme.orders.update": {
          "allowed_principals": []        // explicit "no one"
        }
      }
    }

Default semantics:
    - tool_rules absent or empty -> no extra static restriction; Rego still applies.
    - tool_rules present but tool not listed -> deny (explicit-allow).
    - explicit allowed_principals list excludes principal (including []) -> deny.
    - principal in denied_principals -> deny (wins over allowed_principals).
    - model not in allowed_models -> deny (if allowed_models non-empty).
    - mcp_server not in allowed_mcp_servers -> deny (if non-empty).

The decision is intentionally kept local to a single Mastio. Cross-org
federation (the AcmeCorp Mastio policy when Mario invokes a tool that
targets AcmeCorp's MCP server) lives in Phase D.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mcp_proxy.db import get_config
from mcp_proxy.policy import parse_policy_rules, policy_error_decision

_log = logging.getLogger("mcp_proxy.policy.tool_call")


@dataclass
class ToolCallDecision:
    allowed: bool
    reason: str
    # Pass-through of the optional ADR-029 extended fields when the
    # matching tool_rule has them. None means "no extra constraint".
    scope: dict[str, Any] | None = None
    rate_limit: dict[str, Any] | None = None
    obligations: dict[str, Any] | None = None


async def evaluate_tool_call_policy(
    *,
    principal_id: str,
    principal_type: str,
    model: dict[str, Any] | None,
    target: dict[str, Any] | None,
    invocation: dict[str, Any] | None,
    context: dict[str, Any] | None,
) -> ToolCallDecision:
    """Decide whether `principal` may invoke ``invocation.tool_name``
    via ``model`` against ``target`` right now.

    Returns a ToolCallDecision. The endpoint wrapper writes the audit
    row regardless of outcome so deny attempts stay traceable.
    """
    try:
        rules = parse_policy_rules(await get_config("policy_rules"))
    except Exception:
        error = policy_error_decision("policy_configuration_error")
        return ToolCallDecision(allowed=False, reason=error["reason"])

    from mcp_proxy.policy.composition import tool_decision
    invocation = invocation or {}
    result = tool_decision(rules, {
        "agent_id": principal_id, "principal_type": principal_type,
        "tool_name": invocation.get("tool_name", ""),
        "arguments": invocation.get("arguments", {}),
        "mcp_server_id": invocation.get("mcp_server_id"),
        "model_id": (model or {}).get("id"),
    })
    return ToolCallDecision(
        allowed=result["decision"] == "allow", reason=result.get("reason", "allowed by operator policy"),
        scope=result.get("scope"), rate_limit=result.get("rate_limit"),
        obligations=result.get("obligations"),
    )
