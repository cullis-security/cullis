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
    - tool_rules absent or empty  -> allow (legacy parity).
    - tool_rules present but tool not listed -> deny (explicit-allow).
    - tool listed but principal missing from allowed_principals -> deny.
    - principal in denied_principals -> deny (wins over allowed_principals).
    - model not in allowed_models -> deny (if allowed_models non-empty).
    - mcp_server not in allowed_mcp_servers -> deny (if non-empty).

The decision is intentionally kept local to a single Mastio. Cross-org
federation (the AcmeCorp Mastio policy when Mario invokes a tool that
targets AcmeCorp's MCP server) lives in Phase D.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp_proxy.db import get_config

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
    rules_raw = await get_config("policy_rules")
    rules: dict[str, Any] = {}
    if rules_raw:
        try:
            rules = json.loads(rules_raw)
        except json.JSONDecodeError:
            _log.warning("policy_rules JSON malformed, treating as empty")
            rules = {}

    tool_rules = rules.get("tool_rules")
    if not isinstance(tool_rules, dict):
        tool_rules = {}

    tool_name: str | None = None
    if isinstance(invocation, dict):
        tn = invocation.get("tool_name")
        if isinstance(tn, str) and tn:
            tool_name = tn

    # Legacy default-allow when no tool_rules configured. Operators who
    # have never touched ADR-029 settings see no behaviour change.
    if not tool_rules:
        return ToolCallDecision(
            allowed=True,
            reason="no tool_rules configured (default-allow legacy mode)",
        )

    if not tool_name:
        return ToolCallDecision(
            allowed=False,
            reason="invocation.tool_name missing",
        )

    if tool_name not in tool_rules:
        return ToolCallDecision(
            allowed=False,
            reason=f"tool '{tool_name}' not in tool_rules (explicit-allow mode)",
        )

    rule = tool_rules[tool_name]
    if not isinstance(rule, dict):
        return ToolCallDecision(
            allowed=False,
            reason=f"tool_rules.{tool_name} entry is not a dict",
        )

    # Principal denylist beats allowlist (defense in depth).
    denied_principals = rule.get("denied_principals", [])
    if isinstance(denied_principals, list) and principal_id in denied_principals:
        return ToolCallDecision(
            allowed=False,
            reason=f"principal '{principal_id}' in tool_rules.{tool_name}.denied_principals",
        )

    allowed_principals = rule.get("allowed_principals", [])
    if isinstance(allowed_principals, list) and allowed_principals:
        if principal_id not in allowed_principals:
            return ToolCallDecision(
                allowed=False,
                reason=(
                    f"principal '{principal_id}' not in "
                    f"tool_rules.{tool_name}.allowed_principals"
                ),
            )

    # Model check.
    model_id: str | None = None
    if isinstance(model, dict):
        mid = model.get("id")
        if isinstance(mid, str):
            model_id = mid

    allowed_models = rule.get("allowed_models", [])
    if isinstance(allowed_models, list) and allowed_models:
        if not model_id or model_id not in allowed_models:
            return ToolCallDecision(
                allowed=False,
                reason=(
                    f"model '{model_id}' not in "
                    f"tool_rules.{tool_name}.allowed_models"
                ),
            )

    # MCP server check.
    server_id: str | None = None
    if isinstance(invocation, dict):
        sid = invocation.get("mcp_server_id")
        if isinstance(sid, str):
            server_id = sid

    allowed_servers = rule.get("allowed_mcp_servers", [])
    if isinstance(allowed_servers, list) and allowed_servers:
        if not server_id or server_id not in allowed_servers:
            return ToolCallDecision(
                allowed=False,
                reason=(
                    f"mcp_server '{server_id}' not in "
                    f"tool_rules.{tool_name}.allowed_mcp_servers"
                ),
            )

    # All checks passed. Echo optional scope/rate_limit/obligations
    # back to the Connector so the caller knows what constraints apply
    # to the (now-allowed) tool invocation.
    scope = rule.get("scope") if isinstance(rule.get("scope"), dict) else None
    rate_limit = (
        rule.get("rate_limit") if isinstance(rule.get("rate_limit"), dict) else None
    )
    obligations = (
        rule.get("obligations") if isinstance(rule.get("obligations"), dict) else None
    )

    return ToolCallDecision(
        allowed=True,
        reason=f"allowed by tool_rules.{tool_name}",
        scope=scope,
        rate_limit=rate_limit,
        obligations=obligations,
    )
