"""Local policy evaluation for intra-org messages (ADR-006 Fase 1 / PR #2).

The proxy reads its own ``local_policies`` table — populated by the
admin through the dashboard — and evaluates each outbound intra-org
message against the matching rules. The rule JSON format matches the
broker's ``app/policy/engine.py`` message rules so a policy authored
in either place behaves identically:

    {
      "effect": "allow" | "deny",
      "conditions": {
        "max_payload_size_bytes": <int>,   // optional
        "required_fields": [<str>, ...],   // optional
        "blocked_fields":  [<str>, ...]    // optional
      }
    }

Default is **allow** when no rule matches — same semantics as the broker
for messages (sessions are default-deny; messages are default-allow).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from mcp_proxy.db import get_db

_log = logging.getLogger("mcp_proxy.policy.local_eval")


@dataclass(frozen=True)
class LocalPolicyDecision:
    allowed: bool
    reason: str
    policy_id: str | None = None


async def _load_message_policies(org_id: str) -> list[tuple[str, dict[str, Any]]]:
    """Return ``[(policy_id, rules)]`` for active message-type policies of an org."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT policy_id, rules_json FROM local_policies
                 WHERE enabled = 1
                   AND (policy_type = 'message' OR policy_type IS NULL)
                   AND (org_id = :org_id OR org_id IS NULL)
                """
            ),
            {"org_id": org_id},
        )
        out: list[tuple[str, dict[str, Any]]] = []
        for row in result.mappings():
            try:
                rules = json.loads(row["rules_json"])
            except (ValueError, TypeError):
                _log.warning("Skipping local policy %s — invalid rules_json", row["policy_id"])
                continue
            if not isinstance(rules, dict):
                continue
            out.append((row["policy_id"], rules))
        return out


def _evaluate_rules(
    rules: dict[str, Any],
    payload: dict[str, Any],
    payload_json: str,
    policy_id: str,
) -> LocalPolicyDecision | None:
    """Apply a single rule to a payload. ``None`` means "no verdict, try next"."""
    conditions = rules.get("conditions") or {}
    effect = rules.get("effect", "allow")

    max_size = conditions.get("max_payload_size_bytes")
    if max_size is not None and len(payload_json.encode()) > max_size:
        return LocalPolicyDecision(
            allowed=False,
            reason=f"payload too large: {len(payload_json.encode())}B > {max_size}B",
            policy_id=policy_id,
        )

    required: list[str] = conditions.get("required_fields") or []
    missing = [f for f in required if f not in payload]
    if missing:
        return LocalPolicyDecision(
            allowed=False,
            reason=f"required fields missing: {missing}",
            policy_id=policy_id,
        )

    blocked: list[str] = conditions.get("blocked_fields") or []
    present_blocked = [f for f in blocked if f in payload]
    if present_blocked:
        return LocalPolicyDecision(
            allowed=False,
            reason=f"blocked fields present: {present_blocked}",
            policy_id=policy_id,
        )

    if effect == "deny":
        return LocalPolicyDecision(
            allowed=False,
            reason="explicitly denied by policy",
            policy_id=policy_id,
        )

    return None


async def evaluate_local_message(
    *,
    org_id: str,
    payload: dict[str, Any],
) -> LocalPolicyDecision:
    """Check a payload against the org's intra-org message policies."""
    policies = await _load_message_policies(org_id)
    if not policies:
        return LocalPolicyDecision(allowed=True, reason="no local message policy — default allow")

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    for policy_id, rules in policies:
        verdict = _evaluate_rules(rules, payload, payload_json, policy_id)
        if verdict is not None:
            return verdict

    return LocalPolicyDecision(allowed=True, reason="no rule violated — default allow")
