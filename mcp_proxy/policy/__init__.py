"""Policy configuration and fail-closed Rego evaluation.

The composition module applies static rules and agent delegations before Rego.
Execution additionally enforces capability, device tier and resource binding.
A configured policy that cannot be evaluated denies; absence is permitted only
for tools whose resource metadata and operator rules do not require a delegation.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Optional

from mcp_proxy.policy.rego_engine import (
    CompiledPolicy,
    RegoCompileError,
    RegoEvalError,
    evaluate_decision,
)

__all__ = [
    "RegoCompileError",
    "RegoEvalError",
    "try_rego_decision",
    "parse_policy_rules",
    "policy_error_decision",
]


_log = logging.getLogger("mcp_proxy.policy")


def parse_policy_rules(raw: str | None) -> dict:
    """Decode stored policy configuration; only a missing row is empty policy.

    Malformed JSON or a non-object document must never erase restrictions.
    Callers also catch storage errors and return a policy error decision.
    """
    if raw is None or raw == "":
        return {}
    try:
        rules = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("Invalid policy configuration") from None
    if not isinstance(rules, dict):
        raise ValueError("Policy configuration must be an object")
    return rules


def policy_error_decision(reason: str) -> dict:
    """Deny with a caller-supplied static error code, never exception contents."""
    _log.warning("policy: request denied (%s)", reason)
    return {"decision": "deny", "reason": reason}


def try_rego_decision(
    rules: dict,
    input_doc: dict,
    *,
    surface: str,
) -> Optional[dict]:
    """Evaluate the operator's Rego policy if one is configured.

    Args:
        rules: the decoded ``policy_rules`` config (the JSON document
            ``get_config('policy_rules')`` returns). Two fields drive
            the Rego layer:

              * ``rego`` — the operator's source. Informational only
                here; the compiled artifact is what runs.
              * ``rego_wasm_base64`` — the WASM bundle, base64-encoded
                (because the surrounding container is JSON). Produced
                by ``mcp_proxy.policy.rego_engine.compile_rego`` when
                the operator clicks Save in the dashboard.

        input_doc: the OPA-shaped ``input`` for this decision — the
            same dict the caller would put under ``{"input": ...}``
            in the OPA Data API request body.

        surface: one of ``"session"`` or ``"tool_call"``. Selects the
            Rego entrypoint (``cullis/policy/session`` or
            ``cullis/policy/tool_call``).

    Returns:
        The decision dict (``{"decision": "allow"|"deny",
        "reason"?}``). ``None`` only when both source and artifact are
        absent/empty. A source without its artifact, invalid WASM, runtime
        error or undefined/malformed decision returns deny with a static
        reason. These failures cannot relax an existing delegation.
    """
    if not isinstance(rules, dict):
        return policy_error_decision("policy_configuration_error")
    source = rules.get("rego")
    wasm_b64 = rules.get("rego_wasm_base64")
    if source in (None, "") and wasm_b64 in (None, ""):
        return None
    if not isinstance(wasm_b64, str) or not wasm_b64:
        return policy_error_decision("rego_artifact_error")
    try:
        wasm = base64.b64decode(wasm_b64, validate=True)
    except (ValueError, TypeError):
        return policy_error_decision("rego_artifact_error")

    entrypoint = f"cullis/policy/{surface}"
    policy = CompiledPolicy.from_wasm(wasm)
    try:
        decision = evaluate_decision(
            policy, input_doc, entrypoint=entrypoint,
        )
    except Exception:
        # Covers WASM faults, undefined output and malformed decision values.
        # Exception text can contain policy input or source; never expose it.
        return policy_error_decision("rego_evaluation_error")

    if not isinstance(decision, dict) or decision.get("decision") not in ("allow", "deny"):
        return policy_error_decision("rego_evaluation_error")

    _log.info(
        "policy.rego: %s decision=%s (sha256=%s)",
        surface, decision.get("decision"), policy.sha256[:12],
    )
    return decision
