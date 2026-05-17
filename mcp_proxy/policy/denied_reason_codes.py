"""Stable machine-readable tokens for tool-denial outcomes (F5 follow-up #4).

The executor returns one of these codes on every non-success
``ToolExecuteResponse`` so SDK consumers can dispatch programmatically
(retry vs UX prompt vs deny) without parsing the human-readable
``error`` string. Codes are stable across releases; renaming requires a
deprecation cycle.

Token contract: ``^[a-z][a-z0-9_]+$``, < 64 chars, snake_case.
"""
from __future__ import annotations

# Tool registry lookup missed — the request named a tool the proxy
# doesn't know about.
TOOL_NOT_FOUND = "tool_not_found"

# Principal lacked the capability the tool requires, OR the capability
# resolver failed closed (DB error during capability load).
CAPABILITY_DENIED = "capability_denied"

# Device tier resolved below the tier the capability requires.
# Triggered by the F5 tier gate (ADR-032 Decision E).
INSUFFICIENT_TIER = "insufficient_tier"

# MCP-resource tool reached without an active binding row for this
# principal — covers REST + JSON-RPC ingress symmetrically (CRIT-2 fix).
MISSING_BINDING = "missing_binding"

# Catch-all for handler-side failures: timeouts, ToolExecutionError,
# unexpected exceptions. Operator-facing detail lives in audit + logs.
INTERNAL_ERROR = "internal_error"

ALL_CODES: frozenset[str] = frozenset({
    TOOL_NOT_FOUND,
    CAPABILITY_DENIED,
    INSUFFICIENT_TIER,
    MISSING_BINDING,
    INTERNAL_ERROR,
})
