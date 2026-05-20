"""ADR-029 Phase D-2, federation of tool-call PDP decisions across orgs.

When the Connector hits ``POST /v1/policy/tool-call`` and the target
of the invocation lives in a different org than this Mastio, the
local decision alone is not enough: the target org must also agree.
This module wraps the cross-org HTTP call that asks the target
Mastio's own ``/v1/policy/tool-call`` endpoint to evaluate the same
payload, and intersects the two decisions per ADR-029 §Decision
(scope: intersection, tools_denied: union, rate_limit: min,
obligations: more restrictive).

MVP wiring: the originator Mastio reads the target Mastio's URL from
``MCP_PROXY_TOOL_PDP_FEDERATION_URLS`` (a JSON map org_id ->
endpoint URL). A future iteration (Phase G) will look the URL up
dynamically through the Court registry; for now the operator wires
the map explicitly at deploy time. Missing entry means default-deny
so an admin cannot accidentally bypass the target org by omission.

HMAC signature uses the same ``pdp_webhook_hmac_secret`` as
``/pdp/policy`` and ``/v1/policy/tool-call``, so the receiving Mastio
verifies the call the same way as the broker would.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass

import httpx

from mcp_proxy.policy.tool_call import ToolCallDecision

_log = logging.getLogger("mcp_proxy.policy.federation")

_FEDERATION_TIMEOUT = 5.0  # seconds
_MAX_RESPONSE_BODY = 4096  # bytes


@dataclass
class FederationResult:
    """A federated decision plus a flag distinguishing 'no entry' (deny
    by configuration) from 'remote denied' (deny by policy)."""
    decision: ToolCallDecision
    reached_remote: bool


async def call_remote_tool_call_policy(
    *,
    target_org: str,
    federation_url: str,
    payload: dict,
    hmac_secret: str | None,
) -> FederationResult:
    """POST `payload` to the target Mastio's ``/v1/policy/tool-call``.

    Returns the parsed decision plus ``reached_remote=True`` on a
    successful round-trip. On any transport or schema failure the
    function fails safe (deny) with ``reached_remote=False``.
    """
    try:
        body_bytes = json.dumps(payload).encode()
    except (TypeError, ValueError) as exc:
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation payload encode failed: {exc}",
            ),
            reached_remote=False,
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if hmac_secret:
        sig = hmac.new(
            hmac_secret.encode(), body_bytes, hashlib.sha256,
        ).hexdigest()
        headers["X-ATN-Signature"] = sig

    # F-A-203 (audit 2026-05-20). Validate the federation URL against
    # the SSRF block list before issuing the POST. An operator-configured
    # entry pointing at cloud metadata or internal services would
    # otherwise leak cross-org principal_id / tool_name / model id to
    # the attacker-controlled destination on every PDP call.
    from mcp_proxy.utils.url_safety import (
        UnsafeUrlError,
        assert_safe_outbound_url,
    )
    from mcp_proxy.config import get_settings

    allow_private = bool(
        getattr(get_settings(), "policy_webhook_allow_private_ips", False)
    )
    try:
        assert_safe_outbound_url(federation_url, allow_private=allow_private)
    except UnsafeUrlError as exc:
        _log.warning(
            "federation tool-call refused unsafe URL target=%s url=%s err=%s",
            target_org, federation_url, exc,
        )
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' refused: unsafe URL",
            ),
            reached_remote=False,
        )

    try:
        async with httpx.AsyncClient(
            timeout=_FEDERATION_TIMEOUT, follow_redirects=False,
        ) as client:
            resp = await client.post(
                federation_url, content=body_bytes, headers=headers,
            )
    except httpx.TimeoutException:
        _log.warning(
            "federation tool-call timeout target=%s url=%s",
            target_org, federation_url,
        )
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' timed out after {_FEDERATION_TIMEOUT}s",
            ),
            reached_remote=False,
        )
    except Exception as exc:
        _log.warning(
            "federation tool-call transport error target=%s url=%s err=%s",
            target_org, federation_url, exc,
        )
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' transport error: {exc}",
            ),
            reached_remote=False,
        )

    if resp.status_code == 404:
        # Target Mastio has tool PDP disabled. Conservative interpretation:
        # the target org has not opted in to enforce policy, so the local
        # decision stands. Returning allow lets the originator decide
        # purely on its own rules (the same behaviour the Connector SDK
        # uses against a legacy Mastio).
        return FederationResult(
            decision=ToolCallDecision(
                allowed=True,
                reason=f"target org '{target_org}' has tool PDP disabled (404)",
            ),
            reached_remote=True,
        )
    if resp.status_code in (401, 403):
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' rejected: HTTP {resp.status_code}",
            ),
            reached_remote=False,
        )
    if resp.status_code != 200:
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' returned HTTP {resp.status_code}",
            ),
            reached_remote=False,
        )

    if len(resp.content) > _MAX_RESPONSE_BODY:
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation response too large ({len(resp.content)} bytes)",
            ),
            reached_remote=True,
        )

    try:
        data = resp.json()
    except Exception:
        return FederationResult(
            decision=ToolCallDecision(
                allowed=False,
                reason=f"federation to org '{target_org}' returned non-JSON body",
            ),
            reached_remote=True,
        )

    decision_raw = str(data.get("decision", "deny")).lower()
    allowed = decision_raw == "allow"
    reason = str(data.get("reason", ""))[:512]
    scope = data.get("scope") if isinstance(data.get("scope"), dict) else None
    rate_limit = data.get("rate_limit") if isinstance(data.get("rate_limit"), dict) else None
    obligations = data.get("obligations") if isinstance(data.get("obligations"), dict) else None

    return FederationResult(
        decision=ToolCallDecision(
            allowed=allowed,
            reason=reason or ("allowed by remote" if allowed else "denied by remote"),
            scope=scope,
            rate_limit=rate_limit,
            obligations=obligations,
        ),
        reached_remote=True,
    )


def intersect_decisions(
    local: ToolCallDecision,
    remote: ToolCallDecision,
) -> ToolCallDecision:
    """ADR-029 §Decision, source ∩ target.

    Allow only if both allow. tools_allowed by intersection.
    tools_denied by union. max_session_duration_s by min. rate_limit
    per-axis by min. obligations: require_user_confirmation by OR,
    trace_visibility to the more restrictive of the two.
    """
    if not local.allowed:
        return local
    if not remote.allowed:
        return remote

    # Both allow. Intersect optional fields.
    scope = _intersect_scope(local.scope, remote.scope)
    rate_limit = _intersect_rate_limit(local.rate_limit, remote.rate_limit)
    obligations = _intersect_obligations(local.obligations, remote.obligations)

    return ToolCallDecision(
        allowed=True,
        reason=f"local: {local.reason}; remote: {remote.reason}",
        scope=scope,
        rate_limit=rate_limit,
        obligations=obligations,
    )


def _intersect_scope(
    a: dict | None, b: dict | None,
) -> dict | None:
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a
    out: dict = {}
    a_allowed = a.get("tools_allowed")
    b_allowed = b.get("tools_allowed")
    if isinstance(a_allowed, list) and isinstance(b_allowed, list):
        out["tools_allowed"] = sorted(set(a_allowed) & set(b_allowed))
    elif isinstance(a_allowed, list):
        out["tools_allowed"] = list(a_allowed)
    elif isinstance(b_allowed, list):
        out["tools_allowed"] = list(b_allowed)
    denied: set[str] = set()
    if isinstance(a.get("tools_denied"), list):
        denied.update(a["tools_denied"])
    if isinstance(b.get("tools_denied"), list):
        denied.update(b["tools_denied"])
    if denied:
        out["tools_denied"] = sorted(denied)
    durations = [
        d for d in (a.get("max_session_duration_s"), b.get("max_session_duration_s"))
        if isinstance(d, int) and d > 0
    ]
    if durations:
        out["max_session_duration_s"] = min(durations)
    return out or None


def _intersect_rate_limit(
    a: dict | None, b: dict | None,
) -> dict | None:
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a
    out: dict = {}
    for k in ("per_minute", "per_day"):
        vals = [v for v in (a.get(k), b.get(k)) if isinstance(v, int) and v > 0]
        if vals:
            out[k] = min(vals)
    return out or None


def _intersect_obligations(
    a: dict | None, b: dict | None,
) -> dict | None:
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a
    rank = {"full": 2, "redacted": 1, "off": 0}
    av = a.get("trace_visibility", "redacted")
    bv = b.get("trace_visibility", "redacted")
    if av not in rank:
        av = "redacted"
    if bv not in rank:
        bv = "redacted"
    visibility = av if rank[av] <= rank[bv] else bv
    return {
        "require_user_confirmation": bool(
            a.get("require_user_confirmation") or b.get("require_user_confirmation")
        ),
        "trace_visibility": visibility,
    }
