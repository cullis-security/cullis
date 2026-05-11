"""ADR-029 Phase B: extended payload + extended response on the PDP
webhook channel.

The legacy webhook contract (`initiator_agent_id`, `target_agent_id`,
`capabilities`, `session_context`) keeps working unchanged. The
extended contract adds:

  Outbound:  model, invocation, context (optional dict fields, only
             written to the wire when present)
  Inbound:   scope, rate_limit, obligations (optional dict fields,
             parsed into typed dataclasses; missing fields become None
             and the broker treats them as 'no constraint')

When both sides of a dual-allow return scope/rate_limit/obligations,
the broker intersects them per ADR-029 §Decision (source ∩ target).
"""
from __future__ import annotations

import json

import httpx
import pytest


# ── Outbound payload shape ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_payload_legacy_when_no_extended_kwargs(monkeypatch):
    """call_pdp_webhook without model/invocation/context emits the same
    payload the legacy contract has always seen, no new keys appear."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": "allow"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )

    body = captured["body"]
    assert body["initiator_agent_id"] == "acme::alice"
    assert body["capabilities"] == ["cap.read"]
    assert "model" not in body
    assert "invocation" not in body
    assert "context" not in body
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_payload_includes_extended_kwargs_when_provided(monkeypatch):
    """When the caller passes model/invocation/context, the dicts land
    on the wire under those exact keys."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": "allow"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
        model={"id": "claude-haiku-4-5", "provider": "anthropic"},
        invocation={
            "kind": "session_tool_call",
            "tool_name": "postgres.query",
            "mcp_server_id": "compliance-postgres",
        },
        context={"trace_id": "t_xyz", "parent_session_id": "s_abc"},
    )

    body = captured["body"]
    assert body["model"]["id"] == "claude-haiku-4-5"
    assert body["invocation"]["tool_name"] == "postgres.query"
    assert body["context"]["trace_id"] == "t_xyz"
    get_settings.cache_clear()


# ── Inbound response shape ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_legacy_response_parsed_with_no_extensions(monkeypatch):
    """A PDP that returns the legacy {decision, reason} shape gets the
    same decision object as before: extension fields stay None."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "allow", "reason": "ok"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    d = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )

    assert d.allowed is True
    assert d.scope is None
    assert d.rate_limit is None
    assert d.obligations is None
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_extended_response_parsed(monkeypatch):
    """A PDP that returns scope/rate_limit/obligations lands them on
    the decision as typed dataclasses with the right values."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "decision": "allow",
            "reason": "ok",
            "scope": {
                "tools_allowed": ["acme.catalog.search", "acme.catalog.list"],
                "tools_denied": ["acme.catalog.update"],
                "max_session_duration_s": 1800,
            },
            "rate_limit": {"per_minute": 60, "per_day": 1000},
            "obligations": {
                "require_user_confirmation": True,
                "trace_visibility": "full",
            },
        })

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    d = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )

    assert d.allowed is True
    assert d.scope is not None
    assert d.scope.tools_allowed == ["acme.catalog.search", "acme.catalog.list"]
    assert d.scope.tools_denied == ["acme.catalog.update"]
    assert d.scope.max_session_duration_s == 1800
    assert d.rate_limit is not None
    assert d.rate_limit.per_minute == 60
    assert d.rate_limit.per_day == 1000
    assert d.obligations is not None
    assert d.obligations.require_user_confirmation is True
    assert d.obligations.trace_visibility == "full"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_invalid_trace_visibility_clamps_to_redacted(monkeypatch):
    """An obligations.trace_visibility value outside the allowed set
    (full|redacted|off) clamps to 'redacted', not propagated raw."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "decision": "allow",
            "obligations": {"trace_visibility": "BOGUS_VALUE"},
        })

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    d = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )

    assert d.obligations is not None
    assert d.obligations.trace_visibility == "redacted"
    get_settings.cache_clear()


# ── Cross-org intersection ──────────────────────────────────────────


def test_intersect_scopes_tools_allowed_is_intersection():
    """tools_allowed of (initiator ∩ target). Only what BOTH allow."""
    from app.policy.webhook import DecisionScope, _intersect_scopes
    a = DecisionScope(tools_allowed=["x", "y", "z"])
    b = DecisionScope(tools_allowed=["y", "z", "w"])
    out = _intersect_scopes(a, b)
    assert out is not None
    assert out.tools_allowed == ["y", "z"]


def test_intersect_scopes_tools_denied_is_union():
    """tools_denied of (initiator ∪ target). Anyone says deny → deny."""
    from app.policy.webhook import DecisionScope, _intersect_scopes
    a = DecisionScope(tools_denied=["a", "b"])
    b = DecisionScope(tools_denied=["b", "c"])
    out = _intersect_scopes(a, b)
    assert out is not None
    assert out.tools_denied == ["a", "b", "c"]


def test_intersect_scopes_duration_is_min():
    """Tighter session duration wins."""
    from app.policy.webhook import DecisionScope, _intersect_scopes
    a = DecisionScope(max_session_duration_s=3600)
    b = DecisionScope(max_session_duration_s=900)
    out = _intersect_scopes(a, b)
    assert out is not None
    assert out.max_session_duration_s == 900


def test_intersect_scopes_one_side_none_returns_other():
    """A None scope on one side means 'no restriction from that side'."""
    from app.policy.webhook import DecisionScope, _intersect_scopes
    a = DecisionScope(tools_allowed=["x"])
    assert _intersect_scopes(a, None) == a
    assert _intersect_scopes(None, a) == a
    assert _intersect_scopes(None, None) is None


def test_intersect_rate_limits_takes_min():
    from app.policy.webhook import DecisionRateLimit, _intersect_rate_limits
    a = DecisionRateLimit(per_minute=60, per_day=1000)
    b = DecisionRateLimit(per_minute=30, per_day=2000)
    out = _intersect_rate_limits(a, b)
    assert out is not None
    assert out.per_minute == 30
    assert out.per_day == 1000


def test_intersect_obligations_user_confirmation_is_or():
    """If either side requires user confirmation, the final does too."""
    from app.policy.webhook import DecisionObligations, _intersect_obligations
    a = DecisionObligations(require_user_confirmation=False, trace_visibility="full")
    b = DecisionObligations(require_user_confirmation=True, trace_visibility="full")
    out = _intersect_obligations(a, b)
    assert out is not None
    assert out.require_user_confirmation is True


def test_intersect_obligations_trace_visibility_picks_more_restrictive():
    """'off' beats 'redacted' beats 'full'. More restrictive wins."""
    from app.policy.webhook import DecisionObligations, _intersect_obligations
    full = DecisionObligations(trace_visibility="full")
    redacted = DecisionObligations(trace_visibility="redacted")
    off = DecisionObligations(trace_visibility="off")
    assert _intersect_obligations(full, redacted).trace_visibility == "redacted"
    assert _intersect_obligations(redacted, full).trace_visibility == "redacted"
    assert _intersect_obligations(redacted, off).trace_visibility == "off"
    assert _intersect_obligations(full, off).trace_visibility == "off"


@pytest.mark.asyncio
async def test_dual_allow_returns_intersected_decision(monkeypatch):
    """evaluate_session_via_webhooks with two allow sides returning
    different scopes carries the intersection on the final decision."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "deny")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    def _handler(request: httpx.Request) -> httpx.Response:
        # Different scope per host so we can verify intersection.
        if "initiator" in request.url.host or "initiator" in str(request.url):
            return httpx.Response(200, json={
                "decision": "allow",
                "scope": {
                    "tools_allowed": ["x", "y"],
                    "max_session_duration_s": 3600,
                },
                "rate_limit": {"per_minute": 60},
            })
        return httpx.Response(200, json={
            "decision": "allow",
            "scope": {
                "tools_allowed": ["y", "z"],
                "max_session_duration_s": 900,
            },
            "rate_limit": {"per_minute": 30},
        })

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    d = await wh.evaluate_session_via_webhooks(
        initiator_org_id="acme",
        initiator_webhook_url="https://initiator.example.com/pdp",
        target_org_id="other-org",
        target_webhook_url="https://target.example.com/pdp",
        initiator_agent_id="acme::alice",
        target_agent_id="other-org::bob",
        capabilities=["cap.read"],
    )

    assert d.allowed is True
    assert d.scope is not None
    assert d.scope.tools_allowed == ["y"]
    assert d.scope.max_session_duration_s == 900
    assert d.rate_limit is not None
    assert d.rate_limit.per_minute == 30
    get_settings.cache_clear()
