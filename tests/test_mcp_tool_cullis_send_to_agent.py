"""Tests for the ``cullis_send_to_agent`` MCP builtin (scope #5).

The tool wraps :func:`mcp_proxy.egress.oneshot.send_oneshot_internal`,
so every test mocks that helper with an ``AsyncMock`` (and
:func:`mcp_proxy.db.get_agent` for the sender lookup) and asserts the
contract the model sees:

* the tool registers under the expected name + capability,
* identity propagation (``ctx.agent_id`` → ``sender_agent.agent_id``)
  is enforced server-side — the model cannot spoof a sender,
* default ``target_org_id`` is the caller's org so bare names route
  intra-org,
* content normalization (``str`` → ``{"text": <content>}``),
* ``HTTPException`` from the helper maps to a structured
  ``{"error": ..., "reason": ...}`` dict for every supported status
  code (403 reach / 400 invalid / 503 broker_unavailable / 502
  broker_forward_failed),
* parameter validation rejects bad input before any HTTP call.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import HTTPException

from mcp_proxy.egress.oneshot import SendOneShotResponse
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import tool_registry


# ── Registry contract ──────────────────────────────────────────────────


def test_cullis_send_to_agent_is_registered() -> None:
    """The decorator must have run at import time of
    ``mcp_proxy.tools.builtins`` (verified indirectly by importing
    the module here — same import chain the Mastio uses)."""
    import mcp_proxy.tools.builtins  # noqa: F401 — triggers registration
    td = tool_registry.get("cullis_send_to_agent")
    assert td is not None
    assert td.required_capability == "cullis.a2a.send"
    # External HTTP is forbidden — the tool only invokes in-process
    # helpers, so the allowed_domains whitelist stays empty.
    assert td.allowed_domains == []
    schema = td.parameters_schema or {}
    assert schema.get("required") == ["target_agent_id", "content"]
    props = schema.get("properties", {})
    for key in (
        "target_agent_id", "target_org_id", "content",
        "correlation_id", "reply_to", "ttl_seconds",
    ):
        assert key in props, f"missing schema property: {key}"


# ── Test scaffolding ───────────────────────────────────────────────────


def _agent_record(
    agent_id: str = "orga::alice",
    reach: str = "both",
    is_active: bool = True,
) -> dict:
    return {
        "agent_id": agent_id,
        "display_name": agent_id.split("::", 1)[-1],
        "capabilities": [],
        "created_at": "2026-05-01T00:00:00+00:00",
        "is_active": is_active,
        "cert_pem": None,
        "dpop_jkt": None,
        "reach": reach,
    }


def _ctx(
    parameters: dict[str, Any],
    *,
    agent_id: str = "orga::alice",
    org_id: str = "orga",
    capabilities: list[str] | None = None,
    app_state: Any | None = None,
) -> ToolContext:
    """Build a ToolContext with a no-op httpx client."""
    return ToolContext(
        parameters=parameters,
        agent_id=agent_id,
        org_id=org_id,
        capabilities=capabilities or ["cullis.a2a.send"],
        secrets={},
        http_client=httpx.AsyncClient(),
        request_id="req-test",
        app_state=app_state,
    )


def _ok_response() -> SendOneShotResponse:
    return SendOneShotResponse(
        correlation_id="corr-abc",
        msg_id="msg-123",
        status="enqueued",
    )


_DEFAULT_SENDER = object()


def _patched_dependencies(
    *,
    sender: Any = _DEFAULT_SENDER,
    send_result: Any = None,
):
    """Patch ``get_agent`` + ``send_oneshot_internal`` together so
    every test gets the same mock surface. Pass ``sender=None``
    explicitly to simulate a missing ``internal_agents`` row (typed
    principal fallback path)."""
    if sender is _DEFAULT_SENDER:
        sender = _agent_record()
    get_agent_mock = AsyncMock(return_value=sender)
    if isinstance(send_result, Exception):
        send_mock = AsyncMock(side_effect=send_result)
    else:
        send_mock = AsyncMock(
            return_value=send_result if send_result is not None else _ok_response(),
        )
    return (
        patch("mcp_proxy.db.get_agent", get_agent_mock),
        patch(
            "mcp_proxy.egress.oneshot.send_oneshot_internal",
            send_mock,
        ),
        get_agent_mock,
        send_mock,
    )


# ── Happy path ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_string_content_is_wrapped_as_text_payload() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, get_mock, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "ciao bob",
        }))

    assert result["msg_id"] == "msg-123"
    assert result["correlation_id"] == "corr-abc"
    assert result["status"] == "enqueued"
    # Identity propagation: the helper got the body with the caller's
    # org-qualified recipient and a string-wrapped payload.
    sent_kwargs = send_mock.await_args.kwargs
    body = sent_kwargs["body"]
    assert body.recipient_id == "orga::bob"
    assert body.payload == {"text": "ciao bob"}
    # Sender identity is taken straight from ToolContext — never from
    # the model parameters.
    assert sent_kwargs["agent"].agent_id == "orga::alice"


@pytest.mark.asyncio
async def test_dict_content_passes_through_unchanged() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    payload = {"intent": "ping", "n": 7}
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": payload,
        }))

    assert send_mock.await_args.kwargs["body"].payload == payload


@pytest.mark.asyncio
async def test_fully_qualified_recipient_is_not_re_prefixed() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "orgb::bob",
            "content": "hi",
        }))

    assert send_mock.await_args.kwargs["body"].recipient_id == "orgb::bob"


@pytest.mark.asyncio
async def test_spiffe_recipient_passes_through() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    spiffe = "spiffe://other.example/agent/mario"
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": spiffe,
            "content": "hi",
        }))

    assert send_mock.await_args.kwargs["body"].recipient_id == spiffe


@pytest.mark.asyncio
async def test_explicit_target_org_id_qualifies_bare_name() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "mario",
            "target_org_id": "orgb",
            "content": "ciao",
        }))

    assert send_mock.await_args.kwargs["body"].recipient_id == "orgb::mario"
    assert result["target_org_id"] == "orgb"


@pytest.mark.asyncio
async def test_target_org_id_defaults_to_caller_org() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "hi",
        }, org_id="orga"))

    assert send_mock.await_args.kwargs["body"].recipient_id == "orga::bob"
    # Echoed back so the model can confirm where the send landed.
    assert result["target_org_id"] == "orga"


@pytest.mark.asyncio
async def test_correlation_id_is_generated_when_omitted() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
        }))

    body = send_mock.await_args.kwargs["body"]
    assert body.correlation_id, "tool should backfill a correlation id"


@pytest.mark.asyncio
async def test_explicit_correlation_id_and_reply_to_are_propagated() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
            "correlation_id": "corr-9",
            "reply_to": "msg-prev",
            "ttl_seconds": 120,
        }))

    body = send_mock.await_args.kwargs["body"]
    assert body.correlation_id == "corr-9"
    assert body.reply_to == "msg-prev"
    assert body.ttl_seconds == 120


@pytest.mark.asyncio
async def test_app_state_is_threaded_through_to_helper() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    fake_state = SimpleNamespace(
        broker_bridge="BRIDGE-SENTINEL",
        local_ws_manager="WS-SENTINEL",
    )
    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
        }, app_state=fake_state))

    kwargs = send_mock.await_args.kwargs
    assert kwargs["broker_bridge"] == "BRIDGE-SENTINEL"
    assert kwargs["ws_manager"] == "WS-SENTINEL"


# ── Identity propagation: the model cannot impersonate ─────────────────


@pytest.mark.asyncio
async def test_sender_identity_comes_from_ctx_not_parameters() -> None:
    """Even if a malicious / confused model tries to set ``sender_*`` or
    similar in the tool parameters, the helper only sees the
    ToolContext-derived agent. There is no parameter the model can
    set that ends up on ``send_oneshot_internal``'s ``agent``."""
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
            # Bogus impersonation attempts — the tool must ignore them.
            "sender_agent_id": "orga::admin",
            "sender": "orga::admin",
            "agent_id": "orga::admin",
        }, agent_id="orga::alice"))

    assert send_mock.await_args.kwargs["agent"].agent_id == "orga::alice"


@pytest.mark.asyncio
async def test_typed_principal_falls_back_to_intra_reach() -> None:
    """User / workload principals have no row in ``internal_agents``;
    the tool synthesises a minimal envelope with ``reach='intra'`` so
    cross-org sends from such callers raise at the reach gate."""
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies(sender=None)
    with get_p, send_p:
        await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
        }, agent_id="orga::user::alice"))

    agent_sent = send_mock.await_args.kwargs["agent"]
    assert agent_sent.agent_id == "orga::user::alice"
    assert agent_sent.reach == "intra"
    assert agent_sent.principal_type == "user"


# ── Parameter validation ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_target_agent_id_returns_error_dict() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({"content": "hi"}))

    assert result["error"] == "invalid_parameters"
    assert "target_agent_id" in result["reason"]
    send_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_content_returns_error_dict() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({"target_agent_id": "bob"}))

    assert result["error"] == "invalid_parameters"
    assert "content" in result["reason"]
    send_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_string_non_dict_content_rejected() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    get_p, send_p, _, send_mock = _patched_dependencies()
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": 42,
        }))

    assert result["error"] == "invalid_parameters"
    send_mock.assert_not_awaited()


# ── Error mapping from the helper ──────────────────────────────────────


@pytest.mark.asyncio
async def test_reach_denied_maps_to_reach_denied_error() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    deny = HTTPException(
        status_code=403,
        detail="reach: intra-only agent attempted cross-org send",
    )
    get_p, send_p, _, _ = _patched_dependencies(send_result=deny)
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "orgb::bob",
            "content": "x",
        }))

    assert result["error"] == "reach_denied"
    assert "reach" in result["reason"].lower()


@pytest.mark.asyncio
async def test_policy_denied_maps_to_policy_denied_error() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    deny = HTTPException(
        status_code=403,
        detail="Policy: payload contains forbidden field",
    )
    get_p, send_p, _, _ = _patched_dependencies(send_result=deny)
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "bob",
            "content": "x",
        }))

    assert result["error"] == "policy_denied"


@pytest.mark.asyncio
async def test_invalid_recipient_maps_to_invalid_recipient_error() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    deny = HTTPException(status_code=400, detail="invalid recipient_id")
    get_p, send_p, _, _ = _patched_dependencies(send_result=deny)
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "::malformed",
            "content": "x",
        }))

    assert result["error"] == "invalid_recipient"


@pytest.mark.asyncio
async def test_broker_unavailable_maps_to_broker_unavailable() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    deny = HTTPException(
        status_code=503,
        detail="Broker uplink not configured — cross-org one-shot unavailable",
    )
    get_p, send_p, _, _ = _patched_dependencies(send_result=deny)
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "spiffe://other/agent/bob",
            "content": "x",
        }))

    assert result["error"] == "broker_unavailable"


@pytest.mark.asyncio
async def test_broker_forward_failed_maps_to_broker_forward_failed() -> None:
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    deny = HTTPException(status_code=502, detail="broker forward failed")
    get_p, send_p, _, _ = _patched_dependencies(send_result=deny)
    with get_p, send_p:
        result = await cullis_send_to_agent(_ctx({
            "target_agent_id": "spiffe://other/agent/bob",
            "content": "x",
        }))

    assert result["error"] == "broker_forward_failed"


@pytest.mark.asyncio
async def test_unexpected_exception_propagates_to_executor() -> None:
    """Anything other than HTTPException is the executor's problem to
    surface (audit + JSON-RPC error envelope), not the tool's to
    translate."""
    from mcp_proxy.tools.builtins.cullis_send_to_agent import cullis_send_to_agent

    boom = RuntimeError("DB exploded")
    get_p, send_p, _, _ = _patched_dependencies(send_result=boom)
    with get_p, send_p:
        with pytest.raises(RuntimeError, match="DB exploded"):
            await cullis_send_to_agent(_ctx({
                "target_agent_id": "bob",
                "content": "x",
            }))
