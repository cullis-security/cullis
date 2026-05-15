"""Builtin tool: ``cullis_send_to_agent`` — sessionless A2A messaging.

Roadmap session 2026-05-15 scope #5. Exposes the same code path that
backs ``POST /v1/egress/message/send`` as an MCP tool, so any client
of the Mastio's MCP aggregator (Frontdesk SPA, Claude Code, Codex,
Cursor, LibreChat, ...) can ask the model to send a one-shot message
to another Cullis agent without writing transport code.

Naming: underscored — ``cullis_send_to_agent`` — to match existing
builtins (``query_salesforce``, ``check_erp_inventory``) and dodge
MCP clients that misparse dotted tool names.

The implementation invokes :func:`mcp_proxy.egress.oneshot.send_oneshot_internal`
directly. **No loopback HTTP, no ephemeral DPoP** — the chat_completion
DPoP-pinning pattern (memory feedback ``chat_completion_dpop_pinning_bug``)
is exactly what we are avoiding here. Identity propagation comes for
free: ``ctx.agent_id`` from the tool context is the sender, and we
let the helper apply the same reach / policy / audit gates the HTTP
route applies.

Errors that the helper raises as ``HTTPException`` are translated to
a structured ``{"error": "...", "reason": "..."}`` dict so the model
can react in-band. Anything else (DB outage, asyncio plumbing) is
re-raised so the executor surfaces it through the JSON-RPC error
envelope.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import HTTPException

from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import tool_registry

_log = logging.getLogger("mcp_proxy.tools.builtins.cullis_send_to_agent")


_DESCRIPTION = (
    "Send a one-shot message to another Cullis agent. Routes through "
    "the Mastio's intra-org egress for same-org recipients and through "
    "the broker bridge for cross-org. Identity (sender) + audit chain "
    "are handled by the Mastio — the caller just supplies recipient "
    "and content."
)


_PARAMETERS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_agent_id": {
            "type": "string",
            "description": (
                "Recipient principal identifier. Accepts a bare agent "
                "name (e.g. 'mario' — interpreted in the caller's org), "
                "the canonical ``<org>::<name>`` form, or a SPIFFE URI "
                "(e.g. 'spiffe://other-org.example/agent/mario') for "
                "cross-org delivery."
            ),
        },
        "target_org_id": {
            "type": "string",
            "description": (
                "Optional recipient org id. Defaults to the caller's "
                "org for intra-org routing. Ignored when "
                "``target_agent_id`` is a fully qualified ``<org>::name`` "
                "or SPIFFE URI."
            ),
        },
        "content": {
            "description": (
                "Message body. Pass a string for plaintext (wrapped as "
                "``{\"text\": <content>}`` server-side) or a JSON object "
                "for a structured payload."
            ),
        },
        "correlation_id": {
            "type": "string",
            "description": (
                "Optional correlation id for matching replies. Server "
                "generates one when omitted."
            ),
        },
        "reply_to": {
            "type": "string",
            "description": (
                "Optional correlation_id of the message this one is a "
                "reply to."
            ),
        },
        "ttl_seconds": {
            "type": "integer",
            "default": 300,
            "minimum": 10,
            "maximum": 3600,
            "description": (
                "Server-side TTL for offline delivery (default 5 min, "
                "max 1 h)."
            ),
        },
    },
    "required": ["target_agent_id", "content"],
}


def _normalize_payload(content: Any) -> dict:
    """Wrap a plaintext string in ``{"text": content}``; pass dicts
    through; raise ``ValueError`` for anything else.

    The route handler accepts only ``dict`` payloads via Pydantic;
    keeping the same contract here ensures the tool surface matches
    the HTTP surface exactly.
    """
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        return {"text": content}
    raise ValueError(
        f"content must be a string or JSON object, got {type(content).__name__}"
    )


def _qualify_recipient(target_agent_id: str, target_org_id: str | None, caller_org: str) -> str:
    """Build the ``recipient_id`` that ``send_oneshot_internal`` expects.

    The helper accepts ``org::agent``, SPIFFE URIs, or bare names
    (which it interprets within the caller's org). We pre-qualify
    bare names with ``target_org_id`` (or the caller's org if absent)
    so cross-org U2U sends route correctly without forcing the model
    to know the canonical form.
    """
    if target_agent_id.startswith("spiffe://"):
        return target_agent_id
    if "::" in target_agent_id:
        return target_agent_id
    org = target_org_id or caller_org
    if not org:
        # No way to qualify — let the helper see the bare name and
        # 400 with its own canonical "invalid recipient_id" message.
        return target_agent_id
    return f"{org}::{target_agent_id}"


@tool_registry.register(
    name="cullis_send_to_agent",
    capability="cullis.a2a.send",
    allowed_domains=[],
    description=_DESCRIPTION,
    parameters_schema=_PARAMETERS_SCHEMA,
)
async def cullis_send_to_agent(ctx: ToolContext) -> dict:
    """Send a one-shot message via the in-process ``send_oneshot_internal``.

    Identity (``sender_agent_id``, ``sender_org_id``) comes from the
    ToolContext — no way for the model to spoof a different sender.
    The helper handles reach, policy, audit, and broker forwarding.
    """
    # Lazy imports keep the module cheap to import at registration time
    # (the registry decorator fires on every Mastio startup), and dodge
    # the egress/oneshot ↔ tools cycle in case one ever appears.
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import get_agent
    from mcp_proxy.egress.oneshot import (
        SendOneShotRequest,
        send_oneshot_internal,
    )
    from mcp_proxy.models import InternalAgent

    params = ctx.parameters or {}

    target_agent_id = params.get("target_agent_id")
    if not isinstance(target_agent_id, str) or not target_agent_id:
        return {
            "error": "invalid_parameters",
            "reason": "target_agent_id is required (string)",
        }

    content = params.get("content")
    if content is None:
        return {
            "error": "invalid_parameters",
            "reason": "content is required",
        }
    try:
        payload = _normalize_payload(content)
    except ValueError as exc:
        return {"error": "invalid_parameters", "reason": str(exc)}

    target_org_id = params.get("target_org_id")
    correlation_id = params.get("correlation_id") or str(uuid.uuid4())
    reply_to = params.get("reply_to")
    ttl_seconds = int(params.get("ttl_seconds", 300) or 300)

    recipient_id = _qualify_recipient(target_agent_id, target_org_id, ctx.org_id)

    # Resolve the sender's InternalAgent row so ``send_oneshot_internal``
    # can apply the reach gate (``agent.reach``) the same way the HTTP
    # route does. Typed principals (user / workload) don't live in
    # ``internal_agents``; build a minimal envelope from the
    # ToolContext for those, mirroring ``_maybe_local_internal_agent``.
    agent_record = await get_agent(ctx.agent_id)
    if agent_record is not None and agent_record.get("is_active", True):
        capabilities = agent_record.get("capabilities") or []
        if isinstance(capabilities, str):
            import json
            try:
                capabilities = json.loads(capabilities)
            except Exception:
                capabilities = [c for c in capabilities.split(",") if c]
        sender_agent = InternalAgent(
            agent_id=ctx.agent_id,
            display_name=agent_record.get("display_name") or ctx.agent_id,
            capabilities=list(capabilities),
            created_at=str(agent_record.get("created_at") or ""),
            is_active=bool(agent_record.get("is_active", True)),
            cert_pem=agent_record.get("cert_pem"),
            dpop_jkt=agent_record.get("dpop_jkt"),
            reach=agent_record.get("reach") or "both",
        )
    else:
        # Typed principal (user / workload) — the row isn't in
        # ``internal_agents``. The reach gate is intentionally
        # ``intra`` for these callers; cross-org sends raise at the
        # reach check, surfacing the right error envelope below.
        from datetime import datetime, timezone
        principal_type = "agent"
        if "::user::" in ctx.agent_id:
            principal_type = "user"
        elif "::workload::" in ctx.agent_id:
            principal_type = "workload"
        sender_agent = InternalAgent(
            agent_id=ctx.agent_id,
            display_name=ctx.agent_id,
            capabilities=list(ctx.capabilities or []),
            created_at=datetime.now(timezone.utc).isoformat(),
            is_active=True,
            cert_pem=None,
            dpop_jkt=None,
            reach="intra",
            principal_type=principal_type,
        )

    body = SendOneShotRequest(
        recipient_id=recipient_id,
        payload=payload,
        correlation_id=correlation_id,
        reply_to=reply_to,
        ttl_seconds=ttl_seconds,
    )

    # Pull the cross-subsystem dependencies from the FastAPI app state
    # the executor stashed on ``ctx``. ``None`` here just means the
    # tool was invoked outside a route (CLI / test); the helper raises
    # a clean 503 for the cross-org branch in that case, which we map
    # below.
    broker_bridge = getattr(ctx.app_state, "broker_bridge", None) if ctx.app_state else None
    ws_manager = getattr(ctx.app_state, "local_ws_manager", None) if ctx.app_state else None

    try:
        response = await send_oneshot_internal(
            agent=sender_agent,
            body=body,
            broker_bridge=broker_bridge,
            ws_manager=ws_manager,
            settings=get_settings(),
        )
    except HTTPException as exc:
        # Map the helper's HTTP-shaped errors to a structured dict so
        # the MCP model can branch in-band without parsing prose. The
        # route handler audit row already captured the specific
        # reason for ops.
        reason = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        if exc.status_code == 403:
            error_kind = "reach_denied" if "reach" in reason.lower() else "policy_denied"
        elif exc.status_code == 400:
            error_kind = "invalid_recipient"
        elif exc.status_code == 503:
            error_kind = "broker_unavailable"
        elif exc.status_code == 502:
            error_kind = "broker_forward_failed"
        else:
            error_kind = "send_failed"
        _log.info(
            "cullis_send_to_agent: %s (status=%d, sender=%s, recipient=%s)",
            error_kind, exc.status_code, ctx.agent_id, recipient_id,
        )
        return {"error": error_kind, "reason": reason}

    return {
        "correlation_id": response.correlation_id,
        "msg_id": response.msg_id,
        "status": response.status,
        "target_agent_id": recipient_id,
        "target_org_id": target_org_id or ctx.org_id,
    }
