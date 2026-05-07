"""ADR-020 Phase 4 — proxy-mediated user inbox send.

``POST /v1/egress/inbox/send`` lets an agent (or any cert-authenticated
SDK caller) deliver to a Cullis user / agent / workload principal's
inbox without holding a broker-aud JWT directly. The proxy authenticates
the caller via mTLS+DPoP (same as every ``/v1/egress/*`` route), then
hands off to ``BrokerBridge`` which uses the per-agent broker
``CullisClient`` to call the broker's ``/v1/inbox/send`` on the agent's
behalf.

Why a dedicated endpoint instead of forwarding ``/v1/inbox/*`` straight
to the broker:

  * Tokens issued by the proxy's local ``/v1/auth/token`` have
    ``aud=cullis-local`` (ADR-012), so the broker would reject them at
    ``app.auth.jwt.get_current_agent``. ``BrokerBridge.get_client()``
    holds an agent-scoped client that authenticates with a *broker*-aud
    token, transparently to the SDK caller.
  * Egress audit (``mcp_proxy.local.audit.append_local_audit``) gets the
    same ``oneshot_*`` event-type contract every other egress call
    uses, so the audit chain has a single source of truth for outbound
    messages.

Inbound rate-limit + reach + policy checks live on the broker side
(``app/inbox/store.py::enqueue``); we surface its 403 (reach denied) /
422 (validation) verbatim.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.local.audit import append_local_audit
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.egress.inbox")

router = APIRouter(prefix="/v1/egress", tags=["egress-inbox"])


class InboxSendRequest(BaseModel):
    recipient_org_id: str = Field(..., min_length=1, max_length=128)
    recipient_principal_type: str = Field(..., min_length=1, max_length=16)
    recipient_name: str = Field(..., min_length=1, max_length=128)
    body: str = Field(..., max_length=64 * 1024)
    subject: str | None = Field(None, max_length=256)
    idempotency_key: str | None = Field(None, max_length=256)


class InboxSendResponse(BaseModel):
    msg_id: str
    inserted: bool
    quadrant: str


@router.post("/inbox/send", response_model=InboxSendResponse)
async def send_to_inbox(
    body: InboxSendRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> InboxSendResponse:
    """Forward an inbox-send call to the broker on behalf of ``agent``.

    Returns the broker's ``msg_id`` / ``inserted`` / ``quadrant`` tuple
    on success. 503 when the broker bridge is missing (standalone proxy
    boot before federation is wired). 403 when reach policy denies the
    quadrant.
    """
    settings = get_settings()
    local_org = settings.org_id or ""

    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is None:
        await append_local_audit(
            event_type="inbox_send_denied",
            result="error",
            agent_id=agent.agent_id,
            org_id=local_org,
            details={
                "recipient_org_id": body.recipient_org_id,
                "recipient_principal_type": body.recipient_principal_type,
                "recipient_name": body.recipient_name,
                "reason": "broker_bridge_unavailable",
            },
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Broker uplink not configured — inbox send unavailable on "
                "a standalone proxy."
            ),
        )

    audit_details = {
        "recipient_org_id": body.recipient_org_id,
        "recipient_principal_type": body.recipient_principal_type,
        "recipient_name": body.recipient_name,
        "subject": body.subject,
    }

    try:
        broker_client = await bridge.get_client(agent.agent_id)
        # ``CullisClient.send_to_inbox`` calls the broker's
        # ``POST /v1/inbox/send`` over the broker-aud session that
        # BrokerBridge maintains for this agent.
        result = broker_client.send_to_inbox(
            recipient_org_id=body.recipient_org_id,
            recipient_principal_type=body.recipient_principal_type,
            recipient_name=body.recipient_name,
            body=body.body,
            subject=body.subject,
            idempotency_key=body.idempotency_key,
        )
    except PermissionError as exc:
        await append_local_audit(
            event_type="inbox_send_denied",
            result="denied",
            agent_id=agent.agent_id,
            org_id=local_org,
            details={**audit_details, "reason": str(exc)},
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — surface broker errors as 502
        await append_local_audit(
            event_type="inbox_send_denied",
            result="error",
            agent_id=agent.agent_id,
            org_id=local_org,
            details={**audit_details, "reason": f"broker_forward_failed: {exc}"},
        )
        raise HTTPException(
            status_code=502,
            detail=f"Broker forward failed: {exc}",
        ) from exc

    await append_local_audit(
        event_type="inbox_send_ok",
        result="ok",
        agent_id=agent.agent_id,
        org_id=local_org,
        details={**audit_details, "msg_id": result.get("msg_id", "")},
    )
    return InboxSendResponse(**result)
