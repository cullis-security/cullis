"""
Egress API endpoints — internal agents authenticate with mTLS client
certs and communicate through the Cullis broker without seeing x509
keys, DPoP, or any cryptography directly.

All endpoints require client-cert authentication (via
``get_agent_from_dpop_client_cert``, ADR-014). That dep verifies the
cert nginx forwarded in ``X-SSL-Client-Cert`` against
``internal_agents.cert_pem`` and, when ``CULLIS_EGRESS_DPOP_MODE`` is
``optional`` or ``required``, additionally validates a DPoP proof from
the ``DPoP`` header pinned to the agent's registered ``dpop_jkt``.
"""
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.reach_guard import check_reach, resolve_target_org
from mcp_proxy.egress.routing import decide_route
from mcp_proxy.local import message_queue as local_queue
from mcp_proxy.local.audit import append_local_audit
from mcp_proxy.local.models import SessionCloseReason
from mcp_proxy.local.persistence import save_session as save_local_session
from mcp_proxy.local.session import (
    LocalAgentSessionCapExceeded,
    LocalSession,
    LocalSessionStore,
)
from mcp_proxy.models import InternalAgent
from mcp_proxy.policy.local_eval import evaluate_local_message

logger = logging.getLogger("mcp_proxy.egress.router")

router = APIRouter(prefix="/v1/egress", tags=["egress"])

import re as _re
_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)


def _validate_session_id(session_id: str) -> None:
    """Reject non-UUID session IDs to prevent log injection."""
    if not _UUID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────


class OpenSessionRequest(BaseModel):
    target_agent_id: str
    target_org_id: str
    capabilities: list[str]


class OpenSessionResponse(BaseModel):
    session_id: str
    status: str


class SendMessageRequest(BaseModel):
    session_id: str
    payload: dict
    recipient_agent_id: str
    # ADR-001 Phase 3c — at-least-once fields (mirror broker M3 SDK params).
    # Optional; omitting them keeps pre-3c client behavior.
    ttl_seconds: int = Field(default=local_queue.DEFAULT_TTL_SECONDS, ge=10, le=3600)
    idempotency_key: str | None = None
    # ADR-001 §10 — intra-org mtls-only mode. When omitted or "envelope",
    # payload is opaque ciphertext (legacy behavior). When "mtls-only",
    # payload is plaintext and signature + nonce + timestamp are required
    # so the proxy can verify the sender's signature before enqueueing.
    mode: Literal["envelope", "mtls-only"] = "envelope"
    signature: str | None = None
    nonce: str | None = None
    timestamp: int | None = None
    sender_seq: int | None = None


class DiscoverRequest(BaseModel):
    capabilities: list[str] | None = None
    q: str | None = None


class ResolveRequest(BaseModel):
    """ADR-001 §10 — resolve a recipient and return routing path + metadata.

    The SDK calls this before sending so it can choose the right wire
    format: mtls-only (signed, not encrypted) for intra-org in the
    mtls-only transport mode, or envelope (E2E encrypted) otherwise.
    """
    recipient_id: str


class ResolveResponse(BaseModel):
    path: Literal["intra-org", "cross-org"]
    target_agent_id: str
    target_org_id: str
    target_spiffe: str | None = None
    transport: Literal["envelope", "mtls-only"]
    egress_inspection: bool = False
    target_cert_pem: str | None = None


class PeerInfo(BaseModel):
    """A peer the caller can address with /v1/egress/* (intra-org local
    or, when federation is wired, cross-org cached).

    Mirrors ``cullis_sdk.types.AgentInfo`` so the SDK can deserialize
    via ``AgentInfo.from_dict``.
    """
    agent_id: str
    org_id: str
    display_name: str = ""
    capabilities: list[str] = Field(default_factory=list)
    description: str | None = None
    status: str | None = None
    scope: Literal["intra-org", "cross-org"] = "intra-org"


class PeersResponse(BaseModel):
    peers: list[PeerInfo]
    count: int


class AgentPublicKeyResponse(BaseModel):
    """Body of ``GET /v1/egress/agents/{agent_id}/public-key``.

    ``cert_pem`` is the full x509 PEM — the SDK's pubkey cache stores
    certs (not bare keys) because the crypto verifiers accept either
    form, and the cert carries the subject binding the key to an agent
    identity. Schema is intentionally aligned with ``/v1/egress/resolve``
    which also returns ``target_cert_pem`` rather than a raw public key.
    """
    agent_id: str
    cert_pem: str | None = None


class InvokeToolRequest(BaseModel):
    """Cross-org tool invocation via broker session."""
    session_id: str
    tool_name: str
    parameters: dict = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — BrokerBridge is injected at app startup via app.state
# ─────────────────────────────────────────────────────────────────────────────


def _get_bridge(request: Request):
    """Retrieve the BrokerBridge instance from app state.

    ADR-006 Fase 1: in standalone mode the bridge is deliberately absent
    and any request that reaches this helper is attempting a cross-org
    operation the proxy cannot fulfil. Surface a 400 with a clear
    message instead of the legacy 503 "bridge not initialized" — the
    distinction matters for SDK callers that want to detect
    "standalone-only" vs "broker transiently down".
    """
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is None:
        if get_settings().standalone:
            raise HTTPException(
                status_code=400,
                detail=(
                    "cross-org operations disabled in standalone mode — "
                    "attach the proxy to a broker to enable federation"
                ),
            )
        raise HTTPException(
            status_code=503,
            detail="Egress bridge not initialized — broker_url may be unconfigured",
        )
    return bridge


def _get_local_store(request: Request) -> LocalSessionStore | None:
    """Return the local session store when ADR-001 Phase 3 is active."""
    return getattr(request.app.state, "local_session_store", None)


def _should_route_intra(recipient_agent_id: str, target_org_id: str = "") -> bool:
    """Check whether the caller should be routed by the local store.

    Called from each session endpoint before falling through to the
    broker bridge. When PROXY_INTRA_ORG is off, always false (preserves
    the pre-Phase-2 behavior). When on, the session-open path prefers
    the explicit target_org_id (authoritative from the caller's intent);
    other paths fall back to the SPIFFE-driven decide_route helper.
    """
    settings = get_settings()
    if not settings.intra_org_routing:
        return False
    if target_org_id:
        return target_org_id == settings.org_id
    route = decide_route(
        recipient_agent_id,
        local_org=settings.org_id,
        local_trust_domain=settings.trust_domain,
    )
    return route == "intra"


def _local_session_to_dict(session: LocalSession) -> dict:
    return {
        "session_id": session.session_id,
        "initiator_agent_id": session.initiator_agent_id,
        "target_agent_id": session.target_agent_id,
        "status": session.status.value,
        "requested_capabilities": list(session.requested_capabilities),
        "created_at": session.created_at.isoformat(),
        "last_activity_at": session.last_activity_at.isoformat(),
        "close_reason": session.close_reason.value if session.close_reason else None,
        "scope": "local",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/sessions", response_model=OpenSessionResponse)
async def open_session(
    body: OpenSessionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Open a session on behalf of an internal agent.

    ADR-001 Phase 3a: when `PROXY_INTRA_ORG` is on and the target resolves
    to this proxy's (trust_domain, org), the session is created in the
    local store and never touches the broker. Otherwise the request falls
    through to the broker bridge exactly like before.
    """
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    # Reach gate (migration 0017): refuse before we create a local
    # session row or call out to the broker. ``target_org_id`` on the
    # request body is authoritative when the client sent one; fall
    # back to parsing the handle otherwise.
    _settings = get_settings()
    target_org = resolve_target_org(body.target_agent_id, body.target_org_id)
    try:
        check_reach(agent, target_org, _settings.org_id or "")
    except HTTPException as deny:
        await append_local_audit(
            event_type="session_denied",
            result="denied",
            agent_id=agent.agent_id,
            org_id=_settings.org_id,
            details={
                "target_agent_id": body.target_agent_id,
                "target_org_id": body.target_org_id,
                "reason": "reach",
                "reach": agent.reach,
                "target_org": target_org,
            },
        )
        raise deny

    local_store = _get_local_store(request)
    if local_store is not None and _should_route_intra(body.target_agent_id, body.target_org_id):
        try:
            session = local_store.create(
                initiator_agent_id=agent.agent_id,
                target_agent_id=body.target_agent_id,
                requested_capabilities=body.capabilities,
            )
            await save_local_session(session)
            duration_ms = (time.monotonic() - t0) * 1000
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_session_open_local",
                status="success",
                detail=f"target={body.target_agent_id} session={session.session_id}",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            await append_local_audit(
                event_type="session_opened",
                agent_id=agent.agent_id,
                session_id=session.session_id,
                org_id=get_settings().org_id,
                details={
                    "target_agent_id": body.target_agent_id,
                    "target_org_id": body.target_org_id,
                    "capabilities": body.capabilities,
                },
            )
            return OpenSessionResponse(session_id=session.session_id, status="opened")
        except LocalAgentSessionCapExceeded as exc:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_session_open_local",
                status="error",
                detail=str(exc)[:500],
                request_id=request_id,
            )
            raise HTTPException(
                status_code=429,
                detail={"error": "session_cap_exceeded", "current": exc.current, "cap": exc.cap},
            ) from exc

    bridge = _get_bridge(request)
    try:
        session_id = await bridge.open_session(
            agent.agent_id,
            body.target_agent_id,
            body.target_org_id,
            body.capabilities,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_open",
            status="success",
            detail=f"target={body.target_agent_id} session={session_id}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return OpenSessionResponse(session_id=session_id, status="opened")

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_open",
            status="error",
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        logger.error("Failed to open session for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.get("/sessions")
async def list_sessions(
    request: Request,
    status: str | None = None,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """List sessions for the authenticated agent — local + broker merged."""
    local_store = _get_local_store(request)
    local_sessions: list[dict] = []
    if local_store is not None:
        for s in local_store.list_for_agent(agent.agent_id):
            if status is None or s.status.value == status:
                local_sessions.append(_local_session_to_dict(s))

    broker_sessions: list[dict] = []
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        try:
            broker_sessions = await bridge.list_sessions(agent.agent_id, status)
        except Exception as exc:
            logger.error("Failed to list broker sessions for %s: %s", agent.agent_id, exc)
            # Broker failure degrades to local-only listing rather than 502.
            broker_sessions = []

    return {"sessions": local_sessions + broker_sessions}


@router.post("/sessions/{session_id}/accept")
async def accept_session(
    session_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Accept a pending session (local or broker)."""
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    if local_store is not None:
        async with local_store._lock:
            session = local_store.get(session_id)
            if session is not None:
                if session.target_agent_id != agent.agent_id:
                    raise HTTPException(status_code=403, detail="not the target")
                session = local_store.activate(session_id)
                await save_local_session(session)
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_session_accept_local",
                    status="success",
                    detail=f"session={session_id}",
                )
                await append_local_audit(
                    event_type="session_accepted",
                    agent_id=agent.agent_id,
                    session_id=session_id,
                    org_id=get_settings().org_id,
                )
                return {"status": "accepted", "session_id": session_id}

    bridge = _get_bridge(request)
    try:
        await bridge.accept_session(agent.agent_id, session_id)

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_accept",
            status="success",
            detail=f"session={session_id}",
        )

        return {"status": "accepted", "session_id": session_id}

    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_accept",
            status="error",
            detail=str(exc)[:500],
        )
        logger.error("Failed to accept session for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/sessions/{session_id}/close")
async def close_session(
    session_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Close a session (local or broker)."""
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    if local_store is not None:
        async with local_store._lock:
            session = local_store.get(session_id)
            if session is not None:
                if not session.involves(agent.agent_id):
                    raise HTTPException(status_code=403, detail="not a participant")
                session = local_store.close(session_id, SessionCloseReason.normal)
                await save_local_session(session)
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_session_close_local",
                    status="success",
                    detail=f"session={session_id}",
                )
                await append_local_audit(
                    event_type="session_closed",
                    agent_id=agent.agent_id,
                    session_id=session_id,
                    org_id=get_settings().org_id,
                    details={"reason": "normal"},
                )
                return {"status": "closed", "session_id": session_id}

    bridge = _get_bridge(request)
    try:
        await bridge.close_session(agent.agent_id, session_id)

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_close",
            status="success",
            detail=f"session={session_id}",
        )

        return {"status": "closed", "session_id": session_id}

    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_session_close",
            status="error",
            detail=str(exc)[:500],
        )
        logger.error("Failed to close session %s: %s", session_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/send")
async def send_message(
    body: SendMessageRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Send an E2E-encrypted message.

    ADR-001 Phase 3c: when `body.session_id` refers to a local session,
    the message is enqueued on `local_messages` and pushed over the
    recipient's local WS if connected. Otherwise the request falls
    through to the broker bridge exactly like before.
    """
    _validate_session_id(body.session_id)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    local_store = _get_local_store(request)
    local_session = local_store.get(body.session_id) if local_store else None

    # Reach gate (migration 0017) — session might have been opened
    # while reach was permissive and then tightened by the operator
    # mid-flight; we refuse every non-compliant send to make the
    # toggle actually matter. Intra-org sends come from local_session
    # (same org by definition); broker-session sends are cross-org
    # when ``body.target_org_id != local_org``, cross otherwise the
    # intra short-circuit would have picked them up.
    _settings = get_settings()
    local_org = _settings.org_id or ""
    if local_session is not None:
        send_target_org = local_org
    else:
        send_target_org = resolve_target_org(body.recipient_agent_id)
    try:
        check_reach(agent, send_target_org, local_org)
    except HTTPException as deny:
        await append_local_audit(
            event_type="message_denied",
            result="denied",
            agent_id=agent.agent_id,
            session_id=body.session_id,
            org_id=local_org,
            details={
                "recipient": body.recipient_agent_id,
                "reason": "reach",
                "reach": agent.reach,
                "target_org": send_target_org,
            },
        )
        raise deny

    if local_session is not None:
        if not local_session.involves(agent.agent_id):
            raise HTTPException(status_code=403, detail="not a participant")
        if agent.agent_id == local_session.initiator_agent_id:
            recipient = local_session.target_agent_id
        else:
            recipient = local_session.initiator_agent_id

        # ADR-006 Fase 1 — intra-org policy evaluation. Rules live in
        # local_policies and match the broker JSON schema
        # (max_payload_size_bytes, required_fields, blocked_fields, deny).
        # Envelope mode stores content as opaque ciphertext, so field-level
        # rules only bite on mtls-only payloads; size-on-wire still applies.
        settings = get_settings()
        verdict = await evaluate_local_message(
            org_id=settings.org_id, payload=body.payload,
        )
        if not verdict.allowed:
            await append_local_audit(
                event_type="message_denied",
                result="denied",
                agent_id=agent.agent_id,
                session_id=body.session_id,
                org_id=settings.org_id,
                details={
                    "reason": verdict.reason,
                    "policy_id": verdict.policy_id,
                    "recipient": recipient,
                },
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_send_local_denied",
                status="denied",
                detail=f"policy={verdict.policy_id} reason={verdict.reason}",
                request_id=request_id,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "policy_denied",
                    "reason": verdict.reason,
                    "policy_id": verdict.policy_id,
                },
            )

        # ADR-001 §10 — mtls-only path: sender signs plaintext, proxy verifies
        # the signature before enqueueing. The stored blob carries mode +
        # signature + nonce + timestamp so the recipient SDK can re-verify.
        # Legacy envelope mode stores the opaque ciphertext as-is.
        import json as _json

        if body.mode == "mtls-only":
            from cullis_sdk.crypto import verify_signature

            missing = [
                f for f in ("signature", "nonce", "timestamp")
                if getattr(body, f) is None
            ]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"mtls-only requires fields: {', '.join(missing)}",
                )
            if not agent.cert_pem:
                raise HTTPException(
                    status_code=400,
                    detail="sender has no cert — cannot verify mtls-only signature",
                )
            ok = verify_signature(
                agent.cert_pem,
                body.signature,
                body.session_id,
                agent.agent_id,
                body.nonce,
                body.timestamp,
                body.payload,
                client_seq=body.sender_seq,
            )
            if not ok:
                raise HTTPException(
                    status_code=401,
                    detail="mtls-only signature verification failed",
                )
            stored_blob = _json.dumps(
                {
                    "mode": "mtls-only",
                    "payload": body.payload,
                    "signature": body.signature,
                    "nonce": body.nonce,
                    "timestamp": body.timestamp,
                    "sender_seq": body.sender_seq,
                    "sender_cert_pem": agent.cert_pem,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            payload_cipher = stored_blob
        else:
            # Legacy envelope — ciphertext opaque.
            payload_cipher = _json.dumps(body.payload, separators=(",", ":"))

        try:
            msg_id, inserted = await local_queue.enqueue(
                session_id=body.session_id,
                sender_agent_id=agent.agent_id,
                recipient_agent_id=recipient,
                payload_ciphertext=payload_cipher,
                ttl_seconds=body.ttl_seconds,
                idempotency_key=body.idempotency_key,
            )
        except Exception as exc:
            logger.error("Local enqueue failed for %s: %s", agent.agent_id, exc)
            raise HTTPException(status_code=500, detail="enqueue_failed") from exc

        local_session.touch()
        await save_local_session(local_session)

        # Push-vs-queue: if the recipient is connected, deliver immediately.
        # Even when we push, the row stays pending until the recipient ack's
        # so a crash between send_json and ack does not drop the message.
        ws_manager = getattr(request.app.state, "local_ws_manager", None)
        pushed = False
        if ws_manager is not None and ws_manager.is_connected(recipient):
            push_frame = {
                "type": "new_message",
                "session_id": body.session_id,
                "msg_id": msg_id,
                "sender_agent_id": agent.agent_id,
                "payload": body.payload,
                "enqueued_at": datetime.now(timezone.utc).isoformat(),
                "mode": body.mode,
            }
            if body.mode == "mtls-only":
                push_frame["signature"] = body.signature
                push_frame["nonce"] = body.nonce
                push_frame["timestamp"] = body.timestamp
                push_frame["sender_seq"] = body.sender_seq
                push_frame["sender_cert_pem"] = agent.cert_pem
            pushed = await ws_manager.send_to_agent(recipient, push_frame)

        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send_local",
            status="success",
            detail=(
                f"session={body.session_id} recipient={recipient} "
                f"msg_id={msg_id} inserted={inserted} pushed={pushed}"
            ),
            request_id=request_id,
            duration_ms=duration_ms,
        )
        await append_local_audit(
            event_type="message_sent",
            agent_id=agent.agent_id,
            session_id=body.session_id,
            org_id=get_settings().org_id,
            details={
                "recipient": recipient,
                "msg_id": msg_id,
                "mode": body.mode,
                "duplicate": not inserted,
                "delivered_via": "ws" if pushed else "queue",
            },
        )
        return {
            "status": "sent",
            "session_id": body.session_id,
            "msg_id": msg_id,
            "delivered_via": "ws" if pushed else "queue",
            "duplicate": not inserted,
        }

    if body.mode == "mtls-only":
        # Cross-org through the broker cannot use mtls-only — broker is a
        # non-trusted hop and must only see ciphertext. Reject early so the
        # SDK caller surfaces a clear error instead of leaking plaintext.
        raise HTTPException(
            status_code=400,
            detail="mtls-only is intra-org only; use envelope for cross-org sessions",
        )

    bridge = _get_bridge(request)
    try:
        await bridge.send_message(
            agent.agent_id,
            body.session_id,
            body.payload,
            body.recipient_agent_id,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send",
            status="success",
            detail=f"session={body.session_id} recipient={body.recipient_agent_id}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return {"status": "sent", "session_id": body.session_id}

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_send",
            status="error",
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        if isinstance(exc, httpx.HTTPStatusError):
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=exc.response.text,
            ) from exc
        logger.error("Failed to send message for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.get("/messages/{session_id}")
async def poll_messages(
    session_id: str,
    request: Request,
    after: int = -1,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Poll for messages in a session (local or broker).

    Local path returns pending messages for the caller; the caller must
    still hit the ack endpoint before we flip them to `delivered`. That
    keeps at-least-once semantics even when clients prefer REST polling
    over the WebSocket push.
    """
    _validate_session_id(session_id)

    local_store = _get_local_store(request)
    local_session = local_store.get(session_id) if local_store else None
    if local_session is not None:
        if not local_session.involves(agent.agent_id):
            raise HTTPException(status_code=403, detail="not a participant")
        local_session.touch()
        await save_local_session(local_session)
        pending = await local_queue.fetch_pending_for_recipient(agent.agent_id)
        # Only messages that belong to this session — the queue is global
        # per recipient but the caller asked for a specific session.
        msgs = [m for m in pending if m.session_id == session_id]
        import json as _json
        payload = []
        for m in msgs:
            entry: dict = {
                "msg_id": m.msg_id,
                "session_id": m.session_id,
                "sender_agent_id": m.sender_agent_id,
                "enqueued_at": m.enqueued_at.isoformat() if m.enqueued_at else None,
            }
            # mtls-only blobs are self-describing — parse out the signed
            # plaintext + metadata so the recipient SDK can verify without
            # guessing at wire shape. Legacy ciphertext stays opaque.
            try:
                parsed = _json.loads(m.payload_ciphertext)
                if isinstance(parsed, dict) and parsed.get("mode") == "mtls-only":
                    entry["mode"] = "mtls-only"
                    entry["payload"] = parsed.get("payload")
                    entry["signature"] = parsed.get("signature")
                    entry["nonce"] = parsed.get("nonce")
                    entry["timestamp"] = parsed.get("timestamp")
                    entry["sender_seq"] = parsed.get("sender_seq")
                    entry["sender_cert_pem"] = parsed.get("sender_cert_pem")
                else:
                    entry["mode"] = "envelope"
                    entry["payload_ciphertext"] = m.payload_ciphertext
            except (ValueError, TypeError):
                entry["mode"] = "envelope"
                entry["payload_ciphertext"] = m.payload_ciphertext
            payload.append(entry)
        return {"messages": payload, "count": len(payload), "scope": "local"}

    bridge = _get_bridge(request)
    try:
        messages = await bridge.poll_messages(agent.agent_id, session_id, after)
        return {"messages": messages, "count": len(messages)}
    except Exception as exc:
        # Pass through broker HTTP status codes (e.g. 409 session closed)
        if isinstance(exc, httpx.HTTPStatusError):
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=exc.response.text,
            ) from exc
        logger.error("Failed to poll messages for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/sessions/{session_id}/messages/{msg_id}/ack")
async def ack_message(
    session_id: str,
    msg_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Acknowledge delivery of a queued local message (ADR-001 Phase 3c).

    Only applies to local sessions. Cross-org ack stays implicit via the
    broker's M3 ack endpoint. Returns 404 when the msg_id doesn't exist,
    is already delivered, or belongs to another recipient (same shape
    across all three to avoid enumeration).
    """
    _validate_session_id(session_id)
    local_store = _get_local_store(request)
    local_session = local_store.get(session_id) if local_store else None
    if local_session is None:
        raise HTTPException(status_code=404, detail="session_not_local")
    if not local_session.involves(agent.agent_id):
        raise HTTPException(status_code=403, detail="not a participant")

    ok = await local_queue.mark_delivered(msg_id, agent.agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="message_not_found")
    await log_audit(
        agent_id=agent.agent_id,
        action="egress_ack_local",
        status="success",
        detail=f"session={session_id} msg_id={msg_id}",
    )
    await append_local_audit(
        event_type="message_delivered",
        agent_id=agent.agent_id,
        session_id=session_id,
        org_id=get_settings().org_id,
        details={"msg_id": msg_id},
    )
    return {"status": "acked", "msg_id": msg_id}


@router.post("/resolve", response_model=ResolveResponse)
async def resolve_recipient(
    body: ResolveRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Resolve a recipient and tell the SDK how to send.

    ADR-001 §10: routing decision happens here, before the sender
    encrypts anything. Response tells the SDK which wire format to use
    (envelope vs mtls-only) and whether egress inspection is required.

    Invariants:
      - path == "intra-org" iff SPIFFE trust_domain and org both match local
        (or recipient uses internal `org::agent` form with matching org).
      - transport == "mtls-only" only when path is intra-org AND the proxy
        is configured with transport_intra_org != "envelope".
      - target_cert_pem is populated for intra-org mtls-only so the SDK
        can validate the peer certificate at mTLS handshake time.
    """
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    from mcp_proxy.spiffe import InvalidRecipient, parse_recipient

    settings = get_settings()

    try:
        trust_domain, target_org, target_agent = parse_recipient(body.recipient_id)
    except InvalidRecipient as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    route = decide_route(
        body.recipient_id,
        local_org=settings.org_id,
        local_trust_domain=settings.trust_domain,
    )

    target_spiffe: str | None = None
    if trust_domain is not None:
        target_spiffe = f"spiffe://{trust_domain}/{target_org}/{target_agent}"

    if route == "intra":
        intra_enabled = settings.intra_org_routing
        transport: Literal["envelope", "mtls-only"] = "envelope"
        if intra_enabled and settings.transport_intra_org in ("mtls-only", "hybrid"):
            transport = "mtls-only"

        target_cert_pem: str | None = None
        if transport == "mtls-only":
            # ``internal_agents.agent_id`` is ``<org>::<name>`` in
            # production (ADR-010 invariant) but legacy rows + some
            # test fixtures still use the bare ``<name>`` form. Try
            # full first, then bare — picking the first row via
            # ``ORDER BY`` so the full-form match wins when both
            # exist. 404 only if neither is found.
            full_agent_id = f"{target_org}::{target_agent}"
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT cert_pem, is_active FROM internal_agents "
                        "WHERE agent_id IN (:full_id, :bare_id) "
                        "ORDER BY CASE WHEN agent_id = :full_id "
                        "THEN 0 ELSE 1 END LIMIT 1"
                    ),
                    {"full_id": full_agent_id, "bare_id": target_agent},
                )
                row = result.mappings().first()
                if row is None or not row["is_active"]:
                    raise HTTPException(
                        status_code=404,
                        detail=f"intra-org target not found: {full_agent_id}",
                    )
                target_cert_pem = row["cert_pem"]

        return ResolveResponse(
            path="intra-org",
            target_agent_id=target_agent,
            target_org_id=target_org,
            target_spiffe=target_spiffe,
            transport=transport,
            egress_inspection=settings.egress_inspection_enabled,
            target_cert_pem=target_cert_pem,
        )

    # ADR-008 Phase 1 PR #3 — best-effort peer public key for envelope
    # encryption cross-org. If the broker uplink is present but the fetch
    # fails, fail the resolve (502) so the sender doesn't silently fall
    # back to plaintext. If no bridge is configured at all the proxy is
    # intra-only and callers that actually try to send will still get
    # the legacy behaviour at /v1/egress/send.
    target_cert_pem: str | None = None
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        broker_peer_id = f"{target_org}::{target_agent}"
        try:
            target_cert_pem = await bridge.get_peer_public_key(
                agent.agent_id, broker_peer_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"unable to resolve peer public key: {exc}",
            ) from exc

    return ResolveResponse(
        path="cross-org",
        target_agent_id=target_agent,
        target_org_id=target_org,
        target_spiffe=target_spiffe,
        transport="envelope",
        egress_inspection=settings.egress_inspection_enabled,
        target_cert_pem=target_cert_pem,
    )


@router.get(
    "/agents/{agent_id:path}/public-key",
    response_model=AgentPublicKeyResponse,
)
async def get_agent_public_key(
    agent_id: str,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Return the target agent's x509 certificate PEM.

    Companion endpoint to ``/v1/egress/resolve``: the SDK's
    ``decrypt_oneshot`` needs the sender's cert to verify envelope
    signatures, but device-code-enrolled Connectors don't hold a broker
    JWT and so can't call the Court's ``/v1/federation/agents/{id}/public-key``
    path. This endpoint exposes the same data behind the egress
    ``X-API-Key`` + DPoP auth profile every ``/v1/egress/*`` handler
    already uses.

    Routing follows ``/resolve``:
      - intra-org lookups hit ``internal_agents.cert_pem`` directly;
      - cross-org lookups delegate to ``broker_bridge.get_peer_public_key``
        (and fall back to ``cert_pem=None`` when the bridge is absent,
        mirroring ``/resolve``'s standalone behaviour).

    Rate-limit: inherited from ``get_agent_from_dpop_client_cert`` →
    ``get_agent_from_client_cert``, which enforces the shared
    ``rate_limit_per_minute`` (default 60/min/agent) against every
    ``/v1/egress/*`` call. No per-route override — keeping this aligned
    with ``/resolve`` + ``/peers`` means an enumeration-probing caller
    burns their global egress budget, not a separate one.

    Accepts both the canonical ``org::agent`` form and a SPIFFE URI;
    bare agent names are rejected (the caller knows its own org and
    should canonicalise before calling — keeps the server free of the
    ambiguity intra vs cross carries for bare handles).
    """
    from mcp_proxy.db import get_db
    from mcp_proxy.spiffe import InvalidRecipient, parse_recipient
    from sqlalchemy import text

    try:
        _, target_org, target_agent = parse_recipient(agent_id)
    except InvalidRecipient as exc:
        # Bare agent names (no ``::`` and not a SPIFFE URI) land here
        # too — ``parse_internal`` rejects them. The caller has to
        # canonicalise to ``org::agent`` since the server cannot
        # safely guess which org the caller meant.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    settings = get_settings()
    route = decide_route(
        agent_id,
        local_org=settings.org_id,
        local_trust_domain=settings.trust_domain,
    )

    if route == "intra":
        # ``internal_agents.agent_id`` is ``<org>::<name>`` in production
        # (ADR-010) but legacy rows + some test fixtures still use the
        # bare ``<name>`` form; match the double-lookup ``/resolve``
        # uses so both shapes resolve consistently.
        full_agent_id = f"{target_org}::{target_agent}"
        async with get_db() as conn:
            result = await conn.execute(
                text(
                    "SELECT cert_pem, is_active FROM internal_agents "
                    "WHERE agent_id IN (:full_id, :bare_id) "
                    "ORDER BY CASE WHEN agent_id = :full_id "
                    "THEN 0 ELSE 1 END LIMIT 1"
                ),
                {"full_id": full_agent_id, "bare_id": target_agent},
            )
            row = result.mappings().first()
        if row is None or not row["is_active"]:
            raise HTTPException(
                status_code=404,
                detail=f"intra-org agent not found: {full_agent_id}",
            )
        return AgentPublicKeyResponse(
            agent_id=full_agent_id,
            cert_pem=row["cert_pem"],
        )

    # Cross-org: mirror ``/resolve``'s contract — when no bridge is
    # configured (pure standalone proxy) return cert_pem=None rather
    # than 400, so callers that tolerate a missing cert (e.g. mtls-only
    # intra-only deploys) don't need to special-case the standalone
    # mode detection. When the bridge IS present but the fetch errors,
    # surface a 502 so the caller can retry.
    target_cert_pem: str | None = None
    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        broker_peer_id = f"{target_org}::{target_agent}"
        try:
            target_cert_pem = await bridge.get_peer_public_key(
                agent.agent_id, broker_peer_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"unable to resolve peer public key: {exc}",
            ) from exc

    return AgentPublicKeyResponse(
        agent_id=f"{target_org}::{target_agent}",
        cert_pem=target_cert_pem,
    )


@router.get("/peers", response_model=PeersResponse)
async def list_peers(
    request: Request,
    q: str | None = None,
    limit: int = 50,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> PeersResponse:
    """List peers the caller can address right now via /v1/egress/*.

    Powers the Connector's ``contact("name")`` UX without requiring a
    broker JWT (which device-code-enrolled agents don't hold) and
    without leaking the admin secret. Returns:
      - intra-org agents from ``internal_agents`` (always available)
      - cross-org agents from ``cached_federated_agents`` when federation
        is configured (the cache is empty in pure standalone deploys)

    ``q``: optional case-insensitive substring filter applied to
    ``agent_id`` and ``display_name``. Server-side filter is just a
    prefilter — the caller is expected to do the final ranking
    (e.g. difflib fuzzy match) since "best match" is UX-dependent.
    """
    settings = get_settings()
    local_org = settings.org_id or ""
    qnorm = (q or "").strip().lower()

    # Audit NEW #4 — reach gate mirrors ``check_reach`` used by session
    # open / send, but expressed as a filter rather than a deny: the
    # listing must NEVER surface peers the caller couldn't contact
    # anyway. Without this gate an ``intra``-only agent would receive a
    # ready-made cross-org target list the moment federation primes
    # the cache, which is a layering violation (defence-in-depth if the
    # send-path gate is ever weakened). Unknown reach values default to
    # ``both`` to match ``check_reach``'s permissive fallback.
    caller_reach = (getattr(agent, "reach", None) or "both").lower()
    if caller_reach not in {"intra", "cross", "both"}:
        caller_reach = "both"
    include_intra = caller_reach in {"intra", "both"}
    include_cross = caller_reach in {"cross", "both"}

    from sqlalchemy import text

    from mcp_proxy.db import get_db

    peers: list[PeerInfo] = []

    async with get_db() as conn:
        # Intra-org from the authoritative local registry. Self-row
        # excluded so the caller never sees themselves in their own
        # contact list (the DB stores both bare and ``org::name`` rows
        # historically; check both forms). Skipped entirely when the
        # caller's reach forbids intra-org traffic — the SELECT does
        # not run, so the filter is enforced at the SQL layer (no
        # post-hoc Python strip that could regress silently if
        # refactored).
        if include_intra:
            bare = agent.agent_id.split("::", 1)[-1]
            result = await conn.execute(
                text(
                    """
                    SELECT agent_id, display_name, capabilities, is_active
                      FROM internal_agents
                     WHERE is_active = 1
                       AND agent_id NOT IN (:full, :bare)
                     ORDER BY display_name, agent_id
                    """
                ),
                {"full": agent.agent_id, "bare": bare},
            )
            for row in result.mappings():
                aid_full = (
                    row["agent_id"]
                    if "::" in row["agent_id"]
                    else f"{local_org}::{row['agent_id']}"
                )
                display = row["display_name"] or row["agent_id"]
                if qnorm and qnorm not in aid_full.lower() and qnorm not in display.lower():
                    continue
                peers.append(PeerInfo(
                    agent_id=aid_full,
                    org_id=local_org,
                    display_name=display,
                    capabilities=json.loads(row["capabilities"] or "[]"),
                    status="active",
                    scope="intra-org",
                ))

        # Cross-org cached snapshots, if federation has primed the cache.
        # The table is missing in older standalone deploys — tolerate
        # that and skip silently. Skipped entirely when the caller's
        # reach forbids cross-org traffic (same SQL-level rationale as
        # the intra-org branch above).
        if include_cross:
            try:
                result = await conn.execute(
                    text(
                        """
                        SELECT agent_id, org_id, display_name, capabilities
                          FROM cached_federated_agents
                         WHERE revoked = 0
                           AND org_id != :local_org
                         ORDER BY org_id, display_name
                        """
                    ),
                    {"local_org": local_org},
                )
                for row in result.mappings():
                    aid = row["agent_id"]
                    display = row["display_name"] or aid
                    if qnorm and qnorm not in aid.lower() and qnorm not in display.lower():
                        continue
                    peers.append(PeerInfo(
                        agent_id=aid,
                        org_id=row["org_id"],
                        display_name=display,
                        capabilities=json.loads(row["capabilities"] or "[]"),
                        scope="cross-org",
                    ))
            except Exception as exc:  # noqa: BLE001
                logger.debug("federated cache unreadable, skipping: %s", exc)

    if limit and len(peers) > limit:
        peers = peers[:limit]

    # Audit trail (security audit NEW #6): peer enumeration is a
    # reconnaissance primitive — the Connector now hits this endpoint
    # instead of /v1/federation/agents/search (which does audit), so
    # without an entry here we'd lose the "who listed whom and with
    # what filter" signal that compliance reviewers expect. Matches
    # the detail shape of egress_discover below for consistency.
    try:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_peers_list",
            status="success",
            detail=f"q={q} limit={limit} results={len(peers)}",
        )
    except Exception as audit_exc:  # noqa: BLE001
        # Never let an audit-write failure break the read path — log
        # it and continue. Alembic / schema issues should surface in
        # their own telemetry, not in the user's peer list.
        logger.warning("egress_peers_list audit write failed: %s", audit_exc)

    return PeersResponse(peers=peers, count=len(peers))


@router.post("/discover")
async def discover_agents(
    body: DiscoverRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Discover remote agents on the network."""
    bridge = _get_bridge(request)
    try:
        agents = await bridge.discover_agents(
            agent.agent_id,
            capabilities=body.capabilities,
            q=body.q,
        )

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_discover",
            status="success",
            detail=f"capabilities={body.capabilities} q={body.q} results={len(agents)}",
        )

        return {"agents": agents, "count": len(agents)}

    except Exception as exc:
        logger.error("Failed to discover agents for %s: %s", agent.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc


@router.post("/tools/invoke")
async def invoke_remote_tool(
    body: InvokeToolRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    """Invoke a tool on a remote org via an active broker session.

    Sends a structured MCP tool_call message through the session.
    The remote agent receives the tool_call and should respond with
    a tool_result message in the same session.
    """
    bridge = _get_bridge(request)
    request_id = str(uuid.uuid4())
    t0 = time.monotonic()

    # Build MCP-format tool_call payload
    mcp_payload = {
        "type": "tool_call",
        "tool": body.tool_name,
        "parameters": body.parameters,
        "request_id": request_id,
    }

    try:
        # We need to know the recipient — infer from the session's target
        # For now, send to all participants in the session. The caller should
        # ensure the session is 1:1 with the target agent.
        sessions = await bridge.list_sessions(agent.agent_id)
        target_session = None
        for s in sessions:
            sid = s.get("session_id") or s.get("id")
            if sid == body.session_id:
                target_session = s
                break

        if target_session is None:
            raise HTTPException(
                status_code=404,
                detail=f"Session {body.session_id} not found for agent {agent.agent_id}",
            )

        # Determine recipient from session metadata
        recipient = (
            target_session.get("target_agent_id")
            or target_session.get("initiator_agent_id")
            or target_session.get("peer_agent_id", "")
        )
        # If agent is the initiator, send to target; if target, send to initiator
        initiator = target_session.get("initiator_agent_id", "")
        target = target_session.get("target_agent_id", "")
        if initiator == agent.agent_id:
            recipient = target
        elif target == agent.agent_id:
            recipient = initiator

        if not recipient:
            raise HTTPException(
                status_code=400,
                detail="Cannot determine recipient from session metadata",
            )

        await bridge.send_message(
            agent.agent_id,
            body.session_id,
            mcp_payload,
            recipient,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        await log_audit(
            agent_id=agent.agent_id,
            action="egress_tool_invoke",
            status="success",
            tool_name=body.tool_name,
            detail=f"session={body.session_id} recipient={recipient}",
            request_id=request_id,
            duration_ms=duration_ms,
        )

        return {
            "status": "sent",
            "request_id": request_id,
            "session_id": body.session_id,
            "tool": body.tool_name,
            "recipient": recipient,
        }

    except HTTPException:
        raise
    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_tool_invoke",
            status="error",
            tool_name=body.tool_name,
            detail=str(exc)[:500],
            request_id=request_id,
            duration_ms=duration_ms,
        )
        logger.error(
            "Failed to invoke tool %s for %s: %s", body.tool_name, agent.agent_id, exc,
        )
        raise HTTPException(status_code=502, detail=f"Broker error: {exc}") from exc
