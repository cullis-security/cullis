"""FastAPI router for the Connector enrollment API.

Two audiences share this router:

* **Connector-side** (unauthenticated, keyed by an unguessable session_id):
  - ``POST /v1/enrollment/start`` — start a pending request
  - ``GET  /v1/enrollment/{session_id}/status`` — poll for decision

* **Admin dashboard** (requires dashboard session + CSRF header):
  - ``GET  /v1/admin/enrollments`` — list pending
  - ``POST /v1/admin/enrollments/{session_id}/approve`` — approve
  - ``POST /v1/admin/enrollments/{session_id}/reject`` — reject

Identity on the Connector side is self-declared; the admin is the authority
that decides what gets through. OIDC + SCIM layer on top later without
changing this surface.
"""
from __future__ import annotations

import hmac
import json
import logging

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
)
from mcp_proxy.db import get_db
from mcp_proxy.enrollment import service
from mcp_proxy.enrollment.schemas import (
    EnrollmentApproveRequest,
    EnrollmentRejectRequest,
    EnrollmentStartRequest,
    EnrollmentStartResponse,
    EnrollmentStatusResponse,
    PendingEnrollmentSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["enrollment"])

# Per-IP budgets for the anonymous device-code endpoints. Audit 2026-04-30
# C2 — these were unauthenticated and unrate-limited, letting any caller
# flood the pending_enrollments table or enumerate /status timing.
# ``start`` matches the broker ``onboarding.join`` cadence (5 per 5 min);
# ``status`` allows ~1/sec polling, slightly above ``service.POLL_INTERVAL_S``.
_ENROLLMENT_START_PER_MINUTE = 5
_ENROLLMENT_STATUS_PER_MINUTE = 60


def _client_ip(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


# ── Helpers ──────────────────────────────────────────────────────────────


def _require_logged_in(request: Request) -> ProxyDashboardSession:
    """Variant of ``require_login`` that raises HTTP 401 for JSON endpoints
    instead of redirecting. The dashboard's existing HTML views continue to
    use ``require_login`` (which redirects to ``/proxy/login``); our JSON
    admin API shouldn't 303 an XHR."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        raise HTTPException(status_code=401, detail="Authentication required")
    return session


def _verify_csrf_header(request: Request, session: ProxyDashboardSession) -> None:
    """Check ``X-CSRF-Token`` header against the token bound to the session
    cookie. Raises HTTP 403 on mismatch. Used for JSON mutations — the
    form-based flow keeps using ``verify_csrf`` from the session module."""
    token = request.headers.get("X-CSRF-Token", "")
    if not session.csrf_token or not token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not hmac.compare_digest(token, session.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


def _require_agent_manager(request: Request):
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None:
        raise HTTPException(
            status_code=503,
            detail="agent_manager not initialized (complete broker setup first)",
        )
    return mgr


# ── Connector-facing (unauthenticated, keyed by session_id) ──────────────


@router.post(
    "/v1/enrollment/start",
    response_model=EnrollmentStartResponse,
    status_code=201,
)
async def start_enrollment(
    payload: EnrollmentStartRequest,
    request: Request,
) -> EnrollmentStartResponse:
    client_ip = _client_ip(request)
    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}:enroll.start", _ENROLLMENT_START_PER_MINUTE,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="enrollment rate limit exceeded",
        )

    try:
        async with get_db() as conn:
            started = await service.start_enrollment(
                conn,
                pubkey_pem=payload.pubkey_pem,
                requester_name=payload.requester_name,
                requester_email=payload.requester_email,
                reason=payload.reason,
                device_info=payload.device_info,
                dpop_jwk=payload.dpop_jwk,
            )
    except service.EnrollmentError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc

    base = str(request.base_url).rstrip("/")
    logger.info(
        "enrollment_started",
        extra={
            "session_id": started.session_id,
            "requester_email": payload.requester_email,
        },
    )
    return EnrollmentStartResponse(
        session_id=started.session_id,
        status="pending",
        poll_url=f"{base}/v1/enrollment/{started.session_id}/status",
        enroll_url=f"{base}/enroll?session={started.session_id}",
        poll_interval_s=service.POLL_INTERVAL_S,
        expires_at=started.expires_at.isoformat(timespec="seconds"),
    )


_ENROLLMENT_STATUS_PROOF_HEADER = "X-Enrollment-Proof"
_ENROLLMENT_STATUS_PROOF_DOMAIN = "enrollment-status:v1"


def _verify_enrollment_proof(
    pubkey_pem: str, session_id: str, signature_b64: str,
) -> bool:
    """M-onb-1 audit fix — proof of possession over the original
    enrolment keypair.

    The Connector signs ``"enrollment-status:v1|{session_id}"`` with
    the same private key whose public half it submitted at
    ``POST /v1/enrollment/start``. The server, holding the public
    key on the row, can verify without storing or trusting any
    fresh credential. Without a valid proof the status endpoint
    returns ONLY ``status`` + ``session_id`` so an attacker who
    guesses or steals a session_id cannot exfiltrate the issued
    cert / agent_id / capabilities of an approved enrolment.
    """
    import base64 as _b64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    try:
        sig = _b64.urlsafe_b64decode(
            signature_b64 + "=" * (-len(signature_b64) % 4),
        )
    except Exception:
        return False
    try:
        pub_key = serialization.load_pem_public_key(pubkey_pem.encode())
    except Exception:
        return False
    canonical = (
        f"{_ENROLLMENT_STATUS_PROOF_DOMAIN}|{session_id}".encode("utf-8")
    )
    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                sig, canonical,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


@router.get(
    "/v1/enrollment/{session_id}/status",
    response_model=EnrollmentStatusResponse,
)
async def enrollment_status(
    session_id: str,
    request: Request,
) -> EnrollmentStatusResponse:
    client_ip = _client_ip(request)
    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}:enroll.status", _ENROLLMENT_STATUS_PER_MINUTE,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="enrollment status rate limit exceeded",
        )

    try:
        async with get_db() as conn:
            record = await service.get_record(conn, session_id)
    except service.EnrollmentError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc

    response = EnrollmentStatusResponse(
        session_id=record["session_id"],
        status=record["status"],  # type: ignore[arg-type]
    )

    # M-onb-1 audit fix — gate the sensitive fields (cert_pem, agent_id,
    # capabilities) behind a proof-of-possession over the keypair the
    # Connector registered at start_enrollment. The endpoint stays
    # callable without proof so the Connector can poll the status
    # field cheaply, but only the legitimate enroller (who holds the
    # private key) can pull the issued cert.
    proof_header = request.headers.get(_ENROLLMENT_STATUS_PROOF_HEADER, "")
    enroller_pubkey = record.get("pubkey_pem") or ""
    has_valid_proof = bool(
        proof_header
        and enroller_pubkey
        and _verify_enrollment_proof(
            enroller_pubkey, session_id, proof_header,
        )
    )

    if record["status"] == "approved" and has_valid_proof:
        response.agent_id = record["agent_id_assigned"]
        response.cert_pem = record["cert_pem"]
        caps_raw = record.get("capabilities_assigned") or "[]"
        try:
            response.capabilities = json.loads(caps_raw)
        except json.JSONDecodeError:
            response.capabilities = []
    elif record["status"] == "rejected" and has_valid_proof:
        response.rejection_reason = record["rejection_reason"]
    return response


# ── Admin-facing (dashboard session required + CSRF) ─────────────────────


@router.get(
    "/v1/admin/enrollments",
    response_model=list[PendingEnrollmentSummary],
)
async def admin_list_pending(request: Request) -> list[PendingEnrollmentSummary]:
    _require_logged_in(request)
    async with get_db() as conn:
        rows = await service.list_pending(conn)
    return [
        PendingEnrollmentSummary(
            session_id=r["session_id"],
            requester_name=r["requester_name"],
            requester_email=r["requester_email"],
            reason=r.get("reason"),
            device_info=r.get("device_info"),
            pubkey_fingerprint=r["pubkey_fingerprint"],
            created_at=r["created_at"],
            expires_at=r["expires_at"],
        )
        for r in rows
    ]


@router.post("/v1/admin/enrollments/{session_id}/approve")
async def admin_approve(
    session_id: str,
    payload: EnrollmentApproveRequest,
    request: Request,
) -> dict[str, str]:
    session = _require_logged_in(request)
    _verify_csrf_header(request, session)
    agent_manager = _require_agent_manager(request)

    try:
        async with get_db() as conn:
            record = await service.approve(
                conn,
                session_id=session_id,
                agent_id=payload.agent_id,
                capabilities=payload.capabilities,
                groups=payload.groups,
                admin_name=session.role or "admin",
                agent_manager=agent_manager,
            )
    except service.EnrollmentError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc

    logger.info(
        "enrollment_approved",
        extra={
            "session_id": session_id,
            "agent_id": record["agent_id_assigned"],
            "admin": session.role,
        },
    )
    return {"status": "approved", "agent_id": record["agent_id_assigned"] or ""}


@router.post("/v1/admin/enrollments/{session_id}/reject")
async def admin_reject(
    session_id: str,
    payload: EnrollmentRejectRequest,
    request: Request,
) -> dict[str, str]:
    session = _require_logged_in(request)
    _verify_csrf_header(request, session)

    try:
        async with get_db() as conn:
            await service.reject(
                conn,
                session_id=session_id,
                reason=payload.reason,
                admin_name=session.role or "admin",
            )
    except service.EnrollmentError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc

    logger.info(
        "enrollment_rejected",
        extra={"session_id": session_id, "admin": session.role},
    )
    return {"status": "rejected"}
