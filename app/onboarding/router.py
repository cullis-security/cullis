"""
Onboarding — join request and admin approval.

Flow:
  1. External company calls POST /onboarding/join
     → org created in "pending" state, CA already included
  2. Admin views requests at GET /admin/orgs/pending
  3. Admin approves with POST /admin/orgs/{org_id}/approve
     or rejects with POST /admin/orgs/{org_id}/reject
  4. Approved org → agents can authenticate
"""
from datetime import datetime, timezone, timedelta

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_types
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.auth.revocation import revoke_cert, list_revoked_certs
from app.registry.org_store import (
    get_org_by_id,
    register_org,
    update_org_ca_cert,
    list_pending_orgs,
    set_org_status,
)
from app.rate_limit.limiter import get_client_ip, rate_limiter

onboarding_router = APIRouter(prefix="/onboarding", tags=["onboarding"])
admin_router      = APIRouter(prefix="/admin",      tags=["admin"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def _require_admin(x_admin_secret: str = Header(...)) -> None:
    import hmac
    if not hmac.compare_digest(x_admin_secret, get_settings().admin_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid admin secret")


# ── Models ────────────────────────────────────────────────────────────────────

class JoinRequest(BaseModel):
    org_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    display_name: str = Field(..., max_length=256)
    secret: str = Field(..., max_length=256)   # org secret — used later for binding approval
    ca_certificate: str            # PEM of the organization's CA
    contact_email: str = ""        # informational for the admin
    webhook_url: str | None = None # PDP webhook URL — None means default-deny


class JoinResponse(BaseModel):
    org_id: str
    status: str
    message: str


class RevokeCertRequest(BaseModel):
    serial_hex: str
    org_id: str
    reason: str | None = None
    revoked_by: str = "admin"
    cert_not_after: datetime | None = None   # opzionale — se omesso usa now+1d (safe default)
    agent_id: str | None = None


class RevokeCertResponse(BaseModel):
    serial_hex: str
    org_id: str
    revoked_at: datetime
    agent_id: str | None
    reason: str | None
    message: str


class RevokedCertView(BaseModel):
    serial_hex: str
    org_id: str
    revoked_at: datetime
    revoked_by: str
    reason: str | None
    agent_id: str | None

    model_config = {"from_attributes": True}


class OrgAdminView(BaseModel):
    org_id: str
    display_name: str
    status: str
    contact_email: str
    registered_at: datetime

    model_config = {"from_attributes": True}


# ── Onboarding ────────────────────────────────────────────────────────────────

@onboarding_router.post("/join", response_model=JoinResponse,
                        status_code=status.HTTP_202_ACCEPTED)
async def join_network(
    body: JoinRequest,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Access request to the network from an external organization.
    The org is created in 'pending' state until admin approval.
    """
    # Rate limit by client IP to prevent registration flood
    client_ip = get_client_ip(request)
    await rate_limiter.check(client_ip, "onboarding.join")

    existing = await get_org_by_id(db, body.org_id)
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail="org_id already registered")

    org = await register_org(
        db,
        org_id=body.org_id,
        display_name=body.display_name,
        secret=body.secret,
        metadata={"contact_email": body.contact_email},
        webhook_url=body.webhook_url,
    )
    # Validate CA certificate before storing
    try:
        ca_cert = crypto_x509.load_pem_x509_certificate(body.ca_certificate.encode())
        bc = ca_cert.extensions.get_extension_for_class(crypto_x509.BasicConstraints).value
        if not bc.ca:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="Submitted certificate is not a CA (BasicConstraints CA=false)")
        # Enforce minimum key size
        pub_key = ca_cert.public_key()
        if isinstance(pub_key, rsa_types.RSAPublicKey) and pub_key.key_size < 2048:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"CA RSA key too small ({pub_key.key_size} bits) — minimum 2048 required")
        # Check temporal validity
        now = datetime.now(timezone.utc)
        try:
            not_after = ca_cert.not_valid_after_utc
            not_before = ca_cert.not_valid_before_utc
        except AttributeError:
            not_after = ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = ca_cert.not_valid_before.replace(tzinfo=timezone.utc)
        if now > not_after or now < not_before:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="CA certificate is expired or not yet valid")
    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger("agent_trust").warning("Invalid CA certificate from org '%s': %s", body.org_id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Invalid CA certificate: could not parse or validate the submitted PEM")

    # Set pending status and load the CA immediately
    await set_org_status(db, body.org_id, "pending")
    await update_org_ca_cert(db, body.org_id, body.ca_certificate)

    await log_event(db, "onboarding.join_request", "ok",
                    org_id=body.org_id,
                    details={"display_name": body.display_name,
                             "contact_email": body.contact_email})

    return JoinResponse(
        org_id=org.org_id,
        status="pending",
        message="Request received. Awaiting approval from TrustLink.",
    )


# ── Admin ─────────────────────────────────────────────────────────────────────

@admin_router.get("/orgs/pending", response_model=list[OrgAdminView],
                  dependencies=[Depends(_require_admin)])
async def list_pending(db: AsyncSession = Depends(get_db)):
    """List organizations awaiting approval."""
    orgs = await list_pending_orgs(db)
    return [
        OrgAdminView(
            org_id=o.org_id,
            display_name=o.display_name,
            status=o.status,
            contact_email=o.extra.get("contact_email", ""),
            registered_at=o.registered_at,
        )
        for o in orgs
    ]


@admin_router.post("/orgs/{org_id}/approve",
                   dependencies=[Depends(_require_admin)])
async def approve_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Approve an organization — becomes active and can authenticate."""
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.status == "active":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Organization already active")

    await set_org_status(db, org_id, "active")
    await log_event(db, "onboarding.approved", "ok", org_id=org_id)

    return {"org_id": org_id, "status": "active",
            "message": f"Organization '{org_id}' approved."}


@admin_router.post("/orgs/{org_id}/reject",
                   dependencies=[Depends(_require_admin)])
async def reject_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reject a join request — org transitions to 'rejected' state."""
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.status not in ("pending", "active"):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail=f"Organization already in state '{org.status}'")

    await set_org_status(db, org_id, "rejected")
    await log_event(db, "onboarding.rejected", "denied", org_id=org_id)

    return {"org_id": org_id, "status": "rejected",
            "message": f"Organization '{org_id}' rejected."}


@admin_router.post("/certs/revoke", response_model=RevokeCertResponse,
                   dependencies=[Depends(_require_admin)])
async def revoke_certificate(
    body: RevokeCertRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke an agent certificate. From this point on, any authentication
    attempt with this certificate returns 401.
    """
    # If cert_not_after is not provided, use a conservative default (now + 1y)
    # so that lazy cleanup does not remove it immediately
    cert_not_after = body.cert_not_after or (datetime.now(timezone.utc) + timedelta(days=365))

    record = await revoke_cert(
        db,
        serial_hex=body.serial_hex,
        org_id=body.org_id,
        cert_not_after=cert_not_after,
        revoked_by=body.revoked_by,
        agent_id=body.agent_id,
        reason=body.reason,
    )

    await log_event(db, "cert.revoked", "ok",
                    org_id=body.org_id,
                    agent_id=body.agent_id,
                    details={
                        "serial_hex": body.serial_hex,
                        "reason": body.reason,
                        "revoked_by": body.revoked_by,
                    })

    return RevokeCertResponse(
        serial_hex=record.serial_hex,
        org_id=record.org_id,
        revoked_at=record.revoked_at,
        agent_id=record.agent_id,
        reason=record.reason,
        message=f"Certificate {body.serial_hex} revoked.",
    )


@admin_router.get("/certs/revoked", response_model=list[RevokedCertView],
                  dependencies=[Depends(_require_admin)])
async def get_revoked_certs(
    org_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List revoked certificates, optionally filtered by org."""
    records = await list_revoked_certs(db, org_id=org_id)
    return [RevokedCertView.model_validate(r) for r in records]


# ── Audit Log Export ─────────────────────────────────────────────────────────

@admin_router.get("/audit/export",
                  dependencies=[Depends(_require_admin)])
async def export_audit_logs(
    db: AsyncSession = Depends(get_db),
    start: datetime | None = None,
    end: datetime | None = None,
    org_id: str | None = None,
    event_type: str | None = None,
    format: str = "json",
    limit: int = 10000,
):
    """Export audit logs as JSON (NDJSON) or CSV. Admin-only."""
    import csv
    import io
    import json as json_mod
    from fastapi.responses import StreamingResponse
    from app.db.audit import query_audit_logs

    entries = await query_audit_logs(
        db, start=start, end=end, org_id=org_id,
        event_type=event_type, limit=limit,
    )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "timestamp", "event_type", "agent_id", "session_id",
            "org_id", "result", "details", "entry_hash", "previous_hash",
        ])
        for e in entries:
            writer.writerow([
                e.id,
                e.timestamp.isoformat() if e.timestamp else "",
                e.event_type, e.agent_id or "", e.session_id or "",
                e.org_id or "", e.result, e.details or "",
                e.entry_hash or "", e.previous_hash or "",
            ])
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
        )

    # Default: NDJSON (newline-delimited JSON)
    def _generate():
        for e in entries:
            yield json_mod.dumps({
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "agent_id": e.agent_id,
                "session_id": e.session_id,
                "org_id": e.org_id,
                "result": e.result,
                "details": e.details,
                "entry_hash": e.entry_hash,
                "previous_hash": e.previous_hash,
            }) + "\n"

    return StreamingResponse(
        _generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=audit_export.ndjson"},
    )
