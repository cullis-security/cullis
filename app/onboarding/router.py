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

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.auth.revocation import revoke_cert, list_revoked_certs
from app.registry.org_store import (
    get_org_by_id,
    register_org,
    update_org_ca_cert,
    update_org_webhook,
    list_pending_orgs,
    set_org_status,
)

onboarding_router = APIRouter(prefix="/onboarding", tags=["onboarding"])
admin_router      = APIRouter(prefix="/admin",      tags=["admin"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def _require_admin(x_admin_secret: str = Header(...)) -> None:
    if x_admin_secret != get_settings().admin_secret:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid admin secret")


# ── Models ────────────────────────────────────────────────────────────────────

class JoinRequest(BaseModel):
    org_id: str
    display_name: str
    secret: str                    # org secret — used later for binding approval
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
    db: AsyncSession = Depends(get_db),
):
    """
    Access request to the network from an external organization.
    The org is created in 'pending' state until admin approval.
    """
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
    Revoca un certificato agente. Da quel momento in poi qualsiasi tentativo
    di autenticazione con quel certificato restituisce 401.
    """
    # Se cert_not_after non è fornito usiamo un default conservativo (now)
    # in modo che la lazy cleanup non lo rimuova subito
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
    """Elenca i certificati revocati, opzionalmente filtrati per org."""
    records = await list_revoked_certs(db, org_id=org_id)
    return [RevokedCertView.model_validate(r) for r in records]
