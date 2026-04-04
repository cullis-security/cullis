from datetime import datetime
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.registry.org_store import register_org, get_org_by_id, list_orgs, update_org_ca_cert

router = APIRouter(prefix="/registry", tags=["registry"])


class OrgRegisterRequest(BaseModel):
    org_id: str
    display_name: str
    secret: str
    metadata: dict = {}


class OrgResponse(BaseModel):
    org_id: str
    display_name: str
    status: str
    registered_at: datetime

    model_config = {"from_attributes": True}


@router.post("/orgs", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def register_organization(
    body: OrgRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new organization in the network."""
    existing = await get_org_by_id(db, body.org_id)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="org_id already registered")

    org = await register_org(db, body.org_id, body.display_name, body.secret, body.metadata)
    return OrgResponse(
        org_id=org.org_id,
        display_name=org.display_name,
        status=org.status,
        registered_at=org.registered_at,
    )


@router.get("/orgs", response_model=list[OrgResponse])
async def list_organizations(db: AsyncSession = Depends(get_db)):
    """List active organizations."""
    orgs = await list_orgs(db)
    return [
        OrgResponse(
            org_id=o.org_id,
            display_name=o.display_name,
            status=o.status,
            registered_at=o.registered_at,
        )
        for o in orgs
    ]


@router.get("/orgs/{org_id}", response_model=OrgResponse)
async def get_organization(org_id: str, db: AsyncSession = Depends(get_db)):
    """Organization detail."""
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return OrgResponse(
        org_id=org.org_id,
        display_name=org.display_name,
        status=org.status,
        registered_at=org.registered_at,
    )


class CertUploadRequest(BaseModel):
    ca_certificate: str  # PEM-encoded CA cert


@router.post("/orgs/{org_id}/certificate", status_code=status.HTTP_200_OK)
async def upload_org_ca_certificate(
    org_id: str,
    body: CertUploadRequest,
    db: AsyncSession = Depends(get_db),
    x_org_id: str = Header(...),
    x_org_secret: str = Header(...),
):
    """Upload the organization's CA certificate. Requires x-org-id and x-org-secret."""
    if x_org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="org_id mismatch")

    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if not org.verify_secret(x_org_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid org credentials")

    updated = await update_org_ca_cert(db, org_id, body.ca_certificate)
    return {"org_id": updated.org_id, "ca_certificate_loaded": True}
