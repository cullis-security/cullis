import hmac
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.registry.org_store import (
    get_org_by_id,
    list_orgs,
    register_org,
    update_org_ca_cert,
    verify_org_credentials,
)

router = APIRouter(prefix="/registry", tags=["registry"])


def _require_admin(x_admin_secret: str = Header(...)) -> None:
    """Validate admin secret with timing-safe comparison."""
    if not hmac.compare_digest(x_admin_secret, get_settings().admin_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid admin secret")


class OrgRegisterRequest(BaseModel):
    org_id: str = Field(..., max_length=128)
    display_name: str = Field(..., max_length=256)
    secret: str
    metadata: dict = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def limit_metadata_size(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 16384:
            raise ValueError("metadata exceeds 16 KB limit")
        return v


class OrgResponse(BaseModel):
    org_id: str
    display_name: str
    status: str
    registered_at: datetime

    model_config = {"from_attributes": True}


@router.post("/orgs", response_model=OrgResponse, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(_require_admin)])
async def register_organization(
    body: OrgRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new organization in the network. Requires admin secret."""
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


@router.get("/orgs", response_model=list[OrgResponse],
            dependencies=[Depends(_require_admin)])
async def list_organizations(db: AsyncSession = Depends(get_db)):
    """List active organizations. Requires admin secret."""
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


@router.get("/orgs/me", response_model=OrgResponse)
async def get_own_organization(
    x_org_id: str = Header(...),
    x_org_secret: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Organization self-status check. Uses org credentials, not admin secret.
    Returns org info including status (pending/active/rejected).
    Used by MCP Proxy to poll for approval status.

    Audit F-B-6: auth failures collapse to a single 403 whether the org
    is missing or the secret is wrong, and bcrypt runs on both paths so
    the two cases are indistinguishable by timing. Non-active orgs are
    still allowed to authenticate here (and only here) so they can poll
    their own lifecycle — ``active_only=False``.
    """
    org = await get_org_by_id(db, x_org_id)
    if not verify_org_credentials(org, x_org_secret, active_only=False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid organization credentials",
        )
    return OrgResponse(
        org_id=org.org_id,
        display_name=org.display_name,
        status=org.status,
        registered_at=org.registered_at,
    )


@router.get("/orgs/{org_id}", response_model=OrgResponse,
            dependencies=[Depends(_require_admin)])
async def get_organization(org_id: str, db: AsyncSession = Depends(get_db)):
    """Organization detail. Requires admin secret."""
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
    """Upload the organization's CA certificate. Requires x-org-id and x-org-secret.

    Audit F-B-7: auth failures collapse to a single 403 whether the org
    is missing, inactive, or the secret is wrong, and bcrypt runs on
    every path via ``verify_org_credentials``. Previously the endpoint
    returned 404 on miss and 401 on wrong secret, differentiating the
    two cases by status code and by latency (no bcrypt on miss).
    """
    if x_org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="org_id mismatch")

    org = await get_org_by_id(db, org_id)
    if not verify_org_credentials(org, x_org_secret, active_only=True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid organization credentials",
        )

    # Validate the CA certificate before accepting it
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_types
    try:
        ca_cert = crypto_x509.load_pem_x509_certificate(body.ca_certificate.encode())
        bc = ca_cert.extensions.get_extension_for_class(crypto_x509.BasicConstraints).value
        if not bc.ca:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="Certificate is not a CA (BasicConstraints CA=false)")
        pub_key = ca_cert.public_key()
        if isinstance(pub_key, rsa_types.RSAPublicKey) and pub_key.key_size < 2048:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"CA RSA key too small ({pub_key.key_size} bits) — minimum 2048")
        now_utc = datetime.now()
        try:
            not_after = ca_cert.not_valid_after_utc
            not_before = ca_cert.not_valid_before_utc
        except AttributeError:
            import datetime as _dt
            not_after = ca_cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
            not_before = ca_cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
        import datetime as _dt
        now_utc = _dt.datetime.now(_dt.timezone.utc)
        if now_utc > not_after or now_utc < not_before:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="CA certificate is expired or not yet valid")
    except HTTPException:
        raise
    except Exception as exc:
        # Audit H-IO-2 — cryptography parse-error strings can echo
        # ASN.1/DER internals; log for ops, return a generic 400.
        logging.getLogger("agent_trust").warning(
            "org_router: invalid CA certificate: %s", exc,
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Invalid CA certificate")

    # If replacing an existing CA, invalidate all agent cert thumbprints for this org
    # so they must re-authenticate with certs signed by the new CA
    if org.ca_certificate:
        from app.registry.store import list_agents, invalidate_agent_tokens
        agents = await list_agents(db, org_id=org_id)
        for agent in agents:
            agent.cert_thumbprint = None
            agent.cert_pem = None
            await invalidate_agent_tokens(db, agent.agent_id)

    updated = await update_org_ca_cert(db, org_id, body.ca_certificate)
    return {"org_id": updated.org_id, "ca_certificate_loaded": True}
