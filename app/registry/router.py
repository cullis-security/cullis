import datetime

from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.models import (
    AgentRegisterRequest, AgentResponse, AgentListResponse,
    AgentPublicKeyResponse, RotateCertRequest, RotateCertResponse,
)
from app.registry.store import (
    register_agent, get_agent_by_id, list_agents,
    search_agents_by_capabilities, rotate_agent_cert,
)
from app.registry.org_store import get_org_by_id, verify_org_credentials
from app.spiffe import internal_id_to_spiffe

router = APIRouter(prefix="/registry", tags=["registry"])

import logging
_log = logging.getLogger("agent_trust")


@router.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: AgentRegisterRequest,
    x_org_id: Annotated[str, Header()],
    x_org_secret: Annotated[str, Header()],
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new agent in the network.
    Requires valid organization credentials (X-Org-Id + X-Org-Secret headers).
    """
    org = await get_org_by_id(db, x_org_id)
    if not verify_org_credentials(org, x_org_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Invalid organization credentials")
    if body.org_id != x_org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="org_id in body does not match authenticated organization")

    existing = await get_agent_by_id(db, body.agent_id)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent_id already registered")

    agent = await register_agent(
        db,
        agent_id=body.agent_id,
        org_id=body.org_id,
        display_name=body.display_name,
        capabilities=body.capabilities,
        metadata=body.metadata,
        secret=body.secret,
    )

    await log_event(db, "registry.agent_registered", "ok",
                    agent_id=agent.agent_id, org_id=agent.org_id,
                    details={"capabilities": body.capabilities})

    trust_domain = get_settings().trust_domain
    return AgentResponse(
        agent_id=agent.agent_id,
        org_id=agent.org_id,
        display_name=agent.display_name,
        capabilities=agent.capabilities,
        is_active=agent.is_active,
        registered_at=agent.registered_at,
        metadata=agent.extra,
        agent_uri=internal_id_to_spiffe(agent.agent_id, trust_domain),
    )


@router.get("/agents", response_model=AgentListResponse)
async def list_registered_agents(
    org_id: str | None = None,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """
    List registered agents. An agent can only see its own org, unless admin.
    """
    # An agent can only query its own org
    filter_org = current_agent.org if org_id is None else org_id
    if filter_org != current_agent.org:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You cannot view agents from other organizations")

    agents = await list_agents(db, org_id=filter_org)
    trust_domain = get_settings().trust_domain
    return AgentListResponse(
        agents=[
            AgentResponse(
                agent_id=a.agent_id,
                org_id=a.org_id,
                display_name=a.display_name,
                capabilities=a.capabilities,
                is_active=a.is_active,
                registered_at=a.registered_at,
                metadata=a.extra,
                agent_uri=internal_id_to_spiffe(a.agent_id, trust_domain),
            )
            for a in agents
        ],
        total=len(agents),
    )


@router.get("/agents/search", response_model=AgentListResponse)
async def search_agents(
    capability: list[str] = Query(..., description="One or more capabilities to search for"),
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """
    Discover agents from other organizations that have ALL the requested capabilities.
    Results exclude the requesting agent's own org.

    Example: GET /registry/agents/search?capability=order.read&capability=order.write
    """
    agents = await search_agents_by_capabilities(
        db,
        capabilities=capability,
        exclude_org_id=current_agent.org,
    )
    trust_domain = get_settings().trust_domain
    return AgentListResponse(
        agents=[
            AgentResponse(
                agent_id=a.agent_id,
                org_id=a.org_id,
                display_name=a.display_name,
                capabilities=a.capabilities,
                is_active=a.is_active,
                registered_at=a.registered_at,
                metadata=a.extra,
                agent_uri=internal_id_to_spiffe(a.agent_id, trust_domain),
            )
            for a in agents
        ],
        total=len(agents),
    )


@router.get("/agents/{agent_id}/public-key", response_model=AgentPublicKeyResponse)
async def get_agent_public_key(
    agent_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the agent's PEM public key, extracted from the certificate stored at login.
    Used by the sender to encrypt E2E messages towards this agent.

    Requires same org OR an approved binding between the caller's org and the target agent.
    """
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    # Org isolation: same org is always allowed; cross-org requires an approved binding
    if agent.org_id != current_agent.org:
        from app.registry.binding_store import get_approved_binding
        binding = await get_approved_binding(db, agent.org_id, agent_id)
        if not binding:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="No approved binding with this agent")

    if not agent.cert_pem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not available — agent must login first",
        )

    cert = crypto_x509.load_pem_x509_certificate(agent.cert_pem.encode())
    public_key_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return AgentPublicKeyResponse(agent_id=agent_id, public_key_pem=public_key_pem)


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    # Org isolation: same org always allowed; cross-org requires approved binding
    if agent.org_id != current_agent.org:
        from app.registry.binding_store import get_approved_binding
        binding = await get_approved_binding(db, agent.org_id, agent_id)
        if not binding:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="No approved binding with this agent")

    trust_domain = get_settings().trust_domain
    return AgentResponse(
        agent_id=agent.agent_id,
        org_id=agent.org_id,
        display_name=agent.display_name,
        capabilities=agent.capabilities,
        is_active=agent.is_active,
        registered_at=agent.registered_at,
        metadata=agent.extra,
        agent_uri=internal_id_to_spiffe(agent.agent_id, trust_domain),
    )


def _validate_cert_for_agent(cert_pem: str, agent_id: str, org_ca_pem: str) -> None:
    """
    Validate that a PEM certificate is suitable for the given agent:
    - Signed by the org CA
    - CN matches agent_id
    - Not expired
    Raises HTTPException on failure.
    """
    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid PEM certificate")

    # Verify CN matches agent_id
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != agent_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Certificate CN does not match agent_id")

    # Verify signed by org CA
    try:
        org_ca = crypto_x509.load_pem_x509_certificate(org_ca_pem.encode())
        org_ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Certificate not signed by the organization CA")
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail=f"Certificate chain verification failed: {exc}")

    # Verify not expired
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    if now > not_after or now < not_before:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Certificate is expired or not yet valid")


@router.post("/agents/{agent_id}/rotate-cert", response_model=RotateCertResponse)
async def rotate_cert(
    agent_id: str,
    body: RotateCertRequest,
    x_org_id: Annotated[str, Header()],
    x_org_secret: Annotated[str, Header()],
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate an agent's pinned certificate. Requires org admin credentials.
    Validates that the new cert is signed by the org CA and CN matches.
    Invalidates all active tokens for the agent.
    """
    # Authenticate org
    org = await get_org_by_id(db, x_org_id)
    if not verify_org_credentials(org, x_org_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid organization credentials")

    # Verify agent exists and belongs to org
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if agent.org_id != x_org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Agent does not belong to your organization")

    # Validate the new certificate
    if not org.ca_certificate:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Org CA not configured")
    _validate_cert_for_agent(body.new_certificate, agent_id, org.ca_certificate)

    old_thumbprint = agent.cert_thumbprint
    new_thumbprint = await rotate_agent_cert(db, agent_id, body.new_certificate)

    await log_event(
        db, "agent.cert_rotated", "ok",
        agent_id=agent_id, org_id=x_org_id,
        details={
            "old_thumbprint": old_thumbprint,
            "new_thumbprint": new_thumbprint,
        },
    )

    return RotateCertResponse(agent_id=agent_id, thumbprint=new_thumbprint)
