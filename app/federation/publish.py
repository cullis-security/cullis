"""ADR-010 — Court federation endpoint for Mastio-pushed agent records.

Mastio is authoritative for its own org's agents and publishes the ones it
decides to federate via ``POST /v1/federation/publish-agent``. The Court
keeps the pushed records as a cache for cross-org routing and public-key
lookup; the legacy ``POST /v1/registry/agents`` + org_secret write path
was removed in Phase 6a-4 so this counter-signed endpoint is the sole
write channel.

Auth: ADR-009 counter-signature over the raw request body. The Court
verifies the signature against ``organizations.mastio_pubkey`` pinned
at onboarding. No other auth is accepted — a Mastio whose pubkey is
not pinned cannot federate agents.

Cert chain: the payload's ``cert_pem`` must chain to the org's CA
(the same cert stored in ``organizations.ca_certificate``). We reuse
the validation that ``app/auth/x509_verifier.verify_client_assertion``
performs at login-time, minus the JWT/SPIFFE signing bits.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.mastio_countersig import COUNTERSIG_HEADER, verify_mastio_countersig
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.org_store import get_org_by_id
from app.registry.store import (
    get_agent_by_id, register_agent, update_agent_cert,
    compute_cert_thumbprint,
)


_log = logging.getLogger("agent_trust.federation")

router = APIRouter(prefix="/v1/federation", tags=["federation"])


class PublishAgentRequest(BaseModel):
    agent_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,127}::[a-zA-Z0-9._-]{1,64}$")
    cert_pem: str
    capabilities: list[str] = Field(default_factory=list)
    display_name: str = Field("", max_length=256)
    revoked: bool = False


class PublishAgentResponse(BaseModel):
    agent_id: str
    org_id: str
    status: str  # "created" | "updated" | "revoked"
    cert_thumbprint: str


def _verify_cert_chain(cert_pem: str, org_ca_pem: str) -> x509.Certificate:
    """Return the parsed leaf cert after confirming it's signed by the org CA.

    Mirrors the chain-check step of ``verify_client_assertion`` — we
    don't need the full SPIFFE / DPoP / JWT verification here, only the
    proof that the agent cert was issued by the org the Mastio claims.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cert_pem: malformed PEM ({exc})",
        ) from exc

    try:
        ca_cert = x509.load_pem_x509_certificate(org_ca_pem.encode())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="stored org CA is unreadable",
        ) from exc

    ca_pub = ca_cert.public_key()
    try:
        if isinstance(ca_pub, rsa.RSAPublicKey):
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported org CA key type",
            )
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cert_pem is not signed by the organization's CA",
        )

    return cert


@router.post(
    "/publish-agent",
    response_model=PublishAgentResponse,
    status_code=status.HTTP_200_OK,
)
async def publish_agent(
    request: Request,
    body: PublishAgentRequest,
    mastio_signature: str | None = Header(
        default=None, alias=COUNTERSIG_HEADER,
    ),
    db: AsyncSession = Depends(get_db),
) -> PublishAgentResponse:
    """Mastio pushes an agent to the Court (register, update cert, or revoke).

    - Auth: X-Cullis-Mastio-Signature over the raw JSON body.
    - The body's ``agent_id`` prefix must match the mastio's pinned org
      (so Mastio X can't publish agents in Mastio Y's namespace).
    - The ``cert_pem`` must be signed by the org's CA.
    """
    # 1. Derive org_id from agent_id prefix and look up the mastio pubkey.
    org_id = body.agent_id.split("::", 1)[0]
    org = await get_org_by_id(db, org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )
    if not org.mastio_pubkey:
        await log_event(
            db, "federation.publish_rejected", "denied",
            org_id=org_id,
            details={"reason": "mastio_pubkey_not_pinned",
                     "agent_id": body.agent_id},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "organization has no pinned mastio_pubkey — onboarding "
                "incomplete. Admin must PATCH "
                "/v1/admin/orgs/{id}/mastio-pubkey first."
            ),
        )
    if not org.ca_certificate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="organization has no CA attached — cannot validate agent cert",
        )

    # 2. Verify counter-signature over the raw body bytes.
    raw = await request.body()
    try:
        verify_mastio_countersig(
            client_assertion=raw.decode(),
            signature_b64=mastio_signature,
            mastio_pubkey_pem=org.mastio_pubkey,
        )
    except HTTPException:
        await log_event(
            db, "federation.publish_rejected", "denied",
            org_id=org_id,
            details={"reason": "countersig_invalid",
                     "agent_id": body.agent_id},
        )
        raise

    # 3. Validate the agent cert chains to the org CA (unless we're only
    #    recording a revocation — a revoked agent's cert chain doesn't
    #    need to re-verify since the row already exists).
    existing = await get_agent_by_id(db, body.agent_id)

    if not body.revoked:
        _verify_cert_chain(body.cert_pem, org.ca_certificate)

    # 4. Revocation path: update the existing row and audit.
    if body.revoked:
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="agent not found — cannot revoke",
            )
        existing.is_active = False
        await db.commit()
        await log_event(
            db, "federation.agent_revoked", "ok",
            org_id=org_id, agent_id=body.agent_id,
            details={"source": "federated_push"},
        )
        return PublishAgentResponse(
            agent_id=body.agent_id,
            org_id=org_id,
            status="revoked",
            cert_thumbprint=existing.cert_thumbprint or "",
        )

    # 5. Upsert path.
    thumbprint = compute_cert_thumbprint(body.cert_pem)
    if existing is None:
        new_record = await register_agent(
            db,
            agent_id=body.agent_id,
            org_id=org_id,
            display_name=body.display_name or body.agent_id.split("::", 1)[1],
            capabilities=body.capabilities,
            metadata={"source": "federated_push"},
        )
        # Pin the cert right away so the first /auth/token doesn't create
        # a pinning mismatch.
        await update_agent_cert(
            db, agent_id=new_record.agent_id,
            cert_pem=body.cert_pem, thumbprint=thumbprint,
        )
        await log_event(
            db, "federation.agent_published", "ok",
            org_id=org_id, agent_id=body.agent_id,
            details={"status": "created", "thumbprint": thumbprint},
        )
        return PublishAgentResponse(
            agent_id=body.agent_id,
            org_id=org_id,
            status="created",
            cert_thumbprint=thumbprint,
        )

    # Existing → update cert + capabilities + reactivate.
    existing.capabilities_json = json.dumps(body.capabilities)
    existing.display_name = body.display_name or existing.display_name
    existing.is_active = True
    await db.commit()
    await update_agent_cert(
        db, agent_id=body.agent_id,
        cert_pem=body.cert_pem, thumbprint=thumbprint,
    )
    await log_event(
        db, "federation.agent_published", "ok",
        org_id=org_id, agent_id=body.agent_id,
        details={"status": "updated", "thumbprint": thumbprint},
    )
    return PublishAgentResponse(
        agent_id=body.agent_id,
        org_id=org_id,
        status="updated",
        cert_thumbprint=thumbprint,
    )


# ── /publish-stats ──────────────────────────────────────────────────────────
#
# Fire-and-forget aggregate stats so the Court dashboard can show per-org
# fleet size without knowing individual agents. Separate from /publish-agent
# because it has no idempotency tracking (no per-row revision) and is pushed
# on a looser cadence (minutes, not seconds). Re-uses the same counter-sig
# auth pattern so Mastio identity is still pinned.


class PublishStatsRequest(BaseModel):
    org_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    agent_active_count: int = Field(..., ge=0)
    agent_total_count: int = Field(..., ge=0)
    backend_count: int = Field(..., ge=0)


class PublishStatsResponse(BaseModel):
    org_id: str
    stored_at: str


@router.post(
    "/publish-stats",
    response_model=PublishStatsResponse,
    status_code=status.HTTP_200_OK,
)
async def publish_stats(
    request: Request,
    body: PublishStatsRequest,
    mastio_signature: str | None = Header(
        default=None, alias=COUNTERSIG_HEADER,
    ),
    db: AsyncSession = Depends(get_db),
) -> PublishStatsResponse:
    """Mastio pushes aggregate counters for its org to the Court.

    Stored under ``organizations.metadata_json["stats"]`` — no schema
    migration, the metadata column is already JSON. Overwrites the prior
    snapshot on every push (stats are point-in-time, not append-only).

    Auth mirrors publish-agent: counter-signature against the pinned
    ``mastio_pubkey``. Unknown orgs return 404; orgs without a pinned
    pubkey return 403 so an operator who forgot onboarding step 2 gets
    a clear message instead of a silent no-op.
    """
    org = await get_org_by_id(db, body.org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )
    if not org.mastio_pubkey:
        await log_event(
            db, "federation.stats_rejected", "denied",
            org_id=body.org_id,
            details={"reason": "mastio_pubkey_not_pinned"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="organization has no pinned mastio_pubkey",
        )

    raw = await request.body()
    try:
        verify_mastio_countersig(
            client_assertion=raw.decode(),
            signature_b64=mastio_signature,
            mastio_pubkey_pem=org.mastio_pubkey,
        )
    except HTTPException:
        await log_event(
            db, "federation.stats_rejected", "denied",
            org_id=body.org_id,
            details={"reason": "countersig_invalid"},
        )
        raise

    stored_at = datetime.now(timezone.utc).isoformat()
    # Read–modify–write on metadata_json. OrganizationRecord.extra is a
    # computed property, so we parse the text, set the "stats" sub-key,
    # then serialize back. Invalid JSON in an existing row is recovered to
    # an empty dict rather than failing the push.
    try:
        meta = json.loads(org.metadata_json or "{}")
        if not isinstance(meta, dict):
            meta = {}
    except (TypeError, ValueError):
        meta = {}
    meta["stats"] = {
        "agent_active_count": body.agent_active_count,
        "agent_total_count": body.agent_total_count,
        "backend_count": body.backend_count,
        "updated_at": stored_at,
    }
    org.metadata_json = json.dumps(meta)
    await db.commit()

    await log_event(
        db, "federation.stats_published", "ok",
        org_id=body.org_id,
        details={
            "agent_active": body.agent_active_count,
            "agent_total": body.agent_total_count,
            "backends": body.backend_count,
        },
    )
    return PublishStatsResponse(org_id=body.org_id, stored_at=stored_at)
