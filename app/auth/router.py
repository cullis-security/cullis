import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import TokenRequest, TokenResponse, TokenPayload
from app.auth.jwt import create_access_token, get_current_agent
from app.auth import mastio_countersig
from app.auth.mastio_countersig import COUNTERSIG_HEADER
from app.auth.x509_verifier import verify_client_assertion
from app.auth.dpop import verify_dpop_proof, build_htu
from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.store import (
    get_agent_by_id, update_agent_cert, refresh_agent_cert_svid,
    invalidate_agent_tokens,
)
from app.registry.binding_store import get_approved_binding
from app.rate_limit.limiter import rate_limiter
from app.telemetry import tracer
from app.telemetry_metrics import AUTH_SUCCESS_COUNTER, AUTH_DENY_COUNTER, AUTH_DURATION_HISTOGRAM

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
async def issue_token(
    request: Request,
    body: TokenRequest,
    dpop: str = Header(alias="DPoP"),
    mastio_signature: str | None = Header(default=None, alias=COUNTERSIG_HEADER),
    db: AsyncSession = Depends(get_db),
):
    """
    Issue a DPoP-bound JWT for an agent.
    Authentication: client_assertion (JWT RS256 + x509) + DPoP proof header.

    The issued token includes cnf.jkt — it is bound to the agent's ephemeral
    DPoP key and cannot be used without a matching proof on every subsequent request.

    The first request without a nonce will receive a 401 with DPoP-Nonce header.
    The client must retry with the nonce included in the DPoP proof.
    """
    t0 = time.monotonic()
    with tracer.start_as_current_span("auth.issue_token") as span:
        # ── Rate limit by client IP ──────────────────────────────────────────
        client_host = request.client.host if request.client else "unknown"
        await rate_limiter.check(client_host, "auth.token")

        # ── Verify DPoP proof FIRST — before more expensive x509 verification
        settings = get_settings()
        htu = build_htu(request, settings)
        dpop_jkt = await verify_dpop_proof(dpop, htm="POST", htu=htu, access_token=None)

        # ── Verify certificate and signature ─────────────────────────────────
        agent_id, org_id, cert_pem, cert_thumbprint, svid_mode = await verify_client_assertion(
            body.client_assertion, db, request=request,
        )
        span.set_attribute("agent.id", agent_id)
        span.set_attribute("org.id", org_id)

        # ── ADR-009 — mastio counter-signature (strict, always on) ───────────
        # After Phase 4 there is no legacy path: an org without a pinned
        # mastio_pubkey cannot emit a token. ``mastio_countersig`` is
        # imported at module level so tests/conftest.py can patch
        # ``mastio_countersig.enforce_on_token_request`` to a no-op for
        # the bulk of the suite.
        try:
            await mastio_countersig.enforce_on_token_request(
                db=db,
                org_id=org_id,
                client_assertion=body.client_assertion,
                signature_header=mastio_signature,
            )
        except HTTPException:
            AUTH_DENY_COUNTER.add(1, {"reason": "mastio_countersig"})
            await log_event(
                db, "auth.token_request", "denied",
                agent_id=agent_id, org_id=org_id,
                details={"reason": "mastio_countersig_missing_or_invalid"},
            )
            raise

        # ── Agent checks ─────────────────────────────────────────────────────
        agent = await get_agent_by_id(db, agent_id)
        if agent is None or agent.org_id != org_id:
            AUTH_DENY_COUNTER.add(1, {"reason": "agent_not_found"})
            await log_event(
                db, "auth.token_request", "denied",
                agent_id=agent_id, org_id=org_id,
                details={"reason": "agent not found or org mismatch"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent not found or org mismatch")

        if not agent.is_active:
            AUTH_DENY_COUNTER.add(1, {"reason": "agent_inactive"})
            await log_event(
                db, "auth.token_request", "denied",
                agent_id=agent_id, org_id=org_id,
                details={"reason": "agent inactive"},
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent not active")

        # ── Verify approved binding ──────────────────────────────────────────
        binding = await get_approved_binding(db, org_id, agent_id)
        if not binding:
            AUTH_DENY_COUNTER.add(1, {"reason": "no_binding"})
            await log_event(
                db, "auth.token_request", "denied",
                agent_id=agent_id, org_id=org_id,
                details={"reason": "no approved binding"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No approved binding for this agent and organization",
            )

        # ── Certificate storage ──────────────────────────────────────────────
        # Classic BYOCA: enforce thumbprint pinning (anti Rogue CA).
        # SPIFFE mode: overwrite the stored cert on every login — SPIRE
        # rotates SVIDs on a short schedule, so pinning would reject every
        # rotation. Identity in SPIFFE mode is bound by the chain walk +
        # SPIFFE URI match instead (ADR-003 §2.3). The cert_pem still needs
        # to be current on the server side so outbound-message signature
        # verification in the broker can locate it.
        if svid_mode:
            await refresh_agent_cert_svid(db, agent_id, cert_pem, cert_thumbprint)
        elif not svid_mode:
            pinned_ok = await update_agent_cert(db, agent_id, cert_pem, cert_thumbprint)
            if not pinned_ok:
                from app.telemetry_metrics import CERT_PINNING_MISMATCH_COUNTER
                AUTH_DENY_COUNTER.add(1, {"reason": "cert_thumbprint_mismatch"})
                CERT_PINNING_MISMATCH_COUNTER.add(1, {"org_id": org_id})
                await log_event(
                    db, "auth.token_request", "denied",
                    agent_id=agent_id, org_id=org_id,
                    details={"reason": "cert_thumbprint_mismatch", "presented": cert_thumbprint},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Certificate thumbprint mismatch — use the rotate-cert endpoint to update",
                )

        token, expires_in = await create_access_token(
            agent_id, org_id, scope=binding.scope, dpop_jkt=dpop_jkt
        )

        AUTH_SUCCESS_COUNTER.add(1, {"org_id": org_id})
        AUTH_DURATION_HISTOGRAM.record((time.monotonic() - t0) * 1000)

        await log_event(
            db, "auth.token_issued", "ok",
            agent_id=agent_id, org_id=org_id,
        )

        return TokenResponse(access_token=token, expires_in=expires_in)


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_self(
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """
    Self-logout: invalidate all currently active tokens for the authenticated agent.
    Any token with iat <= now is rejected on the next request.
    """
    await invalidate_agent_tokens(db, current_agent.agent_id)
    await log_event(
        db, "auth.token_revoked", "ok",
        agent_id=current_agent.agent_id, org_id=current_agent.org,
        details={"reason": "self-revoke"},
    )


@router.post("/revoke-agent/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_tokens(
    agent_id: str,
    x_org_id: Annotated[str, Header()],
    x_org_secret: Annotated[str, Header()],
    db: AsyncSession = Depends(get_db),
):
    """
    Admin revoke: invalidate all tokens for any agent in the authenticated organization.
    Authentication via X-Org-Id + X-Org-Secret headers.
    """
    from app.registry.org_store import get_org_by_id, verify_org_credentials

    org = await get_org_by_id(db, x_org_id)
    if not verify_org_credentials(org, x_org_secret):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid organization credentials")

    # Audit F-B-8: collapse "no such agent" and "agent belongs to a
    # different org" into a single 404 with the same detail body.
    # Previously a caller holding one valid org_secret could enumerate
    # agents in *other* orgs by observing 404 vs 403. The caller must
    # only learn about their own org's agents.
    agent = await get_agent_by_id(db, agent_id)
    if not agent or agent.org_id != org.org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Agent not found")

    await invalidate_agent_tokens(db, agent_id)
    await log_event(
        db, "auth.token_revoked", "ok",
        agent_id=agent_id, org_id=org.org_id,
        details={"reason": "admin-revoke", "revoked_by_org": x_org_id},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Transaction Token issuance (dashboard session auth — human-in-the-loop)
# ─────────────────────────────────────────────────────────────────────────────

from pydantic import BaseModel, Field


class TransactionTokenRequest(BaseModel):
    agent_id: str = Field(..., description="Which agent will use this token")
    txn_type: str = Field(..., max_length=64, description="Operation type, e.g. CREATE_ORDER")
    payload_hash: str = Field(..., max_length=64, description="SHA-256 of the approved payload")
    target_agent_id: str | None = Field(None, description="Who to transact with")
    resource_id: str | None = Field(None, description="Bound resource, e.g. rfq_id")
    rfq_id: str | None = Field(None, description="Originating RFQ")
    ttl_seconds: int = Field(default=60, ge=10, le=300)


class TransactionTokenResponse(BaseModel):
    transaction_token: str
    expires_in: int
    jti: str
    txn_type: str


@router.post("/token/transaction", response_model=TransactionTokenResponse)
async def issue_transaction_token(
    body: TransactionTokenRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """
    Issue a single-use transaction token for a specific operation.

    The requesting agent must be authenticated (DPoP). The token authorizes
    exactly one operation matching the payload_hash, and expires in ttl_seconds.
    """
    from app.auth.transaction_token import create_transaction_token

    # Verify the agent is requesting a token for itself
    if body.agent_id != current_agent.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only request transaction tokens for yourself",
        )

    token, record = await create_transaction_token(
        db,
        agent_id=body.agent_id,
        org_id=current_agent.org,
        txn_type=body.txn_type,
        resource_id=body.resource_id,
        payload_hash=body.payload_hash,
        approved_by=current_agent.agent_id,  # self-approval for API; dashboard sets human identity
        parent_jti=current_agent.jti,
        target_agent_id=body.target_agent_id,
        rfq_id=body.rfq_id,
        ttl_seconds=body.ttl_seconds,
    )

    await log_event(
        db, "auth.transaction_token_issued", "ok",
        agent_id=current_agent.agent_id, org_id=current_agent.org,
        details={
            "txn_jti": record.jti,
            "txn_type": body.txn_type,
            "target": body.target_agent_id,
            "rfq_id": body.rfq_id,
        },
    )

    return TransactionTokenResponse(
        transaction_token=token,
        expires_in=body.ttl_seconds,
        jti=record.jti,
        txn_type=body.txn_type,
    )
