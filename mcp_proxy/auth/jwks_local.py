"""ADR-012 §3 — JWKS endpoint for the Mastio local issuer.

Exposes the Mastio leaf public key as a JWKS document so intra-org
validators (Mastio-side middleware, MCP aggregator, local session
store) can verify tokens without a remote round-trip.

The endpoint is served unauthenticated by design — it publishes public
key material only, mirrors the /.well-known/jwks.json pattern used
by the broker, and is read by internal components sharing the same
FastAPI process.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

router = APIRouter(tags=["auth"])


@router.get(
    "/.well-known/jwks-local.json",
    summary="JWKS for the Mastio local issuer (intra-org tokens)",
)
async def jwks_local(request: Request) -> dict:
    issuer = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local issuer not initialized",
        )
    return issuer.jwks()
