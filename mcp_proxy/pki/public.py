"""Public PKI bootstrap endpoint — anonymous CA download.

Exposes the Org CA certificate as a static PEM at ``GET /pki/ca.crt``
without authentication. Self-host operators and Connector clients use
this on first contact to fetch the CA, display the SHA-256 fingerprint
to the human, and pin it locally (TOFU) before any authenticated
request. This closes the bootstrap gap where the only honest option
was ``--no-verify-tls``.

The endpoint publishes public-key material only — the private CA key
never leaves the Vault / DB-backed config blob. It mirrors the
``/.well-known/jwks-local.json`` pattern used for the Mastio local
issuer:

- Rate-limited per IP to deter cache-busting / scraping.
- ETag + ``If-None-Match`` so well-behaved clients skip the body
  after their first warm fetch (CA changes only on rotation, which
  is a days-to-years cadence).
- ``Cache-Control: public, max-age=300`` — 5 minutes is conservative
  given how rarely the CA rotates and how disruptive rotation already
  is for clients that pinned the old fingerprint.

Anyone holding the network path can already reach the TLS leaf cert
that this CA signed; publishing the CA itself adds no information
they couldn't reconstruct from a single TLS handshake. What it does
add is a stable, structured, fingerprintable artifact that a TOFU
pinning UI can actually show to a human.
"""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException, Request, Response, status

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
from mcp_proxy.db import get_config

router = APIRouter(tags=["pki"])

# Same budget as JWKS — both are anonymous, low-traffic, public-key
# endpoints. A Connector polling once per first-contact never touches
# the limiter; only a sustained scraper from one IP gets throttled.
_PKI_CA_RATE_LIMIT_PER_MINUTE = 30


def _client_ip(request: Request) -> str:
    """Return the rate-limit subject for this request.

    H-xff audit fix: the previous implementation read the first
    entry from ``X-Forwarded-For`` directly, which is fully
    attacker-controlled when nginx is bypassed (host port exposed,
    misconfigured deploy) or when nginx forwards the upstream
    XFF as-is. An attacker could spray ``X-Forwarded-For: 1.2.3.4``
    with a different value per request and never trip the limiter.

    The deployed shape runs uvicorn behind nginx with
    ``--proxy-headers --forwarded-allow-ips=<nginx>`` so
    ``ProxyHeadersMiddleware`` rewrites ``request.client`` from the
    last trusted XFF hop. Using ``request.client.host`` directly
    is the same pattern as ``app.rate_limit.limiter.get_client_ip``
    and the dashboard login handler post-H9.
    """
    client = request.client
    return client.host if client is not None else "unknown"


def _compute_etag(pem: str) -> str:
    digest = hashlib.sha256(pem.encode()).hexdigest()
    return f'"{digest[:32]}"'


def _etag_matches(header: str, etag: str) -> bool:
    value = header.strip()
    if value == "*":
        return True
    for candidate in value.split(","):
        token = candidate.strip()
        if token.startswith("W/"):
            token = token[2:]
        if token == etag:
            return True
    return False


@router.get(
    "/pki/ca.crt",
    summary="Org CA certificate (anonymous, for TOFU pinning)",
    response_class=Response,
)
async def pki_public_ca(request: Request):
    client_ip = _client_ip(request)
    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}", _PKI_CA_RATE_LIMIT_PER_MINUTE,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="pki ca rate limit exceeded",
        )

    pem = await get_config("org_ca_cert")
    if not pem:
        # Same shape as POST /pki/export-ca: org CA not provisioned yet.
        # 404 makes it actionable — the caller knows to retry after the
        # operator has completed first-boot setup.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Org CA configured",
        )

    etag = _compute_etag(pem)
    headers = {
        "Cache-Control": "public, max-age=300",
        "ETag": etag,
        # Hint for TOFU UIs that this is meant to be saved as ca.pem.
        "Content-Disposition": 'inline; filename="org-ca.pem"',
    }

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and _etag_matches(if_none_match, etag):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)

    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers=headers,
    )
