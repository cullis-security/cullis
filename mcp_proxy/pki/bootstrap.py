"""Public connector-bootstrap endpoint — first-contact discovery.

Exposes the metadata a Frontdesk Connector needs to start its setup
wizard against this Mastio: the org identity (``org_id``,
``trust_domain``), the CA fingerprint anchor for TOFU pinning, and
the relative URLs of the endpoints the wizard will follow up with
(CA download, enrollment start/poll, JWKS).

Anonymous, like ``/pki/ca.crt`` and ``/.well-known/jwks-local.json``
— it publishes only what an unauthenticated client could already
reconstruct from a TLS handshake plus that anonymous CA fetch. What
it adds is a single structured payload the wizard can probe in
parallel against a small list of candidate URLs (``mastio.local``,
``host.docker.internal``, ``localhost``, ``172.17.0.1``) so the
operator never has to copy-paste an URL or a fingerprint by hand.

The response always returns 200, even when the Mastio has just been
installed and the operator hasn't completed the first-boot setup
yet. In that case ``mode`` is ``"setup"`` and ``org_id`` /
``ca_fingerprint_sha256`` are ``null`` — the wizard distinguishes
"this Mastio exists but isn't configured" from "no Mastio at this
URL" (which manifests as connection refused / timeout, never as a
malformed payload).

URLs in the response are **relative paths**, never absolute. The
client concatenates them with the base URL it probed. Returning
absolute URLs here would force us to know what hostname the
operator pointed at us, which conflicts with the dual semantics of
``MCP_PROXY_PROXY_PUBLIC_URL`` (DPoP htu vs OIDC redirect — see the
``proxy_env_public_url_vm`` failure mode).

Rate-limit budget mirrors ``/pki/ca.crt`` and the JWKS endpoint:
30 hits/minute per IP, enough for any honest first-contact poll
and tight enough to throttle a scraper hammering one host.
"""
from __future__ import annotations

import hashlib
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
from mcp_proxy.config import get_settings
from mcp_proxy.db import get_config

router = APIRouter(tags=["pki"])

_BOOTSTRAP_RATE_LIMIT_PER_MINUTE = 30


def _client_ip(request: Request) -> str:
    """Return the rate-limit subject for this request.

    Uses ``request.client.host`` populated by uvicorn's
    ``ProxyHeadersMiddleware`` (the deployed shape runs uvicorn
    behind nginx with ``--proxy-headers --forwarded-allow-ips=<nginx>``)
    so the value reflects the last trusted XFF hop, not an
    attacker-controlled raw header. Same pattern as
    ``mcp_proxy/pki/public.py`` and ``mcp_proxy/auth/jwks_local.py``.
    """
    client = request.client
    return client.host if client is not None else "unknown"


class BootstrapUrls(BaseModel):
    ca: str = Field(default="/pki/ca.crt")
    enrollment_start: str = Field(default="/v1/enrollment/start")
    enrollment_status_template: str = Field(
        default="/v1/enrollment/{session_id}/status"
    )
    jwks: str = Field(default="/.well-known/jwks-local.json")


class BootstrapResponse(BaseModel):
    """Metadata payload for first-contact connector discovery.

    ``version`` is the schema version. Bump it on breaking shape
    changes — adding a new optional field is not breaking.

    ``mode`` is ``"configured"`` when the operator has finished
    first-boot setup (``org_id`` and Org CA both present), else
    ``"setup"``. The wizard surfaces this as a "configure your
    Mastio first" hint instead of attempting enrollment.
    """

    version: int = 1
    mode: Literal["configured", "setup"]
    org_id: str | None
    trust_domain: str
    ca_fingerprint_sha256: str | None
    urls: BootstrapUrls = Field(default_factory=BootstrapUrls)


def _compute_fingerprint(pem: str) -> str:
    """Hex SHA-256 over the DER body of the PEM cert.

    Same anchor the Connector ``_fetch_ca_pem`` computes when it
    pins the CA — see ``cullis_connector/web.py``. Returning the
    bare hex (no ``:`` separators) lets the wizard render whichever
    grouped form it prefers; the client compares case-insensitively
    after stripping ``:``.
    """
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert.fingerprint(hashes.SHA256()).hex()


def _compute_etag(payload: BootstrapResponse) -> str:
    """Strong ETag over the JSON body.

    Lets a wizard that probes the same Mastio twice in a row skip
    the second body. The fingerprint changes only on CA rotation
    and the org_id is set once at first boot, so the ETag is
    effectively stable per-Mastio between rotations.
    """
    digest = hashlib.sha256(
        payload.model_dump_json().encode()
    ).hexdigest()
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
    "/.well-known/cullis/connector-bootstrap",
    summary="First-contact metadata for the Connector setup wizard",
    response_model=BootstrapResponse,
)
async def connector_bootstrap(request: Request) -> Response:
    client_ip = _client_ip(request)
    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}", _BOOTSTRAP_RATE_LIMIT_PER_MINUTE,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="connector bootstrap rate limit exceeded",
        )

    settings = get_settings()

    # ``app.state.org_id`` is wired in lifespan (mcp_proxy/main.py:313)
    # to the resolved org_id (env override, DB config, or derived from
    # the Org CA in standalone mode). Falling back to
    # ``get_config("org_id")`` covers the rare case where bootstrap
    # is hit before lifespan finishes — we still answer 200 with
    # mode="setup" rather than 503.
    org_id = getattr(request.app.state, "org_id", None)
    if not org_id:
        org_id = await get_config("org_id") or ""

    pem = await get_config("org_ca_cert")
    if pem:
        ca_fingerprint: str | None = _compute_fingerprint(pem)
    else:
        ca_fingerprint = None

    mode: Literal["configured", "setup"]
    if org_id and ca_fingerprint:
        mode = "configured"
    else:
        mode = "setup"

    payload = BootstrapResponse(
        mode=mode,
        org_id=org_id or None,
        trust_domain=settings.trust_domain,
        ca_fingerprint_sha256=ca_fingerprint,
    )

    etag = _compute_etag(payload)
    headers = {
        "Cache-Control": "public, max-age=60",
        "ETag": etag,
    }

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and _etag_matches(if_none_match, etag):
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED, headers=headers,
        )

    return Response(
        content=payload.model_dump_json(),
        media_type="application/json",
        headers=headers,
    )
