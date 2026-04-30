"""ADR-012 Phase 2 — proxy-native ``POST /v1/auth/token``.

When ``MCP_PROXY_LOCAL_AUTH_ENABLED`` is true, the Mastio verifies the
client x509 assertion against its local Org CA and issues a
``LocalIssuer`` token in-process. The Court is never contacted for
intra-org login traffic — closing the metadata leak that today's
reverse-proxy path introduces.

The verifier is intentionally thinner than the Court's
``app.auth.x509_verifier`` — Phase 1 trusts the Org CA pinned in
``proxy_config`` as the sole chain anchor, checks standard JWT claims
(exp/iat/aud/sub), and emits a ``scope=local`` Bearer token. Deeper
checks (jti replay via Redis, SPIFFE SAN enforcement, DPoP binding,
revocation) land in later phases alongside the validator split.

The handler is registered **conditionally**: the router is only mounted
when the flag is on. With the flag off, the reverse-proxy catch-all in
``reverse_proxy/forwarder.py`` keeps forwarding ``/v1/auth/token`` to
the Court, preserving behavior for every caller who hasn't opted in.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Any

import jwt as jose_jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from mcp_proxy.auth.client_cert import _identity_from_cert
from mcp_proxy.auth.local_issuer import LOCAL_AUDIENCE, LOCAL_SCOPE, LocalIssuer
from mcp_proxy.db import get_config

_log = logging.getLogger("mcp_proxy.auth.local_token")

_ASSERTION_AUDIENCE = "agent-trust-broker"
_ALLOWED_HASH_ALGS = (hashes.SHA256, hashes.SHA384, hashes.SHA512)
_MAX_CHAIN_LENGTH = 6

router = APIRouter(tags=["auth"])


class TokenRequest(BaseModel):
    client_assertion: str = Field(
        ...,
        description=(
            "JWT signed by the agent's private key with x5c in the header. "
            "Same wire format as the Court's /v1/auth/token."
        ),
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str = LOCAL_SCOPE
    issued_by: str


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
    )


def _load_chain(cert_bytes_list: list[bytes]) -> list[x509.Certificate]:
    if not cert_bytes_list:
        raise ValueError("empty chain")
    if len(cert_bytes_list) > _MAX_CHAIN_LENGTH:
        raise ValueError(f"chain too long ({len(cert_bytes_list)} > {_MAX_CHAIN_LENGTH})")
    return [x509.load_der_x509_certificate(b) for b in cert_bytes_list]


def _verify_chain(chain: list[x509.Certificate], ca_cert: x509.Certificate) -> None:
    """Walk ``chain`` (leaf → intermediates) and verify the last link is
    signed by ``ca_cert``. Raises ValueError on any failure.
    """
    if not chain:
        raise ValueError("empty chain")

    now = _utcnow()
    for cert in (*chain, ca_cert):
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            raise ValueError("certificate outside validity window")

    # leaf → intermediates: each cert must be signed by its successor.
    for i in range(len(chain) - 1):
        _verify_sig(chain[i], chain[i + 1].public_key())
    # last link of x5c must be signed by the pinned Org CA.
    _verify_sig(chain[-1], ca_cert.public_key())


def _verify_sig(child: x509.Certificate, parent_pub: Any) -> None:
    if not isinstance(child.signature_hash_algorithm, _ALLOWED_HASH_ALGS):
        raise ValueError("weak signature hash algorithm")
    try:
        if isinstance(parent_pub, rsa.RSAPublicKey):
            parent_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
            parent_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            raise ValueError(f"unsupported parent key type: {type(parent_pub).__name__}")
    except InvalidSignature as exc:
        raise ValueError("chain signature invalid") from exc


def _utcnow():
    # Indirected for monkeypatching in tests.
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


async def _load_org_ca() -> x509.Certificate | None:
    pem = await get_config("org_ca_cert")
    if not pem:
        return None
    return x509.load_pem_x509_certificate(pem.encode())


def _decode_assertion(assertion: str, leaf: x509.Certificate) -> dict:
    pub = leaf.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        alg = "RS256"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        alg = "ES256"
    else:
        raise ValueError(f"unsupported leaf key type: {type(pub).__name__}")
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return jose_jwt.decode(
        assertion,
        pub_pem,
        algorithms=[alg],
        audience=_ASSERTION_AUDIENCE,
        options={"require": ["exp", "iat", "sub", "aud"]},
        leeway=30,
    )


def _extract_x5c(assertion: str) -> list[bytes]:
    header = jose_jwt.get_unverified_header(assertion)
    x5c = header.get("x5c")
    if not x5c or not isinstance(x5c, list):
        raise ValueError("x5c header missing or malformed")
    out: list[bytes] = []
    for entry in x5c:
        if not isinstance(entry, str):
            raise ValueError("x5c entry must be a string")
        try:
            out.append(base64.b64decode(entry))
        except Exception as exc:
            raise ValueError("x5c entry is not valid base64") from exc
    return out


@router.post(
    "/v1/auth/token",
    response_model=TokenResponse,
    summary="Issue a Mastio-local intra-org session token (ADR-012)",
)
async def issue_local_token(body: TokenRequest, request: Request) -> TokenResponse:
    issuer: LocalIssuer | None = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local issuer not initialized",
        )

    ca_cert = await _load_org_ca()
    if ca_cert is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Org CA not loaded",
        )

    try:
        x5c_der = _extract_x5c(body.client_assertion)
        chain = _load_chain(x5c_der)
        _verify_chain(chain, ca_cert)
    except ValueError as exc:
        _log.info("local /auth/token rejected: chain invalid: %s", exc)
        raise _unauthorized(f"x509 chain: {exc}") from exc

    leaf = chain[0]
    try:
        claims = _decode_assertion(body.client_assertion, leaf)
    except jose_jwt.PyJWTError as exc:
        _log.info("local /auth/token rejected: assertion invalid: %s", exc)
        raise _unauthorized(f"assertion: {exc}") from exc

    agent_id = claims.get("sub")
    if not agent_id or not isinstance(agent_id, str):
        raise _unauthorized("assertion missing sub")

    # Audit 2026-04-30 lane 1 H1 — bind ``sub`` to the leaf cert's
    # canonical identity. Without this check, any agent holding a
    # valid Org-CA-signed cert (i.e. any enrolled Connector) can sign
    # an assertion claiming ``sub: <other-agent>`` and have the Mastio
    # mint a LOCAL_TOKEN for that identity, bypassing every
    # cert-pin defence the rest of ADR-014 PR-B carefully built. The
    # Court's verifier (app/auth/x509_verifier.py:403) already
    # enforces this; we mirror it on the Mastio side.
    try:
        cert_org, cert_agent = _identity_from_cert(leaf)
    except HTTPException as exc:
        _log.info("local /auth/token rejected: cert identity unparseable: %s", exc.detail)
        raise _unauthorized("cert identity unparseable") from exc
    canonical_agent_id = f"{cert_org}::{cert_agent}"
    if agent_id != canonical_agent_id:
        _log.warning(
            "local /auth/token rejected: sub %s does not match cert %s",
            agent_id, canonical_agent_id,
        )
        raise _unauthorized("sub does not match client cert")

    ttl = _resolve_ttl(request)
    token = issuer.issue(agent_id=agent_id, ttl_seconds=ttl)
    _log.info(
        "local /auth/token issued sub=%s iss=%s kid=%s ttl=%ds",
        agent_id, issuer.issuer, token.kid, ttl,
    )
    return TokenResponse(
        access_token=token.token,
        token_type="Bearer",
        expires_in=ttl,
        scope=LOCAL_SCOPE,
        issued_by=issuer.issuer,
    )


def _resolve_ttl(request: Request) -> int:
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        ttl = getattr(settings, "local_auth_token_ttl_seconds", 0)
        if ttl and ttl > 0:
            return int(ttl)
    return 15 * 60
