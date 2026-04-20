"""ADR-012 Phase 3 — validator for Mastio-issued local tokens.

The counterpart to ``mcp_proxy.auth.local_issuer``: given a Bearer JWT
signed by the Mastio leaf key, verify it against the in-process
``LocalIssuer`` (no remote JWKS fetch needed — the public key is the
one we use ourselves to sign) and surface the claims as a typed payload
downstream handlers can trust.

A FastAPI dependency ``require_local_token`` exposes the validator to
route handlers. Wiring onto the actual egress / ingress endpoints is
the job of a follow-up PR (ADR-012 Phase 4); this module ships the
primitive and its tests so the subsequent wiring PR stays small.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import jwt as jose_jwt
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request, status

from mcp_proxy.auth.local_issuer import (
    LOCAL_AUDIENCE,
    LOCAL_ISSUER_PREFIX,
    LocalIssuer,
)

_log = logging.getLogger("mcp_proxy.auth.local_validator")

_LEEWAY_SECONDS = 30


@dataclass(frozen=True)
class LocalTokenPayload:
    agent_id: str
    issuer: str
    scope: str
    issued_at: int
    expires_at: int
    jti: str
    extra: dict[str, Any]

    @property
    def org_id(self) -> str:
        """Extract the org_id from the issuer claim. Returns ``""`` if
        the issuer doesn't follow the ``cullis-mastio:<org>`` convention
        (defensive — validator has already enforced the prefix).
        """
        prefix = f"{LOCAL_ISSUER_PREFIX}:"
        return self.issuer[len(prefix):] if self.issuer.startswith(prefix) else ""


class LocalTokenError(Exception):
    """Raised when a token fails any validation step."""


def validate_local_token(
    token: str, issuer: LocalIssuer, *, leeway: int = _LEEWAY_SECONDS,
) -> LocalTokenPayload:
    """Verify ``token`` against ``issuer``'s public key.

    Raises ``LocalTokenError`` with a short reason on any failure. The
    caller is responsible for turning it into an HTTP 401 (see
    ``require_local_token``).
    """
    try:
        header = jose_jwt.get_unverified_header(token)
    except jose_jwt.PyJWTError as exc:
        raise LocalTokenError(f"malformed header: {exc}") from exc

    if header.get("alg") != "ES256":
        raise LocalTokenError(f"unexpected alg: {header.get('alg')}")
    if header.get("kid") != issuer.kid:
        raise LocalTokenError(
            f"kid mismatch (got {header.get('kid')!r}, expect {issuer.kid!r})"
        )

    pub_pem = issuer._leaf_pubkey_pem  # noqa: SLF001 — one-process trust boundary
    # Sanity: the PEM must parse. If the issuer was mis-initialized this
    # raises at decode time; turning it into a 401 here is fine.
    serialization.load_pem_public_key(pub_pem.encode())

    try:
        claims = jose_jwt.decode(
            token,
            pub_pem,
            algorithms=["ES256"],
            audience=LOCAL_AUDIENCE,
            issuer=issuer.issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss", "scope", "jti"]},
            leeway=leeway,
        )
    except jose_jwt.ExpiredSignatureError as exc:
        raise LocalTokenError("token expired") from exc
    except jose_jwt.InvalidAudienceError as exc:
        raise LocalTokenError("wrong audience") from exc
    except jose_jwt.InvalidIssuerError as exc:
        raise LocalTokenError("wrong issuer") from exc
    except jose_jwt.PyJWTError as exc:
        raise LocalTokenError(f"invalid: {exc}") from exc

    sub = claims.get("sub")
    scope = claims.get("scope")
    if not isinstance(sub, str) or not sub:
        raise LocalTokenError("sub missing")
    if not isinstance(scope, str):
        raise LocalTokenError("scope missing")

    reserved = {"sub", "iss", "aud", "exp", "iat", "jti", "scope"}
    extra = {k: v for k, v in claims.items() if k not in reserved}

    return LocalTokenPayload(
        agent_id=sub,
        issuer=claims["iss"],
        scope=scope,
        issued_at=int(claims["iat"]),
        expires_at=int(claims["exp"]),
        jti=str(claims["jti"]),
        extra=extra,
    )


async def require_local_token(request: Request) -> LocalTokenPayload:
    """FastAPI dependency — extract+validate a Bearer LOCAL_TOKEN.

    The token is read from ``Authorization: Bearer <jwt>``. 401 on any
    failure, 503 if the issuer isn't wired up (mastio identity didn't
    load yet — the wiring PR will pin hard availability expectations).
    """
    issuer: LocalIssuer | None = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local issuer not initialized",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        )
    token = auth_header[7:].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="empty bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        )

    try:
        return validate_local_token(token, issuer)
    except LocalTokenError as exc:
        _log.info("local token rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc
