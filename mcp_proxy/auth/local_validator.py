"""ADR-012 Phase 3 — validator for Mastio-issued local tokens.

The counterpart to ``mcp_proxy.auth.local_issuer``: given a Bearer
JWT signed by a Mastio key, look the ``kid`` up in the keystore and
verify the signature against the corresponding public key.

Phase 2.0 note: the validator is now keystore-driven instead of
issuer-driven. A kid in the JWT header can match any active *or*
within-grace deprecated row in ``mastio_keys`` (``is_valid_for_verification``);
unknown or expired kids are rejected. This is the structural change
that lets Phase 2.2 serve a rotation grace window without any more
code in the validator itself.

A FastAPI dependency ``require_local_token`` exposes the validator to
route handlers. It reads ``request.app.state.local_keystore``,
populated by the proxy lifespan.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import jwt as jose_jwt
from fastapi import HTTPException, Request, status

from mcp_proxy.auth.local_issuer import LOCAL_AUDIENCE, LOCAL_ISSUER_PREFIX
from mcp_proxy.auth.local_keystore import LocalKeyStore

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


async def validate_local_token(
    token: str,
    keystore: LocalKeyStore,
    *,
    expected_issuer: str,
    leeway: int = _LEEWAY_SECONDS,
) -> LocalTokenPayload:
    """Verify ``token`` against a keystore-resolved public key.

    The ``kid`` in the JWT header is used to look up the signing key
    in ``keystore``. An unknown or expired kid is rejected. The caller
    supplies ``expected_issuer`` (typically
    ``f"cullis-mastio:{org_id}"``) so the validator can enforce the
    ``iss`` claim without taking a second dependency on the issuer
    object.

    Raises ``LocalTokenError`` with a short reason on any failure.
    """
    try:
        header = jose_jwt.get_unverified_header(token)
    except jose_jwt.PyJWTError as exc:
        raise LocalTokenError(f"malformed header: {exc}") from exc

    if header.get("alg") != "ES256":
        raise LocalTokenError(f"unexpected alg: {header.get('alg')}")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise LocalTokenError("kid missing from header")

    key = await keystore.find_by_kid(kid)
    if key is None:
        raise LocalTokenError(f"unknown kid: {kid!r}")
    if not key.is_valid_for_verification:
        raise LocalTokenError(f"kid {kid!r} is no longer valid")

    try:
        claims = jose_jwt.decode(
            token,
            key.pubkey_pem,
            algorithms=["ES256"],
            audience=LOCAL_AUDIENCE,
            issuer=expected_issuer,
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

    Reads the Bearer token from ``Authorization``. 401 on any failure,
    503 if the keystore or issuer aren't wired up yet (Mastio identity
    didn't load — the lifespan has not completed).
    """
    keystore: LocalKeyStore | None = getattr(
        request.app.state, "local_keystore", None,
    )
    # The issuer is still consulted — purely to obtain ``org_id`` and
    # so the validator can enforce ``iss``. Tests that stub the state
    # manually must set both ``local_keystore`` and ``local_issuer``.
    from mcp_proxy.auth.local_issuer import LocalIssuer  # local import to avoid cycle
    issuer: LocalIssuer | None = getattr(request.app.state, "local_issuer", None)
    if keystore is None or issuer is None:
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
        return await validate_local_token(
            token, keystore, expected_issuer=issuer.issuer,
        )
    except LocalTokenError as exc:
        _log.info("local token rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc
