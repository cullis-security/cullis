"""ADR-012 §3 — local ES256 JWT issuer for intra-org operations.

The Mastio signs session tokens locally for intra-org traffic (MCP
calls, intra-org send/receive). These tokens never reach the Court:
the Court is only contacted when an agent performs a cross-org send,
via a runtime token-exchange introduced in a follow-up PR.

Signing key = the active row of ``mastio_keys`` (ADR-012 Phase 2.0
multi-key store, see ``mcp_proxy.auth.local_keystore``). The same
row is used for ADR-009 counter-signatures, so rotation affects
both protocols simultaneously.

The ``kid`` lives on the ``MastioKey`` and is stamped into the JWT
header at ``issue()`` time. Phase 2.2 will expose multiple kids
concurrently during the grace window; the issuer stays single-kid
(it only signs with the current active row) and the validator does
the multi-kid lookup.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt as jose_jwt

from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey

DEFAULT_TTL_SECONDS = 15 * 60
MAX_TTL_SECONDS = 60 * 60
LOCAL_AUDIENCE = "cullis-local"
LOCAL_ISSUER_PREFIX = "cullis-mastio"
LOCAL_SCOPE = "local"

_RESERVED_CLAIMS = frozenset({"iss", "aud", "sub", "exp", "iat", "jti", "scope"})


@dataclass(frozen=True)
class LocalToken:
    token: str
    kid: str
    issued_at: int
    expires_at: int


class LocalIssuer:
    """Issue ES256 JWTs signed by the active Mastio key.

    Claims emitted::

        iss   = "cullis-mastio:{org_id}"
        aud   = "cullis-local"
        sub   = agent_id
        scope = "local"
        iat   = now
        exp   = now + ttl
        jti   = uuid4

    Extra claims may be passed via ``issue(..., extra_claims=...)`` but
    cannot overwrite any of the reserved claims above.

    Rotation handling: a given ``LocalIssuer`` is bound to a specific
    ``MastioKey``. After rotation (Phase 2.1), the proxy lifespan
    rebuilds the issuer so it points at the new current signer. The
    previous issuer's kid continues to be verifiable through the
    keystore during the grace window.
    """

    def __init__(self, org_id: str, active_key: MastioKey) -> None:
        if not org_id:
            raise ValueError("org_id required")
        if not isinstance(active_key, MastioKey):
            raise TypeError("active_key must be a MastioKey instance")
        if not active_key.is_active:
            raise ValueError(
                f"active_key.kid={active_key.kid!r} is not currently active"
            )
        self.org_id = org_id
        self._active_key = active_key

    @property
    def kid(self) -> str:
        return self._active_key.kid

    @property
    def active_key(self) -> MastioKey:
        return self._active_key

    @property
    def issuer(self) -> str:
        return f"{LOCAL_ISSUER_PREFIX}:{self.org_id}"

    def issue(
        self,
        agent_id: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        extra_claims: dict[str, Any] | None = None,
    ) -> LocalToken:
        if not agent_id:
            raise ValueError("agent_id required")
        if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds must be in (0, {MAX_TTL_SECONDS}]",
            )

        now = int(time.time())
        exp = now + ttl_seconds
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "aud": LOCAL_AUDIENCE,
            "sub": agent_id,
            "scope": LOCAL_SCOPE,
            "iat": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
        }
        if extra_claims:
            for key, value in extra_claims.items():
                if key in _RESERVED_CLAIMS:
                    continue
                payload[key] = value

        token = jose_jwt.encode(
            payload,
            self._active_key.privkey_pem,
            algorithm="ES256",
            headers={"kid": self._active_key.kid, "typ": "JWT"},
        )
        return LocalToken(
            token=token,
            kid=self._active_key.kid,
            issued_at=now,
            expires_at=exp,
        )

    def jwks(self) -> dict[str, Any]:
        """Return the JWKS containing only the current active key.

        Phase 2.2 will add a separate endpoint (or extend this one) to
        surface deprecated-but-still-valid kids during the grace
        window. The issuer itself stays single-key to keep the signing
        path unambiguous.
        """
        return {"keys": [self._active_key.jwk()]}


async def build_from_keystore(org_id: str, keystore: LocalKeyStore) -> LocalIssuer:
    """Construct a LocalIssuer pointing at the keystore's current signer.

    Raises whatever ``keystore.current_signer()`` raises (no active
    key, or the invariant was violated).
    """
    active = await keystore.current_signer()
    return LocalIssuer(org_id=org_id, active_key=active)
