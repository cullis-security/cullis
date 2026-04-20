"""ADR-012 §3 — local ES256 JWT issuer for intra-org operations.

The Mastio signs session tokens locally for intra-org traffic (MCP
calls, intra-org send/receive). These tokens never reach the Court:
the Court is only contacted when an agent performs a cross-org send,
via a runtime token-exchange introduced in a follow-up PR.

Signing key = the same EC P-256 Mastio leaf key used for ADR-009
counter-signatures (``AgentManager._mastio_leaf_key``). One key, two
uses, one trust anchor: the ``mastio_pubkey`` pinned at org onboarding.

The ``kid`` is derived from the SHA-256 digest of the leaf public key
PEM (first 16 hex chars). This is stable across restarts — the key is
re-loaded from the DB by ``AgentManager.ensure_mastio_identity()`` —
and unique per Mastio, so validators can pick the right key out of
the JWKS without relying on wall-clock ordering.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt as jose_jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
    """Issue ES256 JWTs signed by the Mastio leaf key.

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
    """

    def __init__(
        self,
        org_id: str,
        leaf_key: ec.EllipticCurvePrivateKey,
        leaf_pubkey_pem: str,
    ) -> None:
        if not org_id:
            raise ValueError("org_id required")
        if not isinstance(leaf_key, ec.EllipticCurvePrivateKey):
            raise TypeError("leaf_key must be an EC private key")
        if not leaf_pubkey_pem:
            raise ValueError("leaf_pubkey_pem required")
        self.org_id = org_id
        self._leaf_key = leaf_key
        self._leaf_pubkey_pem = leaf_pubkey_pem
        self._priv_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._kid = self._compute_kid(leaf_pubkey_pem)

    @staticmethod
    def _compute_kid(pubkey_pem: str) -> str:
        digest = hashlib.sha256(pubkey_pem.encode()).hexdigest()[:16]
        return f"mastio-{digest}"

    @property
    def kid(self) -> str:
        return self._kid

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
            self._priv_pem,
            algorithm="ES256",
            headers={"kid": self._kid, "typ": "JWT"},
        )
        return LocalToken(token=token, kid=self._kid, issued_at=now, expires_at=exp)

    def jwks(self) -> dict[str, Any]:
        pub_key = serialization.load_pem_public_key(self._leaf_pubkey_pem.encode())
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise RuntimeError("leaf pubkey is not an EC key")
        numbers = pub_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": _b64u_int(numbers.x, 32),
                    "y": _b64u_int(numbers.y, 32),
                    "use": "sig",
                    "alg": "ES256",
                    "kid": self._kid,
                }
            ]
        }


def _b64u_int(value: int, length: int) -> str:
    return (
        base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()
    )


def build_from_agent_manager(org_id: str, agent_manager: Any) -> LocalIssuer:
    """Construct a LocalIssuer from a loaded AgentManager.

    Raises RuntimeError if the Mastio identity has not been provisioned
    yet (``ensure_mastio_identity()`` not called, or Org CA not loaded).
    """
    if not getattr(agent_manager, "mastio_loaded", False):
        raise RuntimeError("Mastio identity not loaded")
    leaf_key = getattr(agent_manager, "_mastio_leaf_key", None)
    if leaf_key is None:
        raise RuntimeError("Mastio leaf key missing on agent manager")
    pubkey_pem = agent_manager.get_mastio_pubkey_pem()
    return LocalIssuer(org_id=org_id, leaf_key=leaf_key, leaf_pubkey_pem=pubkey_pem)
