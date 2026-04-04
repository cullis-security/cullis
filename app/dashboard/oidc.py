"""
OIDC (OpenID Connect) client for dashboard federation.

Supports OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636).
Used for both per-org and network-admin OIDC login.
"""
import base64
import hashlib
import logging
import os
import time
from dataclasses import dataclass

import httpx
from authlib.jose import jwt as authlib_jwt, JsonWebKey

_log = logging.getLogger("agent_trust")

# In-memory caches with TTL
_discovery_cache: dict[str, tuple[dict, float]] = {}
_DISCOVERY_TTL = 300  # 5 minutes

_jwks_cache: dict[str, tuple[dict, float]] = {}
_JWKS_TTL = 3600  # 1 hour


class OidcError(Exception):
    """Raised for any OIDC protocol failure."""
    pass


@dataclass
class OidcFlowState:
    state: str
    nonce: str
    code_verifier: str
    role: str              # "admin" or "org"
    org_id: str | None     # None for admin flow

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "nonce": self.nonce,
            "code_verifier": self.code_verifier,
            "role": self.role,
            "org_id": self.org_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OidcFlowState":
        return cls(
            state=d["state"],
            nonce=d["nonce"],
            code_verifier=d["code_verifier"],
            role=d["role"],
            org_id=d.get("org_id"),
        )


@dataclass
class OidcIdentity:
    sub: str
    email: str | None
    name: str | None
    issuer: str


def create_oidc_state(role: str, org_id: str | None = None) -> OidcFlowState:
    """Generate cryptographically random state, nonce, and PKCE code_verifier."""
    return OidcFlowState(
        state=os.urandom(32).hex(),
        nonce=os.urandom(32).hex(),
        code_verifier=base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode(),
        role=role,
        org_id=org_id,
    )


def _pkce_code_challenge(verifier: str) -> str:
    """Compute S256 code challenge from code verifier (RFC 7636)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def _fetch_discovery(issuer_url: str) -> dict:
    """Fetch and cache the OIDC discovery document."""
    now = time.time()
    cached = _discovery_cache.get(issuer_url)
    if cached and now - cached[1] < _DISCOVERY_TTL:
        return cached[0]

    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            raise OidcError(f"OIDC discovery failed for {issuer_url}: HTTP {resp.status_code}")
        doc = resp.json()

    _discovery_cache[issuer_url] = (doc, now)
    return doc


async def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch and cache the IdP's JSON Web Key Set."""
    now = time.time()
    cached = _jwks_cache.get(jwks_uri)
    if cached and now - cached[1] < _JWKS_TTL:
        return cached[0]

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        if resp.status_code != 200:
            raise OidcError(f"JWKS fetch failed: HTTP {resp.status_code}")
        jwks = resp.json()

    _jwks_cache[jwks_uri] = (jwks, now)
    return jwks


async def build_authorization_url(
    issuer_url: str,
    client_id: str,
    redirect_uri: str,
    flow_state: OidcFlowState,
) -> str:
    """Build the OIDC authorization URL with PKCE."""
    doc = await _fetch_discovery(issuer_url)
    auth_endpoint = doc.get("authorization_endpoint")
    if not auth_endpoint:
        raise OidcError("No authorization_endpoint in discovery document")

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": flow_state.state,
        "nonce": flow_state.nonce,
        "code_challenge": _pkce_code_challenge(flow_state.code_verifier),
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in auth_endpoint else "?"
    query = "&".join(f"{k}={httpx.URL('', params={k: v}).params[k]}" for k, v in params.items())
    return f"{auth_endpoint}{sep}{query}"


async def exchange_code_for_identity(
    issuer_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    code: str,
    flow_state: OidcFlowState,
) -> OidcIdentity:
    """Exchange authorization code for ID token and extract identity."""
    doc = await _fetch_discovery(issuer_url)
    token_endpoint = doc.get("token_endpoint")
    jwks_uri = doc.get("jwks_uri")
    if not token_endpoint or not jwks_uri:
        raise OidcError("Missing token_endpoint or jwks_uri in discovery document")

    # Token exchange
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": flow_state.code_verifier,
    }
    if client_secret:
        token_data["client_secret"] = client_secret

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_endpoint, data=token_data)
        if resp.status_code != 200:
            raise OidcError(f"Token exchange failed: HTTP {resp.status_code} — {resp.text[:200]}")
        token_resp = resp.json()

    id_token_str = token_resp.get("id_token")
    if not id_token_str:
        raise OidcError("No id_token in token response")

    # Validate ID token
    jwks_data = await _fetch_jwks(jwks_uri)
    try:
        jwk_set = JsonWebKey.import_key_set(jwks_data)
        claims = authlib_jwt.decode(id_token_str, jwk_set)
        claims.validate()
    except Exception as exc:
        raise OidcError(f"ID token validation failed: {exc}") from exc

    # Verify issuer, audience, nonce
    token_issuer = claims.get("iss", "")
    if token_issuer.rstrip("/") != issuer_url.rstrip("/"):
        raise OidcError(f"Issuer mismatch: expected {issuer_url}, got {token_issuer}")

    token_aud = claims.get("aud", "")
    if isinstance(token_aud, list):
        if client_id not in token_aud:
            raise OidcError(f"Audience mismatch: {client_id} not in {token_aud}")
    elif token_aud != client_id:
        raise OidcError(f"Audience mismatch: expected {client_id}, got {token_aud}")

    if claims.get("nonce") != flow_state.nonce:
        raise OidcError("Nonce mismatch — possible replay attack")

    return OidcIdentity(
        sub=claims["sub"],
        email=claims.get("email"),
        name=claims.get("name"),
        issuer=token_issuer,
    )
