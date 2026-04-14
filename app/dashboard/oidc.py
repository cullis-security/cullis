"""
OIDC (OpenID Connect) client for dashboard federation.

Supports OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636).
Used exclusively for the optional network-admin SSO login. Per-org OIDC
login was removed when the broker dashboard became network-admin-only
(org tenants now log in on the per-org proxy — see ADR-001).
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
    role: str = "admin"            # only "admin" is supported on the broker
    org_id: str | None = None      # unused; kept for cookie schema compat

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
            role=d.get("role", "admin"),
            org_id=d.get("org_id"),
        )


@dataclass
class OidcIdentity:
    sub: str
    email: str | None
    name: str | None
    issuer: str
    claims: dict  # raw claims from id_token (used for role mapping)


def _extract_claim(claims: dict, path: str) -> object:
    """
    Walk a dot-notation path through a claims dict/list tree.

    Examples:
        _extract_claim({"groups": ["a", "b"]}, "groups")        -> ["a", "b"]
        _extract_claim({"role": {"name": "admin"}}, "role.name") -> "admin"
        _extract_claim({"items": [{"id": 1}]}, "items.0.id")    -> 1

    Returns None if any path segment is missing or the type is unwalkable.
    """
    if not path:
        return None
    current: object = claims
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                idx = int(part)
            except ValueError:
                return None
            if 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
        else:
            return None
    return current


def validate_role_mapping(mapping: dict | None, claims: dict) -> tuple[bool, str]:
    """
    Validate OIDC claims against an org's role mapping configuration.

    Mapping schema (stored in organizations.metadata_json.oidc_role_mapping):
        {
          "claim_path": "groups",                    # dot-notation, required
          "admin_values": ["cullis-admin", "ops"],   # list of accepted values
          "default_role": "deny" | "org"             # behavior when claim missing
        }

    Returns (allowed, reason).
      - allowed=True  -> user is granted the "org" role
      - allowed=False -> user is denied (HTTP 403)
      - reason is a short machine-readable code for audit logging

    If `mapping` is None or empty, returns (True, "no_mapping_legacy") for
    backward compatibility with orgs that have not configured a mapping yet.
    """
    if not mapping:
        return True, "no_mapping_legacy"

    claim_path = mapping.get("claim_path")
    admin_values = mapping.get("admin_values") or []
    default_role = mapping.get("default_role", "deny")

    if not claim_path or not admin_values:
        # Misconfigured mapping → fail closed
        return False, "mapping_misconfigured"

    claim_value = _extract_claim(claims, claim_path)

    if claim_value is None:
        if default_role == "deny":
            return False, "claim_missing"
        return True, "default_allow"

    # Normalize to a list of strings (claim can be a single string or a list)
    if isinstance(claim_value, str):
        values = [claim_value]
    elif isinstance(claim_value, list):
        values = [str(v) for v in claim_value if v is not None]
    else:
        return False, "claim_type_invalid"

    admin_set = {str(v) for v in admin_values}
    if any(v in admin_set for v in values):
        return True, "match"

    if default_role == "deny":
        return False, "no_match"
    return True, "default_allow"


def create_oidc_state(role: str = "admin", org_id: str | None = None) -> OidcFlowState:
    """Generate cryptographically random state, nonce, and PKCE code_verifier.

    ``role`` and ``org_id`` are retained only for test/callsite compatibility
    — the broker OIDC flow always resolves to the network-admin session.
    """
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
    additional_scopes: list[str] | None = None,
) -> str:
    """
    Build the OIDC authorization URL with PKCE.

    `additional_scopes` are appended to the base "openid email profile" scope.
    Used by orgs that need extra claims (e.g. "groups") for role mapping.
    """
    doc = await _fetch_discovery(issuer_url)
    auth_endpoint = doc.get("authorization_endpoint")
    if not auth_endpoint:
        raise OidcError("No authorization_endpoint in discovery document")

    base_scopes = ["openid", "email", "profile"]
    if additional_scopes:
        for s in additional_scopes:
            if s and s not in base_scopes:
                base_scopes.append(s)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(base_scopes),
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
        claims=dict(claims),
    )
