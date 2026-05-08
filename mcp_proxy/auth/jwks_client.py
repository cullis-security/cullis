"""
Async JWKS client — fetches and caches public keys from the broker's JWKS endpoint.

Supports:
  - Remote JWKS URL (normal operation)
  - Local override file (air-gapped deployments)
  - Automatic cache refresh on key-id miss (with rate limiting)
"""
import json
import logging
import time

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

_log = logging.getLogger("mcp_proxy")

# JWK crv → (cryptography curve class, expected coord byte length)
_EC_JWK_CURVES = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
    "P-521": (ec.SECP521R1, 66),
}

# Minimum interval between forced re-fetches (prevents abuse)
_MIN_REFETCH_INTERVAL = 60  # seconds


from mcp_proxy.utils.validation import strict_b64url_decode as _strict_b64url_decode


def _b64url_decode(s: str) -> bytes:
    """Strict base64url decode — delegates to ``mcp_proxy.utils.validation``.

    Audit S8: previously inlined; now imports from the single vendored copy
    in mcp_proxy so all Mastio paths stay in sync.
    """
    return _strict_b64url_decode(s)


def _jwk_to_rsa_public_key(jwk: dict) -> RSAPublicKey:
    """Convert a JWK dict (kty=RSA) to a cryptography RSAPublicKey."""
    if jwk.get("kty") != "RSA":
        raise ValueError(f"Expected kty=RSA, got {jwk.get('kty')!r}")
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e=e, n=n).public_key()


def _jwk_to_ec_public_key(jwk: dict):
    """Convert a JWK dict (kty=EC) to a cryptography EllipticCurvePublicKey."""
    crv = jwk.get("crv")
    if crv not in _EC_JWK_CURVES:
        raise ValueError(f"Unsupported EC JWK curve: {crv!r}")
    curve_cls, _ = _EC_JWK_CURVES[crv]
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve_cls()).public_key()


def _jwk_to_public_key(jwk: dict):
    """Dispatch JWK → cryptography PublicKey on kty."""
    kty = jwk.get("kty")
    if kty == "RSA":
        return _jwk_to_rsa_public_key(jwk)
    if kty == "EC":
        return _jwk_to_ec_public_key(jwk)
    raise ValueError(f"Unsupported JWK kty: {kty!r}")


class JWKSClient:
    """Async JWKS fetcher with in-memory cache.

    Args:
        jwks_url: Remote JWKS endpoint URL.
        override_path: Local JSON file path (air-gapped fallback).
        refresh_interval: Maximum cache age in seconds before background refresh.
    """

    def __init__(
        self,
        jwks_url: str = "",
        override_path: str = "",
        refresh_interval: int = 3600,
    ) -> None:
        self._jwks_url = jwks_url
        self._override_path = override_path
        self._refresh_interval = refresh_interval
        self._cache: dict[str, RSAPublicKey] = {}  # kid -> RSAPublicKey
        self._last_fetch: float = 0
        self._http: httpx.AsyncClient | None = None

    async def _get_http(self) -> httpx.AsyncClient:
        """Lazy-init httpx client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
            )
        return self._http

    async def fetch(self) -> dict[str, RSAPublicKey]:
        """Fetch the JWKS and update the cache. Returns the full key map."""
        keys: dict[str, RSAPublicKey] = {}

        if self._override_path:
            # Air-gapped: load from local file
            _log.info("Loading JWKS from local file: %s", self._override_path)
            with open(self._override_path) as f:
                jwks_data = json.load(f)
        elif self._jwks_url:
            # Normal: fetch from remote
            _log.info("Fetching JWKS from: %s", self._jwks_url)
            client = await self._get_http()
            resp = await client.get(self._jwks_url)
            resp.raise_for_status()
            jwks_data = resp.json()
        else:
            _log.debug("No JWKS URL or override path configured — skipping fetch")
            return self._cache

        # Parse JWK set — accept both RSA and EC keys
        for jwk in jwks_data.get("keys", []):
            kid = jwk.get("kid")
            kty = jwk.get("kty")
            if not kid:
                _log.warning("Skipping JWK without kid: %s", jwk.get("alg"))
                continue
            if kty not in ("RSA", "EC"):
                _log.debug("Skipping unsupported kty: kid=%s kty=%s", kid, kty)
                continue
            try:
                keys[kid] = _jwk_to_public_key(jwk)
            except Exception as exc:
                _log.warning("Failed to parse JWK kid=%s: %s", kid, exc)

        # Merge new keys into cache rather than replacing — prevents transient
        # key removal during rotation if the JWKS endpoint temporarily returns
        # incomplete data.
        self._cache.update(keys)
        # Remove keys absent from the latest fetch only if they've been
        # missing for multiple consecutive fetches (tracked via _absent_count).
        if not hasattr(self, "_absent_count"):
            self._absent_count: dict[str, int] = {}
        stale_kids = set(self._cache.keys()) - set(keys.keys())
        for kid in stale_kids:
            self._absent_count[kid] = self._absent_count.get(kid, 0) + 1
            if self._absent_count[kid] >= 3:
                self._cache.pop(kid, None)
                self._absent_count.pop(kid, None)
                _log.info("JWKS key %s removed after 3 consecutive absences", kid)
        # Reset absent count for keys that reappeared
        for kid in keys:
            self._absent_count.pop(kid, None)
        self._last_fetch = time.time()
        _log.info("JWKS cache updated: %d key(s)", len(self._cache))
        return keys

    async def get_public_key(self, kid: str) -> RSAPublicKey:
        """Look up a public key by kid, re-fetching if necessary.

        Raises:
            KeyError: If the kid is not found even after a fresh fetch.
        """
        # Try cache first
        if kid in self._cache:
            return self._cache[kid]

        # Cache miss — re-fetch if cache is old enough
        age = time.time() - self._last_fetch
        if age >= _MIN_REFETCH_INTERVAL:
            _log.info("JWKS cache miss for kid=%s, re-fetching (cache age=%.0fs)", kid, age)
            await self.fetch()
            if kid in self._cache:
                return self._cache[kid]

        raise KeyError(f"Unknown key ID: {kid!r}")

    @property
    def cache_age(self) -> float:
        """Seconds since last fetch, or inf if never fetched."""
        if self._last_fetch == 0:
            return float("inf")
        return time.time() - self._last_fetch

    async def close(self) -> None:
        """Close the httpx client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
        _log.debug("JWKS client closed")
